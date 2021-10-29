//! Wasm represents the final binary
const Wasm = @This();

const std = @import("std");
const Atom = @import("Atom.zig");
const Object = @import("Object.zig");
const wasm = @import("data.zig");
const Symbol = @import("Symbol.zig");
const sections = @import("sections.zig");

const leb = std.leb;
const fs = std.fs;
const Allocator = std.mem.Allocator;

const log = std.log.scoped(.zwld);

/// The binary file that we will write the final binary data to
file: fs.File,
/// Configuration of the linker provided by the user
options: Options,
/// A list with references to objects we link to during `flush()`
objects: std.ArrayListUnmanaged(Object) = .{},
/// A map of global names to their symbol location in an object file
global_symbols: std.StringArrayHashMapUnmanaged(SymbolWithLoc) = .{},
/// Contains all atoms that have been created, used to clean up
managed_atoms: std.ArrayListUnmanaged(*Atom) = .{},
/// Maps atoms to their segment index
atoms: std.AutoHashMapUnmanaged(u32, *Atom) = .{},
/// All symbols created by the linker, rather than through
/// object files will be inserted in this list to manage them.
synthetic_symbols: std.ArrayListUnmanaged(Symbol) = .{},

// OUTPUT SECTIONS //
/// Output function signature types
types: sections.Types = .{},
/// Output import section
imports: sections.Imports = .{},
/// Output function section
functions: sections.Functions = .{},
/// Output table section
tables: sections.Tables = .{},
/// Output memory section, this will only be used when `options.import_memory`
/// is set to false. The limits will be set, based on the total data section size
/// and other configuration options.
memories: wasm.Memory = .{ .limits = .{ .min = 0, .max = null } },
/// Output global section
globals: sections.Globals = .{},
/// Output export section
exports: sections.Exports = .{},
/// Output element section
elements: sections.Elements = .{},
/// Index to a function defining the entry of the wasm file
entry: ?u32 = null,
/// Output data section, keyed by the segment name
/// Represents non-synthetic section entries
/// Used for code, data and custom sections.
segments: std.ArrayListUnmanaged(Segment) = .{},
/// Maps a data segment key (such as .rodata) to the index into `segments`
data_segments: std.StringArrayHashMapUnmanaged(u32) = .{},

/// Index into `atoms` that represents the code section
code_section_index: ?u32 = null,

pub const Segment = struct {
    alignment: u32,
    size: u32,
    offset: u32,
};

pub const SymbolWithLoc = struct {
    sym_index: u32,
    file: u16,
};

/// Options to pass to our linker which affects
/// the end result and tells the linker how to build the final binary.
pub const Options = struct {
    /// When the entry name is different than `_start`
    entry_name: ?[]const u8 = null,
    /// Points to where the global data will start
    global_base: ?u32 = null,
    /// Tells the linker we will import memory from the host environment
    import_memory: bool = false,
    /// Tells the linker we will import the function table from the host environment
    import_table: bool = false,
    /// Sets the initial memory of the data section
    /// Providing a value too low will result in a linking error.
    initial_memory: ?u32 = null,
    /// Sets the max memory for the data section.
    /// Will result in a linking error when it's smaller than `initial_memory`m
    /// or when the initial memory calculated by the linker is larger than the given maximum memory.
    max_memory: ?u32 = null,
    /// Tell the linker to merge data segments
    /// i.e. all '.rodata' will be merged into a .rodata segment.
    merge_data_segments: bool = true,
    /// Tell the linker we do not require a starting entry
    no_entry: bool = false,
    /// Tell the linker to put the stack first, instead of after the data
    stack_first: bool = false,
    /// Specifies the size of the stack in bytes
    stack_size: ?u32 = null,
};

/// Initializes a new wasm binary file at the given path.
/// Will overwrite any existing file at said path.
pub fn openPath(path: []const u8, options: Options) !Wasm {
    const file = try fs.cwd().createFile(path, .{
        .truncate = true,
        .read = true,
    });
    errdefer file.close();

    return Wasm{ .file = file, .options = options };
}

/// Releases any resources that is owned by `Wasm`,
/// usage after calling deinit is illegal behaviour.
pub fn deinit(self: *Wasm, gpa: *Allocator) void {
    for (self.objects.items) |*object| {
        object.file.?.close();
        object.deinit(gpa);
    }
    for (self.global_symbols.keys()) |name| {
        gpa.free(name);
    }
    for (self.managed_atoms.items) |atom| {
        atom.deinit(gpa);
    }
    self.managed_atoms.deinit(gpa);
    self.atoms.deinit(gpa);
    self.data_segments.deinit(gpa);
    self.segments.deinit(gpa);
    self.global_symbols.deinit(gpa);
    self.objects.deinit(gpa);
    self.functions.deinit(gpa);
    self.types.deinit(gpa);
    self.imports.deinit(gpa);
    self.globals.deinit(gpa);
    self.exports.deinit(gpa);
    self.elements.deinit(gpa);
    self.tables.deinit(gpa);
    self.file.close();
    self.* = undefined;
}

/// Parses objects from the given paths as well as append them to `self`
pub fn addObjects(self: *Wasm, gpa: *Allocator, file_paths: []const []const u8) !void {
    for (file_paths) |path| {
        const file = try fs.cwd().openFile(path, .{});
        errdefer file.close();
        var object = try Object.init(gpa, file, path);
        errdefer object.deinit(gpa);
        try self.objects.append(gpa, object);
    }
}

/// Flushes the `Wasm` construct into a final wasm binary by linking
/// the objects, ensuring the final binary file has no collisions.
pub fn flush(self: *Wasm, gpa: *Allocator) !void {
    for (self.objects.items) |_, obj_idx| {
        try self.resolveSymbolsInObject(gpa, @intCast(u16, obj_idx));
    }
    for (self.objects.items) |*object, obj_idx| {
        try object.parseIntoAtoms(gpa, @intCast(u16, obj_idx), self);
    }
    try self.setupLinkerSymbols(gpa);
    try self.setupStart();
    try self.mergeImports(gpa);
    try self.allocateAtoms();
    try self.setupMemory();
    try self.mergeSections(gpa);
    try self.mergeTypes(gpa);
    try self.setupExports(gpa);
    try self.relocateAtoms();

    try @import("emit_wasm.zig").emit(self);
}

fn resolveSymbolsInObject(self: *Wasm, gpa: *Allocator, object_index: u16) !void {
    const object: Object = self.objects.items[object_index];

    log.debug("resolving symbols in {s}", .{object.name});

    for (object.symtable) |*symbol, i| {
        const sym_idx = @intCast(u32, i);

        if (std.mem.eql(u8, symbol.name, Symbol.linker_defined.names.indirect_function_table)) {
            Symbol.linker_defined.indirect_function_table = symbol;
        }

        if (symbol.isWeak() or symbol.isGlobal()) {
            const name = try gpa.dupe(u8, symbol.name);
            const result = try self.global_symbols.getOrPut(gpa, name);
            defer if (result.found_existing) gpa.free(name);

            log.debug("Found symbol '{s}'", .{name});

            if (!result.found_existing) {
                result.value_ptr.* = .{
                    .sym_index = sym_idx,
                    .file = object_index,
                };
                continue;
            }

            const global: SymbolWithLoc = result.value_ptr.*;
            const linked_obj: Object = self.objects.items[global.file];
            const linked_sym = linked_obj.symtable[global.sym_index];

            if (!linked_sym.isUndefined()) {
                if (symbol.isGlobal() and linked_sym.isGlobal()) {
                    log.err("symbol '{s}' defined multiple times", .{name});
                    log.err("  first definition in '{s}'", .{linked_obj.name});
                    log.err("  next definition in '{s}'", .{object.name});
                    return error.SymbolCollision;
                }

                if (symbol.isWeak()) {
                    log.debug("symbol '{s}' already defined; skipping...", .{name});
                    continue;
                }
            }

            // simply overwrite an existing one with the new definition
            // as the symbol is a strong symbol
            result.value_ptr.* = .{
                .sym_index = sym_idx,
                .file = object_index,
            };
        }
    }
}

/// Calculates the new indexes for symbols and their respective symbols
fn mergeSections(self: *Wasm, gpa: *Allocator) !void {
    log.debug("Merging functions", .{});
    for (self.objects.items) |object| {
        for (object.functions) |*func| {
            try self.functions.append(gpa, self.imports.functionCount(), func);
        }
    }
    log.debug("Merged ({d}) functions", .{self.functions.count()});

    // merge globals
    {
        log.debug("Merging globals", .{});
        for (self.objects.items) |object| {
            for (object.globals) |*global| {
                try self.globals.append(gpa, self.imports.globalCount(), global);
            }
        }

        log.debug("Merged ({d}) globals", .{self.globals.count()});
    }

    // merge tables
    {
        // first append the indirect function table if initialized
        if (Symbol.linker_defined.indirect_function_table) |table| {
            log.debug("Appending indirect function table", .{});
            try self.tables.append(gpa, self.imports.tableCount(), table.kind.table.table);
        }
        for (self.objects.items) |object| {
            for (object.tables) |*table| {
                try self.tables.append(gpa, self.imports.tableCount(), table);
            }
        }
    }
}

fn mergeTypes(self: *Wasm, gpa: *Allocator) !void {
    log.debug("Merging types", .{});
    for (self.objects.items) |object| {
        for (object.types) |wasm_type| {
            // ignore the returned index
            _ = try self.types.append(gpa, wasm_type);
        }
    }
    log.debug("Merged ({d}) types from object files", .{self.types.count()});

    log.debug("Building types from import symbols", .{});
    for (self.imports.symbols()) |symbol| {
        if (symbol.kind == .function) {
            log.debug("Adding type from function '{s}'", .{symbol.name});
            // ignore the returned index. type will only be appended if it does
            // not exist yet.
            _ = try self.types.append(gpa, symbol.kind.function.func.func_type.*);
        }
    }

    log.debug("Building types from functions", .{});
    for (self.functions.items.items) |*func| {
        const index = try self.types.append(gpa, func.func_type.*);
        func.type_idx = index;
        func.func_type = self.types.get(index);
    }
    log.debug("Completed building types. Total count: ({d})", .{self.types.count()});
}

fn setupExports(self: *Wasm, gpa: *Allocator) !void {
    log.debug("Building exports from symbols", .{});

    // When importing memory option is false,
    // we export the memory.
    if (!self.options.import_memory) {
        try self.exports.append(gpa, .{ .name = "memory", .kind = .memory, .index = 0 });
    }

    var symbol_it = SymbolIterator.init(self);
    while (symbol_it.next()) |entry| {
        const symbol = entry.symbol;
        if (!symbol.isExported()) continue;
        // TODO: Uncomment this when we implement more of the garbage collection
        // if (!symbol.marked) continue;

        var name: []const u8 = symbol.name;
        var exported: wasm.Export = undefined;
        if (symbol.unwrapAs(.function)) |func| {
            // func cannot be `null` because only defined functions
            // can be exported, which is verified with `isExported()`
            if (func.func.export_name) |export_name| {
                name = export_name;
            }
            exported = .{ .name = name, .kind = .function, .index = func.functionIndex() };
        } else {
            log.debug("TODO: Export non-functions type({s}) name={s}", .{
                @tagName(std.meta.activeTag(symbol.kind)),
                name,
            });
            continue;
        }

        log.debug("Appending export from symbol '{s}' using name: '{s}'", .{
            symbol.name, name,
        });
        try self.exports.append(gpa, exported);
        try self.exports.appendSymbol(gpa, entry.symbol);
    }
    log.debug("Completed building exports. Total count: ({d})", .{self.exports.count()});
}

/// Creates symbols that are made by the linker, rather than the compiler/object file
fn setupLinkerSymbols(self: *Wasm, gpa: *Allocator) !void {
    // Create symbol for our stack pointer
    const stack_symbol = &Symbol.linker_defined.stack_pointer;

    stack_symbol.* = if (self.global_symbols.get("__stack_pointer")) |sym_with_loc| blk: {
        // TODO: Make this a lot nicer by logic to replace symbols
        const object = self.objects.items[sym_with_loc.file];
        const symbol = &object.symtable[sym_with_loc.sym_index];
        symbol.marked = true;
        symbol.setUndefined(false);
        try self.globals.append(gpa, 0, symbol.kind.global.global);
        symbol.kind.global.global = &self.globals.items.items[self.globals.count() - 1];
        break :blk symbol;
    } else null;
}

const SymbolIterator = struct {
    symbol_index: u32,
    file_index: u16,
    wasm: *Wasm,

    const Entry = struct {
        sym_index: u32,
        file_index: u16,
        symbol: *Symbol,
    };

    fn init(wasm_bin: *Wasm) SymbolIterator {
        return .{ .symbol_index = 0, .file_index = 0, .wasm = wasm_bin };
    }

    fn next(self: *SymbolIterator) ?Entry {
        if (self.file_index >= self.wasm.objects.items.len) return null;
        const object: *Object = &self.wasm.objects.items[self.file_index];
        if (self.symbol_index >= object.symtable.len) {
            self.file_index += 1;
            self.symbol_index = 0;
            return self.next();
        }

        const symbol = &object.symtable[self.symbol_index];
        defer self.symbol_index += 1;
        return Entry{
            .sym_index = self.symbol_index,
            .file_index = self.file_index,
            .symbol = symbol,
        };
    }
};

fn mergeImports(self: *Wasm, gpa: *Allocator) !void {
    for (self.objects.items) |object| {
        for (object.symtable) |*symbol| {
            if (!symbol.requiresImport()) {
                continue;
            }
            if (Symbol.linker_defined.indirect_function_table) |table| {
                if (symbol == table) continue;
            }
            log.err("Symbol '{s}' will be imported", .{symbol.name});
            try self.imports.appendSymbol(gpa, symbol);
        }
    }
    if (self.options.import_table) {
        if (Symbol.linker_defined.indirect_function_table) |existing_table| {
            try self.imports.appendSymbol(gpa, existing_table);
        }
    }
}

/// Sets up the memory section of the wasm module, as well as the stack.
fn setupMemory(self: *Wasm) !void {
    log.debug("Setting up memory layout", .{});
    const page_size = 64 * 1024;
    const stack_size = self.options.stack_size orelse page_size * 1;
    const stack_alignment = 16;
    var memory_ptr: u32 = self.options.global_base orelse 1024;
    memory_ptr = std.mem.alignForwardGeneric(u32, memory_ptr, stack_alignment);

    for (self.segments.items) |*segment, i| {
        // skip 'code' segments
        if (self.code_section_index) |index| {
            if (index == i) continue;
        }
        const alignment = @as(u64, 1) << @intCast(u6, segment.alignment);
        memory_ptr = std.mem.alignForwardGeneric(u32, memory_ptr, @truncate(u32, alignment));
        memory_ptr += segment.size;
    }

    memory_ptr = std.mem.alignForwardGeneric(u32, memory_ptr, stack_alignment);
    // TODO: Calculate this according to user input
    memory_ptr += stack_size;

    // Setup the max amount of pages
    const max_memory_allowed: u32 = (1 << 32) - 1;

    if (self.options.initial_memory) |initial_memory| {
        if (!std.mem.isAligned(initial_memory, page_size)) {
            log.err("Initial memory must be {d}-byte aligned", .{page_size});
            return error.MissAlignment;
        }
        if (memory_ptr > initial_memory) {
            log.err("Initial memory too small, must be at least {d} bytes", .{memory_ptr});
            return error.MemoryTooSmall;
        }
        if (initial_memory > max_memory_allowed) {
            log.err("Initial memory exceeds maximum memory {d}", .{max_memory_allowed});
            return error.MemoryTooBig;
        }
        memory_ptr = initial_memory;
    }

    // In case we do not import memory, but define it ourselves,
    // set the minimum amount of pages on the memory section.
    self.memories.limits.min = std.mem.alignForwardGeneric(u32, memory_ptr, page_size) / page_size;
    log.debug("Total memory pages: {d}", .{self.memories.limits.min});

    if (self.options.max_memory) |max_memory| {
        if (!std.mem.isAligned(max_memory, page_size)) {
            log.err("Maximum memory must be {d}-byte aligned", .{page_size});
            return error.MissAlignment;
        }
        if (memory_ptr > max_memory) {
            log.err("Maxmimum memory too small, must be at least {d} bytes", .{memory_ptr});
            return error.MemoryTooSmall;
        }
        if (max_memory > max_memory_allowed) {
            log.err("Maximum memory exceeds maxmium amount {d}", .{max_memory_allowed});
            return error.MemoryTooBig;
        }
        self.memories.limits.max = max_memory / page_size;
        log.debug("Maximum memory pages: {d}", .{self.memories.limits.max});
    }

    // set stack value on global
    if (Symbol.linker_defined.stack_pointer) |stack_pointer| {
        const global: *wasm.Global = stack_pointer.kind.global.global;
        global.init = .{ .i32_const = @bitCast(i32, memory_ptr) };
    }
}

/// From a given object's index and the index of the segment, returns the corresponding
/// index of the segment within the final data section. When the segment does not yet
/// exist, a new one will be initialized and appended. The new index will be returned in that case.
pub fn getMatchingSegment(self: *Wasm, gpa: *Allocator, object_index: u16, relocatable_index: u32) !u32 {
    const object: Object = self.objects.items[object_index];
    const relocatable_data = object.relocatable_data[relocatable_index];
    const index = @intCast(u32, self.segments.items.len);

    switch (relocatable_data.type) {
        .data => {
            const segment_info = object.segment_info[relocatable_data.index];
            const segment_name = if (self.options.merge_data_segments)
                segment_info.outputName()
            else
                segment_info.name;
            const result = try self.data_segments.getOrPut(gpa, segment_name);
            if (!result.found_existing) {
                result.value_ptr.* = index;
                try self.segments.append(gpa, .{
                    .alignment = 1,
                    .size = 0,
                    .offset = 0,
                });
                return index;
            } else return result.value_ptr.*;
        },
        .code => return self.code_section_index orelse blk: {
            self.code_section_index = index;
            try self.segments.append(gpa, .{
                .alignment = 1,
                .size = 0,
                .offset = 0,
            });
            break :blk index;
        },
        .custom => @panic("TODO: Custom section relocation"),
    }
}

fn allocateAtoms(self: *Wasm) !void {
    var it = self.atoms.iterator();
    while (it.next()) |entry| {
        const segment_index = entry.key_ptr.*;
        const segment: Segment = self.segments.items[segment_index];
        var atom: *Atom = entry.value_ptr.*.getFirst();

        log.debug("Allocating atoms for segment '{d}'", .{segment_index});

        var offset: u32 = segment.offset;
        while (true) {
            offset = std.mem.alignForwardGeneric(u32, offset, atom.alignment);
            atom.offset = offset;

            const object: *Object = &self.objects.items[atom.file];
            const symbol = &object.symtable[atom.sym_index];
            symbol.setIndex(segment_index);
            if (symbol.unwrapAs(.data)) |*data| {
                data.offset = offset;
                data.size = atom.size;
            }

            log.debug("Atom '{s}' allocated from 0x{x:0>8} to 0x{x:0>8} size={d}", .{
                symbol.name,
                offset,
                offset + atom.size,
                atom.size,
            });

            offset += atom.size;

            if (atom.next) |next| {
                atom = next;
            } else break;
        }
    }
}

fn relocateAtoms(self: *Wasm) !void {
    var it = self.atoms.valueIterator();
    while (it.next()) |next_atom| {
        var atom: *Atom = next_atom.*.getFirst();
        while (true) {
            // First perform relocations to rewrite the binary data
            try atom.resolveRelocs(self);
            if (atom.next) |next| {
                atom = next;
            } else break;
        }
    }
}

fn setupStart(self: *Wasm) !void {
    if (self.options.no_entry) return;
    const entry_name = self.options.entry_name orelse "_start";

    const symbol_with_loc: SymbolWithLoc = self.global_symbols.get(entry_name) orelse {
        log.err("Entry symbol '{s}' does not exist, use '--no-entry' to suppress", .{entry_name});
        return error.MissingSymbol;
    };
    const object = self.objects.items[symbol_with_loc.file];
    const symbol: *Symbol = &object.symtable[symbol_with_loc.sym_index];

    if (symbol.kind != .function) {
        log.err("Entry symbol '{s}' is not a function", .{entry_name});
        return error.InvalidEntryKind;
    }
    // Simply export the symbol as the start function is reserved
    // for synthetic symbols such as __wasm_start, __wasm_init_memory, and
    // __wasm_apply_global_relocs
    symbol.setFlag(.WASM_SYM_EXPORTED);
}
