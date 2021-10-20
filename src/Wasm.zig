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
/// Output memory section
memories: std.ArrayListUnmanaged(wasm.Memory) = .{},
/// Output global section
globals: sections.Globals = .{},
/// Output export section
exports: sections.Exports = .{},
/// Output element section
elements: sections.Elements = .{},
/// Output code section
code: std.ArrayListUnmanaged([]u8) = .{},
/// Output data section, keyed by the segment name
data: std.StringArrayHashMapUnmanaged(OutputSegment) = .{},

pub const SymbolWithLoc = struct {
    sym_index: u32,
    file: u16,
};

/// Represents a single segment within the data section
pub const OutputSegment = struct {
    /// Index of linear memory
    memory_index: u32,
    /// Where the segment's data within the entire data section starts
    offset: wasm.InitExpression,
    /// The actual data living in this segment
    data: [*]u8,
    /// Segment's alignment
    alignment: u32,
    /// The size of the segment
    size: u32,
    /// The index of this segment into the data section
    segment_index: u32,
    /// Offset into the data section
    section_offset: u32,
};

/// Options to pass to our linker which affects
/// the end result and tells the linker how to build the final binary.
pub const Options = struct {
    /// When the entry name is different than `_start`
    entry_name: ?[]const u8 = null,
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
    merge_data_segments: bool = false,
    /// Tell the linker we do not require a starting entry
    no_entry: bool = false,
    /// Tell the linker to put the stack first, instead of after the data
    stack_first: bool = false,
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
    for (self.data.values()) |segment| {
        gpa.free(segment.data[0..segment.size]);
    }
    for (self.managed_atoms.items) |atom| {
        atom.deinit(gpa);
    }
    self.managed_atoms.deinit(gpa);
    self.atoms.deinit(gpa);

    self.global_symbols.deinit(gpa);
    self.objects.deinit(gpa);
    self.functions.deinit(gpa);
    self.types.deinit(gpa);
    self.imports.deinit(gpa);
    self.globals.deinit(gpa);
    self.exports.deinit(gpa);
    self.elements.deinit(gpa);
    self.tables.deinit(gpa);
    self.code.deinit(gpa);
    self.memories.deinit(gpa);
    self.data.deinit(gpa);
    self.file.close();
    self.* = undefined;
}

/// Parses objects from the given paths as well as append them to `self`
pub fn addObjects(self: *Wasm, gpa: *Allocator, file_paths: []const []const u8) !void {
    errdefer for (self.objects.items) |*object| {
        object.file.?.close();
        object.deinit(gpa);
    } else self.objects.deinit(gpa);

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
    try self.mergeImports(gpa);
    try self.setupLinkerSymbols(gpa);
    try self.allocateAtoms();
    try self.setupMemory(gpa);
    try self.mergeSections(gpa);
    try self.mergeTypes(gpa);
    try self.setupExports(gpa);
    try self.relocateCode(gpa);
    try self.relocateAtoms(gpa);

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
    var symbol_it = SymbolIterator.init(self);
    while (symbol_it.next()) |entry| {
        const symbol = entry.symbol;
        if (!symbol.isExported()) continue;

        var name: []const u8 = symbol.name;
        var exported: wasm.Export = undefined;
        if (symbol.unwrapAs(.function)) |func| {
            // func cannot be `null` because only defined functions
            // can be exported, which is verified with `isExported()`
            if (func.func.export_name) |export_name| {
                name = export_name;
            }
            exported = .{
                .name = name,
                .kind = .function,
                .index = func.func.func_idx,
            };
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
        try self.globals.append(gpa, 0, symbol.kind.global.global);
        symbol.kind.global.global = &self.globals.items.items[symbol.kind.global.global.global_idx];
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

fn relocateCode(self: *Wasm, gpa: *Allocator) !void {
    log.debug("Merging code sections and performing relocations", .{});
    // Each function must have its own body
    try self.code.resize(gpa, self.functions.count());
    for (self.objects.items) |object| {
        for (object.code.bodies) |code, body_index| {
            const body_length = @intCast(u32, code.data.len);
            // check if we must perform relocations
            if (object.relocations.get(@intCast(u32, object.code.index))) |relocations| {
                const _rel: []const wasm.Relocation = relocations;
                log.debug("Found relocations for function body at index {d}", .{body_index});
                for (_rel) |rel| {
                    if (!isInbetween(code.offset, body_length, rel.offset)) {
                        continue;
                    }
                    const symbol: *Symbol = &object.symtable[rel.index];
                    const body_offset = rel.offset - code.offset;
                    switch (rel.relocation_type) {
                        .R_WASM_FUNCTION_INDEX_LEB,
                        .R_WASM_TABLE_INDEX_SLEB,
                        => {
                            log.debug("Performing relocation for function symbol '{s}' at offset=0x{x:0>8}", .{
                                symbol.name,
                                rel.offset,
                            });
                            try self.elements.appendSymbol(gpa, symbol);
                        },
                        .R_WASM_GLOBAL_INDEX_LEB => {
                            log.debug("GLOBAL TY: {s}", .{@tagName(symbol.kind)});
                            if (symbol.kind != .global) {
                                try self.globals.addGOTEntry(gpa, symbol, self);
                            }
                            const index = symbol.kind.global.global.global_idx;
                            log.debug("Performing relocation for global symbol '{s}' at offset=0x{x:0>8} body_offset=0x{x:0>8} index=({d})", .{
                                symbol.name,
                                rel.offset,
                                body_offset,
                                index,
                            });
                            leb.writeUnsignedFixed(5, code.data[body_offset..][0..5], index);
                        },
                        else => |ty| log.debug("TODO: Relocation for type {s}", .{@tagName(ty)}),
                    }
                }
            }
            log.debug("Merging code body for {}", .{code.func.func_idx});
            self.code.items[code.func.func_idx] = code.data;
        }
    }
}

/// Verifies if a given value is in between a minimum -and maximum value.
/// The maxmimum value is calculated using the length, both start and end are inclusive.
inline fn isInbetween(min: u32, length: u32, value: u32) bool {
    return value >= min and value <= min + length;
}

fn mergeImports(self: *Wasm, gpa: *Allocator) !void {
    for (self.objects.items) |object| {
        for (object.symtable) |*symbol| {
            if (symbol.requiresImport()) {
                log.debug("Symbol '{s}' will be imported", .{symbol.name});
                try self.imports.appendSymbol(gpa, symbol);
            }
        }
    }
}

/// Sets up the memory section of the wasm module, as well as the stack.
fn setupMemory(self: *Wasm, gpa: *Allocator) !void {
    log.debug("Setting up memory layout", .{});
    const page_size = 64 * 1024;
    const stack_size = page_size * 1;
    const stack_alignment = 16;
    var memory_ptr: u64 = 0;
    memory_ptr = std.mem.alignForwardGeneric(u64, memory_ptr, stack_alignment);

    // TODO: Calculate this according to user input
    memory_ptr += stack_size;

    // set stack value on global
    if (Symbol.linker_defined.stack_pointer) |stack_pointer| {
        const global: *wasm.Global = stack_pointer.kind.global.global;
        global.init = .{ .i32_const = @intCast(i32, @bitCast(i64, memory_ptr)) };
    }

    // setup memory TODO: Calculate based on data segments and configered pages by user
    try self.memories.append(gpa, .{
        .limits = .{
            .min = 2,
            .max = null,
        },
    });
}

/// From a given object's index and the index of the segment, returns the corresponding
/// index of the segment within the final data section. When the segment does not yet
/// exist, a new one will be initialized and appended. The new index will be returned in that case.
pub fn getMatchingSegment(self: *Wasm, gpa: *Allocator, object_index: u16, segment_index: u32) !u32 {
    const object = self.objects.items[object_index];
    const segment_name = object.segment_info[segment_index].outputName();

    const result = try self.data.getOrPut(gpa, segment_name);
    if (!result.found_existing) {
        const index = @intCast(u32, self.data.count() - 1);
        result.value_ptr.* = .{
            .alignment = 1,
            .data = undefined,
            .memory_index = 0,
            .offset = .{ .i32_const = 0 },
            .section_offset = 0,
            .segment_index = index,
            .size = 0,
        };
        return index;
    } else return result.value_ptr.*.segment_index;
}

fn allocateAtoms(self: *Wasm) !void {
    var it = self.atoms.iterator();
    while (it.next()) |entry| {
        const segment_index = entry.key_ptr.*;
        const segment: OutputSegment = self.data.values()[segment_index];
        var atom: *Atom = entry.value_ptr.*.getFirst();

        log.debug("Allocating atoms for segment '{s}'", .{self.data.keys()[segment_index]});

        var offset: u32 = segment.section_offset;
        while (true) {
            offset = std.mem.alignForwardGeneric(u32, offset, atom.alignment);

            const object: *Object = &self.objects.items[atom.file];
            const symbol = &object.symtable[atom.sym_index].kind.data;
            symbol.offset = offset;
            symbol.index = segment_index;
            symbol.size = atom.size;

            log.debug("Atom '{s}' allocated from 0x{x:8>0} to 0x{x:8>0}", .{
                object.symtable[atom.sym_index].name,
                offset,
                offset + atom.size,
            });

            // Update aliases to this atom
            for (atom.aliases.items) |index| {
                const alias_sym = &object.symtable[index].kind.data;
                alias_sym.offset = offset;
                alias_sym.index = segment_index;
                alias_sym.size = atom.size;
            }

            // Update the symbol contained within this segment
            for (atom.contained.items) |sym_at_off| {
                const contained_sym = &object.symtable[sym_at_off.local_sym_index].kind.data;
                contained_sym.index = segment_index;
                contained_sym.offset = offset + sym_at_off.offset;
            }

            offset += atom.size;

            if (atom.next) |next| {
                atom = next;
            } else break;
        }
    }
}

fn relocateAtoms(self: *Wasm, gpa: *Allocator) !void {
    var it = self.atoms.iterator();
    while (it.next()) |entry| {
        const segment_index = entry.key_ptr.*;
        const segment: *OutputSegment = &self.data.values()[segment_index];
        var atom: *Atom = entry.value_ptr.*.getFirst();

        const code = try gpa.alloc(u8, segment.size);
        std.mem.set(u8, code, 0);
        segment.data = code.ptr;
        while (true) {
            // First perform relocations to rewrite the binary data
            try atom.resolveRelocs(gpa, self);

            // Merge the data into the final segment
            const object = self.objects.items[atom.file];
            const symbol: Symbol = object.symtable[atom.sym_index];
            std.mem.copy(u8, code[symbol.kind.data.offset.?..][0..atom.size], atom.code.items);

            if (atom.next) |next| {
                atom = next;
            } else break;
        }
    }
}
