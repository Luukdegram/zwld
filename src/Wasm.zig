//! Wasm represents the final binary
const Wasm = @This();

const std = @import("std");
const Atom = @import("Atom.zig");
const Object = @import("Object.zig");
const Archive = @import("Archive.zig");
const types = @import("types.zig");
const Symbol = @import("Symbol.zig");
const sections = @import("sections.zig");

const leb = std.leb;
const fs = std.fs;
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;
const mem = std.mem;

const log = std.log.scoped(.zwld);

/// The binary file that we will write the final binary data to
file: fs.File,
/// Configuration of the linker provided by the user
options: Options,
/// Output path of the binary
name: []const u8,
/// A list with references to objects we link to during `flush()`
objects: std.ArrayListUnmanaged(Object) = .{},
/// A list of archive files which are lazily linked with the final binary.
/// Referencing a Symbol from any of its object files will cause the object
/// file to be linked into the final binary.
archives: std.ArrayListUnmanaged(Archive) = .{},
/// A map of global names to their symbol location in an object file
global_symbols: std.AutoHashMapUnmanaged(u32, SymbolWithLoc) = .{},
/// Contains all atoms that have been created, used to clean up
managed_atoms: std.ArrayListUnmanaged(*Atom) = .{},
/// Maps atoms to their segment index
atoms: std.AutoHashMapUnmanaged(u32, *Atom) = .{},
/// Maps a symbol's location to an atom. This can be used to find meta
/// data of a symbol, such as its size, or its offset to perform a relocation.
/// Undefined (and synthetic) symbols do not have an Atom and therefore cannot be mapped.
symbol_atom: std.AutoHashMapUnmanaged(SymbolWithLoc, *Atom) = .{},
/// All symbols created by the linker, rather than through
/// object files will be inserted in this list to manage them.
synthetic_symbols: std.StringArrayHashMapUnmanaged(Symbol) = .{},
/// List of all symbol locations which have been resolved by the linker
/// and will be emit into the final binary.
resolved_symbols: std.AutoArrayHashMapUnmanaged(SymbolWithLoc, void) = .{},
/// Maps discarded symbols and their positions to the location of the symbol
/// it was resolved to.
discarded: std.AutoHashMapUnmanaged(SymbolWithLoc, SymbolWithLoc) = .{},
/// Symbols that remain undefined after symbol resolution.
undefs: std.StringArrayHashMapUnmanaged(SymbolWithLoc) = .{},

/// String table, used to deduplicate all symbol names
string_table: StringTable = .{},

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
memories: std.wasm.Memory = .{ .limits = .{ .min = 0, .max = null } },
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

/// Describes the location of a symbol
pub const SymbolWithLoc = struct {
    /// Symbol entry index within the object/binary file
    sym_index: u32,
    /// When file is `null`, this symbol refers to a synthetic symbol.
    file: ?u16,

    /// From a given location, find the corresponding symbol in the wasm binary.
    pub fn getSymbol(loc: SymbolWithLoc, wasm: *const Wasm) *Symbol {
        if (wasm.discarded.get(loc)) |new_loc| return new_loc.getSymbol(wasm);

        if (loc.file) |file_index| {
            const object = wasm.objects.items[file_index];
            return &object.symtable[loc.sym_index];
        }
        return &wasm.synthetic_symbols.values()[loc.sym_index];
    }

    /// From a given location, returns the name of the symbol.
    pub fn getName(loc: SymbolWithLoc, wasm_bin: *const Wasm) []const u8 {
        if (wasm_bin.discarded.get(loc)) |new_loc| {
            return new_loc.getName(wasm_bin);
        }
        if (loc.file) |object_index| {
            const object: Object = wasm_bin.objects.items[object_index];
            return object.string_table.get(object.symtable[loc.sym_index].name);
        }
        return wasm_bin.string_table.get(wasm_bin.synthetic_symbols.values()[loc.sym_index].name);
    }

    /// From a given symbol location, returns the final location.
    /// e.g. when a symbol was resolved and replaced by the symbol
    /// in a different file, this will return said location.
    /// If the symbol wasn't replaced by another, this will return
    /// the given location itwasm.
    pub fn finalLoc(loc: SymbolWithLoc, wasm_bin: *const Wasm) SymbolWithLoc {
        if (wasm_bin.discarded.get(loc)) |new_loc| {
            return new_loc.finalLoc(wasm_bin);
        }
        return loc;
    }
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

    return Wasm{ .file = file, .options = options, .name = path };
}

/// Releases any resources that is owned by `Wasm`,
/// usage after calling deinit is illegal behaviour.
pub fn deinit(wasm: *Wasm, gpa: Allocator) void {
    for (wasm.objects.items) |*object| {
        object.deinit(gpa);
    }
    for (wasm.archives.items) |*archive| {
        archive.deinit(gpa);
    }
    for (wasm.managed_atoms.items) |atom| {
        atom.deinit(gpa);
    }
    wasm.synthetic_symbols.deinit(gpa);
    wasm.symbol_atom.deinit(gpa);
    wasm.discarded.deinit(gpa);
    wasm.resolved_symbols.deinit(gpa);
    wasm.managed_atoms.deinit(gpa);
    wasm.atoms.deinit(gpa);
    wasm.data_segments.deinit(gpa);
    wasm.segments.deinit(gpa);
    wasm.global_symbols.deinit(gpa);
    wasm.objects.deinit(gpa);
    wasm.archives.deinit(gpa);
    wasm.functions.deinit(gpa);
    wasm.types.deinit(gpa);
    wasm.imports.deinit(gpa);
    wasm.globals.deinit(gpa);
    wasm.exports.deinit(gpa);
    wasm.elements.deinit(gpa);
    wasm.tables.deinit(gpa);
    wasm.string_table.deinit(gpa);
    wasm.undefs.deinit(gpa);
    wasm.file.close();
    wasm.* = undefined;
}

pub fn parseInputFiles(wasm: *Wasm, gpa: Allocator, files: []const []const u8) !void {
    for (files) |path| {
        if (try wasm.parseObjectFile(gpa, path)) continue;
        if (try wasm.parseArchive(gpa, path, false)) continue; // load archives lazily
        log.warn("Unexpected file format at path: '{s}'", .{path});
    }
}

/// Attempts to parse an object file. Returns `false` when given path
/// does not represent an object file.
fn parseObjectFile(wasm: *Wasm, gpa: Allocator, path: []const u8) !bool {
    const file = try fs.cwd().openFile(path, .{});
    errdefer file.close();
    var object = Object.create(gpa, file, path, null) catch |err| switch (err) {
        error.InvalidMagicByte, error.NotObjectFile => {
            // file.close();
            return false;
        },
        else => |e| return e,
    };
    errdefer object.deinit(gpa);
    try wasm.objects.append(gpa, object);
    return true;
}

/// Parses an archive file and will then parse each object file
/// that was found in the archive file.
/// Returns false when the file is not an archive file.
/// May return an error instead when parsing failed.
///
/// When `force_load` is `true`, it will for link all object files in the archive.
/// When false, it will only link with object files that contain symbols that
/// are referenced by other object files or Zig code.
fn parseArchive(wasm: *Wasm, gpa: Allocator, path: []const u8, force_load: bool) !bool {
    const file = try fs.cwd().openFile(path, .{});
    errdefer file.close();

    var archive: Archive = .{
        .file = file,
        .name = path,
    };
    archive.parse(gpa) catch |err| switch (err) {
        error.EndOfStream, error.NotArchive => {
            archive.deinit(gpa);
            return false;
        },
        else => |e| return e,
    };

    if (!force_load) {
        errdefer archive.deinit(gpa);
        try wasm.archives.append(gpa, archive);
        return true;
    }
    defer archive.deinit(gpa);

    // In this case we must force link all embedded object files within the archive
    // We loop over all symbols, and then group them by offset as the offset
    // notates where the object file starts.
    var offsets = std.AutoArrayHashMap(u32, void).init(gpa);
    defer offsets.deinit();
    for (archive.toc.values()) |symbol_offsets| {
        for (symbol_offsets.items) |sym_offset| {
            try offsets.put(sym_offset, {});
        }
    }

    for (offsets.keys()) |file_offset| {
        const object = try wasm.objects.addOne(gpa);
        object.* = try archive.parseObject(gpa, file_offset);
    }

    return true;
}

/// Returns the data section entry count, skipping the .bss section
pub fn dataCount(wasm: Wasm) u32 {
    var i: u32 = 0;
    for (wasm.data_segments.keys()) |key| {
        if (std.mem.eql(u8, key, ".bss") and !wasm.options.import_memory) continue;
        i += 1;
    }
    return i;
}

/// Flushes the `Wasm` construct into a final wasm binary by linking
/// the objects, ensuring the final binary file has no collisions.
pub fn flush(wasm: *Wasm, gpa: Allocator) !void {
    try wasm.setupLinkerSymbols(gpa);
    for (wasm.objects.items) |_, obj_idx| {
        try wasm.resolveSymbolsInObject(gpa, @intCast(u16, obj_idx));
    }
    try wasm.resolveSymbolsInArchives(gpa);
    for (wasm.objects.items) |*object, obj_idx| {
        try object.parseIntoAtoms(gpa, @intCast(u16, obj_idx), wasm);
    }
    try wasm.setupStart();
    try wasm.mergeImports(gpa);
    try wasm.allocateAtoms(gpa);
    try wasm.setupMemory();
    try wasm.mergeSections(gpa);
    try wasm.mergeTypes(gpa);
    try wasm.setupExports(gpa);
    try wasm.relocateAtoms();

    try @import("emit_wasm.zig").emit(wasm, gpa);
}

/// Generic string table that duplicates strings
/// and converts them into offsets instead.
pub const StringTable = struct {
    /// Table that maps string offsets, which is used to de-duplicate strings.
    /// Rather than having the offset map to the data, the `StringContext` holds all bytes of the string.
    /// The strings are stored as a contigious array where each string is zero-terminated.
    string_table: std.HashMapUnmanaged(
        u32,
        void,
        std.hash_map.StringIndexContext,
        std.hash_map.default_max_load_percentage,
    ) = .{},
    /// Holds the actual data of the string table.
    string_data: std.ArrayListUnmanaged(u8) = .{},

    /// Accepts a string and searches for a corresponding string.
    /// When found, de-duplicates the string and returns the existing offset instead.
    /// When the string is not found in the `string_table`, a new entry will be inserted
    /// and the new offset to its data will be returned.
    pub fn put(table: *StringTable, allocator: Allocator, string: []const u8) !u32 {
        const gop = try table.string_table.getOrPutContextAdapted(
            allocator,
            string,
            std.hash_map.StringIndexAdapter{ .bytes = &table.string_data },
            .{ .bytes = &table.string_data },
        );
        if (gop.found_existing) {
            const off = gop.key_ptr.*;
            log.debug("reusing string '{s}' at offset 0x{x}", .{ string, off });
            return off;
        }

        try table.string_data.ensureUnusedCapacity(allocator, string.len + 1);
        const offset = @intCast(u32, table.string_data.items.len);

        log.debug("writing new string '{s}' at offset 0x{x}", .{ string, offset });

        table.string_data.appendSliceAssumeCapacity(string);
        table.string_data.appendAssumeCapacity(0);

        gop.key_ptr.* = offset;

        return offset;
    }

    /// From a given offset, returns its corresponding string value.
    /// Asserts offset does not exceed bounds.
    pub fn get(table: StringTable, off: u32) []const u8 {
        assert(off < table.string_data.items.len);
        return mem.sliceTo(@ptrCast([*:0]const u8, table.string_data.items.ptr + off), 0);
    }

    /// Returns the offset of a given string when it exists.
    /// Will return null if the given string does not yet exist within the string table.
    pub fn getOffset(table: *StringTable, string: []const u8) ?u32 {
        return table.string_table.getKeyAdapted(
            string,
            std.hash_map.StringIndexAdapter{ .bytes = &table.string_data },
        );
    }

    /// Frees all resources of the string table. Any references pointing
    /// to the strings will be invalid.
    pub fn deinit(table: *StringTable, allocator: Allocator) void {
        table.string_data.deinit(allocator);
        table.string_table.deinit(allocator);
        table.* = undefined;
    }
};

fn resolveSymbolsInObject(wasm: *Wasm, gpa: Allocator, object_index: u16) !void {
    const object: Object = wasm.objects.items[object_index];
    log.debug("Resolving symbols in object: '{s}'", .{object.name});

    for (object.symtable) |symbol, i| {
        const sym_index = @intCast(u32, i);
        const location: SymbolWithLoc = .{
            .file = object_index,
            .sym_index = sym_index,
        };
        const sym_name = object.string_table.get(symbol.name);
        if (mem.eql(u8, sym_name, "__indirect_function_table")) {
            continue;
        }
        const sym_name_index = try wasm.string_table.put(gpa, sym_name);

        if (symbol.isLocal()) {
            if (symbol.isUndefined()) {
                log.err("Local symbols are not allowed to reference imports", .{});
                log.err("  symbol '{s}' defined in '{s}'", .{ sym_name, object.name });
                return error.UndefinedLocal;
            }
            try wasm.resolved_symbols.putNoClobber(gpa, location, {});
            continue;
        }

        const maybe_existing = try wasm.global_symbols.getOrPut(gpa, sym_name_index);
        if (!maybe_existing.found_existing) {
            maybe_existing.value_ptr.* = location;
            try wasm.resolved_symbols.putNoClobber(gpa, location, {});

            if (symbol.isUndefined()) {
                try wasm.undefs.putNoClobber(gpa, sym_name, location);
            }
            continue;
        }

        const existing_loc = maybe_existing.value_ptr.*;
        const existing_sym: *Symbol = existing_loc.getSymbol(wasm);

        const existing_file_path = if (existing_loc.file) |file| blk: {
            break :blk wasm.objects.items[file].name;
        } else wasm.name;

        if (!existing_sym.isUndefined()) outer: {
            if (!symbol.isUndefined()) inner: {
                if (symbol.isWeak()) {
                    break :inner; // ignore the new symbol (discard it)
                }
                if (existing_sym.isWeak()) {
                    break :outer; // existing is weak, while new one isn't. Replace it.
                }
                // both are defined and weak, we have a symbol collision.
                log.err("symbol '{s}' defined multiple times", .{sym_name});
                log.err("  first definition in '{s}'", .{existing_file_path});
                log.err("  next definition in '{s}'", .{object.name});
                return error.SymbolCollision;
            }

            try wasm.discarded.put(gpa, location, existing_loc);
            continue; // Do not overwrite defined symbols with undefined symbols
        }

        if (symbol.tag != existing_sym.tag) {
            log.err("symbol '{s}' mismatching type '{s}", .{ sym_name, @tagName(symbol.tag) });
            log.err("  first definition in '{s}'", .{existing_file_path});
            log.err("  next definition in '{s}'", .{object.name});
            return error.SymbolMismatchingType;
        }

        if (existing_sym.isUndefined() and symbol.isUndefined()) {
            const file_index = existing_loc.file.?;
            const obj = wasm.objects.items[file_index];
            const name_index = obj.findImport(symbol.tag.externalType(), existing_sym.index).module_name;
            const existing_name = obj.string_table.get(name_index);

            const module_index = object.findImport(symbol.tag.externalType(), symbol.index).module_name;
            const module_name = object.string_table.get(module_index);
            if (!mem.eql(u8, existing_name, module_name)) {
                log.err("symbol '{s}' module name mismatch. Expected '{s}', but found '{s}'", .{
                    sym_name,
                    existing_name,
                    module_name,
                });
                log.err("  first definition in '{s}'", .{existing_file_path});
                log.err("  next definition in '{s}'", .{object.name});
                return error.ModuleNameMismatch;
            }
        }

        if (existing_sym.tag == .global) {
            const existing_ty = wasm.getGlobalType(existing_loc);
            const new_ty = wasm.getGlobalType(location);
            if (existing_ty.mutable != new_ty.mutable or existing_ty.valtype != new_ty.valtype) {
                log.err("symbol '{s}' mismatching global types", .{sym_name});
                log.err("  first definition in '{s}'", .{existing_file_path});
                log.err("  next definition in '{s}'", .{object.name});
                return error.GlobalTypeMismatch;
            }
        }

        if (existing_sym.tag == .function) {
            const existing_ty = wasm.getFunctionSignature(existing_loc);
            const new_ty = wasm.getFunctionSignature(location);
            if (!existing_ty.eql(new_ty)) {
                log.err("symbol '{s}' mismatching function signatures.", .{sym_name});
                log.err("  expected signature {}, but found signature {}", .{ existing_ty, new_ty });
                log.err("  first definition in '{s}'", .{existing_file_path});
                log.err("  next definition in '{s}'", .{object.name});
                return error.FunctionSignatureMismatch;
            }
        }

        // when both symbols are weak, we skip overwriting
        if (existing_sym.isWeak() and symbol.isWeak()) {
            try wasm.discarded.put(gpa, location, existing_loc);
            continue;
        }

        // simply overwrite with the new symbol
        log.debug("Overwriting symbol '{s}'", .{sym_name});
        log.debug("  old definition in '{s}'", .{existing_file_path});
        log.debug("  new definition in '{s}'", .{object.name});
        try wasm.discarded.putNoClobber(gpa, existing_loc, location);
        maybe_existing.value_ptr.* = location;
        try wasm.global_symbols.put(gpa, sym_name_index, location);
        try wasm.resolved_symbols.put(gpa, location, {});
        assert(wasm.resolved_symbols.swapRemove(existing_loc));
        if (existing_sym.isUndefined()) {
            assert(wasm.undefs.swapRemove(sym_name));
        }
    }
}

/// Resolves the symbols in each archive file.
/// When resolved to a symbol from an object file,
/// this will result into loading the object file within
/// the archive file and linking with it.
fn resolveSymbolsInArchives(wasm: *Wasm, gpa: Allocator) !void {
    if (wasm.archives.items.len == 0) return;

    log.debug("Resolving symbols in archives", .{});
    var index: u32 = 0;
    undef_loop: while (index < wasm.undefs.count()) {
        const undef_sym_loc = wasm.undefs.values()[index];
        const sym_name = undef_sym_loc.getName(wasm);

        for (wasm.archives.items) |archive| {
            const offset = archive.toc.get(sym_name) orelse {
                // symbol does not exist in this archive
                continue;
            };

            log.debug("Detected symbol '{s}' in archive '{s}', parsing objects..", .{ sym_name, archive.name });
            // Symbol is found in unparsed object file within current archive.
            // Parse object and and resolve symbols again before we check remaining
            // undefined symbols.
            const object_file_index = @intCast(u16, wasm.objects.items.len);
            var object = try archive.parseObject(gpa, offset.items[0]);
            try wasm.objects.append(gpa, object);
            try wasm.resolveSymbolsInObject(gpa, object_file_index);

            // continue loop for any remaining undefined symbols that still exist
            // after resolving last object file
            continue :undef_loop;
        }
        index += 1;
    }
}

/// From a given symbol location, returns its `wasm.GlobalType`.
/// Asserts the Symbol represents a global.
fn getGlobalType(wasm: *const Wasm, loc: SymbolWithLoc) std.wasm.GlobalType {
    const symbol = loc.getSymbol(wasm);
    assert(symbol.tag == .global);
    const is_undefined = symbol.isUndefined();
    if (loc.file) |file_index| {
        const obj: Object = wasm.objects.items[file_index];
        if (is_undefined) {
            return obj.findImport(.global, symbol.index).kind.global;
        }
        const import_global_count = obj.importedCountByKind(.global);
        return obj.globals[symbol.index - import_global_count].global_type;
    }
    assert(!is_undefined);
    return wasm.globals.items.items[symbol.index].global_type;
}

/// From a given symbol location, returns its `wasm.Type`.
/// Asserts the Symbol represents a function.
fn getFunctionSignature(wasm: *const Wasm, loc: SymbolWithLoc) std.wasm.Type {
    const symbol = loc.getSymbol(wasm);
    assert(symbol.tag == .function);
    const is_undefined = symbol.isUndefined();
    if (loc.file) |file_index| {
        const obj: Object = wasm.objects.items[file_index];
        if (is_undefined) {
            const ty_index = obj.findImport(.function, symbol.index).kind.function;
            return obj.func_types[ty_index];
        }
        const import_function_count = obj.importedCountByKind(.function);
        const type_index = obj.functions[symbol.index - import_function_count].type_index;
        return obj.func_types[type_index];
    }
    assert(!is_undefined);
    return wasm.types.get(wasm.functions.items.items[symbol.index].type_index).*;
}

/// Calculates the new indexes for symbols and their respective symbols
fn mergeSections(wasm: *Wasm, gpa: Allocator) !void {
    // first append the indirect function table if initialized
    if (wasm.string_table.getOffset("__indirect_function_table")) |offset| {
        log.debug("Appending indirect function table", .{});
        const sym_with_loc = wasm.global_symbols.get(offset).?;
        const object: Object = wasm.objects.items[sym_with_loc.file.?];
        const symbol = sym_with_loc.getSymbol(wasm);
        const imp = object.findImport(.table, object.symtable[sym_with_loc.sym_index].index);
        symbol.index = try wasm.tables.append(gpa, wasm.imports.tableCount(), imp.kind.table);
    }

    log.debug("Merging sections", .{});
    for (wasm.resolved_symbols.keys()) |sym_with_loc| {
        const object = wasm.objects.items[sym_with_loc.file orelse continue]; // synthetic symbols do not need to be merged
        const symbol: *Symbol = &object.symtable[sym_with_loc.sym_index];
        if (symbol.isUndefined()) continue; // skip imports
        switch (symbol.tag) {
            .function => {
                const offset = object.importedCountByKind(.function);
                const original_func = object.functions[symbol.index - offset];
                symbol.index = try wasm.functions.append(
                    gpa,
                    wasm.imports.functionCount(),
                    original_func,
                );
            },
            .global => {
                const offset = object.importedCountByKind(.global);
                const original_global = object.globals[symbol.index - offset];
                symbol.index = try wasm.globals.append(
                    gpa,
                    wasm.imports.globalCount(),
                    original_global,
                );
            },
            .table => {
                const offset = object.importedCountByKind(.table);
                const original_table = object.tables[symbol.index - offset];
                symbol.index = try wasm.tables.append(
                    gpa,
                    wasm.imports.tableCount(),
                    original_table,
                );
            },
            else => {},
        }
    }
    log.debug("Merged ({d}) functions", .{wasm.functions.count()});
    log.debug("Merged ({d}) globals", .{wasm.globals.count()});
    log.debug("Merged ({d}) tables", .{wasm.tables.count()});
}

fn mergeTypes(wasm: *Wasm, gpa: Allocator) !void {
    log.debug("Merging types", .{});
    for (wasm.resolved_symbols.keys()) |sym_with_loc| {
        const object = wasm.objects.items[sym_with_loc.file orelse continue]; // synthetic symbols do not need to be merged
        const symbol: Symbol = object.symtable[sym_with_loc.sym_index];
        if (symbol.tag == .function) {
            if (symbol.isUndefined()) {
                log.debug("Adding type from extern function '{s}'", .{object.string_table.get(symbol.name)});
                const value = &wasm.imports.imported_functions.values()[symbol.index];
                value.type = try wasm.types.append(gpa, object.func_types[value.type]);
                continue;
            }
            log.debug("Adding type from function '{s}'", .{object.string_table.get(symbol.name)});
            const func = &wasm.functions.items.items[symbol.index - wasm.imports.functionCount()];
            func.type_index = try wasm.types.append(gpa, object.func_types[func.type_index]);
        }
    }
    log.debug("Completed building types. Total count: ({d})", .{wasm.types.count()});
}

fn setupExports(wasm: *Wasm, gpa: Allocator) !void {
    log.debug("Building exports from symbols", .{});

    // When importing memory option is false,
    // we export the memory.
    if (!wasm.options.import_memory) {
        try wasm.exports.append(gpa, .{ .name = "memory", .kind = .memory, .index = 0 });
    }

    var symbol_it = SymbolIterator.init(wasm);
    while (symbol_it.next()) |entry| {
        const symbol = entry.symbol;
        if (!symbol.isExported()) continue;

        const name: []const u8 = wasm.string_table.get(symbol.name);
        var exported: std.wasm.Export = undefined;
        if (symbol.tag == .function) {
            exported = .{ .name = name, .kind = .function, .index = symbol.index };
        } else {
            log.warn("TODO: Export non-functions type({s}) name={s}", .{
                @tagName(symbol.tag),
                name,
            });
            continue;
        }

        log.debug("Appending export from symbol '{s}' using name: '{s}' index: {d}", .{
            wasm.string_table.get(symbol.name), name, symbol.index,
        });
        try wasm.exports.append(gpa, exported);
        try wasm.exports.appendSymbol(gpa, entry.symbol);
    }
    log.debug("Completed building exports. Total count: ({d})", .{wasm.exports.count()});
}

/// Creates symbols that are made by the linker, rather than the compiler/object file
fn setupLinkerSymbols(wasm: *Wasm, gpa: Allocator) !void {
    const name_offset = try wasm.string_table.put(gpa, "__stack_pointer");
    var symbol: Symbol = .{
        .flags = 0,
        .name = name_offset,
        .tag = .global,
        .index = 0,
    };

    const global: std.wasm.Global = .{
        .init = .{ .i32_const = 0 },
        .global_type = .{ .valtype = .i32, .mutable = true },
    };

    symbol.index = try wasm.globals.append(gpa, 0, global);

    const sym_index = @intCast(u32, wasm.synthetic_symbols.count());
    const loc: SymbolWithLoc = .{ .sym_index = sym_index, .file = null };
    try wasm.synthetic_symbols.putNoClobber(gpa, wasm.string_table.get(name_offset), symbol);
    try wasm.resolved_symbols.putNoClobber(gpa, loc, {});
    try wasm.global_symbols.putNoClobber(gpa, name_offset, loc);
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

    fn next(iterator: *SymbolIterator) ?Entry {
        if (iterator.file_index >= iterator.wasm.objects.items.len) return null;
        const object: *Object = &iterator.wasm.objects.items[iterator.file_index];
        if (iterator.symbol_index >= object.symtable.len) {
            iterator.file_index += 1;
            iterator.symbol_index = 0;
            return iterator.next();
        }

        const symbol = &object.symtable[iterator.symbol_index];
        defer iterator.symbol_index += 1;
        return Entry{
            .sym_index = iterator.symbol_index,
            .file_index = iterator.file_index,
            .symbol = symbol,
        };
    }
};

fn mergeImports(wasm: *Wasm, gpa: Allocator) !void {
    const maybe_func_table_offset = wasm.string_table.getOffset("__indirect_function_table");
    if (wasm.options.import_table) {
        const table_offset = maybe_func_table_offset orelse {
            log.err("Required import __indirect_function_table is missing from object files", .{});
            return error.MissingSymbol;
        };
        const sym_with_loc = wasm.global_symbols.get(table_offset).?;
        try wasm.imports.appendSymbol(gpa, wasm, sym_with_loc);
    }

    for (wasm.resolved_symbols.keys()) |sym_with_loc| {
        const symbol = sym_with_loc.getSymbol(wasm);
        if (symbol.tag != .data) {
            if (!symbol.requiresImport()) {
                continue;
            }
            if (std.mem.eql(u8, sym_with_loc.getName(wasm), "__indirect_function_table")) {
                continue;
            }
            log.debug("Symbol '{s}' will be imported", .{sym_with_loc.getName(wasm)});
            try wasm.imports.appendSymbol(gpa, wasm, sym_with_loc);
        }
    }
}

/// Sets up the memory section of the wasm module, as well as the stack.
fn setupMemory(wasm: *Wasm) !void {
    log.debug("Setting up memory layout", .{});
    const page_size = 64 * 1024;
    const stack_size = wasm.options.stack_size orelse page_size * 1;
    const stack_alignment = 16;
    const stack_first = wasm.options.stack_first;

    var memory_ptr: u32 = 0;
    if (!stack_first and wasm.options.global_base != null) {
        memory_ptr = wasm.options.global_base.?;
    }

    if (stack_first) {
        memory_ptr = std.mem.alignForwardGeneric(u32, memory_ptr, stack_alignment);
        memory_ptr += stack_size;
        // set stack value on global
        if (wasm.synthetic_symbols.get("__stack_pointer")) |stack_pointer| {
            const global: *std.wasm.Global = &wasm.globals.items.items[stack_pointer.index];
            global.init = .{ .i32_const = @bitCast(i32, memory_ptr) };
        }
    }

    var offset: u32 = memory_ptr;
    for (wasm.segments.items) |*segment, i| {
        // skip 'code' segments
        if (wasm.code_section_index) |index| {
            if (index == i) continue;
        }
        memory_ptr = std.mem.alignForwardGeneric(u32, memory_ptr, segment.alignment);
        memory_ptr += segment.size;
        segment.offset = offset;
        offset += segment.size;
    }

    if (!stack_first) {
        memory_ptr = std.mem.alignForwardGeneric(u32, memory_ptr, stack_alignment);
        memory_ptr += stack_size;
        // set stack value on global
        if (wasm.synthetic_symbols.get("__stack_pointer")) |stack_pointer| {
            const global: *std.wasm.Global = &wasm.globals.items.items[stack_pointer.index];
            global.init = .{ .i32_const = @bitCast(i32, memory_ptr) };
        }
    }

    // Setup the max amount of pages
    const max_memory_allowed: u32 = (1 << 32) - 1;
    if (wasm.options.initial_memory) |initial_memory| {
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
    wasm.memories.limits.min = std.mem.alignForwardGeneric(u32, memory_ptr, page_size) / page_size;
    log.debug("Total memory pages: {d}", .{wasm.memories.limits.min});

    if (wasm.options.max_memory) |max_memory| {
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
        wasm.memories.limits.max = max_memory / page_size;
        log.debug("Maximum memory pages: {?d}", .{wasm.memories.limits.max});
    }
}

/// From a given object's index and the index of the segment, returns the corresponding
/// index of the segment within the final data section. When the segment does not yet
/// exist, a new one will be initialized and appended. The new index will be returned in that case.
pub fn getMatchingSegment(wasm: *Wasm, gpa: Allocator, object_index: u16, relocatable_index: u32) !?u32 {
    const object: Object = wasm.objects.items[object_index];
    const relocatable_data = object.relocatable_data[relocatable_index];
    const index = @intCast(u32, wasm.segments.items.len);

    switch (relocatable_data.type) {
        .data => {
            const segment_info = object.segment_info[relocatable_data.index];
            const segment_name = segment_info.outputName(wasm.options.merge_data_segments);
            const result = try wasm.data_segments.getOrPut(gpa, segment_name);
            if (!result.found_existing) {
                result.value_ptr.* = index;
                try wasm.segments.append(gpa, .{
                    .alignment = 1,
                    .size = 0,
                    .offset = 0,
                });
                return index;
            } else return result.value_ptr.*;
        },
        .code => return wasm.code_section_index orelse blk: {
            wasm.code_section_index = index;
            try wasm.segments.append(gpa, .{
                .alignment = 1,
                .size = 0,
                .offset = 0,
            });
            break :blk index;
        },
        .debug => return null,
    }
}

/// From a given index, append the given `Atom` at the back of the linked list.
/// Simply inserts it into the map of atoms when it doesn't exist yet.
pub fn appendAtomAtIndex(wasm: *Wasm, gpa: Allocator, index: u32, atom: *Atom) !void {
    if (wasm.atoms.getPtr(index)) |last| {
        last.*.next = atom;
        atom.prev = last.*;
        last.* = atom;
    } else {
        try wasm.atoms.putNoClobber(gpa, index, atom);
    }
}

fn allocateAtoms(wasm: *Wasm, gpa: Allocator) !void {
    var it = wasm.atoms.iterator();
    try wasm.symbol_atom.ensureUnusedCapacity(gpa, wasm.atoms.count());
    while (it.next()) |entry| {
        const segment = &wasm.segments.items[entry.key_ptr.*];
        var atom: *Atom = entry.value_ptr.*.getFirst();
        var offset: u32 = 0;
        while (true) {
            offset = std.mem.alignForwardGeneric(u32, offset, atom.alignment);
            atom.offset = offset;
            const symbol_loc = atom.symbolLoc();
            log.debug("Atom '{s}' allocated from 0x{x:0>8} to 0x{x:0>8} size={d}", .{
                symbol_loc.getName(wasm),
                offset,
                offset + atom.size,
                atom.size,
            });
            offset += atom.size;
            try wasm.symbol_atom.put(gpa, symbol_loc, atom); // Update atom pointers
            atom = atom.next orelse break;
        }
        segment.size = std.mem.alignForwardGeneric(u32, offset, segment.alignment);
    }
}

fn relocateAtoms(wasm: *Wasm) !void {
    var it = wasm.atoms.valueIterator();
    while (it.next()) |next_atom| {
        var atom: *Atom = next_atom.*.getFirst();
        while (true) {
            // First perform relocations to rewrite the binary data
            try atom.resolveRelocs(wasm);
            atom = atom.next orelse break;
        }
    }
}

fn setupStart(wasm: *Wasm) !void {
    if (wasm.options.no_entry) return;
    const entry_name = wasm.options.entry_name orelse "_start";
    const entry_name_offset = wasm.string_table.getOffset(entry_name) orelse {
        log.err("Entry symbol '{s}' does not exist, use '--no-entry' to suppress", .{entry_name});
        return error.MissingSymbol;
    };

    const symbol_with_loc: SymbolWithLoc = wasm.global_symbols.get(entry_name_offset).?;
    const symbol = symbol_with_loc.getSymbol(wasm);
    if (symbol.tag != .function) {
        log.err("Entry symbol '{s}' is not a function", .{entry_name});
        return error.InvalidEntryKind;
    }
    // Simply export the symbol as the start function is reserved
    // for synthetic symbols such as __wasm_start, __wasm_init_memory, and
    // __wasm_apply_global_relocs
    symbol.setFlag(.WASM_SYM_EXPORTED);
}
