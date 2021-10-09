//! Wasm represents the final binary
const Wasm = @This();

const Atom = @import("Atom.zig");
const Object = @import("Object.zig");
const spec = @import("spec.zig");
const std = @import("std");

const leb = std.leb;
const fs = std.fs;
const Allocator = std.mem.Allocator;

const log = std.log.scoped(.zwld);

/// The binary file that we will write the final binary data to
file: fs.File,
/// A list with references to objects we link to during `flush()`
objects: std.ArrayListUnmanaged(Object) = .{},
/// A map of global names to their symbol location in an object file
global_symbols: std.StringArrayHashMapUnmanaged(SymbolWithLoc) = .{},

// OUTPUT SECTIONS //
/// Output function signature types
types: std.ArrayListUnmanaged(spec.sections.Type) = .{},
/// Output import section
imports: std.ArrayListUnmanaged(spec.sections.Import) = .{},
/// Output function section
functions: std.ArrayListUnmanaged(spec.sections.Func) = .{},
/// Output table section
tables: std.ArrayListUnmanaged(spec.sections.Table) = .{},
/// Output memory section
memories: std.ArrayListUnmanaged(spec.sections.Memory) = .{},
/// Output global section
globals: std.ArrayListUnmanaged(spec.sections.Global) = .{},
/// Output export section
exports: std.ArrayListUnmanaged(spec.sections.Export) = .{},
/// Output element section
elements: std.ArrayListUnmanaged(spec.sections.Element) = .{},
/// Output code section
code: std.ArrayListUnmanaged([]u8) = .{},

// IMPORTS //
/// Table where the key is represented by an import.
/// Each entry represents an imported function, and maps to the index within this map
imported_functions: std.HashMapUnmanaged(ImportKey, u32, ImportKey.Ctx, max_load) = .{},
/// Table where the key is represented by an import.
/// Each entry represents an imported global from the host environment and maps to the index
/// within this map.
imported_globals: std.HashMapUnmanaged(ImportKey, u32, ImportKey.Ctx, max_load) = .{},
/// Table where the key is represented by an import.
/// Each entry represents an imported table from the host environment and maps to the index
/// within this map.
imported_tables: std.HashMapUnmanaged(ImportKey, u32, ImportKey.Ctx, max_load) = .{},
/// A list of symbols that are imported from a host environment.
imported_symbols: std.ArrayListUnmanaged(SymbolWithLoc) = .{},

// EXPORTS //
/// A list of symbols which are to be exported
exported_symbols: std.ArrayListUnmanaged(*spec.Symbol) = .{},

const max_load = std.hash_map.default_max_load_percentage;

// a global variable that defines the stack pointer of the program
var stack_symbol: ?spec.Symbol = null;

const ImportKey = struct {
    module_name: []const u8,
    name: []const u8,

    const Ctx = struct {
        pub fn hash(ctx: Ctx, key: ImportKey) u64 {
            _ = ctx;
            const hashFunc = std.hash.autoHash;
            var hasher = std.hash.Wyhash.init(0);
            hashFunc(&hasher, key.module_name.len);
            hashFunc(&hasher, key.module_name.ptr);
            hashFunc(&hasher, key.name.len);
            hashFunc(&hasher, key.name.ptr);
            return hasher.final();
        }

        pub fn eql(ctx: Ctx, lhs: ImportKey, rhs: ImportKey) bool {
            _ = ctx;
            return std.mem.eql(u8, lhs.name, rhs.name) and
                std.mem.eql(u8, lhs.module_name, rhs.module_name);
        }
    };
};

pub const SymbolWithLoc = struct {
    sym_index: u32,
    file: u16,
};

/// Initializes a new wasm binary file at the given path.
/// Will overwrite any existing file at said path.
pub fn openPath(path: []const u8) !Wasm {
    const file = try fs.cwd().createFile(path, .{
        .truncate = true,
        .read = true,
    });
    errdefer file.close();

    return Wasm{ .file = file };
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
    self.imported_functions.deinit(gpa);
    self.imported_globals.deinit(gpa);
    self.imported_tables.deinit(gpa);
    self.imported_symbols.deinit(gpa);
    self.exported_symbols.deinit(gpa);
    self.global_symbols.deinit(gpa);
    self.objects.deinit(gpa);
    self.functions.deinit(gpa);
    self.types.deinit(gpa);
    self.globals.deinit(gpa);
    self.exports.deinit(gpa);
    self.tables.deinit(gpa);
    self.code.deinit(gpa);
    self.memories.deinit(gpa);
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

    try self.setupLinkerSymbols(gpa);
    try self.setupMemory(gpa);
    try self.reindex(gpa);
    try self.setupTypes(gpa);
    try self.setupExports(gpa);
    try self.relocateCode(gpa);

    try @import("emit_wasm.zig").emit(self);
}

fn resolveSymbolsInObject(self: *Wasm, gpa: *Allocator, object_index: u16) !void {
    const object: Object = self.objects.items[object_index];

    log.debug("resolving symbols in {s}", .{object.name});

    for (object.symtable) |symbol, i| {
        const sym_idx = @intCast(u32, i);

        // Check if they should be imported, if so: add them to the import section.
        if (symbol.requiresImport()) {
            log.debug("Symbol '{s}' should be imported", .{symbol.name});
            try self.appendImportSymbol(gpa, object_index, sym_idx);
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

/// Checks if a symbol is already imported or not. If not, will be appended as well as appended
/// to a typed list of imports.
fn appendImportSymbol(self: *Wasm, gpa: *Allocator, object_id: u16, symbol_id: u32) !void {
    const object: *Object = &self.objects.items[object_id];
    const symbol = &object.symtable[symbol_id];
    const import = object.imports[symbol.index().?]; // Programmer error: Undefined data symbols are not imported.
    const module_name = import.module_name;
    const import_name = import.name;
    const symbol_with_loc: SymbolWithLoc = .{ .file = object_id, .sym_index = symbol_id };

    switch (symbol.kind) {
        .function => |*func| {
            const ret = try self.imported_functions.getOrPut(gpa, .{
                .module_name = module_name,
                .name = import_name,
            });
            if (!ret.found_existing) {
                try self.imported_symbols.append(gpa, symbol_with_loc);
                ret.value_ptr.* = @intCast(u32, self.imported_functions.count() - 1);
            }
            func.index = ret.value_ptr.*;
            log.debug("Imported function '{s}' at index ({d})", .{ import_name, func.index });
        },
        .global => |*global| {
            const ret = try self.imported_globals.getOrPut(gpa, .{
                .module_name = module_name,
                .name = import_name,
            });
            if (!ret.found_existing) {
                try self.imported_symbols.append(gpa, symbol_with_loc);
                ret.value_ptr.* = @intCast(u32, self.imported_globals.count() - 1);
            }
            global.index = ret.value_ptr.*;
            log.debug("Imported global '{s}' at index ({d})", .{ import_name, global.index });
        },
        .table => |*table| {
            const ret = try self.imported_tables.getOrPut(gpa, .{
                .module_name = module_name,
                .name = import_name,
            });
            if (!ret.found_existing) {
                try self.imported_symbols.append(gpa, symbol_with_loc);
                ret.value_ptr.* = @intCast(u32, self.imported_tables.count() - 1);
            }
            table.index = ret.value_ptr.*;
            log.debug("Imported table '{s}' at index ({d})", .{ import_name, table.index });
        },
        else => unreachable, // programmer error: Given symbol cannot be imported
    }
}

/// Calculates the new indexes for symbols and their respective symbols
fn reindex(self: *Wasm, gpa: *Allocator) !void {
    log.debug("Merging functions", .{});
    for (self.objects.items) |object| {
        for (object.functions) |*func| {
            func.func_idx = @intToEnum(
                spec.indexes.Func,
                @intCast(u32, self.imported_functions.count() + self.functions.items.len),
            );
            try self.functions.append(gpa, func.*);
        }
    }
    log.debug("Merged ({d}) functions", .{self.functions.items.len});

    // merge globals
    {
        log.debug("Merging globals", .{});
        for (self.objects.items) |object| {
            for (object.globals) |*global| {
                global.global_idx = @intToEnum(
                    spec.indexes.Global,
                    @intCast(u32, self.imported_globals.count() + self.globals.items.len),
                );
                try self.globals.append(gpa, global.*);
            }
        }

        var global_index = @intCast(u32, self.imported_globals.count());
        for (self.globals.items) |*global| {
            global.global_idx = @intToEnum(spec.indexes.Global, global_index);
            global_index += 1;
        }
        log.debug("Merged ({d}) globals", .{self.globals.items.len});
    }

    // merge tables
    {
        log.debug("TODO: Merge tables", .{});
        // for (self.objects.items) |object| {
        //     for (object.tables) |*table| {
        //         table.index = @intCast(u32, self.imported_tables.count() + self.tables.items.len);
        //         try self.tables.append(gpa, table.*);
        //     }
        // }

        // var table_index: u32 = @intCast(u32, self.imported_tables.count());
        // for (self.tables.items) |*table| {
        //     _ = table;
        //     table.index = table_index;
        //     table_index += 1;
        // }
    }
}

/// Checks if any type (read: function signature) already exists within
/// the type section. When it does exist, it will return its index.
/// Otherwise, returns `null`.
fn findType(self: *Wasm, wasm_type: spec.sections.Type) ?usize {
    return for (self.types.items) |ty, index| {
        if (std.mem.eql(spec.ValueType, ty.params, wasm_type.params) and
            std.mem.eql(spec.ValueType, ty.returns, wasm_type.returns))
        {
            return index;
        }
    } else null;
}

fn setupTypes(self: *Wasm, gpa: *Allocator) !void {
    log.debug("Merging types", .{});
    for (self.objects.items) |object| {
        for (object.types) |wasm_type| {
            if (self.findType(wasm_type) == null) {
                try self.types.append(gpa, wasm_type);
            }
        }
    }
    log.debug("Merged ({d}) types from object files", .{self.types.items.len});

    log.debug("Building types from import symbols", .{});
    for (self.imported_symbols.items) |symbol_with_loc| {
        const object = self.objects.items[symbol_with_loc.file];
        const symbol = object.symtable[symbol_with_loc.sym_index];
        if (symbol.kind == .function) {
            log.debug("Adding type from function '{s}'", .{symbol.name});
            if (self.findType(object.types[symbol.index().?]) == null) {
                try self.types.append(gpa, object.types[symbol.index().?]);
            }
        }
    }

    log.debug("Building types from functions", .{});
    for (self.functions.items) |*func| {
        if (self.findType(func.func_type.*)) |index| {
            func.type_idx = @intToEnum(spec.indexes.Type, @intCast(u32, index));
        } else {
            func.type_idx = @intToEnum(spec.indexes.Type, @intCast(u32, self.types.items.len));
            try self.types.append(gpa, func.func_type.*);
        }
    }
    log.debug("Completed building types. Total count: ({d})", .{self.types.items.len});
}

fn setupExports(self: *Wasm, gpa: *Allocator) !void {
    var global_index = @intCast(u32, self.imported_globals.count() + self.globals.items.len);
    _ = global_index;

    log.debug("Building exports from symbols", .{});
    var symbol_it = SymbolIterator.init(self);
    while (symbol_it.next()) |entry| {
        const symbol = entry.symbol;
        if (!symbol.isExported()) continue;

        var name: []const u8 = symbol.name;
        var exported: spec.sections.Export = undefined;
        if (symbol.unwrapAs(.function)) |func| {
            // func cannot be `null` because only defined functions
            // can be exported, which is verified with `isExported()`
            if (func.func.?.export_name) |export_name| {
                name = export_name;
            }
            exported = .{
                .name = name,
                .kind = .function,
                .index = @enumToInt(func.func.?.func_idx),
            };
        } else {
            log.debug("TODO: Export non-functions", .{});
            continue;
        }

        log.debug("Appending export from symbol '{s}' using name: '{s}'", .{
            symbol.name, name,
        });
        try self.exports.append(gpa, exported);
        try self.exported_symbols.append(gpa, entry.symbol);
    }
    log.debug("Completed building exports. Total count: ({d})", .{self.exports.items.len});
}

/// Creates symbols that are made by the linker, rather than the compiler/object file
fn setupLinkerSymbols(self: *Wasm, gpa: *Allocator) !void {
    // Create symbol for our stack pointer
    stack_symbol = try self.createGlobal(gpa, "__stack_pointer", .mutable, .i32);
}

fn createGlobal(
    self: *Wasm,
    gpa: *Allocator,
    name: []const u8,
    mutability: enum { mutable, immutable },
    valtype: spec.ValueType,
) !spec.Symbol {
    var global: spec.sections.Global = .{
        .valtype = valtype,
        .mutable = mutability == .mutable,
        .init = .{ .i32_const = 0 },
        .global_idx = @intToEnum(spec.indexes.Global, @intCast(u32, self.globals.items.len)),
    };
    try self.globals.append(gpa, global);

    var sym: spec.Symbol = .{
        .flags = 0,
        .name = name,
        .kind = .{ .global = .{ .index = @enumToInt(global.global_idx) } },
    };
    return sym;
}

const SymbolIterator = struct {
    symbol_index: u32,
    file_index: u16,
    wasm: *Wasm,

    const Entry = struct {
        sym_index: u32,
        file_index: u16,
        symbol: *spec.Symbol,
    };

    fn init(wasm: *Wasm) SymbolIterator {
        return .{ .symbol_index = 0, .file_index = 0, .wasm = wasm };
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
    try self.code.resize(gpa, self.functions.items.len);
    for (self.objects.items) |object| {
        for (object.code.bodies) |code, body_index| {
            const body_length = @intCast(u32, code.data.len);
            // check if we must perform relocations
            if (object.relocations.get(@intCast(u32, object.code.index))) |relocations| {
                const _rel: []const spec.Relocation = relocations;
                log.debug("Found relocations for function body at index {d}", .{body_index});
                for (_rel) |rel| {
                    if (!isInbetween(code.offset, body_length, rel.offset)) {
                        continue;
                    }
                    const symbol: spec.Symbol = object.symtable[rel.index];
                    const body_offset = rel.offset - code.offset;
                    switch (rel.relocation_type) {
                        .R_WASM_FUNCTION_INDEX_LEB,
                        .R_WASM_TABLE_INDEX_SLEB,
                        => {
                            log.debug("Performing relocation for function symbol '{s}' at offset=0x{x:0>8}", .{
                                symbol.name,
                                rel.offset,
                            });
                        },
                        .R_WASM_GLOBAL_INDEX_LEB => {
                            const index: u32 = if (symbol.isUndefined()) blk: {
                                const import = object.imports[symbol.index().?];
                                break :blk self.imported_globals.get(.{ .module_name = import.module_name, .name = import.name }).?;
                            } else @enumToInt(object.globals[symbol.index().?].global_idx);
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
            self.code.items[@enumToInt(code.func.func_idx)] = code.data;
        }
    }
}

/// Verifies if a given value is in between a minimum -and maximum value.
/// The maxmimum value is calculated using the length, both start and end are inclusive.
inline fn isInbetween(min: u32, length: u32, value: u32) bool {
    return value >= min and value <= min + length;
}

const Segment = struct {
    name: []const u8,
    alignment: u32,
    offset: u32,
    flags: u32,
    size: u32,
};

fn relocateData(self: *Wasm, gpa: *Allocator) !void {
    log.debug("Merging data sections and performing relocations", .{});

    // map containing all segments, where the name of the segment is its key
    var segment_map = std.StringArrayHashMap(std.ArrayList(Segment)).init(gpa);
    defer for (segment_map.values()) |val| {
        val.deinit();
    } else segment_map.deinit();

    for (self.object.items) |_object| {
        var object: Object = _object;

        for (object.symtable) |symbol| {
            if (symbol.isUndefined()) continue;
            if (symbol.kind != .data) continue;
            const data_symbol = symbol.kind.data;
            const segment_info = object.segment_info[data_symbol.index.?];

            const result = try segment_map.getOrPut(segment_info.outputName());
            if (!result.found_existing) {
                result.value_ptr.* = std.ArrayList(Segment).init(gpa);
            }

            var segment: Segment = .{
                .name = segment_info.name,
                .alignment = segment_info.alignment,
                .offset = data_symbol.offset.?,
                .flags = segment_info.flags,
                .size = data_symbol.size.?,
            };

            if (result.value_ptr.*.popOrNull()) |prev| {
                segment.offset += prev.size;
                result.value_ptr.*.appendAssumeCapacity(prev);
            }

            try result.value_ptr.*.append(segment);
        }
    }
}

/// Sets up the memory section of the wasm module, as well as the stack.
fn setupMemory(self: *Wasm, gpa: *Allocator) !void {
    log.debug("Setting up memory layout", .{});
    _ = gpa;
    const page_size = 64 * 1024;
    const stack_size = page_size * 1;
    const stack_alignment = 16;
    var memory_ptr: u64 align(stack_alignment) = 0;

    // TODO: Calculate this according to user input
    memory_ptr += stack_size;

    // set stack value on global
    const global: *spec.sections.Global = &self.globals.items[stack_symbol.?.index().?];
    global.init.i32_const = @intCast(i32, @bitCast(i64, memory_ptr));

    // setup memory TODO: Calculate based on data segments and configered pages by user
    try self.memories.append(gpa, .{
        .limits = .{
            .min = 0,
            .max = 2,
        },
    });
}
