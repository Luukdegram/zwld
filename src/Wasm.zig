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

// OUTPUT SECTIONS //
/// Output function signature types
types: sections.Types = .{},
/// Output import section
imports: sections.Imports = .{},
/// Output function section
functions: sections.Functions = .{},
/// Output table section
tables: std.ArrayListUnmanaged(wasm.Table) = .{},
/// Output memory section
memories: std.ArrayListUnmanaged(wasm.Memory) = .{},
/// Output global section
globals: std.ArrayListUnmanaged(wasm.Global) = .{},
/// Output export section
exports: std.ArrayListUnmanaged(wasm.Export) = .{},
/// Output element section
elements: std.ArrayListUnmanaged(wasm.Element) = .{},
/// Output code section
code: std.ArrayListUnmanaged([]u8) = .{},
/// Output data section
data: std.ArrayListUnmanaged(wasm.Data) = .{},

// EXPORTS //
/// A list of symbols which are to be exported
exported_symbols: std.ArrayListUnmanaged(*Symbol) = .{},

/// A list of indirect function calls used for the indirect table
indirect_functions: std.ArrayListUnmanaged(u32) = .{},

const max_load = std.hash_map.default_max_load_percentage;

// a global variable that defines the stack pointer of the program
var stack_symbol: ?Symbol = null;

pub const SymbolWithLoc = struct {
    sym_index: u32,
    file: u16,
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
    for (self.data.items) |data| {
        gpa.free(data.data);
    }

    self.exported_symbols.deinit(gpa);
    self.global_symbols.deinit(gpa);
    self.objects.deinit(gpa);
    self.functions.deinit(gpa);
    self.types.deinit(gpa);
    self.imports.deinit(gpa);
    self.globals.deinit(gpa);
    self.exports.deinit(gpa);
    self.tables.deinit(gpa);
    self.code.deinit(gpa);
    self.memories.deinit(gpa);
    self.data.deinit(gpa);
    self.indirect_functions.deinit(gpa);
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
    try self.mergeTypes(gpa);
    try self.setupExports(gpa);
    try self.relocateCode(gpa);
    try self.relocateData(gpa);

    try @import("emit_wasm.zig").emit(self);
}

fn resolveSymbolsInObject(self: *Wasm, gpa: *Allocator, object_index: u16) !void {
    const object: Object = self.objects.items[object_index];

    log.debug("resolving symbols in {s}", .{object.name});

    for (object.symtable) |*symbol, i| {
        const sym_idx = @intCast(u32, i);

        // Check if they should be imported, if so: add them to the import section.
        if (symbol.requiresImport()) {
            log.debug("Symbol '{s}' should be imported", .{symbol.name});
            try self.imports.appendSymbol(gpa, symbol);
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
fn reindex(self: *Wasm, gpa: *Allocator) !void {
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
                global.global_idx = @intCast(u32, self.imports.globalCount() + self.globals.items.len);
                try self.globals.append(gpa, global.*);
            }
        }

        var global_index = @intCast(u32, self.imports.globalCount());
        for (self.globals.items) |*global| {
            global.global_idx = global_index;
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
    valtype: wasm.ValueType,
) !Symbol {
    var global: wasm.Global = .{
        .valtype = valtype,
        .mutable = mutability == .mutable,
        .init = .{ .i32_const = 0 },
        .global_idx = @intCast(u32, self.globals.items.len),
    };
    try self.globals.append(gpa, global);

    var sym: Symbol = .{
        .flags = 0,
        .name = name,
        .kind = .{ .global = .{ .index = global.global_idx, .global = &self.globals.items[global.global_idx] } },
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
                    const symbol: Symbol = object.symtable[rel.index];
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
                                break :blk self.imports.imported_globals.get(.{
                                    .module_name = symbol.module_name.?,
                                    .name = symbol.name,
                                }).?;
                            } else object.globals[symbol.index().?].global_idx;
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

const Segment = struct {
    name: []const u8,
    alignment: u32,
    offset: u32,
    flags: u32,
    size: u32,
    index: u32,
    file: u16,
};

fn relocateData(self: *Wasm, gpa: *Allocator) !void {
    log.debug("Merging data sections and performing relocations", .{});

    // map containing all segments, where the name of the segment is its key
    var segment_map = std.StringArrayHashMap(std.ArrayList(Segment)).init(gpa);
    defer for (segment_map.values()) |val| {
        val.deinit();
    } else segment_map.deinit();

    for (self.objects.items) |object, object_index| {
        for (object.symtable) |symbol| {
            if (symbol.isUndefined()) continue;
            if (symbol.kind != .data) continue;
            const data_symbol = symbol.kind.data;
            const segment_info = object.segment_info[data_symbol.index.?];

            log.debug("Merging segment {s}", .{segment_info.name});
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
                .index = data_symbol.index.?,
                .file = @intCast(u16, object_index),
            };

            if (result.value_ptr.*.popOrNull()) |prev| {
                segment.offset += prev.size;
                result.value_ptr.*.appendAssumeCapacity(prev);
            }

            try result.value_ptr.*.append(segment);
        }
    }

    var segment_it = segment_map.iterator();
    var offset: u32 = 0;
    while (segment_it.next()) |entry| {
        const segment_list: std.ArrayList(Segment) = entry.value_ptr.*;

        var segment_data = std.ArrayList(u8).init(gpa);
        defer segment_data.deinit();

        // perform relocations
        for (segment_list.items) |segment| {
            const object: Object = self.objects.items[segment.file];
            const data = object.data.segments[segment.index];

            if (object.relocations.get(object.data.index)) |relocations| {
                for (relocations) |_rel| {
                    const rel: wasm.Relocation = _rel;

                    if (!isInbetween(data.seg_offset, @intCast(u32, data.data.len), rel.offset)) {
                        continue;
                    }

                    const symbol: *Symbol = &object.symtable[rel.index];
                    switch (rel.relocation_type) {
                        .R_WASM_TABLE_INDEX_I32 => {
                            const index = symbol.kind.function.func.func_idx;
                            symbol.setTableIndex(@intCast(u32, self.indirect_functions.items.len));
                            try self.indirect_functions.append(gpa, index);

                            log.debug("Relocation: Created table entry for symbol '{s}' with index {}", .{
                                symbol.name,
                                index,
                            });
                        },
                        else => |ty| {
                            log.debug("TODO: Relocate data for type {}", .{ty});
                            continue;
                        },
                    }
                }
            }

            try segment_data.appendSlice(data.data);
        }

        try self.data.append(gpa, .{
            .index = 0,
            .offset = .{ .i32_const = @bitCast(i32, offset) },
            .data = segment_data.toOwnedSlice(),
            .seg_offset = 0,
        });
        offset += @intCast(u32, segment_data.items.len);
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
    const global: *wasm.Global = &self.globals.items[stack_symbol.?.index().?];
    global.init = .{ .i32_const = @intCast(i32, @bitCast(i64, memory_ptr)) };

    // setup memory TODO: Calculate based on data segments and configered pages by user
    try self.memories.append(gpa, .{
        .limits = .{
            .min = 2,
            .max = null,
        },
    });
}
