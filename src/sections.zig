//! Contains the definiton and logic for all the
//! output sections required to build the final file.
const std = @import("std");
const Symbol = @import("Symbol.zig");
const Object = @import("Object.zig");
const wasm = @import("data.zig");
const Allocator = std.mem.Allocator;

const log = std.log.scoped(.zwld);

/// Output function section, holding a list of all
/// function with indexes to their type
pub const Function = struct {
    indexes: std.ArrayList(*wasm.Func) = .{},

    /// Adds a new function to the section while also setting the function index
    /// of the `Func` itself.
    pub fn addFunction(self: *Function, gpa: *Allocator, offset: u32, func: *wasm.Func) !void {
        func.func_idx = offset + self.count();
        try self.indexes.append(gpa, func);
    }

    pub fn count(self: *Function) u32 {
        return @intCast(u32, self.indexes.items.len);
    }
};

/// Output import section, containing all the various import types
pub const Import = struct {
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
    /// A list of symbols representing objects that have been imported.
    imported_symbols: std.ArrayListUnmanaged(*Symbol) = .{},

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

    const max_load = std.hash_map.default_max_load_percentage;

    /// Appends an import symbol into the list of imports. Based on the type, also appends it
    /// to their respective import list (such as imported_functions)
    pub fn appendSymbol(self: *Import, gpa: *Allocator, object: Object, symbol: *Symbol) !void {
        const import = object.imports[symbol.index().?]; // Undefined data symbols cannot be imported
        const module_name = import.module_name;
        const import_name = import.name;
        switch (symbol.kind) {
            .function => |*func| {
                const ret = try self.imported_functions.getOrPut(gpa, .{
                    .module_name = module_name,
                    .name = import_name,
                });
                if (!ret.found_existing) {
                    try self.imported_symbols.append(gpa, symbol);
                    ret.value_ptr.* = @intCast(u32, self.imported_functions.count() - 1);
                }
                func.func.?.func_idx = ret.value_ptr.*;
                log.debug("Imported function '{s}' at index ({d})", .{ import_name, func.index });
            },
            .global => |*global| {
                const ret = try self.imported_globals.getOrPut(gpa, .{
                    .module_name = module_name,
                    .name = import_name,
                });
                if (!ret.found_existing) {
                    try self.imported_symbols.append(gpa, symbol);
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
                    try self.imported_symbols.append(gpa, symbol);
                    ret.value_ptr.* = @intCast(u32, self.imported_tables.count() - 1);
                }
                table.index = ret.value_ptr.*;
                log.debug("Imported table '{s}' at index ({d})", .{ import_name, table.index });
            },
            else => unreachable, // programmer error: Given symbol cannot be imported
        }
    }
};
