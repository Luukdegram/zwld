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
    /// Holds the list of function type indexes.
    /// The list is built from merging all defined functions into this single list.
    /// Once appended, it becomes immutable and should not be mutated outside this list.
    items: std.ArrayList(wasm.Func) = .{},

    /// Adds a new function to the section while also setting the function index
    /// of the `Func` itself.
    pub fn addFunction(self: *Function, gpa: *Allocator, offset: u32, func: *wasm.Func) !void {
        func.func_idx = offset + self.count();
        try self.indexes.append(gpa, func.*);
    }

    /// Returns the count of entires within the function section
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
    ///
    /// NOTE: The given symbol must reside within the given `Object`.
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

    /// Returns the count of functions that have been imported (so far)
    pub fn functionCount(self: Import) u32 {
        return @intCast(u32, self.imported_functions.items.len);
    }

    /// Returns the count of tables that have been imported (so far)
    pub fn tableCount(self: Import) u32 {
        return @intCast(u32, self.imported_tables.items.len);
    }

    /// Returns the count of globals that have been imported (so far)
    pub fn globalCount(self: Import) u32 {
        return @intCast(u32, self.imported_globals.items.len);
    }
};

/// Represents the output global section, containing a list of globals
pub const Globals = struct {
    /// A list of `wasm.Global`s
    /// Once appended to this list, they should no longer be mutated
    items: std.ArrayListUnmanaged(wasm.Global) = .{},

    /// Appends a new global and sets the `global_idx` on the global based on the
    /// current count of globals and the given `offset`.
    pub fn append(self: *Globals, gpa: *Allocator, offset: u32, global: *wasm.Global) !void {
        global.global_idx = offset + self.count();
        try self.globals.append(gpa, global.*);
    }

    /// Returns the total amount of globals of the global section
    pub fn count(self: Globals) u32 {
        return @intCast(u32, self.items.len);
    }
};

/// Represents the type section, containing a list of
/// wasm signature types.
pub const Types = struct {
    /// A list of `wasm.FuncType`, when appending to
    /// this list, duplicates will be removed.
    ///
    /// TODO: Would a hashmap be more efficient?
    items: std.ArrayListUnmanaged(wasm.FuncType) = .{},

    /// Checks if a given type is already present within the list of types.
    /// If not, the given type will be appended to the list.
    /// In all cases, this will return the index within the list of types.
    pub fn append(self: *Types, gpa: *Allocator, func_type: wasm.FuncType) !u32 {
        return self.find(func_type) orelse {
            const index = self.count();
            try self.items.append(gpa, func_type);
            return index;
        };
    }

    /// Checks if any type (read: function signature) already exists within
    /// the type section. When it does exist, it will return its index
    /// otherwise, returns `null`.
    pub fn find(self: Types, func_type: wasm.FuncType) ?u32 {
        return for (self.types.items) |ty, index| {
            if (std.mem.eql(wasm.ValueType, ty.params, func_type.params) and
                std.mem.eql(wasm.ValueType, ty.returns, func_type.returns))
            {
                return @intCast(u32, index);
            }
        } else null;
    }

    /// Returns the amount of entries in the type section
    pub fn count(self: Types) u32 {
        return @intCast(u32, self.items.len);
    }
};

/// Represents the table section, containing a list
/// of tables, as well as the definition of linker-defined
/// tables such as the indirect function table
pub const Tables = struct {
    /// The list of tables that have been merged from all
    /// object files. This does not include any linker-defined
    /// tables. Once inserted in this list, the object becomes immutable.
    items: std.ArrayListUnmanaged(wasm.Table) = .{},

    /// Appends a new table to the list of tables and sets its index to
    /// the position within the list of tables.
    pub fn append(self: *Tables, gpa: *Allocator, offset: u32, table: *wasm.Table) !void {
        const index = offset + self.count();
        _ = index;
        // TODO: Add a 'table_idx' field to wasm.Table
        try self.items.append(gpa, table.*);
    }

    /// Returns the amount of entries in the table section
    pub fn count(self: Tables) u32 {
        return @intCast(u32, self.items.len);
    }
};
