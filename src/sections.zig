//! Contains the definiton and logic for all the
//! output sections required to build the final file.
const std = @import("std");
const Symbol = @import("Symbol.zig");
const Object = @import("Object.zig");
const wasm = @import("data.zig");
const Wasm = @import("Wasm.zig");
const Allocator = std.mem.Allocator;

const log = std.log.scoped(.zwld);

/// Accepts a slice with mutable elements and sets the field `field_name`'s value
/// to the index within the list, based on the given `offset`.
fn setIndex(comptime field_name: []const u8, slice: anytype, offset: u32) void {
    for (slice) |item, index| {
        @field(item, field_name) = @intCast(u32, index + offset);
    }
}

/// Output function section, holding a list of all
/// function with indexes to their type
pub const Functions = struct {
    /// Holds the list of function type indexes.
    /// The list is built from merging all defined functions into this single list.
    /// Once appended, it becomes immutable and should not be mutated outside this list.
    items: std.ArrayListUnmanaged(wasm.Func) = .{},

    /// Adds a new function to the section while also setting the function index
    /// of the `Func` itself.
    pub fn append(self: *Functions, gpa: *Allocator, offset: u32, func: *wasm.Func) !void {
        func.func_idx = offset + self.count();
        try self.items.append(gpa, func.*);
    }

    /// Returns the count of entires within the function section
    pub fn count(self: *Functions) u32 {
        return @intCast(u32, self.items.items.len);
    }

    pub fn deinit(self: *Functions, gpa: *Allocator) void {
        self.items.deinit(gpa);
        self.* = undefined;
    }
};

/// Output import section, containing all the various import types
pub const Imports = struct {
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
    pub fn appendSymbol(self: *Imports, gpa: *Allocator, symbol: *Symbol) !void {
        const module_name = symbol.module_name.?;
        const import_name = symbol.name;

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
                func.func.func_idx = ret.value_ptr.*;
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
                global.global.global_idx = ret.value_ptr.*;
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
                table.table.table_idx = ret.value_ptr.*;
                log.debug("Imported table '{s}' at index ({d})", .{ import_name, table.index });
            },
            else => unreachable, // programmer error: Given symbol cannot be imported
        }
    }

    /// Returns the count of functions that have been imported (so far)
    pub fn functionCount(self: Imports) u32 {
        return @intCast(u32, self.imported_functions.count());
    }

    /// Returns the count of tables that have been imported (so far)
    pub fn tableCount(self: Imports) u32 {
        return @intCast(u32, self.imported_tables.count());
    }

    /// Returns the count of globals that have been imported (so far)
    pub fn globalCount(self: Imports) u32 {
        return @intCast(u32, self.imported_globals.count());
    }

    pub fn deinit(self: *Imports, gpa: *Allocator) void {
        self.imported_functions.deinit(gpa);
        self.imported_globals.deinit(gpa);
        self.imported_tables.deinit(gpa);
        self.imported_symbols.deinit(gpa);
        self.* = undefined;
    }

    /// Returns a slice to pointers to symbols that have been imported
    pub fn symbols(self: Imports) []const *Symbol {
        return self.imported_symbols.items;
    }

    /// Returns the count of symbols which have been imported
    pub fn symbolCount(self: Imports) u32 {
        return @intCast(u32, self.imported_symbols.items.len);
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
        try self.items.append(gpa, global.*);
    }

    /// Returns the total amount of globals of the global section
    pub fn count(self: Globals) u32 {
        return @intCast(u32, self.items.items.len);
    }

    /// Creates a new linker-defined global with the given mutability and value type.
    /// Also appends the new global to the output global section and returns a pointer
    /// to the newly created global.
    ///
    /// This will automatically set `init` to `null` and can manually be updated at a later point using
    /// the returned pointer.
    pub fn create(self: *Globals, gpa: *Allocator, mutability: enum { mutable, immutable }, valtype: wasm.ValueType) !*wasm.Global {
        const index = self.count();
        try self.items.append(gpa, .{
            .valtype = valtype,
            .mutable = mutability == .mutable,
            .init = null,
            .global_idx = index,
        });
        return &self.items.items[index];
    }

    /// Assigns indexes to all functions based on the given `offset`
    /// Meaning that for element 0, with offset 2, will have its first element's index
    /// set to 2, rather than 0.
    pub fn setIndexes(self: *Globals, offset: u32) void {
        setIndex("global_idx", self.items.items, offset);
    }

    pub fn deinit(self: *Globals, gpa: *Allocator) void {
        self.items.deinit(gpa);
        self.* = undefined;
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

    /// Returns a pointer to the function type at given `index`
    /// Asserts the index is within bounds.
    pub fn get(self: Types, index: u32) *wasm.FuncType {
        return &self.items.items[index];
    }

    /// Checks if any type (read: function signature) already exists within
    /// the type section. When it does exist, it will return its index
    /// otherwise, returns `null`.
    pub fn find(self: Types, func_type: wasm.FuncType) ?u32 {
        return for (self.items.items) |ty, index| {
            if (std.mem.eql(wasm.ValueType, ty.params, func_type.params) and
                std.mem.eql(wasm.ValueType, ty.returns, func_type.returns))
            {
                return @intCast(u32, index);
            }
        } else null;
    }

    /// Returns the amount of entries in the type section
    pub fn count(self: Types) u32 {
        return @intCast(u32, self.items.items.len);
    }

    pub fn deinit(self: *Types, gpa: *Allocator) void {
        self.items.deinit(gpa);
        self.* = undefined;
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
        table.table_idx = index;
        try self.items.append(gpa, table.*);
    }

    /// Returns the amount of entries in the table section
    pub fn count(self: Tables) u32 {
        return @intCast(u32, self.items.items.len);
    }

    /// Sets the table indexes of all table elements relative to their position within
    /// the list, starting from `offset` rather than '0'.
    pub fn setIndexes(self: *Tables, offset: u32) void {
        setIndex("table_idx", self.items.items, offset);
    }

    /// Creates a synthetic symbol for the indirect function table and appends it into the
    /// table list.
    pub fn createIndirectFunctionTable(self: *Tables, gpa: *Allocator, wasm_bin: *Wasm) !void {
        // Only create it if it doesn't exist yet
        if (Symbol.linker_defined.indirect_function_table != null) {
            log.debug("Indirect function table already exists, skipping creation...", .{});
            return;
        }

        const index = self.count();
        try self.items.append(.{
            .limits = .{ .min = 0, .max = null },
            .reftype = .funcref,
            .table_idx = index,
        });
        var symbol: Symbol = .{
            .flags = 0, // created defined symbol
            .name = Symbol.linker_defined.names.indirect_function_table, // __indirect_function_table
            .kind = .{ .table = .{ .index = index, .table = &self.items.items[index] } },
        };
        wasm_bin.synthetic_symbols.append(gpa, symbol);
        Symbol.linker_defined.indirect_function_table = &wasm_bin.synthetic_symbols.items[wasm_bin.synthetic_symbols.items.len - 1];

        log.debug("Created indirect function table at index {d}", .{index});
    }

    pub fn deinit(self: *Tables, gpa: *Allocator) void {
        self.items.deinit(gpa);
        self.* = undefined;
    }
};

/// Represents the exports section, built from explicit exports
/// from all object files, as well as global defined symbols that are
/// non-hidden.
pub const Exports = struct {
    /// List of exports, containing both merged exports
    /// as linker-defined exports such as __stack_pointer.
    items: std.ArrayListUnmanaged(wasm.Export) = .{},

    /// Contains a list of pointers to symbols
    /// TODO: Do we really need this list?
    symbols: std.ArrayListUnmanaged(*Symbol) = .{},

    /// Appends a given `wasm.Export` to the list of output exports.
    pub fn append(self: *Exports, gpa: *Allocator, exp: wasm.Export) !void {
        try self.items.append(gpa, exp);
    }

    pub fn appendSymbol(self: *Exports, gpa: *Allocator, symbol: *Symbol) !void {
        try self.symbols.append(gpa, symbol);
    }

    /// Returns the amount of entries in the export section
    pub fn count(self: Exports) u32 {
        return @intCast(u32, self.items.items.len);
    }

    pub fn deinit(self: *Exports, gpa: *Allocator) void {
        self.items.deinit(gpa);
        self.symbols.deinit(gpa);
        self.* = undefined;
    }
};

pub const Elements = struct {
    /// A list of symbols for indirect function calls
    indirect_functions: std.ArrayListUnmanaged(*Symbol) = .{},

    /// Appends a function symbol to the list of indirect function calls.
    /// The table index will be set on the symbol, based on the length
    ///
    /// Asserts symbol represents a function.
    pub fn appendSymbol(self: *Elements, gpa: *Allocator, symbol: *Symbol) !void {
        // Check if symbol is already part of the indirect function table
        if (symbol.kind.function.table_index != null) {
            return;
        }
        symbol.kind.function.table_index = @intCast(u32, self.indirect_functions.items.len);
        try self.indirect_functions.append(gpa, symbol);
    }

    /// Returns true when this section must be written to the binary
    pub fn mustEmit(self: Elements) bool {
        return self.indirect_functions.items.len != 0;
    }

    pub fn functionCount(self: Elements) u32 {
        return @intCast(u32, self.indirect_functions.items.len);
    }

    pub fn deinit(self: *Elements, gpa: *Allocator) void {
        self.indirect_functions.deinit(gpa);
        self.* = undefined;
    }
};
