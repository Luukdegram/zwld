const std = @import("std");
const wasm = std.wasm;
const TypeInfo = std.builtin.TypeInfo;

/// Wasm union that contains the value of each possible `ValueType`
pub const Value = union(ValueType) {
    i32: i32,
    i64: i64,
    f32: f32,
    f64: f64,
    /// Reference to another function regardless of their function type
    funcref: indexes.Func,
    /// Reference to an external object (object from the embedder)
    externref: u32,
};

/// Value types for locals and globals
pub const NumType = enum(u8) {
    i32 = 0x7F,
    i64 = 0x7E,
    f32 = 0xfD,
    f64 = 0xfE,
};

/// Reference types, where the funcref references to a function regardless of its type
/// and ref references an object from the embedder.
pub const RefType = enum(u8) {
    funcref = 0x70,
    externref = 0x6F,
};

/// Represents the several types a wasm value can have
pub const ValueType = MergedEnums(NumType, RefType);

/// Wasm sections, including proposals.
/// Section is built using `std.wasm.Section` and adding
/// proposed sections to it.
///
/// Note: This version is non-exhaustive to continue parsing
/// when a new section is proposed but not yet implemented.
pub const Section = MergedEnum(wasm.Section, &.{
    .{ .name = "module", .value = 14 },
    .{ .name = "instance", .value = 15 },
    .{ .name = "alias", .value = 16 },
});

/// Merges a given enum type and a slice of `EnumField` into a new enum type
fn MergedEnum(comptime T: type, comptime fields: []const TypeInfo.EnumField) type {
    if (@typeInfo(T) != .Enum) {
        @compileError("Given type 'T' must be an enum type but instead was given: " ++ @typeName(T));
    }

    const old_fields = std.meta.fields(T);
    var new_fields: [fields.len + old_fields.len]TypeInfo.EnumField = undefined;
    std.mem.copy(TypeInfo.EnumField, &new_fields, old_fields);
    std.mem.copy(TypeInfo.EnumField, new_fields[old_fields.len..], fields);

    return @Type(.{ .Enum = .{
        .layout = .Auto,
        .tag_type = u8,
        .fields = &new_fields,
        .decls = &.{},
        .is_exhaustive = false,
    } });
}

/// Merges two enums into a single enum type
fn MergedEnums(comptime T: type, comptime Z: type) type {
    return MergedEnum(T, std.meta.fields(Z));
}

/// External types that can be imported or exported between to/from the host
pub const ExternalType = wasm.ExternalKind;

/// Limits classify the size range of resizeable storage associated with memory types and table types.
pub const Limits = struct {
    min: u32,
    max: ?u32,
};

/// The type of block types, similarly to `ValueType` with the difference being
/// that it adds an additional type 'empty' which is used for blocks with no return value.
pub const BlockType = MergedEnum(ValueType, &.{.{
    .name = "block_empty",
    .value = wasm.block_empty,
}});

pub const InitExpression = union(enum) {
    i32_const: i32,
    /// Uses the value of a global at index `global_get`
    global_get: u32,
};

pub const indexes = struct {
    pub const Type = enum(u32) { _ };
    pub const Func = enum(u32) { _ };
    pub const Table = enum(u32) { _ };
    pub const Mem = enum(u32) { _ };
    pub const global = enum(u32) { _ };
    pub const Elem = enum(u32) { _ };
    pub const Data = enum(u32) { _ };
    pub const Local = enum(u32) { _ };
    pub const Label = enum(u32) { _ };
};

pub const sections = struct {
    pub const Custom = struct {
        name: []const u8,
        data: []const u8,
        start: usize,
        end: usize,

        pub fn format(self: Custom, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
            _ = fmt;
            _ = options;
            try writer.print("{s: >8} start=0x{x:0>8} end=0x{x:0>8} (size=0x{x:0>8}) \"{s}\"", .{
                "Custom",
                self.start,
                self.end,
                self.end - self.start,
                self.name,
            });
        }
    };

    pub const Type = struct {
        params: []const ValueType,
        returns: []const ValueType,
    };

    pub const Import = struct {
        module: []const u8,
        name: []const u8,
        kind: Kind,

        pub const Kind = union(ExternalType) {
            function: indexes.Type,
            table: struct {
                reftype: RefType,
                limits: Limits,
            },
            memory: Limits,
            global: struct {
                valtype: ValueType,
                mutable: bool,
            },
        };
    };

    pub const Func = struct {
        type_idx: indexes.Type,
    };

    pub const Table = struct {
        limits: Limits,
        reftype: RefType,
    };

    pub const Memory = struct {
        limits: Limits,
    };

    pub const Global = struct {
        valtype: ValueType,
        mutable: bool,
        init: InitExpression,
    };

    pub const Export = struct {
        name: []const u8,
        kind: ExternalType,
        index: u32,
    };

    pub const Element = struct {
        table_idx: indexes.Table,
        offset: InitExpression,
        func_idxs: []const indexes.Func,
    };

    pub const Code = struct {
        pub const Local = struct {
            valtype: ValueType,
            count: u32,
        };
        locals: []const Local,
        body: []const Instruction,
    };

    pub const Data = struct {
        index: indexes.Mem,
        offset: InitExpression,
        data: []const u8,
    };
};

/// Represents a wasm module, containing the version
/// of the wasm spec it complies with, and access to all of its
/// sections.
pub const Module = struct {
    custom: []const sections.Custom = &.{},
    types: SectionData(sections.Type) = .{},
    imports: SectionData(sections.Import) = .{},
    functions: SectionData(sections.Func) = .{},
    tables: SectionData(sections.Table) = .{},
    memories: SectionData(sections.Memory) = .{},
    globals: SectionData(sections.Global) = .{},
    exports: SectionData(sections.Export) = .{},
    elements: SectionData(sections.Element) = .{},
    code: SectionData(sections.Code) = .{},
    data: SectionData(sections.Data) = .{},
    start: ?indexes.Func = null,
    version: u32,

    /// Returns a custom section by its name.
    /// Will return `null` when the custom section of a given `name` does not exist.
    pub fn customByName(self: Module, name: []const u8) ?sections.Custom {
        return for (self.custom) |custom| {
            if (std.mem.eql(u8, custom.name, name)) break custom;
        } else null;
    }
};

pub fn SectionData(comptime T: type) type {
    return struct {
        data: []const T = &.{},
        start: usize = 0,
        end: usize = 0,

        /// Formats the `SectionData` for debug purposes
        pub fn format(self: @This(), comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
            _ = options;
            _ = fmt;
            const type_name = comptime blk: {
                var name: [@typeName(T).len]u8 = undefined;
                std.mem.copy(u8, &name, @typeName(T));
                name[0] = std.ascii.toUpper(name[0]);
                break :blk name;
            };
            try writer.print("{s: >8} start=0x{x:0>8} end=0x{x:0>8} (size=0x{x:0>8}) count: {d}", .{
                type_name,
                self.start,
                self.end,
                self.end - self.start,
                self.data.len,
            });
        }
    };
}

pub const Instruction = struct {
    opcode: wasm.Opcode,
    secondary: ?SecondaryOpcode = null,
    value: InstrValue,

    pub const InstrValue = union {
        none: void,
        u32: u32,
        i32: i32,
        i64: i64,
        f32: f32,
        f64: f64,
        reftype: RefType,
        blocktype: BlockType,
        multi_valtype: struct {
            data: [*]ValueType,
            len: u32,
        },
        multi: struct {
            x: u32,
            y: u32,
        },
        list: struct {
            data: [*]u32,
            len: u32,
        },
    };
};

/// Secondary opcode belonging to primary opcodes
/// that have as opcode 0xFC
pub const SecondaryOpcode = enum(u8) {
    i32_trunc_sat_f32_s = 0,
    i32_trunc_sat_f32_u = 1,
    i32_trunc_sat_f64_s = 2,
    i32_trunc_sat_f64_u = 3,
    i64_trunc_sat_f32_s = 4,
    i64_trunc_sat_f32_u = 5,
    i64_trunc_sat_f64_s = 6,
    i64_trunc_sat_f64_u = 7,
    memory_init = 8,
    data_drop = 9,
    memory_copy = 10,
    memory_fill = 11,
    table_init = 12,
    table_drop = 13,
    table_copy = 14,
    table_grow = 15,
    table_size = 16,
    table_fill = 17,
    _,
};

pub const need_secondary = @intToEnum(wasm.Opcode, 0xFC);
pub const table_get = @intToEnum(wasm.Opcode, 0x25);
pub const table_set = @intToEnum(wasm.Opcode, 0x26);
