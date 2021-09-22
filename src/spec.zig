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
        /// For custom sections, data may be null when it represents
        /// linking metadata, features or relocations as we parse those individually
        /// into a self-contained type.
        data: ?[]const u8 = null,
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

pub const Relocation = struct {
    /// Represents the type of the `Relocation`
    relocation_type: Type,
    /// Offset of the value to rewrite relative to the relevant section's contents.
    /// When `offset` is zero, its position is immediately after the id and size of the section.
    offset: u32,
    /// The index of the symbol used.
    /// When the type is `R_WASM_TYPE_INDEX_LEB`, it represents the index of the type.
    index: u32,
    /// Addend to add to the address.
    /// This field is only non-null for `R_WASM_MEMORY_ADDR_*`, `R_WASM_FUNCTION_OFFSET_I32` and `R_WASM_SECTION_OFFSET_I32`.
    addend: ?u32,

    /// All possible relocation types currently existing.
    /// This enum is exhaustive as the spec is WIP and new types
    /// can be added but we do not want to have this result in compile errors.
    pub const Type = enum(u8) {
        R_WASM_FUNCTION_INDEX_LEB = 0,
        R_WASM_TABLE_INDEX_SLEB = 1,
        R_WASM_TABLE_INDEX_I32 = 2,
        R_WASM_MEMORY_ADDR_LEB = 3,
        R_WASM_MEMORY_ADDR_SLEB = 4,
        R_WASM_MEMORY_ADDR_I32 = 5,
        R_WASM_TYPE_INDEX_LEB = 6,
        R_WASM_GLOBAL_INDEX_LEB = 7,
        R_WASM_FUNCTION_OFFSET_I32 = 8,
        R_WASM_SECTION_OFFSET_I32 = 9,
        R_WASM_EVENT_INDEX_LEB = 10,
        R_WASM_GLOBAL_INDEX_I32 = 13,
        R_WASM_MEMORY_ADDR_LEB64 = 14,
        R_WASM_MEMORY_ADDR_SLEB64 = 15,
        R_WASM_MEMORY_ADDR_I64 = 16,
        R_WASM_TABLE_INDEX_SLEB64 = 18,
        R_WASM_TABLE_INDEX_I64 = 19,
        R_WASM_TABLE_NUMBER_LEB = 20,
        _,
    };

    /// Returns true for relocation types where the `addend` field is present.
    fn addendIsPresent(reloc_type: Type) bool {
        return switch (reloc_type) {
            .R_WASM_MEMORY_ADDR_LEB,
            .R_WASM_MEMORY_ADDR_SLEB,
            .R_WASM_MEMORY_ADDR_I32,
            .R_WASM_MEMORY_ADDR_LEB64,
            .R_WASM_MEMORY_ADDR_SLEB64,
            .R_WASM_MEMORY_ADDR_I64,
            .R_WASM_FUNCTION_OFFSET_I32,
            .R_WASM_SECTION_OFFSET_I32,
            => true,
            else => false,
        };
    }
};

pub const LinkMetaData = struct {
    /// The version of linking metadata contained in a section.
    /// The current version is 2. This means we can reject unexpected/unsupported versions.
    version: u32,
    /// A sequence of subsections
    subsections: []const Subsection,
};

pub const Subsection = union(enum) {
    segment_info: []const Segment,
    init_funcs: []const InitFunc,
    comdat_info: []const Comdat,
    symbol_table: []const SymInfo,
    empty: void,

    pub const Type = enum(u8) {
        WASM_SEGMENT_INFO = 5,
        WASM_INIT_FUNCS = 6,
        WASM_COMDAT_INFO = 7,
        WASM_SYMBOL_TABLE = 8,
    };
};

pub const Segment = struct {
    /// Segment's name, encoded as UTF-8 bytes.
    name: []const u8,
    /// The required alignment of the segment, encoded as a power of 2
    alignment: u32,
    /// Bitfield containing flags for a segment
    flags: u32,
};

pub const InitFunc = struct {
    /// Priority of the init function
    priority: u32,
    /// The symbol index of init function (not the function index).
    symbol_index: u32,
};

pub const Comdat = struct {
    name: []const u8,
    /// Must be zero, no flags are currently defined by the tool-convention.
    flags: u32,
    symbols: []const ComdatSym,
};

pub const SymInfo = struct {
    kind: Type,
    /// Bitfield containings flags for a symbol
    /// Can contain any of the flags defined in `SymbolFlag`
    flags: u32,
    /// The index of the Wasm object corresponding to the symbol.
    /// When `WASM_SYM_UNDEFINED` flag is set, this refers to an import.
    /// Can be `null` when it refers to a data symbol that is undefined.
    index: ?u32 = null,
    /// Symbol name, can be `null` when index refers to an import and
    /// `WASM_SYM_EXPLICIT_NAME` is not set.
    name: ?[]const u8 = null,
    /// Offset within the segment. Must be smaller than segment's size, and is only
    /// set when the symbol is defined.
    offset: ?u32 = null,
    /// Set when the symbol is defined, can be zero and must be smaller than segment's
    /// size where offset + size.
    size: ?u32 = null,

    pub fn hasFlag(self: SymInfo, flag: SymbolFlag) bool {
        return self.flags & @enumToInt(flag) != 0;
    }

    pub fn setFlag(self: *SymInfo, flag: SymbolFlag) void {
        self.flags |= @enumToInt(flag);
    }

    pub const Type = enum(u8) {
        SYMTAB_FUNCTION = 0,
        SYMTAB_DATA = 1,
        SYMTAB_GLOBAL = 2,
        SYMTAB_SECTION = 3,
        SYMTAB_EVENT = 4,
        SYMTAB_TABLE = 5,
    };

    /// Formats the symbol into human-readable text
    pub fn format(self: SymInfo, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = fmt;
        _ = options;

        const kind_fmt: u8 = switch (self.kind) {
            .SYMTAB_FUNCTION => 'F',
            .SYMTAB_DATA => 'D',
            .SYMTAB_GLOBAL => 'G',
            .SYMTAB_SECTION => 'S',
            .SYMTAB_EVENT => 'E',
            .SYMTAB_TABLE => 'T',
        };
        const visible: []const u8 = if (self.hasFlag(.WASM_SYM_VISIBILITY_HIDDEN)) "no" else "yes";
        const binding: []const u8 = if (self.hasFlag(.WASM_SYM_BINDING_LOCAL)) "local" else "global";

        try writer.print(
            "{c} binding={s} visible={s} id={d} name={s}",
            .{ kind_fmt, binding, visible, self.index, self.name },
        );
    }
};

pub const SymbolFlag = enum(u32) {
    /// Indicates a weak symbol.
    /// When linking multiple modules defining the same symbol, all weak definitions are discarded
    /// in favourite of the strong definition. When no strong definition exists, all weak but one definiton is discarded.
    /// If multiple definitions remain, we get an error: symbol collision.
    WASM_SYM_BINDING_WEAK = 1,
    /// Indicates a local, non-exported, non-module-linked symbol.
    /// The names of local symbols are not required to be unique, unlike non-local symbols.
    WASM_SYM_BINDING_LOCAL = 2,
    /// Indicates a hidden symbol. Hidden symbols will not be exported to the link result, but may
    /// link to other modules.
    WASM_SYM_VISIBILITY_HIDDEN = 4,
    /// Indicates an undefined symbol. For non-data symbols, this must match whether the symbol is
    /// an import or is defined. For data symbols however, determines whether a segment is specified.
    WASM_SYM_UNDEFINED = 0x10,
    /// Indicates a symbol of which its intention is to be exported from the wasm module to the host environment.
    /// This differs from the visibility flag as this flag affects the static linker.
    WASM_SYM_EXPORTED = 0x20,
    /// Indicates the symbol uses an explicit symbol name, rather than reusing the name from a wasm import.
    /// Allows remapping imports from foreign WASM modules into local symbols with a different name.
    WASM_SYM_EXPLICIT_NAME = 0x40,
    /// Indicates the symbol is to be included in the linker output, regardless of whether it is used or has any references to it.
    WASM_SYM_NO_STRIP = 0x80,
};

pub const ComdatSym = struct {
    kind: Type,
    /// Index of the data segment/function/global/event/table within a WASM module.
    /// The object must not be an import.
    index: u32,

    pub const Type = enum(u8) {
        WASM_COMDAT_DATA = 0,
        WASM_COMDAT_FUNCTION = 1,
        WASM_COMDAT_GLOBAL = 2,
        WASM_COMDAT_EVENT = 3,
        WASM_COMDAT_TABLE = 4,
        WASM_COMDAT_SECTION = 5,
    };
};

pub const Feature = struct {
    /// Provides information about the usage of the feature.
    /// - '0x2b' (+): Object uses this feature, and the link fails if feature is not in the allowed set.
    /// - '0x2d' (-): Object does not use this feature, and the link fails if this feature is in the allowed set.
    /// - '0x3d' (=): Object uses this feature, and the link fails if this feature is not in the allowed set,
    /// or if any object does not use this feature.
    prefix: u8,
    /// name of the feature, must be unique in the sequence of features.
    name: []const u8,
};

pub const known_features = std.ComptimeStringMap(void, .{
    .{"atomics"},
    .{"bulk-memory"},
    .{"exception-handling"},
    .{"multivalue"},
    .{"mutable-globals"},
    .{"nontrapping-fptoint"},
    .{"sign-ext"},
    .{"simd128"},
    .{"tail-call"},
});
