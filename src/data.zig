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
    funcref: u32,
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
pub const ValueType = enum(u8) {
    i32 = 0x7F,
    i64 = 0x7E,
    f32 = 0xfD,
    f64 = 0xfE,
    funcref = 0x70,
    externref = 0x6F,
};

/// Wasm sections, including proposals.
/// Section is built using `std.wasm.Section` and adding
/// proposed sections to it.
///
/// Note: This version is non-exhaustive to continue parsing
/// when a new section is proposed but not yet implemented.
pub const SectionType = enum(u8) {
    custom,
    type,
    import,
    function,
    table,
    memory,
    global,
    @"export",
    start,
    element,
    code,
    data,
    data_count,
    _,
};

/// Represents a wasm section entry within a wasm module
/// A section contains meta data that can be used to parse its contents from within a file.
pub const Section = struct {
    /// The type of a section
    section_kind: SectionType,
    /// Offset into the object file where the section starts
    offset: usize,
    /// Size in bytes of the section
    size: usize,
};

/// Merges a given enum type and a slice of `EnumField` into a new enum type
fn MergedEnum(comptime T: type, comptime fields: []const TypeInfo.EnumField) type {
    if (@typeInfo(T) != .Enum) {
        @compileError("Given type 'T' must be an enum type but instead was given: " ++ @typeName(T));
    }

    const new_fields = std.meta.fields(T) ++ fields;

    return @Type(.{ .Enum = .{
        .layout = .Auto,
        .tag_type = u8,
        .fields = new_fields,
        .decls = &.{},
        .is_exhaustive = false,
    } });
}

/// External types that can be imported or exported between to/from the host
pub const ExternalType = wasm.ExternalKind;

/// Limits classify the size range of resizeable storage associated with memory types and table types.
pub const Limits = struct {
    min: u32,
    max: ?u32,
};

pub const InitExpression = union(enum) {
    i32_const: i32,
    /// Uses the value of a global at index `global_get`
    global_get: u32,
};

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

pub const FuncType = struct {
    params: []const ValueType,
    returns: []const ValueType,

    pub fn format(self: FuncType, comptime fmt: []const u8, opt: std.fmt.FormatOptions, writer: anytype) !void {
        _ = fmt;
        _ = opt;
        try writer.writeByte('(');
        for (self.params) |param, i| {
            try writer.print("{s}", .{@tagName(param)});
            if (i + 1 != self.params.len) {
                try writer.writeAll(", ");
            }
        }
        try writer.writeAll(") -> ");
        if (self.returns.len == 0) {
            try writer.writeAll("nil");
        } else {
            for (self.returns) |return_ty, i| {
                try writer.print("{s}", .{@tagName(return_ty)});
                if (i + 1 != self.returns.len) {
                    try writer.writeAll(", ");
                }
            }
        }
    }
};

pub const Import = struct {
    module_name: []const u8,
    name: []const u8,
    kind: Kind,

    pub const Kind = union(ExternalType) {
        function: Func,
        table: Table,
        memory: Limits,
        global: Global,
    };
};

pub const Func = struct {
    /// Index into the list of types
    type_idx: u32,
    /// Index into the list of functions
    func_idx: u32,

    /// Pointer to a `Type`
    /// This should be the same type that can be found using the `type_idx`
    /// into the list of types
    func_type: *const FuncType,

    /// When the function is exported, this field will be set.
    export_name: ?[]const u8 = null,
};

pub const Table = struct {
    limits: Limits,
    reftype: RefType,

    /// Represents the index within the list of tables
    table_idx: u32,
};

pub const Memory = struct {
    limits: Limits,
};

pub const Global = struct {
    valtype: ValueType,
    mutable: bool,
    init: ?InitExpression = null, // null for imported globals

    /// Index into the list of globals of the wasm module
    global_idx: u32,
};

pub const Export = struct {
    name: []const u8,
    kind: ExternalType,
    index: u32,
};

pub const Element = struct {
    table_idx: u32,
    offset: InitExpression,
    func_idxs: []const u32,
};

pub const Code = struct {
    /// Offset into the code section where the body starts
    offset: u32,
    /// Body of the function in bytes
    data: []u8,
    /// Pointer to the function this body belongs to
    func: *const Func,
};

pub const Data = struct {
    index: u32,
    offset: InitExpression,
    data: []u8,
    /// Offset within the data section itself
    seg_offset: u32,
};

pub const Relocation = struct {
    /// Represents the type of the `Relocation`
    relocation_type: RelocationType,
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
    /// can be added which means that a generated binary will be invalid,
    /// so instead we will show an error in such cases.
    pub const RelocationType = enum(u8) {
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

        /// Returns true for relocation types where the `addend` field is present.
        pub fn addendIsPresent(self: RelocationType) bool {
            return switch (self) {
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

    /// Verifies the relocation type of a given `Relocation` and returns
    /// true when the relocation references a function call or address to a function.
    pub fn isFunction(self: Relocation) bool {
        return switch (self.relocation_type) {
            .R_WASM_FUNCTION_INDEX_LEB,
            .R_WASM_TABLE_INDEX_SLEB,
            => true,
            else => false,
        };
    }

    pub fn format(self: Relocation, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = fmt;
        _ = options;
        try writer.print("{s} offset=0x{x:0>6} symbol={d}", .{
            @tagName(self.relocation_type),
            self.offset,
            self.index,
        });
    }
};

pub const SubsectionType = enum(u8) {
    WASM_SEGMENT_INFO = 5,
    WASM_INIT_FUNCS = 6,
    WASM_COMDAT_INFO = 7,
    WASM_SYMBOL_TABLE = 8,
};

pub const Segment = struct {
    /// Segment's name, encoded as UTF-8 bytes.
    name: []const u8,
    /// The required alignment of the segment, encoded as a power of 2
    alignment: u32,
    /// Bitfield containing flags for a segment
    flags: u32,

    pub fn outputName(self: Segment) []const u8 {
        if (std.mem.startsWith(u8, self.name, ".rodata.")) {
            return ".rodata";
        } else if (std.mem.startsWith(u8, self.name, ".text.")) {
            return ".text";
        } else if (std.mem.startsWith(u8, self.name, ".rodata.")) {
            return ".rodata";
        } else if (std.mem.startsWith(u8, self.name, ".data.")) {
            return ".data";
        } else if (std.mem.startsWith(u8, self.name, ".bss.")) {
            return ".bss";
        }
        return self.name;
    }
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
