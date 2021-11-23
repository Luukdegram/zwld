const std = @import("std");
const wasm = std.wasm;
const TypeInfo = std.builtin.TypeInfo;

/// Reference types, where the funcref references to a function regardless of its type
/// and ref references an object from the embedder.
pub const RefType = enum(u8) {
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

pub const FuncType = struct {
    params: []const wasm.Valtype,
    returns: []const wasm.Valtype,

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

    pub const Kind = union(wasm.ExternalKind) {
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
    valtype: wasm.Valtype,
    mutable: bool,
    init: ?InitExpression = null, // null for imported globals

    /// Index into the list of globals of the wasm module
    global_idx: u32,
};

pub const Export = struct {
    name: []const u8,
    kind: wasm.ExternalKind,
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
    prefix: Prefix,
    /// Type of the feature, must be unique in the sequence of features.
    tag: Tag,

    pub const Tag = enum {
        atomics,
        bulk_memory,
        exception_handling,
        multivalue,
        mutable_globals,
        nontrapping_fptoint,
        sign_ext,
        simd128,
        tail_call,
    };

    pub const Prefix = enum(u8) {
        used = '+',
        disallowed = '-',
        required = '=',
    };

    pub fn toString(self: Feature) []const u8 {
        return switch (self.tag) {
            .bulk_memory => "bulk-memory",
            .exception_handling => "exception-handling",
            .mutable_globals => "mutable-globals",
            .nontrapping_fptoint => "nontrapping-fptoint",
            .sign_ext => "sign-ext",
            .tail_call => "tail-call",
            else => @tagName(self),
        };
    }

    pub fn format(self: Feature, comptime fmt: []const u8, opt: std.fmt.FormatOptions, writer: anytype) !void {
        _ = opt;
        _ = fmt;
        try writer.print("{c} {s}", .{ self.prefix, self.toString() });
    }
};

pub const known_features = std.ComptimeStringMap(Feature.Tag, .{
    .{ "atomics", .atomics },
    .{ "bulk-memory", .bulk_memory },
    .{ "exception-handling", .exception_handling },
    .{ "multivalue", .multivalue },
    .{ "mutable-globals", .mutable_globals },
    .{ "nontrapping-fptoint", .nontrapping_fptoint },
    .{ "sign-ext", .sign_ext },
    .{ "simd128", .simd128 },
    .{ "tail-call", .tail_call },
});
