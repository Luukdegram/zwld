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
pub const SectionType = MergedEnum(wasm.Section, &.{
    .{ .name = "data_count", .value = 12 },
    .{ .name = "module", .value = 14 },
    .{ .name = "instance", .value = 15 },
    .{ .name = "alias", .value = 16 },
});

/// Represents a wasm section entry within a wasm module
/// A section contains meta data that can be used to parse its contents from within a file.
pub const Section = struct {
    /// The type of a section
    section_kind: SectionType,
    /// Offset into the object file where the section starts
    offset: usize,
    /// Size in bytes of the section
    size: usize,

    /// Returns the index of a given section type within a given slice of sections.
    /// When the section type is not found, `null` will be returned.
    ///
    /// Asserts `sec_type` is not a custom section
    pub fn getIndex(section_slice: []const Section, sec_type: SectionType) ?u16 {
        std.debug.assert(sec_type != .custom);
        return for (section_slice) |section, idx| {
            if (section.section_kind == sec_type) {
                break @intCast(u16, idx);
            }
        } else null;
    }
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
    pub const Global = enum(u32) { _ };
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

        pub fn format(self: Type, comptime fmt: []const u8, opt: std.fmt.FormatOptions, writer: anytype) !void {
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
            function: indexes.Type,
            table: sections.Table,
            memory: Limits,
            global: struct {
                valtype: ValueType,
                mutable: bool,
            },
        };
    };

    pub const Func = struct {
        /// Index into the list of types
        type_idx: indexes.Type,
        /// Index into the list of functions
        func_idx: indexes.Func,

        /// Pointer to a `Type`
        /// This should be the same type that can be found using the `type_idx`
        /// into the list of types
        func_type: *const sections.Type,

        /// When the function is exported, this field will be set.
        export_name: ?[]const u8 = null,
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

        /// Index into the list of globals of the wasm module
        global_idx: indexes.Global,
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
        /// Offset into the code section where the body starts
        offset: u32,
        /// Body of the function in bytes
        data: []u8,
        /// Pointer to the function this body belongs to
        func: *const Func,
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

        /// Returns true for relocation types where the `addend` field is present.
        pub fn addendIsPresent(self: Type) bool {
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

pub const Symbol = struct {
    /// Bitfield containings flags for a symbol
    /// Can contain any of the flags defined in `SymbolFlag`
    flags: u32,
    /// Symbol name, when undefined this will be taken from the import.
    name: []const u8,
    /// Index into the symbol table of the final file
    /// It's illegal to read this before it's set.
    output_index: u32 = undefined,
    /// An union that represents both the type of symbol
    /// as well as the data it holds.
    kind: Kind,

    /// A union of possible symbol types, providing
    /// access to type-dependent information.
    pub const Kind = union(enum) {
        function: Function,
        data: Data,
        global: Global,
        section: u32,
        event: Event,
        table: Table,

        pub const Tag = std.meta.Tag(Kind);
    };

    /// Attempts to unwrap a symbol based on a given expected `Kind`.
    /// When the kind is not the active tag of the symbol, this returns null.
    pub fn unwrapAs(self: Symbol, comptime kind: Kind.Tag) ?std.meta.TagPayload(Kind, kind) {
        if (std.meta.activeTag(self.kind) != kind) return null;

        return @field(self.kind, @tagName(kind));
    }

    /// Returns the index the symbol points to.
    /// In case of a data symbol, this can result into `null`.
    pub fn index(self: Symbol) ?u32 {
        return switch (self.kind) {
            .function => |func| func.index,
            .data => |data| data.index,
            .global => |global| global.index,
            .section => |section| section,
            .event => |event| event.index,
            .table => |table| table.index,
        };
    }

    /// Sets the index of a symbol.
    pub fn setIndex(self: *Symbol, idx: u32) void {
        return switch (self.kind) {
            .function => |*func| func.index = idx,
            .data => |*data| data.index = idx,
            .global => |*global| global.index = idx,
            .section => |*section| section.* = idx,
            .event => |*event| event.index = idx,
            .table => |*table| table.index = idx,
        };
    }

    /// Verifies if the given symbol should be imported from the
    /// host environment or not
    pub fn requiresImport(self: Symbol) bool {
        if (self.kind == .data) return false;
        if (!self.isUndefined() and self.isWeak()) return true;
        if (!self.isUndefined()) return false;
        if (self.isWeak()) return false;

        return true;
    }

    pub const Data = struct {
        index: ?u32 = null,
        offset: ?u32 = null,
        size: ?u32 = null,
    };

    pub const Global = struct {
        index: u32,
    };

    pub const Function = struct {
        index: u32,
        /// Pointer to the function representing this symbol
        func: ?*const sections.Func,
    };

    pub const Event = struct {
        index: u32,
    };

    pub const Table = struct {
        index: u32,
    };

    pub fn hasFlag(self: Symbol, flag: SymbolFlag) bool {
        return self.flags & @enumToInt(flag) != 0;
    }

    pub fn setFlag(self: *Symbol, flag: SymbolFlag) void {
        self.flags |= @enumToInt(flag);
    }

    pub fn isUndefined(self: Symbol) bool {
        return self.flags & @enumToInt(SymbolFlag.WASM_SYM_UNDEFINED) != 0;
    }

    pub fn isVisible(self: Symbol) bool {
        return self.flags & @enumToInt(SymbolFlag.WASM_SYM_VISIBILITY_HIDDEN) == 0;
    }

    pub fn isLocal(self: Symbol) bool {
        return self.flags & @enumToInt(SymbolFlag.WASM_SYM_BINDING_LOCAL) != 0;
    }

    pub fn isGlobal(self: Symbol) bool {
        return self.flags & @enumToInt(SymbolFlag.WASM_SYM_BINDING_LOCAL) == 0;
    }

    pub fn isExported(self: Symbol) bool {
        return self.flags & @enumToInt(SymbolFlag.WASM_SYM_EXPORTED) != 0;
    }

    pub fn isWeak(self: Symbol) bool {
        return self.flags & @enumToInt(SymbolFlag.WASM_SYM_BINDING_WEAK) != 0;
    }

    pub fn eqlBinding(self: Symbol, other: Symbol) bool {
        if (self.isLocal() != other.isLocal()) {
            return false;
        }
        if (self.isWeak() != other.isWeak()) {
            return false;
        }
        return true;
    }

    /// Formats the symbol into human-readable text
    pub fn format(self: Symbol, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = fmt;
        _ = options;

        const kind_fmt: u8 = switch (self.kind) {
            .function => 'F',
            .data => 'D',
            .global => 'G',
            .section => 'S',
            .event => 'E',
            .table => 'T',
        };
        const visible: []const u8 = if (self.isVisible()) "yes" else "no";
        const binding: []const u8 = if (self.isLocal()) "local" else "global";

        try writer.print(
            "{c} binding={s} visible={s} id={d} name={s}",
            .{ kind_fmt, binding, visible, self.index(), self.name },
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
