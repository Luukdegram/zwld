//! Wasm symbols describing its kind,
//! name and its properties.
const Symbol = @This();

const std = @import("std");
const wasm = @import("data.zig");

/// Bitfield containings flags for a symbol
/// Can contain any of the flags defined in `Flag`
flags: u32,
/// Symbol name, when undefined this will be taken from the import.
name: []const u8,
/// An union that represents both the type of symbol
/// as well as the data it holds.
kind: Kind,

/// A union of possible symbol types, providing
/// access to type-dependent information.
pub const Kind = union(Tag) {
    function: Function,
    data: Data,
    global: Global,
    section: u32,
    event: Event,
    table: Table,

    pub const Tag = enum {
        function,
        data,
        global,
        section,
        event,
        table,

        /// From a given symbol kind, returns the `ExternalType`
        pub fn externalType(self: Tag) wasm.ExternalType {
            return switch (self) {
                .function => .function,
                .global => .global,
                .data => .memory,
                .section => unreachable, // Not an external type
                .event => unreachable, // Not an external type
                .table => .table,
            };
        }
    };
};

pub const Flag = enum(u32) {
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

/// Sets the table index for the given symbol.
/// Asserts the symbol is a function.
pub fn setTableIndex(self: *Symbol, table_index: u32) void {
    self.kind.function.table_index = table_index;
}

/// Returns the table index of the symbol.
/// Asserts the given symbol is a function symbol.
pub fn getTableIndex(self: *Symbol) ?u32 {
    return self.kind.function.table_index;
}

/// Verifies if the given symbol should be imported from the
/// host environment or not
pub fn requiresImport(self: Symbol) bool {
    if (self.kind == .data) return false;
    if (self.isDefined() and self.isWeak()) return true; //TODO: Only when building shared lib
    if (self.isDefined()) return false;
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

    /// Reference to the Global represented by this symbol
    global: *wasm.Global,
};

pub const Function = struct {
    index: u32,
    /// Pointer to the function representing this symbol
    func: *wasm.Func,
    /// When set, this function is an indirect function call
    /// and this index represents its position within the table.
    table_index: ?u32 = null,
};

pub const Event = struct {
    index: u32,
};

pub const Table = struct {
    index: u32,

    /// Reference to a table that is represented by this symbol
    table: *wasm.Table,
};

pub fn hasFlag(self: Symbol, flag: Flag) bool {
    return self.flags & @enumToInt(flag) != 0;
}

pub fn setFlag(self: *Symbol, flag: Flag) void {
    self.flags |= @enumToInt(flag);
}

pub fn isUndefined(self: Symbol) bool {
    return self.flags & @enumToInt(Flag.WASM_SYM_UNDEFINED) != 0;
}

pub fn isDefined(self: Symbol) bool {
    return !self.isUndefined();
}

pub fn isVisible(self: Symbol) bool {
    return self.flags & @enumToInt(Flag.WASM_SYM_VISIBILITY_HIDDEN) == 0;
}

pub fn isLocal(self: Symbol) bool {
    return self.flags & @enumToInt(Flag.WASM_SYM_BINDING_LOCAL) != 0;
}

pub fn isGlobal(self: Symbol) bool {
    return self.flags & @enumToInt(Flag.WASM_SYM_BINDING_LOCAL) == 0;
}

pub fn isExported(self: Symbol) bool {
    if (self.isDefined() and self.isWeak()) return true;
    if (self.isUndefined()) return false;
    if (self.isVisible()) return true;
    return self.flags & @enumToInt(Flag.WASM_SYM_EXPORTED) != 0;
}

pub fn isWeak(self: Symbol) bool {
    return self.flags & @enumToInt(Flag.WASM_SYM_BINDING_WEAK) != 0;
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
