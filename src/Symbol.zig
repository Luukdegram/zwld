//! Wasm symbols describing its kind,
//! name and its properties.
const Symbol = @This();

const std = @import("std");
const types = @import("types.zig");

/// Bitfield containings flags for a symbol
/// Can contain any of the flags defined in `Flag`
flags: u32,
/// Symbol name, when undefined this will be taken from the import.
name: []const u8,
/// Represents what type of symbol this represents.
tag: Tag,
/// This is `undefined` when the `tag` is `Data` and the symbol is undefined.
/// Therefore accessing the index field in such cases is illegal behavior.
index: u32,

pub const Tag = enum {
    function,
    data,
    global,
    section,
    event,
    table,
};

/// From a given symbol kind, returns the `ExternalType`
/// Asserts the given tag can be represented as an external type.
pub fn externalType(self: Symbol) std.wasm.ExternalKind {
    return switch (self.tag) {
        .function => .function,
        .global => .global,
        .data => .memory,
        .section => unreachable, // Not an external type
        .event => unreachable, // Not an external type
        .table => .table,
    };
}

pub const Flag = enum(u32) {
    /// Indicates a weak symbol.
    /// When linking multiple modules defining the same symbol, all weak definitions are discarded
    /// in favourite of the strong definition. When no strong definition exists, all weak but one definiton is discarded.
    /// If multiple definitions remain, we get an error: symbol collision.
    WASM_SYM_BINDING_WEAK = 0x1,
    /// Indicates a local, non-exported, non-module-linked symbol.
    /// The names of local symbols are not required to be unique, unlike non-local symbols.
    WASM_SYM_BINDING_LOCAL = 0x2,
    /// Represents the binding of a symbol, indicating if it's local or not, and weak or not.
    WASM_SYM_BINDING_MASK = 0x3,
    /// Indicates a hidden symbol. Hidden symbols will not be exported to the link result, but may
    /// link to other modules.
    WASM_SYM_VISIBILITY_HIDDEN = 0x4,
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
    /// Indicates a symbol is TLS
    WASM_SYM_TLS = 0x100,
};

/// Verifies if the given symbol should be imported from the
/// host environment or not
pub fn requiresImport(self: Symbol) bool {
    if (!self.isUndefined()) return false;
    if (self.isWeak()) return false;
    if (self.tag == .data) return false;
    // if (self.isDefined() and self.isWeak()) return true; //TODO: Only when building shared lib

    return true;
}

pub fn hasFlag(self: Symbol, flag: Flag) bool {
    return self.flags & @enumToInt(flag) != 0;
}

pub fn setFlag(self: *Symbol, flag: Flag) void {
    self.flags |= @enumToInt(flag);
}

pub fn isUndefined(self: Symbol) bool {
    return self.flags & @enumToInt(Flag.WASM_SYM_UNDEFINED) != 0;
}

pub fn setUndefined(self: *Symbol, is_undefined: bool) void {
    if (is_undefined) {
        self.setFlag(.WASM_SYM_UNDEFINED);
    } else {
        self.flags &= ~@enumToInt(Flag.WASM_SYM_UNDEFINED);
    }
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

pub fn isHidden(self: Symbol) bool {
    return self.flags & @enumToInt(Flag.WASM_SYM_VISIBILITY_HIDDEN) != 0;
}

pub fn isNoStrip(self: Symbol) bool {
    return self.flags & @enumToInt(Flag.WASM_SYM_NO_STRIP) != 0;
}

pub fn isExported(self: Symbol) bool {
    if (self.isUndefined() or self.isLocal()) return false;
    if (self.isHidden()) return false;
    return true;
}

pub fn isWeak(self: Symbol) bool {
    return self.flags & @enumToInt(Flag.WASM_SYM_BINDING_WEAK) != 0;
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

/// Namespace containing all symbols that are linker defined,
/// rather than imported/defined by an object file.
///
/// By default all symbols are initialized by having their value set to `null`.
/// They will be initialized by the linker depending on the definiton of the object files.
pub const linker_defined = struct {
    /// Represents a synthetic stack pointer,
    /// used by wasm modules to emulate an explicit stack.
    pub var stack_pointer: ?*Symbol = null;
    /// Initialized when an object file notates the need for one.
    pub var indirect_function_table: ?*Symbol = null;

    /// Names of the linker defined symbols as known by the wasm tool convention
    pub const names = struct {
        pub const stack_pointer = "__stack_pointer";
        pub const indirect_function_table = "__indirect_function_table";
    };
};
