const Atom = @This();

const std = @import("std");
const spec = @import("spec.zig");
const Wasm = @import("Wasm.zig");

const mem = std.mem;
const Allocator = mem.Allocator;

/// Local symbol index
sym_index: u32,
/// Index into a list of object files
file: u16,
/// List of symbol aliases pointing to the same atom by different objects.
aliases: std.ArrayListUnmanaged(u32) = .{},
/// List of symbols contained within this atom (data symbols)
contained: std.ArrayListUnmanaged(SymbolAtOffset) = .{},
/// Size of the atom, used to calculate section sizes in the final binary
size: u32,
/// List of relocations belonging to this atom
relocs: std.ArrayListUnmanaged(spec.Relocation) = .{},
/// Contains the binary data of an atom, which can be non-relocated
code: std.ArrayListUnmanaged(u8) = .{},

/// Next atom in relation to this atom.
/// When null, this atom is the last atom
next: ?*Atom,
/// Previous atom in relation to this atom.
/// is null when this atom is the first in its order
prev: ?*Atom,

pub const SymbolAtOffset = struct {
    local_sym_index: u32,
    offset: u32,
};

/// Creates a new Atom with default fields
pub fn createEmpty(gpa: *Allocator) !*Atom {
    const atom = try gpa.create(Atom);
    atom.* = .{
        .sym_index = 0,
        .file = undefined,
        .size = 0,
        .prev = null,
        .next = null,
    };
    return atom;
}

/// Frees all resources owned by this `Atom`.
/// Also destroys itself, making any usage of this atom illegal.
pub fn deinit(self: *Atom, gpa: *Allocator) void {
    self.relocs.deinit(gpa);
    self.aliases.deinit(gpa);
    gpa.destroy(self);
}

pub fn format(self: Atom, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
    _ = fmt;
    _ = options;
    _ = self;
    writer.print("TODO print Atoms", .{});
}

pub fn resolveRelocs(self: *Atom, wasm: *Wasm) !void {
    _ = self;
    _ = wasm;
    @panic("TODO: Implement resolving relocations");
}
