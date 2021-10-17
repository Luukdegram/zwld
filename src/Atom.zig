const Atom = @This();

const std = @import("std");
const wasm = @import("data.zig");
const Wasm = @import("Wasm.zig");
const Symbol = @import("Symbol.zig");

const leb = std.leb;
const log = std.log.scoped(.zwld);
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
relocs: std.ArrayListUnmanaged(wasm.Relocation) = .{},
/// Contains the binary data of an atom, which can be non-relocated
code: std.ArrayListUnmanaged(u8) = .{},
/// For code this is 1, for data this is set to the highest value of all segments
alignment: u32,

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
pub fn create(gpa: *Allocator) !*Atom {
    const atom = try gpa.create(Atom);
    atom.* = .{
        .alignment = 0,
        .file = undefined,
        .next = null,
        .prev = null,
        .size = 0,
        .sym_index = 0,
    };
    return atom;
}

/// Frees all resources owned by this `Atom`.
/// Also destroys itself, making any usage of this atom illegal.
pub fn deinit(self: *Atom, gpa: *Allocator) void {
    self.relocs.deinit(gpa);
    self.aliases.deinit(gpa);
    self.contained.deinit(gpa);
    self.code.deinit(gpa);
    gpa.destroy(self);
}

pub fn format(self: Atom, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
    _ = fmt;
    _ = options;
    _ = self;
    writer.print("TODO print Atoms", .{});
}

/// Returns the first `Atom` from a given atom
pub fn getFirst(self: *Atom) *Atom {
    var tmp = self;
    while (tmp.prev) |prev| tmp = prev;
    return tmp;
}

/// Returns the last `Atom` from a given atom
pub fn getLast(self: *Atom) *Atom {
    var tmp = self;
    while (tmp.next) |next| tmp = next;
    return tmp;
}

pub fn resolveRelocs(self: *Atom, gpa: *Allocator, wasm_bin: *Wasm) !void {
    const object = wasm_bin.objects.items[self.file];
    const symbol = object.symtable[self.sym_index];

    log.debug("Resolving relocs in atom '{s}' count({d})", .{
        symbol.name,
        self.relocs.items.len,
    });

    for (self.relocs.items) |reloc| {
        switch (reloc.relocation_type) {
            .R_WASM_TABLE_INDEX_I32 => {
                const rel_symbol = &object.symtable[reloc.index];
                if (requiresGOT(rel_symbol.*)) continue;
                log.debug("Relocating '{s}' ({s})", .{ rel_symbol.name, @tagName(reloc.relocation_type) });
                try wasm_bin.elements.appendSymbol(gpa, rel_symbol);
            },
            else => |tag| log.debug("TODO: support relocation type '{s}'", .{@tagName(tag)}),
        }
    }
}

/// Determines if a given symbol requires access to the global offset table
fn requiresGOT(symbol: Symbol) bool {
    if (symbol.isHidden() or symbol.isLocal()) return false;
    if (symbol.isDefined()) return false;
    return true;
}
