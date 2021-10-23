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
/// Size of the atom, used to calculate section sizes in the final binary
size: u32,
/// List of relocations belonging to this atom
relocs: std.ArrayListUnmanaged(wasm.Relocation) = .{},
/// Contains the binary data of an atom, which can be non-relocated
code: std.ArrayListUnmanaged(u8) = .{},
/// For code this is 1, for data this is set to the highest value of all segments
alignment: u32,
/// Offset into the section where the atom lives, this already accounts
/// for alignment.
offset: u32,

/// Next atom in relation to this atom.
/// When null, this atom is the last atom
next: ?*Atom,
/// Previous atom in relation to this atom.
/// is null when this atom is the first in its order
prev: ?*Atom,

/// Creates a new Atom with default fields
pub fn create(gpa: *Allocator) !*Atom {
    const atom = try gpa.create(Atom);
    atom.* = .{
        .alignment = 0,
        .file = undefined,
        .next = null,
        .offset = 0,
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
    self.code.deinit(gpa);
    gpa.destroy(self);
}

pub fn format(self: Atom, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
    _ = fmt;
    _ = options;
    writer.print("Atom{{ .sym_index = {d}, .alignment = {d}, .size = {d}, .offset = 0x{x:0>8} }}", .{
        self.sym_index,
        self.alignment,
        self.size,
        self.offset,
    });
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
    const symbol: Symbol = object.symtable[self.sym_index];

    log.debug("Resolving relocs in atom '{s}' count({d})", .{
        symbol.name,
        self.relocs.items.len,
    });

    for (self.relocs.items) |reloc| {
        const rel_symbol: *Symbol = &object.symtable[reloc.index];
        switch (reloc.relocation_type) {
            .R_WASM_TABLE_INDEX_I32 => {
                if (!requiresGOTAccess(wasm_bin, rel_symbol.*)) {
                    try wasm_bin.elements.appendSymbol(gpa, rel_symbol);
                }
                const index = rel_symbol.getTableIndex() orelse 0;
                log.debug("Relocating '{s}' referenced in '{s}' offset=0x{x:0>8} index={d}", .{
                    rel_symbol.name,
                    symbol.name,
                    reloc.offset,
                    index,
                });
                std.mem.writeIntLittle(u32, self.code.items[reloc.offset..][0..4], index);
            },
            .R_WASM_TABLE_INDEX_SLEB => {
                const index = symbol.kind.function.func.func_idx;
                log.debug("Relocating '{s}' referenced in '{s}' offset=0x{x:0>8} index={d}", .{
                    rel_symbol.name,
                    symbol.name,
                    reloc.offset,
                    index,
                });
                leb.writeUnsignedFixed(5, self.code.items[reloc.offset..][0..5], index);
            },
            .R_WASM_GLOBAL_INDEX_LEB => {
                const index = rel_symbol.kind.global.global.global_idx;
                log.debug("Relocating '{s}' referenced in '{s}' offset=0x{x:0>8} index={d}", .{
                    rel_symbol.name,
                    symbol.name,
                    reloc.offset,
                    index,
                });
                leb.writeUnsignedFixed(5, self.code.items[reloc.offset..][0..5], index);
            },
            .R_WASM_FUNCTION_INDEX_LEB => {
                const index = rel_symbol.kind.function.functionIndex();
                log.debug("Relocating '{s}' referenced in '{s}' offset=0x{x:0>8} index={d}", .{
                    rel_symbol.name,
                    symbol.name,
                    reloc.offset,
                    index,
                });
                leb.writeUnsignedFixed(5, self.code.items[reloc.offset..][0..5], index);
            },
            else => |tag| log.debug("TODO: support relocation type '{s}'", .{@tagName(tag)}),
        }
    }
}

/// Determines if a given symbol requires access to the global offset table
fn requiresGOTAccess(wasm_bin: *const Wasm, symbol: Symbol) bool {
    // TODO: replace below check with checking if this is not
    // a PIE binary. Because only then, GOTAccess *may* be required.
    _ = wasm_bin;
    if (true) return false;
    if (symbol.isHidden() or symbol.isLocal()) return false;
    if (symbol.isDefined()) return false;
    return true;
}
