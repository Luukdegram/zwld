const Atom = @This();

const std = @import("std");
const types = @import("types.zig");
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
relocs: std.ArrayListUnmanaged(types.Relocation) = .{},
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
pub fn create(gpa: Allocator) !*Atom {
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
pub fn deinit(self: *Atom, gpa: Allocator) void {
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

/// Resolves the relocations within the atom, writing the new value
/// at the calculated offset.
pub fn resolveRelocs(self: *Atom, wasm_bin: *const Wasm) !void {
    const object = wasm_bin.objects.items[self.file];
    const symbol: Symbol = object.symtable[self.sym_index];

    log.debug("Resolving relocs in atom '{s}' count({d})", .{
        symbol.name,
        self.relocs.items.len,
    });

    for (self.relocs.items) |reloc| {
        const value = self.relocationValue(reloc, wasm_bin);
        log.debug("Relocating '{s}' referenced in '{s}' offset=0x{x:0>8} value={d}", .{
            object.symtable[reloc.index].name,
            symbol.name,
            reloc.offset,
            value,
        });

        switch (reloc.relocation_type) {
            .R_WASM_TABLE_INDEX_I32,
            .R_WASM_FUNCTION_OFFSET_I32,
            .R_WASM_GLOBAL_INDEX_I32,
            .R_WASM_MEMORY_ADDR_I32,
            .R_WASM_SECTION_OFFSET_I32,
            => std.mem.writeIntLittle(u32, self.code.items[reloc.offset..][0..4], @intCast(u32, value)),
            .R_WASM_TABLE_INDEX_I64,
            .R_WASM_MEMORY_ADDR_I64,
            => std.mem.writeIntLittle(u64, self.code.items[reloc.offset..][0..8], value),
            .R_WASM_GLOBAL_INDEX_LEB,
            .R_WASM_EVENT_INDEX_LEB,
            .R_WASM_FUNCTION_INDEX_LEB,
            .R_WASM_MEMORY_ADDR_LEB,
            .R_WASM_MEMORY_ADDR_SLEB,
            .R_WASM_TABLE_INDEX_SLEB,
            .R_WASM_TABLE_NUMBER_LEB,
            .R_WASM_TYPE_INDEX_LEB,
            => leb.writeUnsignedFixed(5, self.code.items[reloc.offset..][0..5], @intCast(u32, value)),
            .R_WASM_MEMORY_ADDR_LEB64,
            .R_WASM_MEMORY_ADDR_SLEB64,
            .R_WASM_TABLE_INDEX_SLEB64,
            => leb.writeUnsignedFixed(10, self.code.items[reloc.offset..][0..10], value),
        }
    }
}

/// From a given `relocation` will return the new value to be written.
/// All values will be represented as a `u64` as all values can fit within it.
/// The final value must be casted to the correct size.
fn relocationValue(self: *Atom, relocation: types.Relocation, wasm_bin: *const Wasm) u64 {
    const object = wasm_bin.objects.items[self.file];
    const symbol: Symbol = object.symtable[relocation.index];
    const symbol_loc = wasm_bin.symbol_resolver.get(symbol.name).?;
    const actual_symbol = symbol_loc.getSymbol(wasm_bin);
    return switch (relocation.relocation_type) {
        .R_WASM_FUNCTION_INDEX_LEB => actual_symbol.index().?,
        .R_WASM_TABLE_NUMBER_LEB => symbol.kind.table.table.table_idx,
        .R_WASM_TABLE_INDEX_I32,
        .R_WASM_TABLE_INDEX_I64,
        .R_WASM_TABLE_INDEX_SLEB,
        .R_WASM_TABLE_INDEX_SLEB64,
        => wasm_bin.elements.indirect_functions.get(symbol_loc) orelse 0,
        .R_WASM_TYPE_INDEX_LEB => wasm_bin.functions.items.items[symbol.index().?].type_index,
        .R_WASM_GLOBAL_INDEX_I32,
        .R_WASM_GLOBAL_INDEX_LEB,
        => actual_symbol.index().?,
        .R_WASM_MEMORY_ADDR_I32,
        .R_WASM_MEMORY_ADDR_I64,
        .R_WASM_MEMORY_ADDR_LEB,
        .R_WASM_MEMORY_ADDR_LEB64,
        .R_WASM_MEMORY_ADDR_SLEB,
        .R_WASM_MEMORY_ADDR_SLEB64,
        => blk: {
            if (symbol.isUndefined() and (symbol.kind == .data or symbol.isWeak())) {
                return 0;
            }
            const segment_name = object.segment_info[symbol.index().?].outputName();
            const atom_index = wasm_bin.data_segments.get(segment_name).?;
            var target_atom = wasm_bin.atoms.getPtr(atom_index).?.*.getFirst();
            while (true) {
                if (target_atom.sym_index == relocation.index) break;
                if (target_atom.next) |next| {
                    target_atom = next;
                } else break;
            }
            const segment = wasm_bin.segments.items[atom_index];
            const base = wasm_bin.options.global_base orelse 1024;
            const offset = target_atom.offset + segment.offset;
            break :blk offset + base + (relocation.addend orelse 0);
        },
        .R_WASM_EVENT_INDEX_LEB => symbol.kind.event.index,
        .R_WASM_SECTION_OFFSET_I32,
        .R_WASM_FUNCTION_OFFSET_I32,
        => relocation.offset,
    };
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
