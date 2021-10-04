//! Writes all the wasm sections that are valid
//! to the final binary file that was passed to the `Wasm` object.
//! When a section contains no entries, the section will not be emitted.

const Wasm = @import("Wasm.zig");
const spec = @import("spec.zig");
const std = @import("std");

const leb = std.leb;
const fs = std.fs;

/// Writes the given `Wasm` object into a binary file as-is.
pub fn write(wasm: *Wasm) !void {
    const writer = wasm.file.writer();
    const file = wasm.file;

    if (wasm.types.items.len != 0) {
        const offset = try reserveSectionHeader(file);
        for (wasm.types.items) |type_entry| {
            try writeType(type_entry, writer);
        }
        try writeSectionHeader(file, offset, .type, wasm.types.items.len);
    }
    if (wasm.imports.items.len != 0) {
        const offset = try reserveSectionHeader(file);

        for (wasm.imported_symbols.items) |sym_with_loc| {
            try writeImportSymbol(wasm, sym_with_loc);
        }

        for (wasm.types.items) |import_entry| {
            try writeImport(import_entry, writer);
        }
        try writeSectionHeader(file, offset, .import, wasm.imports.items.len);
    }
}

/// Reserves enough space within the file to write our section header.
/// Returns the offset into the file where the header will be written.
fn reserveSectionHeader(file: fs.File) !u64 {
    // section id, section byte size, section entry count
    const header_size = 1 + 5 + 5;
    try file.seekBy(header_size);
    return (try file.getPos()) - header_size;
}

/// Emits the actual section header at the given `offset`.
/// Will write the section id, the section byte length, as well as the section entry count.
/// The amount of bytes is calculated using the current position, minus the offset (and reserved header bytes).
fn writeSectionHeader(
    file: fs.File,
    offset: u64,
    section_type: spec.SectionType,
    entries: usize,
) !void {
    // section id, section byte size, section entry count
    var buf: [1 + 5 + 5]u8 = undefined;
    buf[0] = @enumToInt(section_type);

    const pos = try file.getPos();
    const byte_size = pos - (offset + buf.len);
    leb.writeUnsignedFixed(5, buf[1..6], byte_size);
    leb.writeUnsignedFixed(5, buf[6..], entries);
    try file.pwriteAll(&buf, offset);
}

fn writeType(type_entry: spec.sections.Type, writer: anytype) !void {
    try leb.writeULEB128(writer, @as(u8, 0x60)); //functype
    try leb.writeULEB128(writer, @intCast(u32, type_entry.params.len));
    for (type_entry.params) |para_ty| {
        try leb.writeULEB128(writer, @enumToInt(para_ty));
    }
    try leb.writeULEB128(writer, @intCast(u32, type_entry.returns.len));
    for (type_entry.returns) |ret_ty| {
        try leb.writeULEB128(writer, @enumToInt(ret_ty));
    }
}

fn writeImportSymbol(wasm: *Wasm, sym_with_loc: Wasm.SymbolWithLoc) !void {
    const object = wasm.objects.items[sym_with_loc.file];
    const sym: spec.Symbol = object.symtable[sym_with_loc.sym_index];
    const import: spec.sections.Import = .{
        .module_name = object.imports[sym.index()].module_name,
        .module_name = sym.name,
        .kind = undefined,
    };

    switch (sym.kind) {
        .function => |func| import.kind = .{ .function = func.func.?.type_idx },
        .global => |global| {
            const obj_global = object.globals[global.index];
            import.kind = .{ .global = .{ .valtype = obj_global.valtype, .mutable = obj_global.mutable } };
        },
        else => {},
    }
}

fn writeImport(import_entry: spec.sections.Import, writer: anytype) !void {
    try leb.writeULEB128(writer, @intCast(u32, import_entry.module_name.len));
    try writer.writeAll(import_entry.module_name);

    try leb.writeULEB128(writer, @intCast(u32, import_entry.name));
    try writer.writeAll(import_entry.name);

    try leb.writeULEB128(writer, @enumToInt(import_entry.kind));
    switch (import_entry.kind) {
        .function => |index| try leb.writeULEB128(writer, @enumToInt(index)),
        .table => |table| {
            try leb.writeULEB128(writer, @enumToInt(table.reftype));
            try leb.writeULEB128(writer, @boolToInt(table.limits.max != null));
            try leb.writeULEB128(writer, table.limits.min);
            if (table.limits.max) |max| {
                try leb.writeULEB128(writer, max);
            }
        },
        .global => |global| {
            try leb.writeULEB128(writer, @enumToInt(global.valtype));
            try leb.writeULEB128(writer, @boolToInt(global.mutable));
        },
        .memory => |mem| {
            try leb.writeULEB128(writer, @boolToInt(mem.max != null));
            try leb.writeULEB128(writer, mem.min);
            if (mem.max) |max| {
                try leb.writeULEB128(writer, max);
            }
        },
    }
    try leb.writeULEB128(writer, @enumToInt(spec.ExternalType.function));
}
