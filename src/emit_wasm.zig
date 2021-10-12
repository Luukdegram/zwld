//! Writes all the wasm sections that are valid
//! to the final binary file that was passed to the `Wasm` object.
//! When a section contains no entries, the section will not be emitted.

const Wasm = @import("Wasm.zig");
const Symbol = @import("Symbol.zig");
const data = @import("data.zig");
const std = @import("std");

const leb = std.leb;
const fs = std.fs;
const log = std.log.scoped(.zwld);

/// Writes the given `Wasm` object into a binary file as-is.
pub fn emit(wasm: *Wasm) !void {
    const writer = wasm.file.writer();
    const file = wasm.file;

    // magic bytes and wasm version
    try emitWasmHeader(writer);

    // emit sections
    if (wasm.types.items.len != 0) {
        log.debug("Writing 'Types' section ({d})", .{wasm.types.items.len});
        const offset = try reserveSectionHeader(file);
        for (wasm.types.items) |type_entry| {
            try emitType(type_entry, writer);
        }
        try emitSectionHeader(file, offset, .type, wasm.types.items.len);
    }
    if (wasm.imports.items.len != 0) {
        log.debug("Writing 'Imports' section ({d})", .{wasm.imports.items.len + wasm.imported_symbols.items.len});
        const offset = try reserveSectionHeader(file);

        for (wasm.imported_symbols.items) |sym_with_loc| {
            try emitImportSymbol(wasm, sym_with_loc);
        }

        for (wasm.imports.items) |import_entry| {
            try emitImport(import_entry, writer);
        }
        try emitSectionHeader(file, offset, .import, wasm.imports.items.len);
    }
    if (wasm.functions.items.len != 0) {
        log.debug("Writing 'Functions' section ({d})", .{wasm.functions.items.len});
        const offset = try reserveSectionHeader(file);
        for (wasm.functions.items) |func| {
            try emitFunction(func, writer);
        }
        try emitSectionHeader(file, offset, .function, wasm.functions.items.len);
    }
    if (wasm.tables.items.len != 0) {
        log.debug("Writing 'Tables' section ({d})", .{wasm.tables.items.len});
        const offset = try reserveSectionHeader(file);
        for (wasm.tables.items) |table| {
            try emitTable(table, writer);
        }
        try emitSectionHeader(file, offset, .table, wasm.tables.items.len);
    }
    if (wasm.memories.items.len != 0) {
        log.debug("Writing 'Memories' section ({d})", .{wasm.memories.items.len});
        const offset = try reserveSectionHeader(file);
        for (wasm.memories.items) |mem| {
            try emitMemory(mem, writer);
        }
        try emitSectionHeader(file, offset, .memory, wasm.memories.items.len);
    }
    if (wasm.globals.items.len != 0) {
        log.debug("Writing 'Globals' section ({d})", .{wasm.globals.items.len});
        const offset = try reserveSectionHeader(file);
        for (wasm.globals.items) |global| {
            try emitGlobal(global, writer);
        }
        try emitSectionHeader(file, offset, .global, wasm.globals.items.len);
    }
    if (wasm.exports.items.len != 0) {
        log.debug("Writing 'Exports' section ({d})", .{wasm.exports.items.len});
        const offset = try reserveSectionHeader(file);
        for (wasm.exports.items) |exported| {
            try emitExport(exported, writer);
        }
        try emitSectionHeader(file, offset, .@"export", wasm.exports.items.len);
    }
    log.debug("TODO: Start section", .{});
    if (wasm.elements.items.len != 0) {
        log.debug("TODO: Element section", .{});
        const offset = try reserveSectionHeader(file);
        for (wasm.elements.items) |element| {
            try emitElement(element, writer);
        }
        try emitSectionHeader(file, offset, .element, wasm.elements.items.len);
    }
    if (wasm.code.items.len != 0) {
        log.debug("Writing 'Code' section ({d})", .{wasm.code.items.len});
        const offset = try reserveSectionHeader(file);
        for (wasm.code.items) |code| {
            try leb.writeULEB128(writer, @intCast(u32, code.len));
            try writer.writeAll(code);
        }
        try emitSectionHeader(file, offset, .code, wasm.code.items.len);
    }

    if (wasm.data.items.len != 0) {
        log.debug("Writing 'Data' section ({d})", .{wasm.data.items.len});
        const offset = try reserveSectionHeader(file);
        for (wasm.data.items) |item| {
            try emitData(item, writer);
        }
        try emitSectionHeader(file, offset, .data, wasm.data.items.len);
    }
}

fn emitWasmHeader(writer: anytype) !void {
    try writer.writeAll(&std.wasm.magic);
    try writer.writeIntLittle(u32, 1); // version
}

/// Reserves enough space within the file to write our section header.
/// Returns the offset into the file where the header will be written.
fn reserveSectionHeader(file: fs.File) !u64 {
    // section id, section byte size, section entry count
    const header_size = 1 + 5 + 5;
    try file.seekBy(header_size);
    return (try file.getPos());
}

/// Emits the actual section header at the given `offset`.
/// Will write the section id, the section byte length, as well as the section entry count.
/// The amount of bytes is calculated using the current position, minus the offset (and reserved header bytes).
fn emitSectionHeader(
    file: fs.File,
    offset: u64,
    section_type: data.SectionType,
    entries: usize,
) !void {
    // section id, section byte size, section entry count
    var buf: [1 + 5 + 5]u8 = undefined;
    buf[0] = @enumToInt(section_type);

    const pos = try file.getPos();
    const byte_size = pos + 5 - offset; // +5 due to 'entries' also being part of byte size
    leb.writeUnsignedFixed(5, buf[1..6], @intCast(u32, byte_size));
    leb.writeUnsignedFixed(5, buf[6..], @intCast(u32, entries));
    try file.pwriteAll(&buf, offset - buf.len);
    log.debug("Written section '{s}' offset=0x{x:0>8} size={d} count={d}", .{
        @tagName(section_type),
        offset - buf.len,
        byte_size,
        entries,
    });
}

fn emitType(type_entry: data.FuncType, writer: anytype) !void {
    log.debug("Writing type {}", .{type_entry});
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

fn emitImportSymbol(wasm: *Wasm, sym_with_loc: Wasm.SymbolWithLoc) !void {
    const object = wasm.objects.items[sym_with_loc.file];
    const sym: Symbol = object.symtable[sym_with_loc.sym_index];
    var import: data.Import = .{
        .module_name = object.imports[sym.index().?].module_name,
        .name = sym.name,
        .kind = undefined,
    };

    switch (sym.kind) {
        .function => |func| import.kind = .{ .function = func.func.?.type_idx },
        .global => |global| {
            const obj_global = object.globals[global.index];
            import.kind = .{ .global = .{ .valtype = obj_global.valtype, .mutable = obj_global.mutable } };
        },
        .table => |table| import.kind = .{ .table = object.tables[table.index] },
        else => unreachable,
    }

    try emitImport(import, wasm.file.writer());
}

fn emitImport(import_entry: data.Import, writer: anytype) !void {
    try leb.writeULEB128(writer, @intCast(u32, import_entry.module_name.len));
    try writer.writeAll(import_entry.module_name);

    try leb.writeULEB128(writer, @intCast(u32, import_entry.name.len));
    try writer.writeAll(import_entry.name);

    try leb.writeULEB128(writer, @enumToInt(import_entry.kind));
    switch (import_entry.kind) {
        .function => |index| try leb.writeULEB128(writer, index),
        .table => |table| try emitTable(table, writer),
        .global => |global| {
            try leb.writeULEB128(writer, @enumToInt(global.valtype));
            try leb.writeULEB128(writer, @boolToInt(global.mutable));
        },
        .memory => |mem| try emitLimits(mem, writer),
    }
    try leb.writeULEB128(writer, @enumToInt(data.ExternalType.function));
}

fn emitFunction(func: data.Func, writer: anytype) !void {
    log.debug("Writing func with type index: {d}", .{func.type_idx});
    try leb.writeULEB128(writer, func.type_idx);
}

fn emitTable(table: data.Table, writer: anytype) !void {
    try leb.writeULEB128(writer, @enumToInt(table.reftype));
    try emitLimits(table.limits, writer);
}

fn emitLimits(limits: data.Limits, writer: anytype) !void {
    try leb.writeULEB128(writer, @boolToInt(limits.max != null));
    try leb.writeULEB128(writer, limits.min);
    if (limits.max) |max| {
        try leb.writeULEB128(writer, max);
    }
}

fn emitMemory(mem: data.Memory, writer: anytype) !void {
    try emitLimits(mem.limits, writer);
}

fn emitGlobal(global: data.Global, writer: anytype) !void {
    try leb.writeULEB128(writer, @enumToInt(global.valtype));
    try leb.writeULEB128(writer, @boolToInt(global.mutable));
    try emitInitExpression(global.init, writer);
}

fn emitInitExpression(init: data.InitExpression, writer: anytype) !void {
    switch (init) {
        .i32_const => |val| {
            try leb.writeULEB128(writer, std.wasm.opcode(.i32_const));
            try leb.writeILEB128(writer, val);
        },
        .global_get => |index| {
            try leb.writeULEB128(writer, std.wasm.opcode(.global_get));
            try leb.writeULEB128(writer, index);
        },
    }
    try leb.writeULEB128(writer, std.wasm.opcode(.end));
}

fn emitExport(exported: data.Export, writer: anytype) !void {
    try leb.writeULEB128(writer, @intCast(u32, exported.name.len));
    try writer.writeAll(exported.name);
    try leb.writeULEB128(writer, @enumToInt(exported.kind));
    try leb.writeULEB128(writer, exported.index);
}

fn emitElement(element: data.Element, writer: anytype) !void {
    _ = element;
    _ = writer;
    // TODO
}

fn emitData(segment: data.Data, writer: anytype) !void {
    try leb.writeULEB128(writer, @as(u32, 0));
    try emitInitExpression(segment.offset, writer);
    try leb.writeULEB128(writer, @intCast(u32, segment.data.len));
    try writer.writeAll(segment.data);
}
