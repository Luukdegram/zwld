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
    if (wasm.types.count() != 0) {
        log.debug("Writing 'Types' section ({d})", .{wasm.types.count()});
        const offset = try reserveSectionHeader(file);
        for (wasm.types.items.items) |type_entry| {
            try emitType(type_entry, writer);
        }
        try emitSectionHeader(file, offset, .type, wasm.types.count());
    }
    if (wasm.imports.symbolCount() != 0) {
        log.debug("Writing 'Imports' section ({d})", .{wasm.imports.symbolCount()});
        const offset = try reserveSectionHeader(file);

        for (wasm.imports.symbols()) |symbol| {
            try emitImportSymbol(symbol.*, writer);
        }

        // TODO: Also emit GOT symbols and memory if the CLI option was provided

        try emitSectionHeader(file, offset, .import, wasm.imports.symbolCount());
    }
    if (wasm.functions.count() != 0) {
        log.debug("Writing 'Functions' section ({d})", .{wasm.functions.count()});
        const offset = try reserveSectionHeader(file);
        for (wasm.functions.items.items) |func| {
            try emitFunction(func, writer);
        }
        try emitSectionHeader(file, offset, .function, wasm.functions.count());
    }
    if (wasm.tables.count() != 0) {
        log.debug("Writing 'Tables' section ({d})", .{wasm.tables.count()});
        const offset = try reserveSectionHeader(file);
        for (wasm.tables.items.items) |table| {
            try emitTable(table, writer);
        }
        try emitSectionHeader(file, offset, .table, wasm.tables.count());
    }
    if (!wasm.options.import_memory) {
        log.debug("Writing 'Memory' section", .{});
        const offset = try reserveSectionHeader(file);
        try emitLimits(wasm.memories.limits, writer);
        try emitSectionHeader(file, offset, .memory, 1);
    }
    if (wasm.globals.count() != 0) {
        log.debug("Writing 'Globals' section ({d})", .{wasm.globals.count()});
        const offset = try reserveSectionHeader(file);
        for (wasm.globals.items.items) |global| {
            try emitGlobal(global, writer);
        }
        try emitSectionHeader(file, offset, .global, wasm.globals.count());
    }
    if (wasm.exports.count() != 0) {
        log.debug("Writing 'Exports' section ({d})", .{wasm.exports.count()});
        const offset = try reserveSectionHeader(file);
        for (wasm.exports.items.items) |exported| {
            try emitExport(exported, writer);
        }
        try emitSectionHeader(file, offset, .@"export", wasm.exports.count());
    }
    log.debug("TODO: Start section", .{});
    if (wasm.elements.mustEmit()) {
        log.debug("Writing 'Element' section (1)", .{});
        const offset = try reserveSectionHeader(file);
        try emitElement(wasm.elements, writer);
        try emitSectionHeader(file, offset, .element, 1);
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

    if (wasm.data_segments.count() != 0) {
        const data_count = @intCast(u32, wasm.data_segments.count());
        log.debug("Writing 'Data' section ({d}", .{data_count});
        const offset = try reserveSectionHeader(file);
        for (wasm.data_segments.values()) |segment_index| {
            try emitSegment(wasm.segments.items[segment_index], writer);
        }
        try emitSectionHeader(file, offset, .data, data_count);
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

fn emitImportSymbol(symbol: Symbol, writer: anytype) !void {
    var import: data.Import = .{
        .module_name = symbol.module_name.?,
        .name = symbol.name,
        .kind = undefined,
    };

    switch (symbol.kind) {
        .function => |func| import.kind = .{ .function = func.func.* },
        .global => |global| import.kind = .{ .global = global.global.* },
        .table => |table| import.kind = .{ .table = table.table.* },
        else => unreachable,
    }

    try emitImport(import, writer);
}

fn emitImport(import_entry: data.Import, writer: anytype) !void {
    try leb.writeULEB128(writer, @intCast(u32, import_entry.module_name.len));
    try writer.writeAll(import_entry.module_name);

    try leb.writeULEB128(writer, @intCast(u32, import_entry.name.len));
    try writer.writeAll(import_entry.name);

    try leb.writeULEB128(writer, @enumToInt(import_entry.kind));
    switch (import_entry.kind) {
        .function => |func| try leb.writeULEB128(writer, func.type_idx),
        .table => |table| try emitTable(table, writer),
        .global => |global| {
            try leb.writeULEB128(writer, @enumToInt(global.valtype));
            try leb.writeULEB128(writer, @boolToInt(global.mutable));
        },
        .memory => |mem| try emitLimits(mem, writer),
    }
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
    if (global.init) |init| try emitInitExpression(init, writer);
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

fn emitElement(element: @import("sections.zig").Elements, writer: anytype) !void {
    var flags: u32 = 0;
    var index: ?u32 = if (Symbol.linker_defined.indirect_function_table) |symbol| blk: {
        flags |= 0x2;
        break :blk symbol.kind.table.index;
    } else null;
    try leb.writeULEB128(writer, flags);
    if (index) |idx|
        try leb.writeULEB128(writer, idx);

    try emitInitExpression(.{ .i32_const = 0 }, writer);
    if (flags & 0x3 != 0) {
        try leb.writeULEB128(writer, @as(u8, 0));
    }

    try leb.writeULEB128(writer, element.functionCount());
    for (element.indirect_functions.items) |symbol, el_index| {
        std.debug.assert(symbol.kind.function.table_index.? == el_index);
        try leb.writeULEB128(writer, symbol.kind.function.functionIndex());
    }
}

fn emitSegment(segment: Wasm.Segment, writer: anytype) !void {
    try leb.writeULEB128(writer, @as(u32, 0));
    try emitInitExpression(.{ .i32_const = @bitCast(i32, segment.offset) }, writer);
    try leb.writeULEB128(writer, segment.size);
    try writer.writeAll(segment.data[0..segment.size]);
}
