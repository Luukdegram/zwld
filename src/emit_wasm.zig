//! Writes all the wasm sections that are valid
//! to the final binary file that was passed to the `Wasm` object.
//! When a section contains no entries, the section will not be emitted.

const Object = @import("Object.zig");
const std = @import("std");
const Symbol = @import("Symbol.zig");
const types = @import("types.zig");
const Wasm = @import("Wasm.zig");

const fs = std.fs;
const leb = std.leb;
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
    if (wasm.imports.symbolCount() != 0 or wasm.options.import_memory) {
        const count = wasm.imports.symbolCount() + @boolToInt(wasm.options.import_memory);
        log.debug("Writing 'Imports' section ({d})", .{count});
        const offset = try reserveSectionHeader(file);

        if (wasm.options.import_memory) {
            const mem_import: types.Import = .{
                .module_name = "env",
                .name = "memory",
                .kind = .{ .memory = wasm.memories.limits },
            };
            try emitImport(mem_import, writer);
        }

        for (wasm.imports.symbols()) |sym_with_loc| {
            const object = wasm.objects.items[sym_with_loc.file];
            try emitImportSymbol(object, sym_with_loc.sym_index, writer);
        }

        // TODO: Also emit GOT symbols
        try emitSectionHeader(file, offset, .import, count);
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

    if (wasm.entry) |entry_index| {
        const offset = try reserveSectionHeader(file);
        try emitSectionHeader(file, offset, .start, entry_index);
    }

    if (wasm.elements.functionCount() != 0) {
        log.debug("Writing 'Element' section (1)", .{});
        const offset = try reserveSectionHeader(file);
        try emitElement(wasm.elements, writer);
        try emitSectionHeader(file, offset, .element, 1);
    }
    if (wasm.code_section_index) |index| {
        log.debug("Writing 'Code' section ({d})", .{wasm.functions.count()});
        const offset = try reserveSectionHeader(file);
        var atom = wasm.atoms.get(index).?.getFirst();
        while (true) {
            try leb.writeULEB128(writer, atom.size);
            try writer.writeAll(atom.code.items);

            if (atom.next) |next| {
                atom = next;
            } else break;
        }
        try emitSectionHeader(file, offset, .code, wasm.functions.count());
    }

    if (wasm.data_segments.count() != 0) {
        const data_count = @intCast(u32, wasm.dataCount());
        log.debug("Writing 'Data' section ({d})", .{data_count});
        const offset = try reserveSectionHeader(file);
        const base_offset = wasm.options.global_base orelse 1024;

        var it = wasm.data_segments.iterator();
        while (it.next()) |entry| {
            // do not output the 'bss' section
            if (std.mem.eql(u8, entry.key_ptr.*, ".bss")) continue;
            const atom_index = entry.value_ptr.*;
            var atom = wasm.atoms.getPtr(atom_index).?.*.getFirst();
            const segment = wasm.segments.items[atom_index];
            const segment_offset = base_offset + segment.offset;

            try leb.writeULEB128(writer, @as(u32, 0)); // flag and memory index (always 0);
            try emitInitExpression(.{ .i32_const = @bitCast(i32, segment_offset) }, writer);
            try leb.writeULEB128(writer, segment.size);

            var current_offset: u32 = 0;
            while (true) {
                // TODO: Verify if this is faster than allocating segment's size
                // Setting all zeroes, memcopy all segments and then writing.
                if (current_offset != atom.offset) {
                    const diff = atom.offset - current_offset;
                    try writer.writeByteNTimes(0, diff);
                    current_offset += diff;
                }
                std.debug.assert(current_offset == atom.offset);
                try writer.writeAll(atom.code.items);
                std.debug.assert(atom.code.items.len == atom.size);

                current_offset += atom.size;
                if (atom.next) |next| {
                    atom = next;
                } else {
                    // Also make sure that if the last atom has extra bytes, we write 0's.
                    if (current_offset != segment.size) {
                        try writer.writeByteNTimes(0, segment.size - current_offset);
                    }
                    break;
                }
            }
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
    section_type: types.SectionType,
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

fn emitType(type_entry: types.FuncType, writer: anytype) !void {
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

fn emitImportSymbol(object: Object, symbol_index: u32, writer: anytype) !void {
    const symbol = object.symtable[symbol_index];
    var import: types.Import = .{
        .module_name = object.imports[symbol.index().?].module_name,
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

fn emitImport(import_entry: types.Import, writer: anytype) !void {
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

fn emitFunction(func: types.Func, writer: anytype) !void {
    log.debug("Writing func with type index: {d}", .{func.type_idx});
    try leb.writeULEB128(writer, func.type_idx);
}

fn emitTable(table: types.Table, writer: anytype) !void {
    try leb.writeULEB128(writer, @enumToInt(table.reftype));
    try emitLimits(table.limits, writer);
}

fn emitLimits(limits: types.Limits, writer: anytype) !void {
    try leb.writeULEB128(writer, @boolToInt(limits.max != null));
    try leb.writeULEB128(writer, limits.min);
    if (limits.max) |max| {
        try leb.writeULEB128(writer, max);
    }
}

fn emitMemory(mem: types.Memory, writer: anytype) !void {
    try emitLimits(mem.limits, writer);
}

fn emitGlobal(global: types.Global, writer: anytype) !void {
    try leb.writeULEB128(writer, @enumToInt(global.valtype));
    try leb.writeULEB128(writer, @boolToInt(global.mutable));
    if (global.init) |init| try emitInitExpression(init, writer);
}

fn emitInitExpression(init: types.InitExpression, writer: anytype) !void {
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

fn emitExport(exported: types.Export, writer: anytype) !void {
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
