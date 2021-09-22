const std = @import("std");
const io = std.io;
const clap = @import("clap");
const Object = @import("Object.zig");
const Linker = @import("Linker.zig");
const spec = @import("spec.zig");

var gpa = std.heap.GeneralPurposeAllocator(.{}){};
const ally = &gpa.allocator;

pub fn log(
    comptime level: std.log.Level,
    comptime scope: @TypeOf(.EnumLiteral),
    comptime format: []const u8,
    args: anytype,
) void {
    if (@import("build_flags").enable_logging) {
        std.log.defaultLog(level, scope, format, args);
    }
}

pub fn main() !void {
    defer if (std.builtin.mode == .Debug) {
        _ = gpa.deinit();
    };
    const params = comptime [_]clap.Param(clap.Help){
        clap.parseParam("    --help             Display this help and exit.              ") catch unreachable,
        clap.parseParam("-h, --h                Display summaries of the headers of each section.") catch unreachable,
        clap.parseParam("-o, --output <STR>     Path to file to write output to.") catch unreachable,
        clap.parseParam("-s, --symbols          Display the symbol table") catch unreachable,
        clap.parseParam("-r, --reloc            Display the relocations") catch unreachable,
        clap.parseParam("-a, --all              Displays section headers, symbols and relocations") catch unreachable,
        clap.parseParam("<FILE>...") catch unreachable,
    };

    var diag: clap.Diagnostic = .{};
    var args = clap.parse(clap.Help, &params, .{ .diagnostic = &diag }) catch |err| {
        diag.report(writer(), err) catch {};
        return;
    };
    defer args.deinit();

    if (args.flag("--help")) {
        try clap.help(writer(), &params);
        return;
    }

    const positionals = args.positionals();
    if (positionals.len == 0) {
        print("Missing file path argument", .{});
        return;
    }
    const path = positionals[0];
    const file = std.fs.cwd().openFile(path, .{}) catch {
        print("Could not open file: {s}", .{path});
        return;
    };
    defer file.close();

    var object = try Object.init(ally, file);
    defer object.deinit(ally);

    if (args.option("-o") != null) {
        const output_path = args.option("-o").?;
        try linkFileAndWriteToPath(positionals[0], output_path);
        return;
    }

    print("\n{s}:      file format wasm 0x{x:2>0}\n\n", .{ path, object.version });

    if (args.flag("-h") or args.flag("-a")) {
        try summarizeHeaders(object);
    }
    if (args.flag("-s") or args.flag("-a")) {
        try summarizeSymbols(object);
    }
    if (args.flag("-r") or args.flag("-a")) {
        try summarizeRelocs(object);
    }
}

fn summarizeHeaders(object: Object) !void {
    print("Sections:\n\n", .{});
    if (!object.types.isEmpty()) print("{}\n", .{object.types});
    if (!object.imports.isEmpty()) print("{}\n", .{object.imports});
    if (!object.functions.isEmpty()) print("{}\n", .{object.functions});
    if (!object.tables.isEmpty()) print("{}\n", .{object.tables});
    if (!object.memories.isEmpty()) print("{}\n", .{object.memories});
    if (!object.globals.isEmpty()) print("{}\n", .{object.globals});
    if (!object.exports.isEmpty()) print("{}\n", .{object.exports});
    if (!object.elements.isEmpty()) print("{}\n", .{object.elements});
    if (!object.code.isEmpty()) print("{}\n", .{object.code});
    if (!object.data.isEmpty()) print("{}\n", .{object.data});
    for (object.custom) |custom| {
        print("{}\n", .{custom});
    }
    print("\n", .{});
}

fn summarizeSymbols(object: Object) !void {
    const link_data = object.link_data orelse return;

    var symbols = std.ArrayList(spec.SymInfo).init(ally);
    defer symbols.deinit();

    for (link_data.subsections) |subsection| {
        if (subsection == .symbol_table) {
            try symbols.appendSlice(subsection.symbol_table);
        }
    }

    print("Symbol table:\n\n", .{});
    for (symbols.items) |symbol, i| {
        print(" {d}: {}\n", .{ i, symbol });
    }
    print("\n", .{});
}

fn summarizeRelocs(object: Object) !void {
    print("Relocations:\n\n", .{});
    var it = object.relocations.iterator();
    while (it.next()) |entry| {
        print("Relocations for section: {d} [{d}]\n", .{ entry.key_ptr.*, entry.value_ptr.len });
        const relocs: []const spec.Relocation = entry.value_ptr.*;
        for (relocs) |relocation| {
            print(" {}\n", .{relocation});
        }
    }
    // @panic("TODO");
}

fn linkFileAndWriteToPath(in_path: []const u8, out_path: []const u8) !void {
    const file_in = std.fs.cwd().openFile(in_path, .{}) catch |err| {
        return print("Could not open file {s} due to error: {s}\n", .{ in_path, @errorName(err) });
    };
    defer file_in.close();
    const file_out = std.fs.cwd().createFile(out_path, .{}) catch |err| {
        return print("Could not create file {s} due to error: {s}\n", .{ out_path, @errorName(err) });
    };
    defer file_out.close();
    print("TODO!", .{});
}

fn print(comptime fmt: []const u8, args: anytype) void {
    io.getStdErr().writer().print(fmt, args) catch unreachable;
}

fn writer() std.fs.File.Writer {
    return io.getStdErr().writer();
}
