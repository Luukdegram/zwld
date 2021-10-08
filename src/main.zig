const clap = @import("clap");
const Linker = @import("Linker.zig");
const Object = @import("Object.zig");
const spec = @import("spec.zig");
const std = @import("std");
const Wasm = @import("Wasm.zig");

const io = std.io;

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

    if (args.option("-o") != null) {
        const output_path = args.option("-o").?;
        try linkFileAndWriteToPath(output_path, positionals);
        return;
    }

    var object = try Object.init(ally, file, path);
    defer object.deinit(ally);

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
    for (object.sections) |section, id| {
        print("{d: >3}: {s: >10} offset=0x{x:0>8} end=0x{x:0>8} size(0x{x:0>8})\n", .{
            id,
            @tagName(section.section_kind),
            section.offset,
            section.offset + section.size,
            section.size,
        });
    }
    print("\n", .{});
}

fn summarizeSymbols(object: Object) !void {
    print("Symbol table:\n\n", .{});
    for (object.symtable) |symbol, i| {
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
}

fn linkFileAndWriteToPath(out_path: []const u8, file_paths: []const []const u8) !void {
    var bin = try Wasm.openPath(out_path);
    defer bin.deinit(ally);

    try bin.addObjects(ally, file_paths);
    try bin.flush(ally);
}

fn print(comptime fmt: []const u8, args: anytype) void {
    io.getStdErr().writer().print(fmt, args) catch unreachable;
}

fn writer() std.fs.File.Writer {
    return io.getStdErr().writer();
}
