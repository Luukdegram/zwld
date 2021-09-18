const std = @import("std");
const io = std.io;
const clap = @import("clap");
const wasmparser = @import("wasmparser");

var gpa = std.heap.GeneralPurposeAllocator(.{}){};
const ally = &gpa.allocator;

pub fn main() !void {
    defer if (std.builtin.mode == .Debug) {
        _ = gpa.deinit();
    };
    const params = comptime [_]clap.Param(clap.Help){
        clap.parseParam("    --help             Display this help and exit.              ") catch unreachable,
        clap.parseParam("-h, --h                Display summaries of the headers of each section.") catch unreachable,
        clap.parseParam("<POS>...") catch unreachable,
    };

    var diag: clap.Diagnostic = .{};
    var args = clap.parse(clap.Help, &params, .{ .diagnostic = &diag }) catch |err| {
        diag.report(writer(), err) catch {};
        return;
    };
    defer args.deinit();

    const positionals = args.positionals();
    if (positionals.len == 0) {
        print("Missing file path argument", .{});
        return;
    }

    if (args.flag("--help")) {
        try clap.help(writer(), &params);
    } else if (args.flag("-h")) {
        try summarizeHeaders(positionals[0]);
    } else {
        try clap.help(writer(), &params);
    }
}

fn summarizeHeaders(path: []const u8) !void {
    const file = std.fs.cwd().openFile(path, .{}) catch {
        print("Could not open file: {s}", .{path});
        return;
    };
    defer file.close();
    var result = try wasmparser.parse(ally, file.reader());
    defer result.deinit(ally);
    const module = result.module;

    print("\n{s}:      file format wasm 0x{x:2>0}\n\n", .{ path, module.version });
    print("Sections:\n\n", .{});
    if (module.types.data.len != 0) print("{}\n", .{module.types});
    if (module.imports.data.len != 0) print("{}\n", .{module.imports});
    if (module.functions.data.len != 0) print("{}\n", .{module.functions});
    if (module.tables.data.len != 0) print("{}\n", .{module.tables});
    if (module.memories.data.len != 0) print("{}\n", .{module.memories});
    if (module.globals.data.len != 0) print("{}\n", .{module.globals});
    if (module.exports.data.len != 0) print("{}\n", .{module.exports});
    if (module.elements.data.len != 0) print("{}\n", .{module.elements});
    if (module.code.data.len != 0) print("{}\n", .{module.code});
    if (module.data.data.len != 0) print("{}\n", .{module.data});
    for (module.custom) |custom| {
        print("{}\n", .{custom});
    }
}

fn print(comptime fmt: []const u8, args: anytype) void {
    io.getStdErr().writer().print(fmt, args) catch unreachable;
}

fn writer() std.fs.File.Writer {
    return io.getStdErr().writer();
}
