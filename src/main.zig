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
    if (module.types.len != 0) print("Type count: {d}\n", .{module.types.len});
    if (module.imports.len != 0) print("Import count: {d}\n", .{module.types.len});
    if (module.functions.len != 0) print("Function count: {d}\n", .{module.types.len});
    if (module.tables.len != 0) print("Table count: {d}\n", .{module.types.len});
    if (module.memories.len != 0) print("Memory count: {d}\n", .{module.types.len});
    if (module.globals.len != 0) print("Global count: {d}\n", .{module.types.len});
    if (module.exports.len != 0) print("Export count: {d}\n", .{module.types.len});
    if (module.elements.len != 0) print("Element count: {d}\n", .{module.types.len});
    if (module.code.len != 0) print("Code count: {d}\n", .{module.types.len});
    if (module.data.len != 0) print("Data count: {d}\n", .{module.types.len});
    for (module.custom) |custom| {
        print("Custom \"{s}\"\n", .{custom.name});
    }
}

fn print(comptime fmt: []const u8, args: anytype) void {
    io.getStdErr().writer().print(fmt, args) catch unreachable;
}

fn writer() std.fs.File.Writer {
    return io.getStdErr().writer();
}
