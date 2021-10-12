const std = @import("std");
const Wasm = @import("Wasm.zig");
const mem = std.mem;

const io = std.io;

var gpa_allocator = std.heap.GeneralPurposeAllocator(.{}){};
const gpa = &gpa_allocator.allocator;

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

const usage =
    \\Usage: zwld [options] [files...] -o [path]
    \\
    \\Options:
    \\-h, --help                         Print this help and exit
    \\-o [path]                          Output path of the binary
    \\--entry <entry>                    Name of entry point symbol
    \\--import-memory                    Import memory from the host environment
    \\--import-table                     Import function table from the host environment
    \\--initial-memory=<value>           Initial size of the linear memory
    \\--max-memory=<value>               Maximum size of the linear memory
    \\--merge-data-segments              Enable merging data segments
    \\--no-entry                         Do not output any entry point
    \\--stack-first                      Place stack at start of linear memory instead of after data
;

pub fn main() !void {
    defer if (std.builtin.mode == .Debug) {
        _ = gpa_allocator.deinit();
    };

    // we use arena for the arguments and its parsing
    var arena_allocator = std.heap.ArenaAllocator.init(gpa);
    defer arena_allocator.deinit();
    const arena = &arena_allocator.allocator;

    const process_args = try std.process.argsAlloc(arena);
    defer std.process.argsFree(arena, process_args);

    const args = process_args[1..]; // exclude 'zwld' binary
    if (args.len == 0) {
        printHelpAndExit();
    }

    var positionals = std.ArrayList([]const u8).init(arena);
    var entry_name: ?[]const u8 = null;
    var import_memory: bool = false;
    var import_table: bool = false;
    var initial_memory: ?u32 = null;
    var max_memory: ?u32 = null;
    var merge_data_segments = false;
    var no_entry = false;
    var stack_first = false;
    var output_path: ?[]const u8 = null;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (mem.eql(u8, arg, "-h") or mem.eql(u8, arg, "--help")) {
            printHelpAndExit();
        }
        if (mem.eql(u8, arg, "--entry")) {
            if (i + 1 > args.len) printErrorAndExit("Missing entry name argument", .{});
            entry_name = args[i + 1];
            i += 1;
            continue;
        }
        if (mem.eql(u8, arg, "--import-memory")) {
            import_memory = true;
            continue;
        }
        if (mem.eql(u8, arg, "--import_table")) {
            import_table = true;
            continue;
        }
        if (mem.startsWith(u8, arg, "--initial-memory")) {
            const index = std.mem.indexOfScalar(u8, arg, '=') orelse printErrorAndExit("Missing '=' symbol and value for initial memory", .{});
            initial_memory = std.fmt.parseInt(u32, arg[index + 1 ..], 10) catch printErrorAndExit(
                "Could not parse value '{s}' into integer",
                .{arg[index + 1 ..]},
            );
            continue;
        }
        if (mem.startsWith(u8, arg, "--max-memory")) {
            const index = std.mem.indexOfScalar(u8, arg, '=') orelse printErrorAndExit("Missing '=' symbol and value for max memory", .{});
            max_memory = std.fmt.parseInt(u32, arg[index + 1 ..], 10) catch printErrorAndExit(
                "Could not parse value '{s}' into integer",
                .{arg[index + 1 ..]},
            );
            continue;
        }
        if (mem.eql(u8, arg, "--merge-data-segments")) {
            merge_data_segments = true;
            continue;
        }
        if (mem.eql(u8, arg, "--no-entry")) {
            no_entry = true;
            continue;
        }
        if (mem.eql(u8, arg, "--stack-first")) {
            stack_first = true;
            continue;
        }
        if (mem.eql(u8, arg, "-o")) {
            if (i + 1 >= args.len) printErrorAndExit("Missing output file argument", .{});
            output_path = args[i + 1];
            i += 1;
            continue;
        }
        try positionals.append(arg);
    }

    if (positionals.items.len == 0) {
        printErrorAndExit("Expected one or more object files, none were given", .{});
    }

    if (output_path == null) {
        printErrorAndExit("Missing output path", .{});
    }

    var wasm_bin = try Wasm.openPath(output_path.?, .{
        .entry_name = entry_name,
        .import_memory = import_memory,
        .import_table = import_table,
        .initial_memory = initial_memory,
        .max_memory = max_memory,
        .merge_data_segments = merge_data_segments,
        .no_entry = no_entry,
        .stack_first = stack_first,
    });
    defer wasm_bin.deinit(gpa);

    try wasm_bin.addObjects(gpa, positionals.items);
    try wasm_bin.flush(gpa);
}

fn printHelpAndExit() noreturn {
    io.getStdOut().writer().print("{s}\n", .{usage}) catch {};
    std.process.exit(0);
}

fn printErrorAndExit(comptime fmt: []const u8, args: anytype) noreturn {
    io.getStdErr().writer().print(fmt, args) catch {};
    std.process.exit(1);
}
