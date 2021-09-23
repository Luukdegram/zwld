//! Wasm represents the final binary
const Wasm = @This();

const std = @import("std");
const Object = @import("Object.zig");
const spec = @import("spec.zig");
const fs = std.fs;
const Allocator = std.mem.Allocator;

gpa: *Allocator,
/// The binary file that we will write the final binary data to
file: fs.File,
/// A list with references to objects we link to during `flush()`
objects: std.ArrayListUnmanaged(Object) = .{},
/// Merged globals will be appended to this list
globals: std.ArrayListUnmanaged(spec.sections.Global) = .{},
/// Merged function sections are appended to this list
funcs: std.ArrayListUnmanaged(spec.sections.Func) = .{},

/// Initializes a new wasm binary file at the given path.
/// Will overwrite any existing file at said path.
pub fn openPath(gpa: *Allocator, path: []const u8) !Wasm {
    const file = try fs.cwd().createFile(path, .{
        .truncate = true,
        .read = true,
    });
    errdefer file.close();

    return .{ .gpa = gpa, .file = file };
}

/// Releases any resources that is owned by `Wasm`,
/// usage after calling deinit is illegal behaviour.
pub fn deinit(self: *Wasm) void {
    for (self.objects.items) |object| {
        object.file.close();
        object.deinit(self.gpa);
    }
    self.objects.deinit(self.gpa);
    self.file.close();
    self.* = undefined;
}

/// Parses objects from the given paths as well as append them to `self`
pub fn addObjects(self: *Wasm, file_paths: []const []const u8) !void {
    errdefer for (self.objects.items) |object| {
        object.file.close();
        object.deinit(self.gpa);
    } else self.objects.deinit(self.gpa);

    for (file_paths) |path| {
        const file = fs.cwd().openFile(path, .{});
        errdefer file.close();
        var object = try Object.init(self.gpa, file);
        errdefer object.deinit(self.gpa);
        try self.objects.append(self.gpa, object);
    }
}

/// Flushes the `Wasm` construct into a final wasm binary by linking
/// the objects, ensuring the final binary file has no collisions.
pub fn flush(self: *Wasm) !void {
    try self.mergeFunctions();
}

/// Merges all function sections into the final binary, and patches 
fn mergeFunctions(self: *Wasm) !void {
    for (self.objects.items) |object| {
        const func_sections: Object.SectionData(spec.sections.Func) = object.funcs;
        if (func_sections.isEmpty()) continue;

        for (func_sections) |func| {
            const id = @intCast(u32, self.funcs.items.len);
            try self.funcs.append(self.gpa, func);
        }
    }
}
