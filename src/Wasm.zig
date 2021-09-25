//! Wasm represents the final binary
const Wasm = @This();

const Atom = @import("Atom.zig");
const Object = @import("Object.zig");
const spec = @import("spec.zig");
const std = @import("std");

const fs = std.fs;
const Allocator = std.mem.Allocator;

const log = std.log.scoped(.zwld);

/// The binary file that we will write the final binary data to
file: fs.File,
/// A list with references to objects we link to during `flush()`
objects: std.ArrayListUnmanaged(Object) = .{},
/// A list of references to atoms
managed_atoms: std.ArrayListUnmanaged(*Atom) = .{},

/// A slice of sections with their new index.
/// To be used with a section resolved where the key is the file index.
const Reindex = std.ArrayListUnmanaged(struct {
    section_type: spec.Section,
    new_index: u32,
    old_index: u32,
});

/// Initializes a new wasm binary file at the given path.
/// Will overwrite any existing file at said path.
pub fn openPath(path: []const u8) !Wasm {
    const file = try fs.cwd().createFile(path, .{
        .truncate = true,
        .read = true,
    });
    errdefer file.close();

    return .{ .file = file };
}

/// Releases any resources that is owned by `Wasm`,
/// usage after calling deinit is illegal behaviour.
pub fn deinit(self: *Wasm, gpa: *Allocator) void {
    for (self.managed_atoms.items) |atom| {
        atom.deinit(gpa);
    }
    self.managed_atoms.deinit(gpa);
    for (self.objects.items) |object| {
        object.file.close();
        object.deinit(gpa);
    }
    self.objects.deinit(gpa);
    self.file.close();
    self.* = undefined;
}

/// Parses objects from the given paths as well as append them to `self`
pub fn addObjects(self: *Wasm, gpa: *Allocator, file_paths: []const []const u8) !void {
    errdefer for (self.objects.items) |object| {
        object.file.close();
        object.deinit(gpa);
    } else self.objects.deinit(gpa);

    for (file_paths) |path| {
        const file = fs.cwd().openFile(path, .{});
        errdefer file.close();
        var object = try Object.init(gpa, file);
        errdefer object.deinit(gpa);
        if (object.link_data == null) {
            log.crit("Object file {s} missing \"linking\" section", .{path});
            return error.MissingLinkingSection;
        }
        try self.objects.append(gpa, object);
    }
}

/// Flushes the `Wasm` construct into a final wasm binary by linking
/// the objects, ensuring the final binary file has no collisions.
pub fn flush(self: *Wasm) !void {
    _ = self;
}
