//! Wasm represents the final binary
const Wasm = @This();

const std = @import("std");
const Object = @import("Object.zig");
const spec = @import("spec.zig");
const fs = std.fs;
const Allocator = std.mem.Allocator;
const log = std.log.scoped(.zwld);

gpa: *Allocator,
/// The binary file that we will write the final binary data to
file: fs.File,
/// A list with references to objects we link to during `flush()`
objects: std.ArrayListUnmanaged(Object) = .{},
/// Merged globals will be appended to this list
globals: std.ArrayListUnmanaged(spec.sections.Global) = .{},
/// Merged function sections are appended to this list
funcs: std.ArrayListUnmanaged(spec.sections.Func) = .{},
/// Contains all the code sections. While the slice of code sections
/// is immutable, we can still modify the individual bytes within a singular code section.
/// This allows us to perform relocations inside the code section before flushing.
code: std.ArrayListUnmanaged([]u8) = .{},
/// Merged table sections in non-binary form
tables: std.ArrayListUnmanaged(spec.sections.Table) = .{},
/// A table where the key is the file index (the same index into `objects`),
/// and the value is list where each element contains a section kind and its new index.
section_resolver: std.AutoHashMapUnmanaged(u8, Reindex) = .{},

/// A slice of sections with their new index.
/// To be used with a section resolved where the key is the file index.
const Reindex = std.ArrayListUnmanaged(struct {
    section_type: spec.Section,
    new_index: u32,
    old_index: u32,
});

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
    try self.mergeGlobals();
    try self.mergeFunctions();
    try self.mergeTables();
}

/// Merges all function and code sections into the final binary.
/// Does not perform any relocations for function references inside code sections.
fn mergeFunctions(self: *Wasm) !void {
    for (self.objects.items) |object, file_index| {
        const func_sections: Object.SectionData(spec.sections.Func) = object.funcs;
        if (func_sections.isEmpty()) continue;

        for (func_sections.data) |func, func_index| {
            const new_idx = @intCast(u32, self.funcs.items.len);
            try self.funcs.append(self.gpa, func);
            try self.appendReindex(file_index, .func, func_index, new_idx);
        }

        // as each function section also contains a code section,
        // we're free to merge those as well
        const code_sections = object.code;
        if (code_sections.count() != func_sections.count()) {
            log.crit("Code sections do not match function sections count: {d} vs {d}", .{
                code_sections.count(),
                func_sections.count(),
            });
            return error.MismatchingSectionCount;
        }
        for (code_sections.data) |code, code_index| {
            const new_idx = @intCast(u32, self.code.items.len);
            try self.code.append(self.gpa, code);
            try self.appendReindex(file_index, .code, code_index, new_idx);
        }
    }
}

/// Merges the globals of all object files into the final binary
/// This will not perform any relocations of references to globals.
fn mergeGlobals(self: *Wasm) !void {
    for (self.objects.items) |object, file_index| {
        const global_section = object.globals;
        if (global_section.isEmpty()) continue;

        for (global_section.data) |global, global_index| {
            const new_idx = @intCast(u32, self.globals.items.len);
            try self.globals.append(self.gpa, global);
            try self.appendReindex(file_index, .global, global_index, new_idx);
        }
    }
}

/// Merges the table sections of all object files into the final binary
/// This will however not perform any relocations
fn mergeTables(self: *Wasm) !void {
    for (self.objects.items) |object, file_index| {
        const table_section = object.tables;
        if (table_section.isEmpty()) continue;

        for (table_section.data) |table, table_index| {
            const new_idx = @intCast(u32, self.tables.items.len);
            try self.tables.append(self.gpa, table);
            try self.appendReindex(file_index, .table, table_index, new_idx);
        }
    }
}

/// Appends a new reindex into `section_resolver`
fn appendReindex(self: *Wasm, file_index: usize, section_type: spec.Section, old_index: usize, new_index: usize) !void {
    const result = try self.section_resolver.getOrPut(self.gpa, @intCast(u8, file_index));
    if (!result.found_existing) {
        result.value_ptr.* = .{};
    }
    try result.value_ptr.append(self.gpa, .{
        .section_type = section_type,
        .old_index = @intCast(u32, old_index),
        .new_index = @intCast(u32, new_index),
    });
}

/// Based on the index of a object file, and a section-type, it will try to resolve
/// the new index of the section.
fn resolveNewSectionIndex(self: Wasm, file_index: usize, section_type: spec.Section, old_index: u32) ?u32 {
    const reindexes = self.section_resolver.get(@intCast(u8, file_index)) orelse return null;
    return for (reindexes) |reindex| {
        if (reindex.section_type == section_type and reindex.old_index == old_index) {
            break reindex.new_index;
        }
    } else null;
}
