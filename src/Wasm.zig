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
/// A map of global names to their symbol location in an object file
globals: std.StringArrayHashMapUnmanaged(SymbolWithLoc) = .{},
/// List of sections to be emitted to the binary file
sections: std.ArrayListUnmanaged(spec.Section) = .{},
/// A table that maps from a section to an Atom linked list
atoms: std.AutoHashMapUnmanaged(u16, *Atom) = .{},

pub const SymbolWithLoc = struct {
    sym_index: u32,
    file: u16,
};

/// Initializes a new wasm binary file at the given path.
/// Will overwrite any existing file at said path.
pub fn openPath(path: []const u8) !Wasm {
    const file = try fs.cwd().createFile(path, .{
        .truncate = true,
        .read = true,
    });
    errdefer file.close();

    return Wasm{ .file = file };
}

/// Releases any resources that is owned by `Wasm`,
/// usage after calling deinit is illegal behaviour.
pub fn deinit(self: *Wasm, gpa: *Allocator) void {
    self.atoms.deinit(gpa);
    for (self.managed_atoms.items) |atom| {
        atom.deinit(gpa);
    }
    self.managed_atoms.deinit(gpa);
    for (self.objects.items) |*object| {
        object.file.?.close();
        object.deinit(gpa);
    }
    for (self.globals.keys()) |name| {
        gpa.free(name);
    }
    self.globals.deinit(gpa);
    self.objects.deinit(gpa);
    self.sections.deinit(gpa);
    self.file.close();
    self.* = undefined;
}

/// Parses objects from the given paths as well as append them to `self`
pub fn addObjects(self: *Wasm, gpa: *Allocator, file_paths: []const []const u8) !void {
    errdefer for (self.objects.items) |*object| {
        object.file.?.close();
        object.deinit(gpa);
    } else self.objects.deinit(gpa);

    for (file_paths) |path| {
        const file = try fs.cwd().openFile(path, .{});
        errdefer file.close();
        var object = try Object.init(gpa, file, path);
        errdefer object.deinit(gpa);
        try self.objects.append(gpa, object);
    }
}

/// Flushes the `Wasm` construct into a final wasm binary by linking
/// the objects, ensuring the final binary file has no collisions.
pub fn flush(self: *Wasm, gpa: *Allocator) !void {
    _ = self;

    for (self.objects.items) |_, obj_idx| {
        try self.resolveSymbolsInObject(gpa, @intCast(u16, obj_idx));
    }

    for (self.objects.items) |*object, obj_idx| {
        try object.parseIntoAtoms(gpa, @intCast(u16, obj_idx), self);
    }
}

fn resolveSymbolsInObject(self: *Wasm, gpa: *Allocator, object_index: u16) !void {
    const object: Object = self.objects.items[object_index];

    log.info("resolving symbols in {s}", .{object.name});

    for (object.symtable) |symbol, i| {
        const sym_idx = @intCast(u32, i);

        if (symbol.isWeak() or symbol.isGlobal()) {
            const name = try gpa.dupe(u8, object.resolveSymbolName(symbol));
            const result = try self.globals.getOrPut(gpa, name);
            defer if (result.found_existing) gpa.free(name);

            log.debug("Found symbol '{s}'", .{name});

            if (!result.found_existing) {
                result.value_ptr.* = .{
                    .sym_index = sym_idx,
                    .file = object_index,
                };
                continue;
            }

            const global: SymbolWithLoc = result.value_ptr.*;
            const linked_obj: Object = self.objects.items[global.file];
            const linked_sym = linked_obj.symtable[global.sym_index];

            if (!linked_sym.isUndefined()) {
                if (symbol.isGlobal() and linked_sym.isGlobal()) {
                    log.err("symbol '{s}' defined multiple times", .{name});
                    log.err("  first definition in '{s}'", .{linked_obj.name});
                    log.err("  next definition in '{s}'", .{object.name});
                    return error.SymbolCollision;
                }

                if (symbol.isWeak()) {
                    log.info("symbol '{s}' already defined; skipping...", .{name});
                    continue;
                }
            }

            // simply overwrite an existing one with the new definition
            // as the symbol is a strong symbol
            result.value_ptr.* = .{
                .sym_index = sym_idx,
                .file = object_index,
            };
        }
    }
}

/// Returns the index of a section within the final binary file based on a given object index
/// and section index. When the section does not yet exist in the wasm binary file, it will create
/// one and return its index.
pub fn getMatchingSection(self: *Wasm, gpa: *Allocator, object_index: u16, section_index: u16) !?u16 {
    const object: Object = self.objects.items[object_index];
    const section = object.sections[section_index];

    if (section.section_kind == .custom) {
        log.debug("TODO: Custom sections", .{});
        return null;
    }

    const index = spec.Section.getIndex(self.sections.items, section.section_kind) orelse blk: {
        const new_index = @intCast(u16, self.sections.items.len);
        try self.sections.append(gpa, .{
            .offset = 0,
            .size = 0,
            .section_kind = section.section_kind,
        });
        break :blk new_index;
    };

    return index;
}
