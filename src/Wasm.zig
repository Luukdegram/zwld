//! Wasm represents the final binary
const Wasm = @This();

const Atom = @import("Atom.zig");
const Object = @import("Object.zig");
const spec = @import("spec.zig");
const std = @import("std");

const leb = std.leb;
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
global_symbols: std.StringArrayHashMapUnmanaged(SymbolWithLoc) = .{},
/// List of sections to be emitted to the binary file
sections: std.ArrayListUnmanaged(spec.Section) = .{},
/// A table that maps from a section to an Atom linked list
atoms: std.AutoArrayHashMapUnmanaged(u16, *Atom) = .{},
/// A list of all symbols, which is used to map from object file
/// specified symbols to their index into this table.
symtab: std.ArrayListUnmanaged(spec.Symbol) = .{},

// OUTPUT SECTIONS //
/// Output function signature types
types: std.ArrayListUnmanaged(spec.sections.Type) = .{},
/// Output import section
imports: std.ArrayListUnmanaged(spec.sections.Import) = .{},
/// Output function section
functions: std.ArrayListUnmanaged(spec.sections.Func) = .{},
/// Output table section
tables: std.ArrayListUnmanaged(spec.sections.Table) = .{},
/// Output memory section
memories: std.ArrayListUnmanaged(spec.sections.Memory) = .{},
/// Output global section
globals: std.ArrayListUnmanaged(spec.sections.Global) = .{},
/// Output export section
exports: std.ArrayListUnmanaged(spec.sections.Export) = .{},
/// Output element section
elements: std.ArrayListUnmanaged(spec.sections.Element) = .{},
/// Output code section
code: std.ArrayListUnmanaged([]u8) = .{},

// IMPORTS //
/// Table where the key is represented by an import.
/// Each entry represents an imported function, and maps to the index within this map
imported_functions: std.HashMapUnmanaged(ImportKey, u32, ImportKey.Ctx, max_load) = .{},
/// Table where the key is represented by an import.
/// Each entry represents an imported global from the host environment and maps to the index
/// within this map.
imported_globals: std.HashMapUnmanaged(ImportKey, u32, ImportKey.Ctx, max_load) = .{},
/// Table where the key is represented by an import.
/// Each entry represents an imported table from the host environment and maps to the index
/// within this map.
imported_tables: std.HashMapUnmanaged(ImportKey, u32, ImportKey.Ctx, max_load) = .{},
/// A list of symbols that are imported from a host environment.
imported_symbols: std.ArrayListUnmanaged(spec.Symbol) = .{},

const max_load = std.hash_map.default_max_load_percentage;

const ImportKey = struct {
    module_name: []const u8,
    name: []const u8,

    const Ctx = struct {
        pub fn hash(ctx: Ctx, key: ImportKey) u64 {
            _ = ctx;
            const hashFunc = std.hash.autoHash;
            var hasher = std.hash.Wyhash.init(0);
            hashFunc(&hasher, key.module_name.len);
            hashFunc(&hasher, key.module_name.ptr);
            hashFunc(&hasher, key.name.len);
            hashFunc(&hasher, key.name.ptr);
            return hasher.final();
        }

        pub fn eql(ctx: Ctx, lhs: ImportKey, rhs: ImportKey) bool {
            _ = ctx;
            return std.mem.eql(u8, lhs.name, rhs.name) and
                std.mem.eql(u8, lhs.module_name, rhs.module_name);
        }
    };
};

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
    for (self.global_symbols.keys()) |name| {
        gpa.free(name);
    }
    self.imported_functions.deinit(gpa);
    self.imported_globals.deinit(gpa);
    self.imported_tables.deinit(gpa);
    self.imported_symbols.deinit(gpa);
    self.global_symbols.deinit(gpa);
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
    for (self.objects.items) |_, obj_idx| {
        try self.resolveSymbolsInObject(gpa, @intCast(u16, obj_idx));
    }

    // for (self.objects.items) |object| {
    //     try self.buildSections(gpa, object);
    // }

    // for (self.objects.items) |*object, obj_idx| {
    //     try object.parseIntoAtoms(gpa, @intCast(u16, obj_idx), self);
    // }

    // try self.allocateAtoms();
    try self.writeMagicBytes();
    try self.writeAtoms(gpa);
}

fn populateSymbolTable(self: *Wasm, gpa: *Allocator) !void {
    for (self.objects.items) |object| {
        for (object.symtable) |symbol| {
            const index = @intCast(u32, self.symtab.items.len);
            symbol.output_index = index;
            self.symtab.append(gpa, symbol);
        }
    }
}

// fn buildRelocations(self: *Wasm, gpa: *Allocator, object_id: u16) !void {
// const object: *Object = self.objects.items[object_id];
// const types = object.types;
// }

fn sortSections(lhs: spec.Section, rhs: spec.Section) bool {
    if (rhs.section_kind == .custom) return false;
    const lhs_idx = @enumToInt(lhs.section_kind);
    const rhs_idx = @enumToInt(rhs.section_kind);

    if (rhs.section_kind == .data_count and lhs_idx >= @enumToInt(spec.SectionType.code)) {
        return true;
    }
    return rhs_idx < lhs_idx;
}

/// Finds all used sections from each object file, and then 
fn buildSections(self: *Wasm, gpa: *Allocator, object_id: u16) !void {
    const object: Object = self.objects.items[object_id];
    for (object.sections) |obj_section, section_id| {
        switch (obj_section.section_kind) {
            .custom,
            .data_count,
            .data,
            => continue,
            else => {},
        }
        const index = (try getMatchingSection(gpa, object_id, section_id)) orelse continue;
        const section: *spec.Section = &self.sections.items[index];
        section.size += obj_section.size;
        section.count += obj_section.count;
    }
}

fn resolveSymbolsInObject(self: *Wasm, gpa: *Allocator, object_index: u16) !void {
    const object: Object = self.objects.items[object_index];

    log.debug("resolving symbols in {s}", .{object.name});

    for (object.symtable) |symbol, i| {
        const sym_idx = @intCast(u32, i);

        // Check if they should be imported, if so: add them to the import section.
        if (symbol.requiresImport()) {
            log.debug("Symbol '{s}' should be imported", .{symbol.name});
            try self.appendImportSymbol(gpa, object_index, sym_idx);
        }

        if (symbol.isWeak() or symbol.isGlobal()) {
            const name = try gpa.dupe(u8, symbol.name);
            const result = try self.global_symbols.getOrPut(gpa, name);
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
                    log.debug("symbol '{s}' already defined; skipping...", .{name});
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

/// Returns the index of a section based on a given object index
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

/// Checks if a symbol is already imported or not. If not, will be appended as well as appended
/// to a typed list of imports.
fn appendImportSymbol(self: *Wasm, gpa: *Allocator, object_id: u16, symbol_id: u32) !void {
    const object: *Object = &self.objects.items[object_id];
    const symbol = &object.symtable[symbol_id];
    const import = object.imports[symbol.index().?]; // Programmer error: Undefined data symbols are not imported.
    const module_name = import.module_name;
    const import_name = import.name;

    switch (symbol.kind) {
        .function => |*func| {
            const ret = try self.imported_functions.getOrPut(gpa, .{
                .module_name = module_name,
                .name = import_name,
            });
            if (!ret.found_existing) {
                try self.imported_symbols.append(gpa, symbol.*);
                ret.value_ptr.* = @intCast(u32, self.imported_functions.count() - 1);
            }
            func.index = ret.value_ptr.*;
            log.debug("Imported function '{s}' at index ({d})", .{ import_name, func.index });
        },
        .global => |*global| {
            const ret = try self.imported_globals.getOrPut(gpa, .{
                .module_name = module_name,
                .name = import_name,
            });
            if (!ret.found_existing) {
                try self.imported_symbols.append(gpa, symbol.*);
                ret.value_ptr.* = @intCast(u32, self.imported_globals.count() - 1);
            }
            global.index = ret.value_ptr.*;
            log.debug("Imported global '{s}' at index ({d})", .{ import_name, global.index });
        },
        .table => |*table| {
            const ret = try self.imported_tables.getOrPut(gpa, .{
                .module_name = module_name,
                .name = import_name,
            });
            if (!ret.found_existing) {
                try self.imported_symbols.append(gpa, symbol.*);
                ret.value_ptr.* = @intCast(u32, self.imported_tables.count() - 1);
            }
            table.index = ret.value_ptr.*;
            log.debug("Imported table '{s}' at index ({d})", .{ import_name, table.index });
        },
        else => unreachable, // programmer error: Given symbol cannot be imported
    }
}

fn allocateAtoms(self: *Wasm) !void {
    // iterate over all sections and the atoms that belong to that section
    var it = self.atoms.iterator();
    while (it.next()) |entry| {
        const section_id: u16 = entry.key_ptr.*;
        const section = self.sections.items[section_id];
        var atom: *Atom = entry.value_ptr.*.getFirst();

        log.debug("Allocating atoms in '{s}' section", .{@tagName(section.section_kind)});

        var offset = @intCast(u32, section.offset);
        while (true) {
            const object: *Object = &self.objects.items[atom.file];
            const sym = &object.symtable[atom.sym_index];
            sym.offset = offset;

            for (atom.aliases.items) |index| {
                const alias_sym = &object.symtable[index];
                alias_sym.offset = offset;
            }

            for (atom.contained.items) |sym_at_offset| {
                const contained_sym = &object.symtable[sym_at_offset.local_sym_index];
                if (contained_sym.offset) |*sym_offset| {
                    sym_offset.* += offset;
                } else contained_sym.offset = offset;
            }

            offset += atom.size;

            if (atom.next) |next| {
                atom = next;
            } else break;
        }
    }
}

fn writeMagicBytes(self: *Wasm) !void {
    try self.file.writeAll(&std.wasm.magic);
    try self.file.writer().writeIntLittle(u32, 1);
}

fn writeAtoms(self: *Wasm, gpa: *Allocator) !void {
    const writer = self.file.writer();
    var it = self.atoms.iterator();
    while (it.next()) |entry| {
        const section_id = entry.key_ptr.*;
        const section = self.sections.items[section_id];
        log.debug("Writing section: {d}({s})", .{
            section_id,
            @tagName(section.section_kind),
        });
        var atom: *Atom = entry.value_ptr.*.getFirst();

        // calculate the amount of items in the section
        var count: u32 = 0;
        var code = std.ArrayList(u8).init(gpa);
        defer code.deinit();

        while (true) {
            // const object = self.objects.items[atom.file];
            // const sym = object.symtable.items[atom.sym_index];

            var fbs = std.io.fixedBufferStream(atom.code.items);
            const reader = fbs.reader();

            try atom.resolveRelocs(self);
            count += try leb.readULEB128(u32, reader);
            try code.appendSlice(atom.code.items[fbs.pos..]);

            if (atom.next) |next| {
                atom = next;
            } else break;
        }

        try writer.writeByte(@enumToInt(section.section_kind));
        try leb.writeULEB128(writer, code.items.len + 1);
        try leb.writeULEB128(writer, count);
        try writer.writeAll(code.items);
    }
}
