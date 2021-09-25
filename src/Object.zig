//! Object represents a wasm object file. When initializing a new
//! `Object`, it will parse the contents of a given file handler, and verify
//! the data on correctness. The result can then be used by the linker.
const Object = @This();

const Atom = @import("Atom.zig");
const spec = @import("spec.zig");
const std = @import("std");
const Wasm = @import("Wasm.zig");

const Allocator = std.mem.Allocator;
const leb = std.leb;
const meta = std.meta;

const log = std.log.scoped(.zwld);

/// Wasm spec version used for this `Object`
version: u32 = 0,
/// The entire object file is read and parsed in a single pass.
/// For this reason it's a lot simpler to use an arena and store the entire
/// state after parsing. This also allows to free all memory at once.
arena: std.heap.ArenaAllocator.State = .{},
/// The file descriptor that represents the wasm object file.
file: ?std.fs.File = null,
/// Name [read path] of the object file.
name: []const u8,
/// A list of all sections this module contains.
sections: []const Section = &.{},
/// Represents the function ID that must be called on startup.
/// This is `null` by default as runtimes may determine the startup
/// function themselves. This is essentially legacy.
start: ?spec.indexes.Func = null,
/// A slice of features that tell the linker what features are mandatory,
/// used (or therefore missing) and must generate an error when another
/// object uses features that are not supported by the other.
features: []const spec.Feature = &.{},
/// A table that maps the relocations we must perform where the key represents
/// the section that the list of relocations applies to.
relocations: std.AutoArrayHashMapUnmanaged(u32, []const spec.Relocation) = .{},
/// Table of symbols belonging to this Object file
symtable: []const spec.SymInfo = &.{},
/// Extra metadata about the linking section, such as alignment of segments and their name
segment_info: []const spec.Segment = &.{},
/// A sequence of function initializers that must be called on startup
init_funcs: []const spec.InitFunc = &.{},
/// Comdat information
comdat_info: []const spec.Comdat = &.{},

/// Initializes a new `Object` from a wasm object file.
pub fn init(gpa: *Allocator, file: std.fs.File, path: []const u8) !Object {
    var object: Object = .{
        .file = file,
        .name = path,
    };

    var arena = std.heap.ArenaAllocator.init(gpa);
    errdefer arena.deinit();

    try object.parse(&arena.allocator, file.reader());
    object.arena = arena.state;

    return object;
}

/// Frees all memory of `Object` at once. The given `Allocator` must be
/// the same allocator that was used when `init` was called.
pub fn deinit(self: *Object, gpa: *Allocator) void {
    self.arena.promote(gpa).deinit();
    self.* = undefined;
}

/// Returns a section from a given section type. Will return `null` if the section
/// does not exist within the wasm module.
/// Asserts given `section_type` is not `.custom` as custom sections are not unique by type (id)
/// but by name.
pub fn sectionByType(self: *Object, section_type: spec.Section) ?Section {
    std.debug.assert(section_type != .custom);
    return for (self.sections) |section| {
        if (section.section_kind == section_type) {
            break section;
        }
    } else null;
}

/// Represents a wasm section entry within a wasm module
/// A section contains meta data that can be used to parse its contents from within a file.
pub const Section = struct {
    /// The type of a section
    section_kind: spec.Section,
    /// Offset into the object file where the section starts
    offset: usize,
    /// Size in bytes of the section
    size: usize,
    /// The count of entries within a section
    count: usize,
};

/// Error set containing parsing errors.
/// Merged with reader's errorset by `Parser`
pub const ParseError = error{
    /// The magic byte is either missing or does not contain \0Asm
    InvalidMagicByte,
    /// The wasm version is either missing or does not match the supported version.
    InvalidWasmVersion,
    /// Expected the functype byte while parsing the Type section but did not find it.
    ExpectedFuncType,
    /// Missing an 'end' opcode when defining a constant expression.
    MissingEndForExpression,
    /// Missing an 'end' opcode at the end of a body expression.
    MissingEndForBody,
    /// The size defined in the section code mismatches with the actual payload size.
    MalformedSection,
    /// Stream has reached the end. Unreachable for caller and must be handled internally
    /// by the parser.
    EndOfStream,
    /// Ran out of memory when allocating.
    OutOfMemory,
    /// A non-zero flag was provided for comdat info
    UnexpectedValue,
    /// An import symbol contains an index to an import that does
    /// not exist, or no imports were defined.
    InvalidIndex,
    /// The section "linking" contains a version that is not supported.
    UnsupportedVersion,
    /// When reading the data in leb128 compressed format, its value was overflown.
    Overflow,
};

fn parse(self: *Object, gpa: *Allocator, reader: anytype) Parser(@TypeOf(reader)).Error!void {
    var parser = Parser(@TypeOf(reader)).init(self, reader);
    return parser.parseObject(gpa);
}

fn Parser(comptime ReaderType: type) type {
    return struct {
        const Self = @This();
        const Error = ReaderType.Error || ParseError;

        reader: std.io.CountingReader(ReaderType),
        /// Object file we're building
        object: *Object,

        fn init(object: *Object, reader: ReaderType) Self {
            return .{ .object = object, .reader = std.io.countingReader(reader) };
        }

        /// Verifies that the first 4 bytes contains \0Asm
        fn verifyMagicBytes(self: *Self) Error!void {
            var magic_bytes: [4]u8 = undefined;

            try self.reader.reader().readNoEof(&magic_bytes);
            if (!std.mem.eql(u8, &magic_bytes, &std.wasm.magic)) {
                log.info("Invalid magic bytes '{s}'", .{&magic_bytes});
                return error.InvalidMagicByte;
            }
        }

        fn parseObject(self: *Self, gpa: *Allocator) Error!void {
            try self.verifyMagicBytes();
            const version = try self.reader.reader().readIntLittle(u32);

            self.object.version = version;

            var sections = std.ArrayList(Section).init(gpa);
            defer sections.deinit();

            while (self.reader.reader().readByte()) |byte| {
                const len = try readLeb(u32, self.reader.reader());
                try sections.append(.{
                    .offset = self.reader.bytes_read,
                    .size = len,
                    .section_kind = @intToEnum(spec.Section, byte),
                });

                // We only parse extra information when it's a custom section
                // all other sections we simply skip
                if (byte != 0x00) {
                    try self.reader.reader().skipBytes(len, .{});
                } else {
                    const reader = std.io.limitedReader(self.reader.reader(), len).reader();
                    const name_len = try readLeb(u32, reader);
                    const name = try gpa.alloc(u8, name_len);
                    defer gpa.free(name);
                    try reader.readNoEof(name);

                    if (std.mem.eql(u8, name, "linking")) {
                        try self.parseMetadata(gpa, reader.context.bytes_left);
                    } else if (std.mem.startsWith(u8, name, "reloc")) {
                        try self.parseRelocations(gpa);
                    } else if (std.mem.eql(u8, name, "target_features")) {
                        try self.parseFeatures(gpa);
                    } else {
                        try reader.skipBytes(reader.context.bytes_left, .{});
                    }
                }
            } else |err| switch (err) {
                error.EndOfStream => {}, // finished parsing the file
                else => |e| return e,
            }
            self.object.sections = sections.toOwnedSlice();
        }

        /// Based on the "features" custom section, parses it into a list of
        /// features that tell the linker what features were enabled and may be mandatory
        /// to be able to link.
        /// Logs an info message when an undefined feature is detected.
        fn parseFeatures(self: *Self, gpa: *Allocator) !void {
            const reader = self.reader.reader();
            for (try readVec(&self.object.features, reader, gpa)) |*feature| {
                const prefix = try leb.readULEB128(u8, reader);
                const name_len = try leb.readULEB128(u32, reader);
                const name = try gpa.alloc(u8, name_len);
                try reader.readNoEof(name);

                feature.* = .{
                    .prefix = prefix,
                    .name = name,
                };

                if (!spec.known_features.has(name)) {
                    log.info("Detected unknown feature: {s}", .{name});
                }
            }
        }

        /// Parses a "reloc" custom section into a list of relocations.
        /// The relocations are mapped into `Object` where the key is the section
        /// they apply to.
        fn parseRelocations(self: *Self, gpa: *Allocator) !void {
            const reader = self.reader.reader();
            const section = try leb.readULEB128(u32, reader);
            const count = try leb.readULEB128(u32, reader);
            const relocations = try gpa.alloc(spec.Relocation, count);

            log.info("Found {d} relocations for section index {d}", .{ count, section });

            for (relocations) |*relocation| {
                const rel_type = try leb.readULEB128(u8, reader);
                const rel_type_enum = @intToEnum(spec.Relocation.Type, rel_type);
                relocation.* = .{
                    .relocation_type = rel_type_enum,
                    .offset = try leb.readULEB128(u32, reader),
                    .index = try leb.readULEB128(u32, reader),
                    .addend = if (rel_type_enum.addendIsPresent()) try leb.readULEB128(u32, reader) else null,
                };
                log.info("Found relocation: type({s}) offset({d}) index({d}) addend({d})", .{
                    @tagName(relocation.relocation_type),
                    relocation.offset,
                    relocation.index,
                    relocation.addend,
                });
            }

            try self.object.relocations.putNoClobber(gpa, section, relocations);
        }

        /// Parses the "linking" custom section. Versions that are not
        /// supported will be an error. `payload_size` is required to be able
        /// to calculate the subsections we need to parse, as that data is not
        /// available within the section itself.
        fn parseMetadata(self: *Self, gpa: *Allocator, payload_size: usize) !void {
            var limited = std.io.limitedReader(self.reader, payload_size);
            const limited_reader = limited.reader();

            const version = try leb.readULEB128(u32, limited_reader);
            log.info("Link meta data version: {d}", .{version});
            if (version != 2) return error.UnsupportedVersion;

            while (limited.bytes_left > 0) {
                try self.parseSubsection(gpa, limited_reader);
            }
        }

        /// Parses a `spec.Subsection`.
        /// The `reader` param for this is to provide a `LimitedReader`, which allows
        /// us to only read until a max length.
        ///
        /// `self` is used to provide access to other sections that may be needed,
        /// such as access to the `import` section to find the name of a symbol.
        fn parseSubsection(self: *Self, gpa: *Allocator, reader: anytype) !void {
            const sub_type = try leb.readULEB128(u8, reader);
            log.info("Found subsection: {s}", .{@tagName(@intToEnum(spec.SubsectionType, sub_type))});
            const payload_len = try leb.readULEB128(u32, reader);
            if (payload_len == 0) return;

            var limited = std.io.limitedReader(reader, payload_len);
            const limited_reader = limited.reader();

            // every subsection contains a 'count' field
            const count = try leb.readULEB128(u32, limited_reader);

            switch (@intToEnum(spec.SubsectionType, sub_type)) {
                .WASM_SEGMENT_INFO => {
                    const segments = try gpa.alloc(spec.Segment, count);
                    for (segments) |*segment| {
                        const name_len = try leb.readULEB128(u32, reader);
                        const name = try gpa.alloc(u8, name_len);
                        try reader.readNoEof(name);
                        segment.* = .{
                            .name = name,
                            .alignment = try leb.readULEB128(u32, reader),
                            .flags = try leb.readULEB128(u32, reader),
                        };
                        log.info("Found segment: {s} align({d}) flags({b})", .{
                            segment.name,
                            segment.alignment,
                            segment.flags,
                        });
                    }
                    self.object.segment_info = segments;
                },
                .WASM_INIT_FUNCS => {
                    const funcs = try gpa.alloc(spec.InitFunc, count);
                    for (funcs) |*func| {
                        func.* = .{
                            .priority = try leb.readULEB128(u32, reader),
                            .symbol_index = try leb.readULEB128(u32, reader),
                        };
                        log.info("Found function - prio: {d}, index: {d}", .{ func.priority, func.symbol_index });
                    }
                    self.object.init_funcs = funcs;
                },
                .WASM_COMDAT_INFO => {
                    const comdats = try gpa.alloc(spec.Comdat, count);
                    for (comdats) |*comdat| {
                        const name_len = try leb.readULEB128(u32, reader);
                        const name = try gpa.alloc(u8, name_len);
                        try reader.readNoEof(name);

                        const flags = try leb.readULEB128(u32, reader);
                        if (flags != 0) {
                            return error.UnexpectedValue;
                        }

                        const symbol_count = try leb.readULEB128(u32, reader);
                        const symbols = try gpa.alloc(spec.ComdatSym, symbol_count);
                        for (symbols) |*symbol| {
                            symbol.* = .{
                                .kind = @intToEnum(spec.ComdatSym.Type, try leb.readULEB128(u8, reader)),
                                .index = try leb.readULEB128(u32, reader),
                            };
                        }

                        comdat.* = .{
                            .name = name,
                            .flags = flags,
                            .symbols = symbols,
                        };
                    }

                    self.object.comdat_info = comdats;
                },
                .WASM_SYMBOL_TABLE => {
                    const symbols = try gpa.alloc(spec.SymInfo, count);
                    for (symbols) |*symbol| {
                        symbol.* = try self.parseSymbol(gpa, reader);

                        log.info("Found symbol: type({s}) name({s}) flags(0x{x})", .{
                            @tagName(symbol.kind),
                            symbol.name,
                            symbol.flags,
                        });
                    }

                    self.object.symtable = symbols;
                },
            }
        }

        /// Parses the symbol information based on its kind,
        /// requires access to `Object` to find the name of a symbol when it's
        /// an import and flag `WASM_SYM_EXPLICIT_NAME` is not set.
        fn parseSymbol(gpa: *Allocator, reader: anytype) !spec.SymInfo {
            var symbol: spec.SymInfo = undefined;

            symbol.kind = @intToEnum(spec.SymInfo.Type, try leb.readULEB128(u8, reader));
            symbol.flags = try leb.readULEB128(u32, reader);

            switch (symbol.kind) {
                .SYMTAB_DATA => {
                    const name_len = try leb.readULEB128(u32, reader);
                    const name = try gpa.alloc(u8, name_len);
                    try reader.readNoEof(name);
                    symbol.name = name;

                    // Data symbols only have the following fields if the symbol is defined
                    if (!symbol.hasFlag(.WASM_SYM_UNDEFINED)) {
                        symbol.index = try leb.readULEB128(u32, reader);
                        symbol.offset = try leb.readULEB128(u32, reader);
                        symbol.size = try leb.readULEB128(u32, reader);
                    }
                },
                .SYMTAB_SECTION => {
                    symbol.index = try leb.readULEB128(u32, reader);
                },
                else => {
                    symbol.index = try leb.readULEB128(u32, reader);

                    const is_import = symbol.hasFlag(.WASM_SYM_UNDEFINED);
                    const explicit_name = symbol.hasFlag(.WASM_SYM_EXPLICIT_NAME);
                    if (!(is_import and !explicit_name)) {
                        const name_len = try leb.readULEB128(u32, reader);
                        const name = try gpa.alloc(u8, name_len);
                        try reader.readNoEof(name);
                        symbol.name = name;
                    }
                },
            }
            return symbol;
        }
    };
}

/// First reads the count from the reader and then allocate
/// a slice of ptr child's element type.
fn readVec(ptr: anytype, reader: anytype, gpa: *Allocator) ![]ElementType(@TypeOf(ptr)) {
    const len = try readLeb(u32, reader);
    const slice = try gpa.alloc(ElementType(@TypeOf(ptr)), len);
    ptr.* = slice;
    return slice;
}

fn ElementType(comptime ptr: type) type {
    return meta.Elem(meta.Child(ptr));
}

/// Uses either `readILEB128` or `readULEB128` depending on the
/// signedness of the given type `T`.
/// Asserts `T` is an integer.
fn readLeb(comptime T: type, reader: anytype) !T {
    if (comptime std.meta.trait.isSignedInt(T)) {
        return try leb.readILEB128(T, reader);
    } else {
        return try leb.readULEB128(T, reader);
    }
}

/// Reads an enum type from the given reader.
/// Asserts `T` is an enum
fn readEnum(comptime T: type, reader: anytype) !T {
    switch (@typeInfo(T)) {
        .Enum => |enum_type| return @intToEnum(T, try readLeb(enum_type.tag_type, reader)),
        else => @compileError("T must be an enum. Instead was given type " ++ @typeName(T)),
    }
}

fn readLimits(reader: anytype) !spec.Limits {
    const flags = try readLeb(u1, reader);
    const min = try readLeb(u32, reader);
    return spec.Limits{
        .min = min,
        .max = if (flags == 0) null else try readLeb(u32, reader),
    };
}

fn readInit(reader: anytype) !spec.InitExpression {
    const opcode = try reader.readByte();
    const init_expr: spec.InitExpression = switch (@intToEnum(std.wasm.Opcode, opcode)) {
        .i32_const => .{ .i32_const = try readLeb(i32, reader) },
        .global_get => .{ .global_get = try readLeb(u32, reader) },
        else => unreachable,
    };

    if ((try readEnum(std.wasm.Opcode, reader)) != .end) return error.MissingEndForExpression;
    return init_expr;
}

fn assertEnd(reader: anytype) !void {
    var buf: [1]u8 = undefined;
    const len = try reader.read(&buf);
    if (len != 0) return error.MalformedSection;
    if (reader.context.bytes_left != 0) return error.MalformedSection;
}

/// Parses a single object file into a linked list of atoms
pub fn parseIntoAtoms(self: *Object, gpa: *Allocator, object_index: u16, wasm: *Wasm) !void {
    // self.symtable[0].kind
    _ = self;
    _ = gpa;
    _ = object_index;
    _ = wasm;
    var symbols_by_section = std.AutoHashMap(spec.Section, std.ArrayList(u32)).init(gpa);
    defer symbols_by_section.deinit();

    for (self.sections) |section| {
        try symbols_by_section.putNoClobber(section.section_kind, std.ArrayList(u32).init(gpa));
    }

    for (self.symtable) |sym, sym_index| {
        const sect_ty: spec.Section = switch (sym.kind) {
            .SYMTAB_FUNCTION => .func,
            .SYMTAB_DATA => .data,
            .SYMTAB_GLOBAL => .global,
            .SYMTAB_SECTION => continue,
            .SYMTAB_EVENT => continue,
            .SYMTAB_TABLE => .table,
        };
        const map = symbols_by_section.getPtr(sect_ty) orelse continue;
        try map.append(@intCast(u32, sym_index));
    }

    for (self.sections) |section, idx| {
        log.info("Parsing section '{s}'", .{@tagName(section.section_kind)});

        const match_index = (try wasm.getMatchingSection(object_index, idx)) orelse {
            log.info("unhandled section", .{});
            continue;
        };

        const atom = try Atom.
    }
}
