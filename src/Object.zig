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
/// Name (read path) of the object file.
name: []const u8,
/// A list of all sections this module contains.
/// This contains metadata such as offset, size, type and the contents in bytes.
sections: []const spec.Section = &.{},
/// Parsed type section
types: []const spec.sections.Type = &.{},
/// A list of all imports for this module
imports: []const spec.sections.Import = &.{},
/// Parsed function section
functions: []spec.sections.Func = &.{},
/// Parsed table section
tables: []const spec.sections.Table = &.{},
/// Parsed memory section
memories: []const spec.sections.Memory = &.{},
/// Parsed global section
globals: []spec.sections.Global = &.{},
/// Parsed export section
exports: []const spec.sections.Export = &.{},
/// Parsed element section
elements: []const spec.sections.Element = &.{},
/// Parsed code section
code: struct {
    /// Index of the section in the module
    index: u32,
    /// Function bodies containing the bytes
    /// and a pointer to the actual function.
    bodies: []spec.sections.Code,
} = .{ .bodies = &.{}, .index = undefined },
/// Parsed data section
data: struct {
    /// Index of this section within the module
    index: u32,
    /// All data segments
    segments: []const spec.sections.Data = &.{},
},
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
symtable: []spec.Symbol = &.{},
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
pub fn sectionByType(self: *Object, section_type: spec.SectionType) ?spec.Section {
    std.debug.assert(section_type != .custom);
    return for (self.sections) |section| {
        if (section.section_kind == section_type) {
            break section;
        }
    } else null;
}

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
        /// The currently parsed sections
        sections: std.ArrayListUnmanaged(spec.Section) = .{},

        fn init(object: *Object, reader: ReaderType) Self {
            return .{ .object = object, .reader = std.io.countingReader(reader) };
        }

        /// Verifies that the first 4 bytes contains \0Asm
        fn verifyMagicBytes(self: *Self) Error!void {
            var magic_bytes: [4]u8 = undefined;

            try self.reader.reader().readNoEof(&magic_bytes);
            if (!std.mem.eql(u8, &magic_bytes, &std.wasm.magic)) {
                log.debug("Invalid magic bytes '{s}'", .{&magic_bytes});
                return error.InvalidMagicByte;
            }
        }

        fn parseObject(self: *Self, gpa: *Allocator) Error!void {
            try self.verifyMagicBytes();
            const version = try self.reader.reader().readIntLittle(u32);

            self.object.version = version;

            while (self.reader.reader().readByte()) |byte| {
                const len = try readLeb(u32, self.reader.reader());
                try self.sections.append(gpa, .{
                    .offset = self.reader.bytes_read,
                    .size = len,
                    .section_kind = @intToEnum(spec.SectionType, byte),
                });
                const reader = std.io.limitedReader(self.reader.reader(), len).reader();

                // We only parse extra information when it's a custom section
                // or an import section. All other sections we simply skip till the end.
                switch (@intToEnum(spec.SectionType, byte)) {
                    .custom => {
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
                    },
                    .type => {
                        for (try readVec(&self.object.types, reader, gpa)) |*type_val| {
                            if ((try reader.readByte()) != std.wasm.function_type) return error.ExpectedFuncType;

                            for (try readVec(&type_val.params, reader, gpa)) |*param| {
                                param.* = try readEnum(spec.ValueType, reader);
                            }

                            for (try readVec(&type_val.returns, reader, gpa)) |*result| {
                                result.* = try readEnum(spec.ValueType, reader);
                            }
                        }
                        try assertEnd(reader);
                    },
                    .import => {
                        for (try readVec(&self.object.imports, reader, gpa)) |*import| {
                            const module_len = try readLeb(u32, reader);
                            const module_name = try gpa.alloc(u8, module_len);
                            try reader.readNoEof(module_name);

                            const name_len = try readLeb(u32, reader);
                            const name = try gpa.alloc(u8, name_len);
                            try reader.readNoEof(name);

                            const kind = try readEnum(spec.ExternalType, reader);
                            const kind_value: spec.sections.Import.Kind = switch (kind) {
                                .function => .{ .function = try readEnum(spec.indexes.Type, reader) },
                                .memory => .{ .memory = try readLimits(reader) },
                                .global => .{ .global = .{
                                    .valtype = try readEnum(spec.ValueType, reader),
                                    .mutable = (try reader.readByte()) == 0x01,
                                } },
                                .table => .{ .table = .{
                                    .reftype = try readEnum(spec.RefType, reader),
                                    .limits = try readLimits(reader),
                                } },
                            };

                            import.* = .{
                                .module_name = module_name,
                                .name = name,
                                .kind = kind_value,
                            };
                        }
                        try assertEnd(reader);
                    },
                    .function => {
                        for (try readVec(&self.object.functions, reader, gpa)) |*func, index| {
                            func.type_idx = try readEnum(spec.indexes.Type, reader);
                            func.func_idx = @intToEnum(spec.indexes.Func, @intCast(u32, index));
                            func.func_type = &self.object.types[@enumToInt(func.type_idx)];
                        }
                        try assertEnd(reader);
                    },
                    .table => {
                        for (try readVec(&self.object.tables, reader, gpa)) |*table| {
                            table.* = .{
                                .reftype = try readEnum(spec.RefType, reader),
                                .limits = try readLimits(reader),
                            };
                        }
                        try assertEnd(reader);
                    },
                    .memory => {
                        for (try readVec(&self.object.memories, reader, gpa)) |*memory| {
                            memory.* = .{ .limits = try readLimits(reader) };
                        }
                        try assertEnd(reader);
                    },
                    .global => {
                        for (try readVec(&self.object.globals, reader, gpa)) |*global, index| {
                            global.* = .{
                                .valtype = try readEnum(spec.ValueType, reader),
                                .mutable = (try reader.readByte()) == 0x01,
                                .init = try readInit(reader),
                                .global_idx = @intToEnum(spec.indexes.Global, @intCast(u32, index)),
                            };
                        }
                        try assertEnd(reader);
                    },
                    .@"export" => {
                        for (try readVec(&self.object.exports, reader, gpa)) |*exp| {
                            const name_len = try readLeb(u32, reader);
                            const name = try gpa.alloc(u8, name_len);
                            try reader.readNoEof(name);
                            exp.* = .{
                                .name = name,
                                .kind = try readEnum(spec.ExternalType, reader),
                                .index = try readLeb(u32, reader),
                            };

                            if (exp.kind == .function) {
                                self.object.functions[exp.index].export_name = name;
                            }
                        }
                        try assertEnd(reader);
                    },
                    .start => {
                        self.object.start = try readEnum(spec.indexes.Func, reader);
                        try assertEnd(reader);
                    },
                    .element => {
                        for (try readVec(&self.object.elements, reader, gpa)) |*elem| {
                            elem.table_idx = try readEnum(spec.indexes.Table, reader);
                            elem.offset = try readInit(reader);

                            for (try readVec(&elem.func_idxs, reader, gpa)) |*idx| {
                                idx.* = try readEnum(spec.indexes.Func, reader);
                            }
                        }
                        try assertEnd(reader);
                    },
                    .code => {
                        var start = reader.context.bytes_left;
                        const count = try readLeb(u32, reader);
                        self.object.code.bodies = try gpa.alloc(spec.sections.Code, count);
                        self.object.code.index = @intCast(u32, self.sections.items.len - 1);
                        for (self.object.code.bodies) |*code, index| {
                            const code_len = try readLeb(u32, reader);
                            code.* = .{
                                .data = try gpa.alloc(u8, code_len),
                                .func = &self.object.functions[index],
                                .offset = @intCast(u32, start - reader.context.bytes_left),
                            };
                            try reader.readNoEof(code.data);
                        }
                    },
                    .data => {
                        var start = reader.context.bytes_left;
                        self.object.data.index = @intCast(u32, self.sections.items.len - 1);
                        for (try readVec(self.object.data.segments)) |*segment| {
                            segment.index = try readEnum(spec.indexes.Mem, reader);
                            segment.offset = try readInit(reader);
                            const init_len = try readLeb(u32, reader);
                            segment.seg_offset = @intCast(u32, start - reader.context.bytes_left);
                            const init_data = try gpa.alloc(u8, init_len);
                            try reader.readNoEof(init_data);
                            segment.data = init_data;
                        }
                    },
                    else => try self.reader.reader().skipBytes(len, .{}),
                }
                if (byte != 0x00) {} else {}
            } else |err| switch (err) {
                error.EndOfStream => {}, // finished parsing the file
                else => |e| return e,
            }
            self.object.sections = self.sections.toOwnedSlice(gpa);
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
                    log.debug("Detected unknown feature: {s}", .{name});
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

            log.debug("Found {d} relocations for section ({d}): {s}", .{
                count,
                section,
                @tagName(self.sections.items[section].section_kind),
            });

            for (relocations) |*relocation| {
                const rel_type = try leb.readULEB128(u8, reader);
                const rel_type_enum = @intToEnum(spec.Relocation.Type, rel_type);
                relocation.* = .{
                    .relocation_type = rel_type_enum,
                    .offset = try leb.readULEB128(u32, reader),
                    .index = try leb.readULEB128(u32, reader),
                    .addend = if (rel_type_enum.addendIsPresent()) try leb.readULEB128(u32, reader) else null,
                };
                log.debug("Found relocation: type({s}) offset({d}) index({d}) addend({d})", .{
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
            var limited = std.io.limitedReader(self.reader.reader(), payload_size);
            const limited_reader = limited.reader();

            const version = try leb.readULEB128(u32, limited_reader);
            log.debug("Link meta data version: {d}", .{version});
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
            log.debug("Found subsection: {s}", .{@tagName(@intToEnum(spec.SubsectionType, sub_type))});
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
                        log.debug("Found segment: {s} align({d}) flags({b})", .{
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
                        log.debug("Found function - prio: {d}, index: {d}", .{ func.priority, func.symbol_index });
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
                    const symbols = try gpa.alloc(spec.Symbol, count);
                    for (symbols) |*symbol| {
                        symbol.* = try self.parseSymbol(gpa, reader);

                        log.debug("Found symbol: type({s}) name({s}) flags(0x{x})", .{
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
        fn parseSymbol(self: *Self, gpa: *Allocator, reader: anytype) !spec.Symbol {
            const kind = @intToEnum(spec.Symbol.Kind.Tag, try leb.readULEB128(u8, reader));
            const flags = try leb.readULEB128(u32, reader);
            var symbol: spec.Symbol = .{
                .flags = flags,
                .kind = undefined,
                .name = undefined,
            };

            switch (kind) {
                .data => {
                    const name_len = try leb.readULEB128(u32, reader);
                    const name = try gpa.alloc(u8, name_len);
                    try reader.readNoEof(name);
                    symbol.name = name;
                    symbol.kind = .{ .data = .{} };

                    // Data symbols only have the following fields if the symbol is defined
                    if (!symbol.hasFlag(.WASM_SYM_UNDEFINED)) {
                        symbol.kind.data.index = try leb.readULEB128(u32, reader);
                        symbol.kind.data.offset = try leb.readULEB128(u32, reader);
                        symbol.kind.data.size = try leb.readULEB128(u32, reader);
                    }
                },
                .section => {
                    symbol.kind = .{ .section = try leb.readULEB128(u32, reader) };
                    symbol.name = @tagName(symbol.kind);
                },
                else => |tag| {
                    const index = try leb.readULEB128(u32, reader);

                    const is_import = symbol.hasFlag(.WASM_SYM_UNDEFINED);
                    const explicit_name = symbol.hasFlag(.WASM_SYM_EXPLICIT_NAME);
                    if (!(is_import and !explicit_name)) {
                        const name_len = try leb.readULEB128(u32, reader);
                        const name = try gpa.alloc(u8, name_len);
                        try reader.readNoEof(name);
                        symbol.name = name;
                    } else {
                        symbol.name = self.object.imports[index].name;
                    }

                    symbol.kind = switch (tag) {
                        .function => .{ .function = .{
                            .index = index,
                            .func = if (is_import) null else &self.object.functions[index],
                        } },
                        .global => .{ .global = .{ .index = index } },
                        .event => .{ .event = .{ .index = index } },
                        .table => .{ .table = .{ .index = index } },
                        else => unreachable,
                    };
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
