//! Object represents a wasm object file. When initializing a new
//! `Object`, it will parse the contents of a given file handler, and verify
//! the data on correctness. The result can then be used by the linker.
const Object = @This();

const Atom = @import("Atom.zig");
const wasm = @import("data.zig");
const std = @import("std");
const Wasm = @import("Wasm.zig");
const Symbol = @import("Symbol.zig");

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
sections: []const wasm.Section = &.{},
/// Parsed type section
types: []const wasm.FuncType = &.{},
/// A list of all imports for this module
imports: []wasm.Import = &.{},
/// Parsed function section
functions: []wasm.Func = &.{},
/// Parsed table section
tables: []wasm.Table = &.{},
/// Parsed memory section
memories: []const wasm.Memory = &.{},
/// Parsed global section
globals: []wasm.Global = &.{},
/// Parsed export section
exports: []const wasm.Export = &.{},
/// Parsed element section
elements: []const wasm.Element = &.{},
/// Parsed code section
code: struct {
    /// Index of the section in the module
    index: u32,
    /// Function bodies containing the bytes
    /// and a pointer to the actual function.
    bodies: []wasm.Code,
} = .{ .bodies = &.{}, .index = undefined },
/// Parsed data section
data: struct {
    /// Index of this section within the module
    index: u32,
    /// All data segments
    segments: []const wasm.Data = &.{},
} = .{ .index = undefined, .segments = &.{} },
/// Represents the function ID that must be called on startup.
/// This is `null` by default as runtimes may determine the startup
/// function themselves. This is essentially legacy.
start: ?u32 = null,
/// A slice of features that tell the linker what features are mandatory,
/// used (or therefore missing) and must generate an error when another
/// object uses features that are not supported by the other.
features: []const wasm.Feature = &.{},
/// A table that maps the relocations we must perform where the key represents
/// the section that the list of relocations applies to.
relocations: std.AutoArrayHashMapUnmanaged(u32, []const wasm.Relocation) = .{},
/// Table of symbols belonging to this Object file
symtable: []Symbol = &.{},
/// Extra metadata about the linking section, such as alignment of segments and their name
segment_info: []const wasm.Segment = &.{},
/// A sequence of function initializers that must be called on startup
init_funcs: []const wasm.InitFunc = &.{},
/// Comdat information
comdat_info: []const wasm.Comdat = &.{},

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

/// Finds the import within the list of imports from a given kind and index of that kind.
/// Asserts the import exists
pub fn findImport(self: *const Object, import_kind: wasm.ExternalType, index: u32) *wasm.Import {
    var i: u32 = 0;
    return for (self.imports) |*import| {
        if (std.meta.activeTag(import.kind) == import_kind) {
            if (i == index) return import;
            i += 1;
        }
    } else unreachable; // Only existing imports are allowed to be found
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
        sections: std.ArrayListUnmanaged(wasm.Section) = .{},

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
                    .section_kind = @intToEnum(wasm.SectionType, byte),
                });
                const reader = std.io.limitedReader(self.reader.reader(), len).reader();

                // We only parse extra information when it's a custom section
                // or an import section. All other sections we simply skip till the end.
                switch (@intToEnum(wasm.SectionType, byte)) {
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
                                param.* = try readEnum(wasm.ValueType, reader);
                            }

                            for (try readVec(&type_val.returns, reader, gpa)) |*result| {
                                result.* = try readEnum(wasm.ValueType, reader);
                            }
                        }
                        try assertEnd(reader);
                    },
                    .import => {
                        for (try readVec(&self.object.imports, reader, gpa)) |*import, index| {
                            const module_len = try readLeb(u32, reader);
                            const module_name = try gpa.alloc(u8, module_len);
                            try reader.readNoEof(module_name);

                            const name_len = try readLeb(u32, reader);
                            const name = try gpa.alloc(u8, name_len);
                            try reader.readNoEof(name);

                            const kind = try readEnum(wasm.ExternalType, reader);
                            const kind_value: wasm.Import.Kind = switch (kind) {
                                .function => .{
                                    .function = blk: {
                                        const type_index = try readLeb(u32, reader);
                                        break :blk wasm.Func{
                                            .type_idx = type_index,
                                            .func_idx = @intCast(u32, index),
                                            .func_type = &self.object.types[type_index],
                                        };
                                    },
                                },
                                .memory => .{ .memory = try readLimits(reader) },
                                .global => .{ .global = .{
                                    .valtype = try readEnum(wasm.ValueType, reader),
                                    .mutable = (try reader.readByte()) == 0x01,
                                    .global_idx = @intCast(u32, index),
                                } },
                                .table => .{ .table = .{
                                    .reftype = try readEnum(wasm.RefType, reader),
                                    .limits = try readLimits(reader),
                                    .table_idx = @intCast(u32, index),
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
                            func.* = .{
                                .type_idx = try readLeb(u32, reader),
                                .func_idx = @intCast(u32, index),
                                .func_type = &self.object.types[func.type_idx],
                            };
                        }
                        try assertEnd(reader);
                    },
                    .table => {
                        for (try readVec(&self.object.tables, reader, gpa)) |*table, index| {
                            table.* = .{
                                .reftype = try readEnum(wasm.RefType, reader),
                                .limits = try readLimits(reader),
                                .table_idx = @intCast(u32, index),
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
                                .valtype = try readEnum(wasm.ValueType, reader),
                                .mutable = (try reader.readByte()) == 0x01,
                                .init = try readInit(reader),
                                .global_idx = @intCast(u32, index),
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
                                .kind = try readEnum(wasm.ExternalType, reader),
                                .index = try readLeb(u32, reader),
                            };

                            if (exp.kind == .function) {
                                self.object.functions[exp.index].export_name = name;
                            }
                        }
                        try assertEnd(reader);
                    },
                    .start => {
                        self.object.start = try readLeb(u32, reader);
                        try assertEnd(reader);
                    },
                    .element => {
                        for (try readVec(&self.object.elements, reader, gpa)) |*elem| {
                            elem.table_idx = try readLeb(u32, reader);
                            elem.offset = try readInit(reader);

                            for (try readVec(&elem.func_idxs, reader, gpa)) |*idx| {
                                idx.* = try readLeb(u32, reader);
                            }
                        }
                        try assertEnd(reader);
                    },
                    .code => {
                        var start = reader.context.bytes_left;
                        self.object.code.index = @intCast(u32, self.sections.items.len - 1);
                        for (try readVec(&self.object.code.bodies, reader, gpa)) |*code, index| {
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
                        for (try readVec(&self.object.data.segments, reader, gpa)) |*segment| {
                            segment.index = try readLeb(u32, reader);
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

                if (!wasm.known_features.has(name)) {
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
            const relocations = try gpa.alloc(wasm.Relocation, count);

            log.debug("Found {d} relocations for section ({d}): {s}", .{
                count,
                section,
                @tagName(self.sections.items[section].section_kind),
            });

            for (relocations) |*relocation| {
                const rel_type = try leb.readULEB128(u8, reader);
                const rel_type_enum = @intToEnum(wasm.Relocation.RelocationType, rel_type);
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
            log.debug("Found subsection: {s}", .{@tagName(@intToEnum(wasm.SubsectionType, sub_type))});
            const payload_len = try leb.readULEB128(u32, reader);
            if (payload_len == 0) return;

            var limited = std.io.limitedReader(reader, payload_len);
            const limited_reader = limited.reader();

            // every subsection contains a 'count' field
            const count = try leb.readULEB128(u32, limited_reader);

            switch (@intToEnum(wasm.SubsectionType, sub_type)) {
                .WASM_SEGMENT_INFO => {
                    const segments = try gpa.alloc(wasm.Segment, count);
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
                    const funcs = try gpa.alloc(wasm.InitFunc, count);
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
                    const comdats = try gpa.alloc(wasm.Comdat, count);
                    for (comdats) |*comdat| {
                        const name_len = try leb.readULEB128(u32, reader);
                        const name = try gpa.alloc(u8, name_len);
                        try reader.readNoEof(name);

                        const flags = try leb.readULEB128(u32, reader);
                        if (flags != 0) {
                            return error.UnexpectedValue;
                        }

                        const symbol_count = try leb.readULEB128(u32, reader);
                        const symbols = try gpa.alloc(wasm.ComdatSym, symbol_count);
                        for (symbols) |*symbol| {
                            symbol.* = .{
                                .kind = @intToEnum(wasm.ComdatSym.Type, try leb.readULEB128(u8, reader)),
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
                    const symbols = try gpa.alloc(Symbol, count);
                    for (symbols) |*symbol| {
                        symbol.* = try self.parseSymbol(gpa, reader);

                        log.debug("Found symbol: type({s}) name({s}) flags(0b{b:0>8})", .{
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
        fn parseSymbol(self: *Self, gpa: *Allocator, reader: anytype) !Symbol {
            const kind = @intToEnum(Symbol.Kind.Tag, try leb.readULEB128(u8, reader));
            const flags = try leb.readULEB128(u32, reader);
            var symbol: Symbol = .{
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
                    if (symbol.isDefined()) {
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
                    var maybe_import: ?*wasm.Import = null;

                    const is_undefined = symbol.isUndefined();
                    if (is_undefined) {
                        maybe_import = self.object.findImport(kind.externalType(), index);
                        symbol.module_name = maybe_import.?.module_name;
                    }
                    const explicit_name = symbol.hasFlag(.WASM_SYM_EXPLICIT_NAME);
                    if (!(is_undefined and !explicit_name)) {
                        const name_len = try leb.readULEB128(u32, reader);
                        const name = try gpa.alloc(u8, name_len);
                        try reader.readNoEof(name);
                        symbol.name = name;
                    } else {
                        symbol.name = maybe_import.?.name;
                    }

                    symbol.kind = switch (tag) {
                        .function => blk: {
                            const func: *wasm.Func = if (is_undefined)
                                &maybe_import.?.kind.function
                            else
                                &self.object.functions[index];

                            break :blk .{ .function = .{ .index = index, .func = func } };
                        },
                        .global => blk: {
                            const global = if (is_undefined)
                                &maybe_import.?.kind.global
                            else
                                &self.object.globals[index];
                            break :blk .{ .global = .{ .index = index, .global = global } };
                        },
                        .table => blk: {
                            const table = if (is_undefined)
                                &maybe_import.?.kind.table
                            else
                                &self.object.tables[index];
                            break :blk .{ .table = .{ .index = index, .table = table } };
                        },
                        .event => .{ .event = .{ .index = index } },
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

fn readLimits(reader: anytype) !wasm.Limits {
    const flags = try readLeb(u1, reader);
    const min = try readLeb(u32, reader);
    return wasm.Limits{
        .min = min,
        .max = if (flags == 0) null else try readLeb(u32, reader),
    };
}

fn readInit(reader: anytype) !wasm.InitExpression {
    const opcode = try reader.readByte();
    const init_expr: wasm.InitExpression = switch (@intToEnum(std.wasm.Opcode, opcode)) {
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

/// Parses an object file into atoms, for code and data sections
pub fn parseIntoAtoms(self: *Object, gpa: *Allocator, object_index: u16, wasm_bin: *Wasm) !void {
    log.debug("Parsing data section into atoms", .{});
    var symbols_per_segment = std.AutoHashMap(u32, std.ArrayList(u32)).init(gpa);
    defer symbols_per_segment.deinit();

    for (self.data.segments) |_, index| {
        try symbols_per_segment.putNoClobber(@intCast(u32, index), std.ArrayList(u32).init(gpa));
    }

    for (self.symtable) |symbol, symbol_index| {
        switch (symbol.kind) {
            .data => |data| {
                const index = data.index orelse continue;
                const syms = try symbols_per_segment.getPtr(index).?; // symbols cannot point to non-existing segment
                try syms.append(@intCast(u32, symbol_index));
            },
            else => continue,
        }
    }

    for (self.data.segments) |segment, segment_index| {
        const segment_meta = self.segment_info[segment_index];
        log.debug("Parsing segment '{s}'", .{segment_meta.name});

        const final_segment_index = try wasm_bin.getMatchingSegment(gpa, object_index, @intCast(u32, segment_index));

        const atom = try Atom.create(gpa);
        errdefer atom.deinit(gpa);

        try wasm_bin.managed_atoms.append(gpa, atom);
        atom.file = object_index;
        atom.size = @intCast(u32, segment.data.len);
        atom.alignment = @intCast(u32, segment_meta.alignment);

        const symbol_list = symbols_per_segment.get(@intCast(u32, segment_index));
        for (symbol_list) |symbol_index| {
            const symbol = self.symtable[symbol_index].kind.data;
            if (symbol.offset.? > 0) {
                try atom.contained.append(gpa, .{
                    .local_sym_index = symbol_index,
                    .offset = symbol.offset.?,
                });
            } else {
                try atom.aliases.append(gpa, symbol_index);
            }
        }

        const relocations: []const wasm.Relocation = self.relocations.get(self.data.index) orelse &{};
        for (relocations) |relocation| {
            if (isInbetween(segment.seg_offset, atom.size, relocation.offset)) {
                try atom.relocs.append(gpa, relocation);
            }
        }

        std.sort.sort(u32, atom.aliases.items, wasm_bin.objects.items[object_index], sort);
        atom.sym_index = atom.aliases.swapRemove(0); // alias should never be empty
        try atom.code.appendSlice(segment.data);

        const final_segment: Wasm.OutputSegment = &wasm_bin.data.entries.items(.value)[final_segment_index];
        final_segment.alignment = std.math.max(final_segment.alignment, atom.alignment);
        final_segment.size = std.mem.alignForwardGeneric(
            u32,
            std.mem.alignForwardGeneric(u32, final_segment.size, atom.alignment) + atom.size,
            final_segment.alignment,
        );

        if (wasm_bin.atoms.getPtr(final_segment_index)) |last| {
            last.*.next = atom;
            atom.prev = last.*;
            last.* = atom;
        } else {
            try wasm_bin.atoms.putNoClobber(gpa, final_segment_index, atom);
        }
    }
}

/// Compares 2 symbols and returns true when the lhs symbol
/// has a higher seniority than rhs.
fn sort(object: Object, lhs: u32, rhs: u32) bool {
    const lhs_sym = object.symtable[lhs];
    const rhs_sym = object.symtable[rhs];

    const lhs_binding = lhs_sym.flags & @enumToInt(Symbol.Flag.WASM_SYM_BINDING_MASK);
    const rhs_binding = rhs_sym.flags & @enumToInt(Symbol.Flag.WASM_SYM_BINDING_MASK);

    if (lhs_binding == rhs_binding) return false;
    if (lhs_sym.isGlobal()) return true;
    if (lhs_sym.isWeak() and rhs_sym.isLocal()) return true;
    return false;
}

/// Verifies if a given value is in between a minimum -and maximum value.
/// The maxmimum value is calculated using the length, both start and end are inclusive.
inline fn isInbetween(min: u32, length: u32, value: u32) bool {
    return value >= min and value <= min + length;
}
