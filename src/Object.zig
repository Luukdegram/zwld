//! Object represents a wasm object file. When initializing a new
//! `Object`, it will parse the contents of a given file handler, and verify
//! the data on correctness. The result can then be used by the linker.
const Object = @This();

const std = @import("std");
const spec = @import("spec.zig");
const Allocator = std.mem.Allocator;
const leb = std.leb;
const meta = std.meta;
const log = std.log.scoped(.zwld);

/// Generic over type `T` that represents a section.
/// While a section contains its own data structure, each section
/// is essentially a sequence of that section in a wasm binary, meaning
/// they all contain a slice of `T`, and a start -and end position within the binary.
pub fn SectionData(comptime T: type) type {
    return struct {
        const Self = @This();
        data: []const T = &.{},
        start: usize = 0,
        end: usize = 0,
        id: usize = 0,

        /// Formats the `SectionData` for debug purposes
        pub fn format(self: Self, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
            _ = options;
            _ = fmt;
            const type_name = comptime blk: {
                var name: [@typeName(T).len]u8 = undefined;
                std.mem.copy(u8, &name, @typeName(T));
                name[0] = std.ascii.toUpper(name[0]);
                break :blk name;
            };
            try writer.print("{s: >8} start=0x{x:0>8} end=0x{x:0>8} (size=0x{x:0>8}) count: {d}", .{
                type_name,
                self.start,
                self.end,
                self.end - self.start,
                self.data.len,
            });
        }

        /// Returns true when the section is empty (read: non-existant)
        pub fn isEmpty(self: Self) bool {
            return self.data.len == 0;
        }

        /// From a given index, attempts to retrieve the value within the `data` slice
        /// at that index. When `data` is empty, or the given index exceeds its bounds,
        /// returns `null`.
        pub fn atIndex(self: Self, idx: usize) ?T {
            if (idx >= self.data.len - 1) return null;
            return self.data[idx];
        }
    };
}

/// Wasm spec version used for this `Object`
version: u32,
/// The entire object file is read and parsed in a single pass.
/// For this reason it's a lot simpler to use an arena and store the entire
/// state after parsing. This also allows to free all memory at once.
arena: std.heap.ArenaAllocator.State,
/// The file descriptor that represents the wasm object file.
file: std.fs.File,
/// Represents all custom sections
custom: []const spec.sections.Custom = &.{},
/// Contains all types (currently only function types)
types: SectionData(spec.sections.Type) = .{},
/// Contains all host environment imports for this object
imports: SectionData(spec.sections.Import) = .{},
/// A list of all functions (both used and unused)
functions: SectionData(spec.sections.Func) = .{},
/// A list of tables, mapping id's
tables: SectionData(spec.sections.Table) = .{},
/// All memories that wasm object contains.
/// This is always at most 1 in the current spec.
memories: SectionData(spec.sections.Memory) = .{},
/// A list of globals
globals: SectionData(spec.sections.Global) = .{},
/// All functions, globals, etc that are to be exported to
/// the host environment
exports: SectionData(spec.sections.Export) = .{},
/// A list of elements
elements: SectionData(spec.sections.Element) = .{},
/// A list of code spec.sections, where each code section
/// belongs to a function definition.
code: SectionData(spec.sections.Code) = .{},
/// A list of data spec.sections, referenced by a memory section.
/// In the current version of the wasm spec, this is at most 1.
data: SectionData(spec.sections.Data) = .{},
/// Represents the function ID that must be called on startup.
/// This is `null` by default as runtimes may determine the startup
/// function themselves. This is essentially 'legacy'.
start: ?spec.indexes.Func = null,
/// A slice of features that tell the linker what features are mandatory,
/// used (or therefore missing) and must generate an error when another
/// object uses features that are not supported by the other.
features: []const spec.Feature = &.{},
/// Contains meta data, required for the linker to ensure the correct symbols
/// are exported. This should never be `null` after parsing.
link_data: ?spec.LinkMetaData = null,
/// A table that maps the relocations we must perform where the key represents
/// the section that the list of relocations applies to.
relocations: std.AutoArrayHashMapUnmanaged(u32, []const spec.Relocation) = .{},

/// Initializes a new `Object` from a wasm object file.
pub fn init(gpa: *Allocator, file: std.fs.File) !Object {
    var object: Object = undefined;
    object.file = file;

    var arena = std.heap.ArenaAllocator.init(gpa);
    errdefer arena.deinit();

    try object.parse(&arena.allocator, file.reader());
    object.arena = arena.state;

    return object;
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
};

fn parse(self: *Object, gpa: *Allocator, reader: anytype) Parser(@TypeOf(reader)).Error!void {
    var parser = Parser(@TypeOf(reader)).init(self, reader);
    return parser.parseObject(gpa);
}

const LebError = error{Overflow};

fn Parser(comptime ReaderType: type) type {
    return struct {
        const Self = @This();
        const Error = ReaderType.Error || ParseError || LebError;

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
            if (!std.mem.eql(u8, &magic_bytes, &std.wasm.magic)) return error.InvalidMagicByte;
        }

        fn parseObject(self: *Self, gpa: *Allocator) Error!void {
            try self.verifyMagicBytes();
            const version = try self.reader.reader().readIntLittle(u32);

            self.object.version = version;

            // custom sections do not provide a count, as they are each their very own
            // section that simply share the same section ID. For this reason we use
            // an arraylist so we can append them individually.
            var custom_sections = std.ArrayList(spec.sections.Custom).init(gpa);

            while (self.reader.reader().readByte()) |byte| {
                const len = try readLeb(u32, self.reader.reader());
                var reader = std.io.limitedReader(self.reader.reader(), len).reader();

                switch (@intToEnum(spec.Section, byte)) {
                    .custom => {
                        const start = self.reader.bytes_read;
                        const custom = try custom_sections.addOne();
                        const name_len = try readLeb(u32, reader);
                        const name = try gpa.alloc(u8, name_len);
                        try reader.readNoEof(name);

                        const data: ?[]const u8 = blk: {
                            if (std.mem.eql(u8, name, "linking")) {
                                try self.parseMetadata(gpa, reader.context.bytes_left);
                                break :blk null;
                            } else if (std.mem.startsWith(u8, name, "reloc")) {
                                try self.parseRelocations(gpa);
                                break :blk null;
                            } else if (std.mem.eql(u8, name, "target_features")) {
                                try self.parseFeatures(gpa);
                                break :blk null;
                            }

                            const data = try gpa.alloc(u8, reader.context.bytes_left);
                            try reader.readNoEof(data);
                            break :blk data;
                        };

                        custom.* = .{ .name = name, .data = data, .start = start, .end = self.reader.bytes_read };
                    },
                    .type => {
                        self.object.types.start = self.reader.bytes_read;
                        for (try readVec(&self.object.types.data, reader, gpa)) |*type_val| {
                            if ((try reader.readByte()) != std.wasm.function_type) return error.ExpectedFuncType;

                            for (try readVec(&type_val.params, reader, gpa)) |*param| {
                                param.* = try readEnum(spec.ValueType, reader);
                            }

                            for (try readVec(&type_val.returns, reader, gpa)) |*result| {
                                result.* = try readEnum(spec.ValueType, reader);
                            }
                        }
                        self.object.types.end = self.reader.bytes_read;
                        try assertEnd(reader);
                    },
                    .import => {
                        self.object.imports.start = self.reader.bytes_read;
                        for (try readVec(&self.object.imports.data, reader, gpa)) |*import| {
                            const module_len = try readLeb(u32, reader);
                            const module_name = try gpa.alloc(u8, module_len);
                            import.module = module_name;
                            try reader.readNoEof(module_name);

                            const name_len = try readLeb(u32, reader);
                            const name = try gpa.alloc(u8, name_len);
                            import.name = name;
                            try reader.readNoEof(name);

                            const kind = try readEnum(spec.ExternalType, reader);
                            import.kind = switch (kind) {
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
                        }
                        self.object.imports.end = self.reader.bytes_read;
                        try assertEnd(reader);
                    },
                    .function => {
                        self.object.functions.start = self.reader.bytes_read;
                        for (try readVec(&self.object.functions.data, reader, gpa)) |*func| {
                            func.type_idx = try readEnum(spec.indexes.Type, reader);
                        }
                        self.object.functions.end = self.reader.bytes_read;
                        try assertEnd(reader);
                    },
                    .table => {
                        self.object.tables.start = self.reader.bytes_read;
                        for (try readVec(&self.object.tables.data, reader, gpa)) |*table| {
                            table.* = .{
                                .reftype = try readEnum(spec.RefType, reader),
                                .limits = try readLimits(reader),
                            };
                        }
                        self.object.tables.end = self.reader.bytes_read;
                        try assertEnd(reader);
                    },
                    .memory => {
                        self.object.memories.start = self.reader.bytes_read;
                        for (try readVec(&self.object.memories.data, reader, gpa)) |*memory| {
                            memory.* = .{ .limits = try readLimits(reader) };
                        }
                        self.object.memories.end = self.reader.bytes_read;
                        try assertEnd(reader);
                    },
                    .global => {
                        self.object.globals.start = self.reader.bytes_read;
                        for (try readVec(&self.object.globals.data, reader, gpa)) |*global| {
                            global.* = .{
                                .valtype = try readEnum(spec.ValueType, reader),
                                .mutable = (try reader.readByte()) == 0x01,
                                .init = try readInit(reader),
                            };
                        }
                        self.object.globals.end = self.reader.bytes_read;
                        try assertEnd(reader);
                    },
                    .@"export" => {
                        self.object.exports.start = self.reader.bytes_read;
                        for (try readVec(&self.object.exports.data, reader, gpa)) |*exp| {
                            const name_len = try readLeb(u32, reader);
                            const name = try gpa.alloc(u8, name_len);
                            try reader.readNoEof(name);
                            exp.* = .{
                                .name = name,
                                .kind = try readEnum(spec.ExternalType, reader),
                                .index = try readLeb(u32, reader),
                            };
                        }
                        self.object.exports.end = self.reader.bytes_read;
                        try assertEnd(reader);
                    },
                    .start => {
                        self.object.start = try readEnum(spec.indexes.Func, reader);
                        try assertEnd(reader);
                    },
                    .element => {
                        self.object.elements.start = self.reader.bytes_read;
                        for (try readVec(&self.object.elements.data, reader, gpa)) |*elem| {
                            elem.table_idx = try readEnum(spec.indexes.Table, reader);
                            elem.offset = try readInit(reader);

                            for (try readVec(&elem.func_idxs, reader, gpa)) |*idx| {
                                idx.* = try readEnum(spec.indexes.Func, reader);
                            }
                        }
                        self.object.elements.end = self.reader.bytes_read;
                        try assertEnd(reader);
                    },
                    .code => {
                        self.object.code.start = self.reader.bytes_read;
                        for (try readVec(&self.object.code.data, reader, gpa)) |*code| {
                            const body_len = try readLeb(u32, reader);

                            var code_reader = std.io.limitedReader(reader, body_len).reader();

                            // first parse the local declarations
                            {
                                const locals_len = try readLeb(u32, code_reader);
                                const locals = try gpa.alloc(spec.sections.Code.Local, locals_len);
                                for (locals) |*local| {
                                    local.* = .{
                                        .count = try readLeb(u32, code_reader),
                                        .valtype = try readEnum(spec.ValueType, code_reader),
                                    };
                                }

                                code.locals = locals;
                            }

                            {
                                var instructions = std.ArrayList(spec.Instruction).init(gpa);
                                defer instructions.deinit();

                                while (readEnum(std.wasm.Opcode, code_reader)) |opcode| {
                                    const instr = try buildInstruction(opcode, gpa, code_reader);
                                    try instructions.append(instr);
                                } else |err| switch (err) {
                                    error.EndOfStream => {
                                        const maybe_end = instructions.popOrNull() orelse return error.MissingEndForBody;
                                        if (maybe_end.opcode != .end) return error.MissingEndForBody;
                                    },
                                    else => |e| return e,
                                }

                                code.body = instructions.toOwnedSlice();
                            }
                            try assertEnd(code_reader);
                        }
                        self.object.code.end = self.reader.bytes_read;
                        try assertEnd(reader);
                    },
                    .data => {
                        self.object.data.start = self.reader.bytes_read;
                        for (try readVec(&self.object.data.data, reader, gpa)) |*data| {
                            data.index = try readEnum(spec.indexes.Mem, reader);
                            data.offset = try readInit(reader);

                            const init_len = try readLeb(u32, reader);
                            const init_data = try gpa.alloc(u8, init_len);
                            data.data = init_data;
                            try reader.readNoEof(init_data);
                        }
                        self.object.data.end = self.reader.bytes_read;
                        try assertEnd(reader);
                    },
                    .module => @panic("TODO: Implement 'module' section"),
                    .instance => @panic("TODO: Implement 'instance' section"),
                    .alias => @panic("TODO: Implement 'alias' section"),
                    _ => |id| std.log.scoped(.wasmparser).debug("Found unimplemented section with id '{d}'", .{id}),
                }
            } else |err| switch (err) {
                error.EndOfStream => {},
                else => |e| return e,
            }
            self.object.custom = custom_sections.toOwnedSlice();
        }

        /// Based on the "features" custom section, parses it into a list of
        /// features that tell the linker what features were enabled and may be mandatory
        /// to be able to link.
        /// Logs an info message when an undefined feature is detected.
        fn parseFeatures(self: *Self, gpa: *Allocator) !void {
            for (try readVec(&self.object.features, self.reader, gpa)) |*feature| {
                const prefix = try leb.readULEB128(u8, self.reader);
                const name_len = try leb.readULEB128(u32, self.reader);
                const name = try gpa.alloc(u8, name_len);
                try self.reader.readNoEof(name);

                feature.* = .{
                    .prefix = prefix,
                    .name = name,
                };

                if (!spec.known_features.has(name)) {
                    std.log.info("Detected unknown feature: {s}", .{name});
                }
            }
        }

        /// Parses a "reloc" custom section into a list of relocations.
        /// The relocations are mapped into `Object` where the key is the section
        /// they apply to.
        fn parseRelocations(self: *Self, gpa: *Allocator) !void {
            const section = try leb.readULEB128(u32, self.reader);
            const count = try leb.readULEB128(u32, self.reader);
            const relocations = try gpa.alloc(spec.Relocation, count);

            for (relocations) |*relocation| {
                const rel_type = try leb.readULEB128(u8, self.reader);
                const rel_type_enum = @intToEnum(spec.Relocation.Type, rel_type);
                relocation.* = .{
                    .relocation_type = rel_type_enum,
                    .offset = try leb.readULEB128(u32, self.reader),
                    .index = try leb.readULEB128(u32, self.reader),
                    .addend = if (spec.Relocation.addendIsPresent(rel_type_enum)) try leb.readULEB128(u32, self.reader) else null,
                };
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
            std.log.info("Link meta data version: {d}", .{version});
            if (version != 2) return error.UnsupportedVersion;

            var subsections = std.ArrayList(spec.Subsection).init(gpa);

            while (limited.bytes_left > 0) {
                const subsection = try subsections.addOne();
                subsection.* = try self.parseSubsection(gpa, limited_reader);
            }
        }

        /// Parses a `spec.Subsection`.
        /// The `reader` param for this is to provide a `LimitedReader`, which allows
        /// us to only read until a max length.
        ///
        /// `self` is used to provide access to other sections that may be needed,
        /// such as access to the `import` section to find the name of a symbol.
        fn parseSubsection(self: Self, gpa: *Allocator, reader: anytype) !spec.Subsection {
            const sub_type = try leb.readULEB128(u8, reader);
            log.info("Found subsection: {s}", .{@tagName(@intToEnum(spec.Subsection.Type, sub_type))});
            const payload_len = try leb.readULEB128(u32, reader);
            if (payload_len == 0) return .{ .empty = {} };
            var limited = std.io.limitedReader(reader, payload_len);
            const limited_reader = limited.reader();

            // every subsection contains a 'count' field
            const count = try leb.readULEB128(u32, limited_reader);

            switch (@intToEnum(spec.Subsection.Type, sub_type)) {
                .WASM_SEGMENT_INFO => {
                    const segments = try gpa.alloc(spec.Segment, count);
                    for (segments) |*segment| {
                        segment.* = try spec.Segment.fromReader(gpa, limited_reader);
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
                    return .{ .segment_info = segments };
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

                    return .{ .init_funcs = funcs };
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

                    return .{ .comdat_info = comdats };
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

                    return .{ .symbol_table = symbols };
                },
            }
        }

        /// Parses the symbol information based on its kind,
        /// requires access to `Object` to find the name of a symbol when it's
        /// an import and flag `WASM_SYM_EXPLICIT_NAME` is not set.
        fn parseSymbol(self: Self, gpa: *Allocator, reader: anytype) !spec.SymInfo {
            var symbol: spec.SymInfo = undefined;

            symbol.kind = @intToEnum(spec.SymInfo.Type, try leb.readULEB128(u8, reader));
            symbol.flags = try leb.readULEB128(u32, reader);

            switch (symbol.kind) {
                .SYMTAB_DATA => {
                    const name_len = try leb.readULEB128(u32, reader);
                    const name = try gpa.alloc(u8, name_len);
                    try reader.readNoEof(name);
                    symbol.name = name;
                    symbol.index = try leb.readULEB128(u32, reader);
                    symbol.offset = try leb.readULEB128(u32, reader);
                    symbol.size = try leb.readULEB128(u32, reader);
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
                    } else if (is_import) {
                        // symbol is an import and flag for explicit name is not set
                        self.object.imports.data[symbol.index];
                        const import = self.object.imports.atIndex(symbol.index) orelse {
                            log.info("Import at index {d} does not exist for symbol", .{symbol.index});
                            return error.InvalidIndex;
                        };
                        symbol.name = try gpa.dupe(u8, import.name);
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

fn buildInstruction(opcode: std.wasm.Opcode, gpa: *Allocator, reader: anytype) !spec.Instruction {
    var instr: spec.Instruction = .{
        .opcode = opcode,
        .value = undefined,
    };

    instr.value = switch (opcode) {
        .block,
        .loop,
        .@"if",
        => .{ .blocktype = try readEnum(spec.BlockType, reader) },
        .br,
        .br_if,
        .call,
        // ref.func 'x'
        @intToEnum(std.wasm.Opcode, 0xD2),
        .local_get,
        .local_set,
        .local_tee,
        .global_get,
        .global_set,
        spec.table_get,
        spec.table_set,
        .memory_size,
        .memory_grow,
        => .{ .u32 = try readLeb(u32, reader) },
        .call_indirect,
        .i32_load,
        .i64_load,
        .f32_load,
        .f64_load,
        .i32_load8_s,
        .i32_load8_u,
        .i32_load16_s,
        .i32_load16_u,
        .i64_load8_s,
        .i64_load8_u,
        .i64_load16_s,
        .i64_load16_u,
        .i64_load32_s,
        .i64_load32_u,
        .i32_store,
        .i64_store,
        .f32_store,
        .f64_store,
        .i32_store8,
        .i32_store16,
        .i64_store8,
        .i64_store16,
        .i64_store32,
        => .{ .multi = .{
            .x = try readLeb(u32, reader),
            .y = try readLeb(u32, reader),
        } },
        .br_table => blk: {
            const len = try readLeb(u32, reader);
            const list = try gpa.alloc(u32, len);

            for (list) |*item| {
                item.* = try readLeb(u32, reader);
            }
            break :blk .{ .list = .{ .data = list.ptr, .len = len } };
        },
        // ref.null 't'
        @intToEnum(std.wasm.Opcode, 0xD0) => .{ .reftype = try readEnum(spec.RefType, reader) },
        // select 'vec(t)'
        @intToEnum(std.wasm.Opcode, 0x1C) => blk: {
            const len = try readLeb(u32, reader);
            const list = try gpa.alloc(spec.ValueType, len);
            errdefer gpa.free(list);

            for (list) |*item| {
                item.* = try readEnum(spec.ValueType, reader);
            }
            break :blk .{ .multi_valtype = .{ .data = list.ptr, .len = len } };
        },
        spec.need_secondary => @as(spec.Instruction.InstrValue, blk: {
            const secondary = try readEnum(spec.SecondaryOpcode, reader);
            instr.secondary = secondary;
            switch (secondary) {
                .i32_trunc_sat_f32_s,
                .i32_trunc_sat_f32_u,
                .i32_trunc_sat_f64_s,
                .i32_trunc_sat_f64_u,
                .i64_trunc_sat_f32_s,
                .i64_trunc_sat_f32_u,
                .i64_trunc_sat_f64_s,
                .i64_trunc_sat_f64_u,
                => break :blk .{ .none = {} },
                .table_init,
                .table_copy,
                .memory_init,
                .data_drop,
                .memory_copy,
                => break :blk .{ .multi = .{
                    .x = try readLeb(u32, reader),
                    .y = try readLeb(u32, reader),
                } },
                else => break :blk .{ .u32 = try readLeb(u32, reader) },
            }
        }),
        .i32_const => .{ .i32 = try readLeb(i32, reader) },
        .i64_const => .{ .i64 = try readLeb(i64, reader) },
        .f32_const => .{ .f32 = @bitCast(f32, try readLeb(u32, reader)) },
        .f64_const => .{ .f64 = @bitCast(f64, try readLeb(u64, reader)) },
        else => .{ .none = {} },
    };

    return instr;
}
