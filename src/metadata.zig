const std = @import("std");
const wasm = @import("wasmparser").wasm;
const leb = std.leb;
const Allocator = std.mem.Allocator;
const log = std.log.scoped(.zwld);

pub const Relocations = struct {
    /// Index of the target section
    section: u32,
    /// Sequence of relocation entries
    entries: []const Relocation,

    /// From a given `reader` will parse the data into a sequence of relocations.
    /// Memory is owned by the caller.
    pub fn fromReader(gpa: *Allocator, reader: anytype) @TypeOf(reader).Error!Relocations {
        const section = try leb.readULEB128(u32, reader);
        const count = try leb.readULEB128(u32, reader);

        var entries = try std.ArrayList(Relocation).initCapacity(gpa, count);
        errdefer entries.deinit();

        var i: usize = 0;
        while (i < count) : (i += 1) {
            const entry = entries.addOneAssumeCapacity();
            entry.* = try Relocation.fromReader(reader);
        }

        return Relocations{
            .section = section,
            .entries = entries.toOwnedSlice(),
        };
    }

    /// Frees the memory allocated for `entries` and sets itself to `undefined`.
    /// Any usage after calling `deinit` is illegal behaviour.
    pub fn deinit(self: *Relocations, gpa: *Allocator) void {
        gpa.free(self.entries);
        self.* = undefined;
    }
};

pub const Relocation = struct {
    /// Represents the type of the `Relocation`
    relocation_type: Type,
    /// Offset of the value to rewrite relative to the relevant section's contents.
    /// When `offset` is zero, its position is immediately after the id and size of the section.
    offset: u32,
    /// The index of the symbol used.
    /// When the type is `R_WASM_TYPE_INDEX_LEB`, it represents the index of the type.
    index: u32,
    /// Addend to add to the address.
    /// This field is only non-null for `R_WASM_MEMORY_ADDR_*`, `R_WASM_FUNCTION_OFFSET_I32` and `R_WASM_SECTION_OFFSET_I32`.
    addend: ?u32,

    /// All possible relocation types currently existing.
    /// This enum is exhaustive as the spec is WIP and new types
    /// can be added but we do not want to have this result in compile errors.
    pub const Type = enum(u8) {
        R_WASM_FUNCTION_INDEX_LEB = 0,
        R_WASM_TABLE_INDEX_SLEB = 1,
        R_WASM_TABLE_INDEX_I32 = 2,
        R_WASM_MEMORY_ADDR_LEB = 3,
        R_WASM_MEMORY_ADDR_SLEB = 4,
        R_WASM_MEMORY_ADDR_I32 = 5,
        R_WASM_TYPE_INDEX_LEB = 6,
        R_WASM_GLOBAL_INDEX_LEB = 7,
        R_WASM_FUNCTION_OFFSET_I32 = 8,
        R_WASM_SECTION_OFFSET_I32 = 9,
        R_WASM_EVENT_INDEX_LEB = 10,
        R_WASM_GLOBAL_INDEX_I32 = 13,
        R_WASM_MEMORY_ADDR_LEB64 = 14,
        R_WASM_MEMORY_ADDR_SLEB64 = 15,
        R_WASM_MEMORY_ADDR_I64 = 16,
        R_WASM_TABLE_INDEX_SLEB64 = 18,
        R_WASM_TABLE_INDEX_I64 = 19,
        R_WASM_TABLE_NUMBER_LEB = 20,
        _,
    };

    /// From a given `reader` will parse the data into a `Relocation`
    pub fn fromReader(reader: anytype) !Relocation {
        const rel_type = try reader.readByte(reader);
        const rel_type_enum = @intToEnum(Type, rel_type);
        return Relocation{
            .relocation_type = rel_type_enum,
            .offset = try leb.readULEB128(u32, reader),
            .index = try leb.readULEB128(u32, reader),
            .addend = if (addendIsPresent(rel_type_enum)) try leb.readULEB128(u32, reader) else null,
        };
    }

    /// Returns true for relocation types where the `addend` field is present.
    fn addendIsPresent(reloc_type: Type) bool {
        return switch (reloc_type) {
            .R_WASM_MEMORY_ADDR_LEB,
            .R_WASM_MEMORY_ADDR_SLEB,
            .R_WASM_MEMORY_ADDR_I32,
            .R_WASM_MEMORY_ADDR_LEB64,
            .R_WASM_MEMORY_ADDR_SLEB64,
            .R_WASM_MEMORY_ADDR_I64,
            .R_WASM_FUNCTION_OFFSET_I32,
            .R_WASM_SECTION_OFFSET_I32,
            => true,
            else => false,
        };
    }
};

pub const LinkMetaData = struct {
    /// The version of linking metadata contained in a section.
    /// The current version is 2. This means we can reject unexpected/unsupported versions.
    version: u32,
    /// A sequence of subsections
    subsections: []const Subsection,

    pub fn fromReader(gpa: *Allocator, reader: anytype, payload_size: usize) !LinkMetaData {
        var limited = std.io.limitedReader(reader, payload_size);
        const limited_reader = limited.reader();

        const version = try leb.readULEB128(u32, limited_reader);
        log.info("Link meta data version: {d}", .{version});
        if (version != 2) return error.UnexpectedVersion;

        var subsections = std.ArrayList(Subsection).init(gpa);

        while (limited.bytes_left > 0) {
            const subsection = try subsections.addOne();
            subsection.* = try Subsection.fromReader(gpa, limited_reader);
        }

        return LinkMetaData{
            .version = version,
            .subsections = subsections.toOwnedSlice(),
        };
    }

    pub fn deinit(self: *LinkMetaData, gpa: *Allocator) void {
        for (self.subsections) |subsection| {
            subsection.deinit(gpa);
        }
        gpa.free(self.subsections);
        self.* = undefined;
    }
};

pub const Subsection = union(enum) {
    segment_info: []const Segment,
    init_funcs: []const InitFunc,
    comdat_info: []const Comdat,
    symbol_table: []const SymInfo,
    empty: void,

    pub const Type = enum(u8) {
        WASM_SEGMENT_INFO = 5,
        WASM_INIT_FUNCS = 6,
        WASM_COMDAT_INFO = 7,
        WASM_SYMBOL_TABLE = 8,
    };

    /// Returns an `Subsection` union that sets the corresponding tag and fields
    /// based on the subsection's type that was found.
    pub fn fromReader(gpa: *Allocator, reader: anytype) !Subsection {
        const sub_type = try leb.readULEB128(u8, reader);
        log.info("Found subsection: {s}", .{@tagName(@intToEnum(Subsection.Type, sub_type))});
        const payload_len = try leb.readULEB128(u32, reader);
        if (payload_len == 0) return Subsection{ .empty = {} };
        var limited = std.io.limitedReader(reader, payload_len);
        const limited_reader = limited.reader();

        // every subsection contains a 'count' field
        const count = try leb.readULEB128(u32, limited_reader);

        switch (@intToEnum(Type, sub_type)) {
            .WASM_SEGMENT_INFO => {
                var segments = try std.ArrayList(Segment).initCapacity(gpa, count);
                errdefer segments.deinit();

                var i: usize = 0;
                while (i < count) : (i += 1) {
                    const segment = segments.addOneAssumeCapacity();
                    segment.* = try Segment.fromReader(gpa, limited_reader);
                    log.info("Found segment: {s} align({d}) flags({b})", .{
                        segment.name,
                        segment.alignment,
                        segment.flags,
                    });
                }
                return Subsection{ .segment_info = segments.toOwnedSlice() };
            },
            .WASM_INIT_FUNCS => {
                var funcs = try std.ArrayList(InitFunc).initCapacity(gpa, count);
                errdefer funcs.deinit();

                var i: usize = 0;
                while (i < count) : (i += 1) {
                    const func = funcs.addOneAssumeCapacity();
                    func.* = .{
                        .priority = try leb.readULEB128(u32, limited_reader),
                        .symbol_index = try leb.readULEB128(u32, limited_reader),
                    };
                    log.info("Found function - prio: {d}, index: {d}", .{ func.priority, func.symbol_index });
                }

                return Subsection{ .init_funcs = funcs.toOwnedSlice() };
            },
            .WASM_COMDAT_INFO => {
                var comdats = try std.ArrayList(Comdat).initCapacity(gpa, count);
                errdefer comdats.deinit();

                var i: usize = 0;
                while (i < count) : (i += 1) {
                    const comdat = comdats.addOneAssumeCapacity();
                    comdat.* = try Comdat.fromReader(gpa, limited_reader);
                }
                return Subsection{ .comdat_info = comdats.toOwnedSlice() };
            },
            .WASM_SYMBOL_TABLE => {
                var symbols = try std.ArrayList(SymInfo).initCapacity(gpa, count);
                errdefer symbols.deinit();

                var i: usize = 0;
                while (i < count) : (i += 1) {
                    const symbol = symbols.addOneAssumeCapacity();
                    symbol.* = try SymInfo.fromReader(gpa, limited_reader);
                    log.info("Found symbol: type({s}) name({s}) flags(0x{x})", .{
                        @tagName(symbol.kind),
                        symbol.name,
                        symbol.flags,
                    });
                }

                return Subsection{ .symbol_table = symbols.toOwnedSlice() };
            },
        }
    }

    pub fn deinit(self: Subsection, gpa: *Allocator) void {
        switch (self) {
            .segment_info => |segment_info| for (segment_info) |segment| {
                gpa.free(segment.name);
            } else gpa.free(segment_info),
            .init_funcs => |funcs| gpa.free(funcs),
            .comdat_info => |comdats| for (comdats) |comdat| {
                comdat.deinit(gpa);
            } else gpa.free(comdats),
            .symbol_table => |table| for (table) |symbol| {
                if (symbol.name) |name| {
                    gpa.free(name);
                }
            } else gpa.free(table),
            .empty => {},
        }
    }
};

pub const Segment = struct {
    /// Segment's name, encoded as UTF-8 bytes.
    name: []const u8,
    /// The required alignment of the segment, encoded as a power of 2
    alignment: u32,
    /// Bitfield containing flags for a segment
    flags: u32,

    pub fn fromReader(gpa: *Allocator, reader: anytype) !Segment {
        const name_len = try leb.readULEB128(u32, reader);
        const name = try gpa.alloc(u8, name_len);
        errdefer gpa.free(name);
        try reader.readNoEof(name);

        return Segment{
            .name = name,
            .alignment = try leb.readULEB128(u32, reader),
            .flags = try leb.readULEB128(u32, reader),
        };
    }
};

pub const InitFunc = struct {
    /// Priority of the init function
    priority: u32,
    /// The symbol index of init function (not the function index).
    symbol_index: u32,
};

pub const Comdat = struct {
    name: []const u8,
    /// Must be zero, no flags are currently defined by the tool-convention.
    flags: u32,
    symbols: []const ComdatSym,

    pub fn fromReader(gpa: *Allocator, reader: anytype) !Comdat {
        const name_len = try leb.readULEB128(u32, reader);
        const name = try gpa.alloc(u8, name_len);
        errdefer gpa.free(name);

        const flags = try leb.readULEB128(u32, reader);
        if (flags != 0) {
            return error.UnexpectedValue;
        }

        const symbol_count = try leb.readULEB128(u32, reader);
        var symbols = try std.ArrayList(ComdatSym).initCapacity(gpa, symbol_count);
        errdefer symbols.deinit();

        var i: usize = 0;
        while (i < symbol_count) : (i += 1) {
            const symbol = symbols.addOneAssumeCapacity();
            symbol.* = .{
                .kind = @intToEnum(ComdatSym.Type, try leb.readULEB128(u8, reader)),
                .index = try leb.readULEB128(u32, reader),
            };
        }

        return Comdat{
            .name = name,
            .flags = flags,
            .symbols = symbols.toOwnedSlice(),
        };
    }

    pub fn deinit(self: Comdat, gpa: *Allocator) void {
        gpa.free(self.name);
        gpa.free(self.symbols);
    }
};

pub const SymInfo = struct {
    kind: Type,
    /// Bitfield containings flags for a symbol
    /// Can contain any of the flags defined in `SymbolFlag`
    flags: u32,
    /// The index of the Wasm object corresponding to the symbol.
    /// When `WASM_SYM_UNDEFINED` flag is set, this refers to an import.
    /// Can be `null` when it refers to a data symbol that is undefined.
    index: ?u32 = null,
    /// Symbol name, can be `null` when index refers to an import and
    /// `WASM_SYM_EXPLICIT_NAME` is not set.
    name: ?[]const u8 = null,
    /// Offset within the segment. Must be smaller than segment's size, and is only
    /// set when the symbol is defined.
    offset: ?u32 = null,
    /// Set when the symbol is defined, can be zero and must be smaller than segment's
    /// size where offset + size.
    size: ?u32 = null,

    pub fn hasFlag(self: SymInfo, flag: SymbolFlag) bool {
        return self.flags & @enumToInt(flag) != 0;
    }

    pub fn setFlag(self: *SymInfo, flag: SymbolFlag) void {
        self.flags |= @enumToInt(flag);
    }

    pub const Type = enum(u8) {
        SYMTAB_FUNCTION = 0,
        SYMTAB_DATA = 1,
        SYMTAB_GLOBAL = 2,
        SYMTAB_SECTION = 3,
        SYMTAB_EVENT = 4,
        SYMTAB_TABLE = 5,
    };

    pub fn fromReader(gpa: *Allocator, reader: anytype) !SymInfo {
        var symbol: SymInfo = undefined;

        symbol.kind = @intToEnum(Type, try leb.readULEB128(u8, reader));
        symbol.flags = try leb.readULEB128(u32, reader);

        switch (symbol.kind) {
            .SYMTAB_DATA => {
                const name_len = try leb.readULEB128(u32, reader);
                const name = try gpa.alloc(u8, name_len);
                errdefer gpa.free(name);
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
                    errdefer gpa.free(name);
                    try reader.readNoEof(name);
                    symbol.name = name;
                }
            },
        }
        return symbol;
    }

    /// Formats the symbol into human-readable text
    pub fn format(self: SymInfo, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = fmt;
        _ = options;

        const kind_fmt: u8 = switch (self.kind) {
            .SYMTAB_FUNCTION => 'F',
            .SYMTAB_DATA => 'D',
            .SYMTAB_GLOBAL => 'G',
            .SYMTAB_SECTION => 'S',
            .SYMTAB_EVENT => 'E',
            .SYMTAB_TABLE => 'T',
        };
        const visible: []const u8 = if (self.hasFlag(.WASM_SYM_VISIBILITY_HIDDEN)) "no" else "yes";
        const binding: []const u8 = if (self.hasFlag(.WASM_SYM_BINDING_LOCAL)) "local" else "global";

        try writer.print(
            "{c} binding={s} visible={s} id={d} name={s}",
            .{ kind_fmt, binding, visible, self.index, self.name },
        );
    }
};

pub const SymbolFlag = enum(u32) {
    /// Indicates a weak symbol.
    /// When linking multiple modules defining the same symbol, all weak definitions are discarded
    /// in favourite of the strong definition. When no strong definition exists, all weak but one definiton is discarded.
    /// If multiple definitions remain, we get an error: symbol collision.
    WASM_SYM_BINDING_WEAK = 1,
    /// Indicates a local, non-exported, non-module-linked symbol.
    /// The names of local symbols are not required to be unique, unlike non-local symbols.
    WASM_SYM_BINDING_LOCAL = 2,
    /// Indicates a hidden symbol. Hidden symbols will not be exported to the link result, but may
    /// link to other modules.
    WASM_SYM_VISIBILITY_HIDDEN = 4,
    /// Indicates an undefined symbol. For non-data symbols, this must match whether the symbol is
    /// an import or is defined. For data symbols however, determines whether a segment is specified.
    WASM_SYM_UNDEFINED = 0x10,
    /// Indicates a symbol of which its intention is to be exported from the wasm module to the host environment.
    /// This differs from the visibility flag as this flag affects the static linker.
    WASM_SYM_EXPORTED = 0x20,
    /// Indicates the symbol uses an explicit symbol name, rather than reusing the name from a wasm import.
    /// Allows remapping imports from foreign WASM modules into local symbols with a different name.
    WASM_SYM_EXPLICIT_NAME = 0x40,
    /// Indicates the symbol is to be included in the linker output, regardless of whether it is used or has any references to it.
    WASM_SYM_NO_STRIP = 0x80,
};

pub const ComdatSym = struct {
    kind: Type,
    /// Index of the data segment/function/global/event/table within a WASM module.
    /// The object must not be an import.
    index: u32,

    pub const Type = enum(u8) {
        WASM_COMDAT_DATA = 0,
        WASM_COMDAT_FUNCTION = 1,
        WASM_COMDAT_GLOBAL = 2,
        WASM_COMDAT_EVENT = 3,
        WASM_COMDAT_TABLE = 4,
        WASM_COMDAT_SECTION = 5,
    };
};

pub const Features = struct {
    list: []const Features,

    pub fn fromReader(gpa: *Allocator, reader: anytype) !Features {
        const count = try leb.readULEB128(u32, reader);

        var entries = std.ArrayList(Feature).initCapacity(gpa, count);
        errdefer for (entries.items) |feature| {
            gpa.free(feature.name);
        } else entries.deinit();

        var i: usize = 0;
        while (i < count) : (i += 1) {
            const prefix = try reader.readByte();
            const name_len = try leb.readULEB128(u32, reader);
            const name = try gpa.alloc(u8, name_len); // cleaned up above errdefer on error
            const entry = entries.addOneAssumeCapacity();
            entry.* = .{
                .prefix = prefix,
                .name = name,
            };
            try reader.readNoEof(name);

            if (!known_features.has(name)) {
                std.log.info("Detected unknown feature: {s}", .{name});
            }
        }

        return .{ .list = entries.toOwnedSlice() };
    }
};

pub const Feature = struct {
    /// Provides information about the usage of the feature.
    /// - '0x2b' (+): Object uses this feature, and the link fails if feature is not in the allowed set.
    /// - '0x2d' (-): Object does not use this feature, and the link fails if this feature is in the allowed set.
    /// - '0x3d' (=): Object uses this feature, and the link fails if this feature is not in the allowed set,
    /// or if any object does not use this feature.
    prefix: u8,
    /// name of the feature, must be unique in the sequence of features.
    name: []const u8,
};

pub const known_features = std.ComptimeStringMap(void, .{
    .{"atomics"},
    .{"bulk-memory"},
    .{"exception-handling"},
    .{"multivalue"},
    .{"mutable-globals"},
    .{"nontrapping-fptoint"},
    .{"sign-ext"},
    .{"simd128"},
    .{"tail-call"},
});
