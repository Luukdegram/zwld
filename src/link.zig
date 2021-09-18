const std = @import("std");
const wasm = @import("wasmparser").wasm;
const leb = std.leb;
const Allocator = std.mem.Allocator;

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
    pub fn fromReader(reader: anytype) @TypeOf(reader).Error!Relocation {
        const rel_type = try leb.readULEB128(u8, reader);
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

    pub fn fromReader(gpa: *Allocator, reader: anytype) (@TypeOf(reader).Error || error{UnexpectedVersion})!LinkMetaData {
        const version = try leb.readULEB128(u32, reader);
        if (version != 2) return error.UnexpectedVersion;

        const count = try leb.readULEB128(u32, reader);
        var subsections = std.ArrayList(Subsection).initCapacity(gpa, count);
        errdefer subsections.deinit();

        var i: usize = 0;
        while (i < count) : (i += 1) {
            const subsection = subsections.addOneAssumeCapacity();
            subsection.* = try Subsection.fromReader(reader);
        }

        return LinkMetaData{
            .version = version,
            .subsections = subsections.toOwnedSlice(),
        };
    }

    pub fn deinit(self: *LinkMetaData, gpa: *Allocator) void {
        gpa.free(self.subsections);
        self.* = undefined;
    }
};

pub const Subsection = union(enum) {
    segment_info,
    init_funcs,
    comdat_info,
    symbol_table,

    pub const Type = enum(u8) {
        WASM_SEGMENT_INFO = 5,
        WASM_INIT_FUNCS = 6,
        WASM_COMDAT_INFO = 7,
        WASM_SYMBOL_TABLE = 8,
        _,
    };

    /// Returns an `Subsection` union that sets the corresponding tag and fields
    /// based on the subsection's type that was found.
    pub fn fromReader(reader: anytype) @TypeOf(reader)!Subsection {}
};

pub const Segment = struct {
    /// Segment's name, encoded as UTF-8 bytes.
    name: []const u8,
    /// The required alignment of the segment, encoded as a power of 2
    alignment: u32,
    /// Bitfield containing flags for a segment
    flags: u32,
};

pub const InitFunc = struct {
    /// Priority of the init function
    priority: u32,
    /// The symbol index of init function (not the function index).
    symbol_index: u32,
};
