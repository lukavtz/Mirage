const std = @import("std");
const testing = std.testing;

pub const SQLITE_MAGIC = "SQLite format 3\x00";

pub const PageType = enum(u8) {
    interior_index = 0x02,
    interior_table = 0x05,
    leaf_index = 0x0A,
    leaf_table = 0x0D,
};

pub const SqliteHeader = struct {
    magic: [16]u8,
    page_size: u16,
    write_version: u8,
    read_version: u8,
    reserved_space: u8,
    max_payload_pct: u8,
    min_payload_pct: u8,
    leaf_payload_pct: u8,
    file_change_counter: u32,
    page_count: u32,
    first_freelist_trunk: u32,
    total_freelist_pages: u32,
    schema_cookie: u32,
    schema_format: u32,
    default_pcache_size: u32,
    largest_b_tree_page: u32,
    text_encoding: u32,
    user_version: u32,
    incremental_vacuum: u32,
    version_valid_for: u32,
    sqlite_version: u32,
};

pub fn readHeader(data: []const u8) SqliteHeader {
    return SqliteHeader{
        .magic = data[0..16].*,
        .page_size = std.mem.readInt(u16, data[16..18], .big),
        .write_version = data[18],
        .read_version = data[19],
        .reserved_space = data[20],
        .max_payload_pct = data[21],
        .min_payload_pct = data[22],
        .leaf_payload_pct = data[23],
        .file_change_counter = std.mem.readInt(u32, data[24..28], .big),
        .page_count = std.mem.readInt(u32, data[28..32], .big),
        .first_freelist_trunk = std.mem.readInt(u32, data[32..36], .big),
        .total_freelist_pages = std.mem.readInt(u32, data[36..40], .big),
        .schema_cookie = std.mem.readInt(u32, data[40..44], .big),
        .schema_format = std.mem.readInt(u32, data[44..48], .big),
        .default_pcache_size = std.mem.readInt(u32, data[48..52], .big),
        .largest_b_tree_page = std.mem.readInt(u32, data[52..56], .big),
        .text_encoding = std.mem.readInt(u32, data[56..60], .big),
        .user_version = std.mem.readInt(u32, data[60..64], .big),
        .incremental_vacuum = std.mem.readInt(u32, data[64..68], .big),
        .version_valid_for = std.mem.readInt(u32, data[88..92], .big),
        .sqlite_version = std.mem.readInt(u32, data[96..100], .big),
    };
}

pub const CellPointer = packed struct(u16) {
    offset: u16,
};

pub const PageHeader = struct {
    page_type: PageType,
    first_freeblock: u16,
    cell_count: u16,
    cell_content_area: u16,
    fragmented_free_bytes: u8,
    // Для interior таблиц:
    right_most_pointer: u32,
};

pub const Varint = struct {
    value: u64,
    bytes_read: usize,
};

pub fn readVarint(data: []const u8) Varint {
    var value: u64 = 0;
    var i: usize = 0;
    while (i < 9 and i < data.len) {
        const byte = data[i];
        value = (value << 7) | @as(u64, byte & 0x7F);
        i += 1;
        if ((byte & 0x80) == 0) break;
    }
    return .{ .value = value, .bytes_read = i };
}

pub const SerialType = union(enum) {
    null: void,
    int8: u8,
    int16: i16,
    int24: i32,
    int32: i32,
    int48: i64,
    int64: i64,
    float64: f64,
    zero: void,
    one: void,
    blob: []const u8,
    text: []const u8,

    pub fn size(serial_type: u64) usize {
        if (serial_type == 0) return 0;
        if (serial_type == 1) return 1;
        if (serial_type == 2) return 2;
        if (serial_type == 3) return 3;
        if (serial_type == 4) return 4;
        if (serial_type == 5) return 6;
        if (serial_type == 6) return 8;
        if (serial_type == 7) return 8;
        if (serial_type == 8) return 0;
        if (serial_type == 9) return 0;
        if (serial_type == 10 or serial_type == 11) return 0;
        return @as(usize, @intCast((serial_type - 12) / 2));
    }

    pub fn isBlob(serial_type: u64) bool {
        return serial_type >= 12 and serial_type % 2 == 0;
    }

    pub fn isText(serial_type: u64) bool {
        return serial_type >= 13 and serial_type % 2 == 1;
    }
};

pub const Cell = struct {
    row_id: i64,
    payload: Record,
};

pub const Record = struct {
    values: []const Value,
};

pub const Value = union(enum) {
    null: void,
    int: i64,
    float: f64,
    text: []const u8,
    blob: []const u8,
};

pub const SqliteDb = struct {
    header: SqliteHeader,
    allocator: std.mem.Allocator,
    file_data: []const u8,

    pub fn open(allocator: std.mem.Allocator, data: []const u8) !SqliteDb {
        if (data.len < 100) return error.InvalidDatabase;
        if (!std.mem.eql(u8, data[0..16], SQLITE_MAGIC)) return error.NotSQLite;
        const header = readHeader(data);

        if (header.page_size < 512 or header.page_size > 65536) return error.InvalidPageSize;

        return SqliteDb{
            .header = header,
            .allocator = allocator,
            .file_data = data,
        };
    }

    pub fn deinit(self: *SqliteDb) void {
        _ = self;
    }

    pub fn getPage(self: *SqliteDb, page_num: u32) ![]const u8 {
        const page_size = self.header.page_size;
        if (page_num < 1) return error.PageOutOfBounds;
        const offset = @as(usize, @intCast(page_num - 1)) * page_size;
        if (offset + page_size > self.file_data.len) return error.PageOutOfBounds;
        return self.file_data[offset .. offset + page_size];
    }

    pub fn pageHeaderOffset(self: *SqliteDb, page_num: u32) usize {
        _ = self;
        return if (page_num == 1) 100 else 0;
    }

    pub fn readPageType(self: *SqliteDb, page_num: u32) !PageHeader {
        const page = try self.getPage(page_num);
        const hdr_off = self.pageHeaderOffset(page_num);
        const page_type = @as(PageType, @enumFromInt(page[hdr_off]));
        var ph = PageHeader{
            .page_type = page_type,
            .first_freeblock = std.mem.readInt(u16, page[hdr_off + 1 .. hdr_off + 3], .big),
            .cell_count = std.mem.readInt(u16, page[hdr_off + 3 .. hdr_off + 5], .big),
            .cell_content_area = std.mem.readInt(u16, page[hdr_off + 5 .. hdr_off + 7], .big),
            .fragmented_free_bytes = page[hdr_off + 7],
            .right_most_pointer = 0,
        };

        if (page_type == PageType.interior_table) {
            ph.right_most_pointer = std.mem.readInt(u32, page[hdr_off + 8 .. hdr_off + 12], .big);
        }

        return ph;
    }

    pub fn readCellPointers(self: *SqliteDb, page_num: u32, ph: PageHeader) ![]const u16 {
        const page = try self.getPage(page_num);
        const hdr_off = self.pageHeaderOffset(page_num);
        const ptr_offset = hdr_off + switch (ph.page_type) {
            .leaf_table, .leaf_index => 8,
            .interior_table, .interior_index => 12,
        };
        const count = @as(usize, ph.cell_count);
        const end_of_ptrs = ptr_offset + count * 2;
        if (end_of_ptrs > page.len) return error.CorruptPage;

        var ptrs = try self.allocator.alloc(u16, count);
        for (0..count) |i| {
            ptrs[i] = std.mem.readInt(u16, page[ptr_offset + i * 2 ..][0..2], .big);
        }
        return ptrs;
    }

    pub fn readCell(self: *SqliteDb, page_num: u32, cell_offset: u16) !Cell {
        const page = try self.getPage(page_num);
        const data = page[cell_offset..];
        var pos: usize = 0;

        const payload_len_v = readVarint(data);
        pos += payload_len_v.bytes_read;
        const payload_len = payload_len_v.value;

        const row_id_v = readVarint(data[pos..]);
        pos += row_id_v.bytes_read;
        const row_id = @as(i64, @intCast(row_id_v.value));

        const usable = self.header.page_size - self.header.reserved_space;
        var max_local: usize = usable - 35;
        if (payload_len <= max_local) {
            const record = try self.readRecord(data[pos..][0..@intCast(payload_len)]);
            return Cell{ .row_id = row_id, .payload = record };
        }
        max_local = ((usable - 12) * 255) / 256 - 23;
        if (max_local > payload_len) max_local = @intCast(payload_len);

        const local_portion = data[pos..][0..max_local];
        const overflow_page = std.mem.readInt(u32, data[pos + max_local ..][0..4], .big);

        var overflow_data = try self.allocator.alloc(u8, @intCast(payload_len));
        errdefer self.allocator.free(overflow_data);
        @memcpy(overflow_data[0..max_local], local_portion);

        var off: usize = max_local;
        var next_page = overflow_page;
        var page_iter: usize = 0;
        const max_overflow_pages: usize = (payload_len / (self.header.page_size - 4)) + 2;
        while (next_page != 0 and off < payload_len) : (page_iter += 1) {
            if (page_iter > max_overflow_pages) return error.CyclicOverflowChain;
            const op = try self.getPage(next_page);
            const remaining = payload_len - off;
            const chunk_size = @as(usize, @intCast(@min(@as(u64, remaining), self.header.page_size - 4)));
            const overflow_size = self.header.page_size - self.header.reserved_space;
            const copy_size = @min(chunk_size, overflow_size - 4);

            if (off + copy_size <= overflow_data.len) {
                @memcpy(overflow_data[off..][0..copy_size], op[4 .. 4 + copy_size]);
            }
            off += copy_size;
            next_page = std.mem.readInt(u32, op[0..4], .big);
        }

        const record = try self.readRecord(overflow_data);
        self.allocator.free(overflow_data);
        return Cell{ .row_id = row_id, .payload = record };
    }

    pub fn readRecord(self: *SqliteDb, payload: []const u8) !Record {
        // Read header size varint
        const header_size_v = readVarint(payload);
        const header_size = header_size_v.value;
        var pos = header_size_v.bytes_read;

        // Count serial types
        var type_pos = pos;
        var field_count: usize = 0;
        while (type_pos < header_size) {
            const st = readVarint(payload[type_pos..]);
            if (st.bytes_read == 0) break;
            type_pos += st.bytes_read;
            field_count += 1;
        }

        // Read all serial types
        const types = try self.allocator.alloc(u64, field_count);
        type_pos = pos;
        for (0..field_count) |i| {
            const st = readVarint(payload[type_pos..]);
            types[i] = st.value;
            type_pos += st.bytes_read;
        }
        pos = type_pos;

        // Read all values
        var values = try self.allocator.alloc(Value, field_count);
        for (0..field_count) |i| {
            const st = types[i];
            const val_size = SerialType.size(st);

            if (st == 0) {
                values[i] = Value{ .null = {} };
            } else if (st == 1) {
                values[i] = Value{ .int = payload[pos] };
                pos += 1;
            } else if (st == 2) {
                const v = std.mem.readInt(i16, payload[pos..][0..2], .big);
                values[i] = Value{ .int = v };
                pos += 2;
            } else if (st == 3) {
                const v = readInt24(payload[pos..]);
                values[i] = Value{ .int = v };
                pos += 3;
            } else if (st == 4) {
                const v = std.mem.readInt(i32, payload[pos..][0..4], .big);
                values[i] = Value{ .int = v };
                pos += 4;
            } else if (st == 5) {
                const v = std.mem.readInt(i48, payload[pos..][0..6], .big);
                values[i] = Value{ .int = v };
                pos += 6;
            } else if (st == 6) {
                const v = std.mem.readInt(i64, payload[pos..][0..8], .big);
                values[i] = Value{ .int = v };
                pos += 8;
            } else if (st == 7) {
                const as_u64 = std.mem.readInt(u64, payload[pos..][0..8], .big);
                values[i] = Value{ .float = @as(f64, @bitCast(as_u64)) };
                pos += 8;
            } else if (st == 8) {
                values[i] = Value{ .int = 0 };
            } else if (st == 9) {
                values[i] = Value{ .int = 1 };
            } else if (st >= 12) {
                const data_slice = payload[pos..][0..val_size];
                pos += val_size;
                if (SerialType.isText(st)) {
                    values[i] = Value{ .text = data_slice };
                } else {
                    values[i] = Value{ .blob = data_slice };
                }
            } else {
                values[i] = Value{ .null = {} };
            }
        }

        self.allocator.free(types);
        return Record{ .values = values };
    }
};

fn readInt24(data: []const u8) i32 {
    var buf: [4]u8 = undefined;
    buf[0] = 0;
    for (0..3) |i| {
        buf[1 + i] = data[i];
    }
    return std.mem.readInt(i32, &buf, .big);
}

fn readInt48(data: []const u8) i64 {
    var buf: [8]u8 = undefined;
    buf[0] = 0;
    buf[1] = 0;
    for (0..6) |i| {
        buf[2 + i] = data[i];
    }
    return std.mem.readInt(i64, &buf, .big);
}

pub fn findColumnIndex(columns: [][]const u8, comptime name: []const u8) ?usize {
    for (columns, 0..) |col, i| {
        if (std.mem.eql(u8, col, name)) return i;
    }
    return null;
}

pub fn parseColumnNames(create_sql: []const u8, allocator: std.mem.Allocator) ![][]const u8 {
    var paren_start: usize = 0;
    var paren_depth: usize = 0;
    var in_paren: bool = false;

    for (create_sql, 0..) |c, i| {
        if (c == '(') {
            if (!in_paren) {
                paren_start = i + 1;
                in_paren = true;
            }
            paren_depth += 1;
        } else if (c == ')') {
            paren_depth -= 1;
            if (in_paren and paren_depth == 0) {
                const cols_section = create_sql[paren_start..i];
                return extractColumnNames(cols_section, allocator);
            }
        }
    }
    return error.NoColumnsFound;
}

fn extractColumnNames(section: []const u8, allocator: std.mem.Allocator) ![][]const u8 {
    var names_buf: [64][]const u8 = undefined;
    var name_count: usize = 0;

    var i: usize = 0;
    var in_paren: usize = 0;

    while (i < section.len) {
        while (i < section.len and (section[i] == ' ' or section[i] == '\t' or section[i] == '\n' or section[i] == '\r')) {
            i += 1;
        }
        if (i >= section.len) break;
        if (section[i] == ',') {
            i += 1;
            continue;
        }
        if (section[i] == '(') {
            in_paren += 1;
            i += 1;
            continue;
        }
        if (section[i] == ')') {
            if (in_paren > 0) in_paren -= 1;
            i += 1;
            continue;
        }
        if (in_paren > 0) {
            i += 1;
            continue;
        }

        const col_start = i;
        while (i < section.len and section[i] != ' ' and section[i] != '\t' and section[i] != ',' and section[i] != '(' and section[i] != ')') {
            i += 1;
        }
        if (i > col_start) {
            if (name_count >= names_buf.len) return error.TooManyColumns;
            const col_name = try allocator.dupe(u8, section[col_start..i]);
            names_buf[name_count] = col_name;
            name_count += 1;
        }

        while (i < section.len and section[i] != ',') {
            if (section[i] == '(') {
                var depth: usize = 1;
                i += 1;
                while (i < section.len and depth > 0) {
                    if (section[i] == '(') depth += 1;
                    if (section[i] == ')') depth -= 1;
                    i += 1;
                }
            } else {
                i += 1;
            }
        }
    }

    const result = try allocator.alloc([]const u8, name_count);
    for (0..name_count) |j| {
        result[j] = names_buf[j];
    }
    return result;
}

pub fn getColumnNames(self: *SqliteDb, table_name: []const u8) ![][]const u8 {
    const create_stmt = self.getCreateStmt(table_name) orelse return error.TableNotFound;
    defer self.allocator.free(create_stmt);
    return parseColumnNames(create_stmt, self.allocator);
}

fn getCreateStmt(self: *SqliteDb, table_name: []const u8) ?[]u8 {
    const ph = self.readPageType(1) catch return null;
    if (ph.page_type != .leaf_table and ph.page_type != .interior_table) return null;

    var cells = std.ArrayList(Cell).init(self.allocator);
    defer {
        for (cells.items) |c| {
            self.allocator.free(c.payload.values);
        }
        cells.deinit();
    }
    self.collectLeafCells(1, &cells) catch return null;

    for (cells.items) |cell| {
        const vals = cell.payload.values;
        if (vals.len >= 5) {
            const tbl_name_val = vals[2];
            const sql_val = vals[4];
            if (tbl_name_val == .text and std.mem.eql(u8, tbl_name_val.text, table_name)) {
                if (sql_val == .text) {
                    return self.allocator.dupe(u8, sql_val.text) catch null;
                }
            }
        }
    }
    return null;
}

// Returns all records from a named table by traversing the B-tree
pub fn readTable(self: *SqliteDb, table_name: []const u8) ![][]Value {
    // Find the table in sqlite_master
    const root_page = self.findTable(table_name) orelse return error.TableNotFound;
    // Collect all leaf cells from the B-tree
    var all_cells = std.ArrayList(Cell).init(self.allocator);
    defer {
        for (all_cells.items) |c| {
            self.allocator.free(c.payload.values);
        }
        all_cells.deinit();
    }

    try self.collectLeafCells(root_page, &all_cells);

    // Convert cells to Value arrays
    var result = try self.allocator.alloc([]Value, all_cells.items.len);
    for (all_cells.items, 0..) |cell, i| {
        result[i] = cell.payload.values;
    }
    return result;
}

fn findTable(self: *SqliteDb, table_name: []const u8) !?u32 {
    // sqlite_master is always on page 1
    const ph = try self.readPageType(1);
    if (ph.page_type != PageType.leaf_table and ph.page_type != PageType.interior_table) return null;

    // For sqlite_master, collect all cells
    // Handle both leaf and interior table structure
    var cells = std.ArrayList(Cell).init(self.allocator);
    defer {
        for (cells.items) |c| {
            self.allocator.free(c.payload.values);
        }
        cells.deinit();
    }

    try self.collectLeafCells(1, &cells);

    for (cells.items) |cell| {
        const vals = cell.payload.values;
        // sqlite_master columns: type(0), name(1), tbl_name(2), rootpage(3), sql(4)
        if (vals.len >= 4) {
            const tbl_name_val = vals[2];
            const rootpage_val = vals[3];
            if (tbl_name_val == .text and std.mem.eql(u8, tbl_name_val.text, table_name)) {
                if (rootpage_val == .int) {
                    return @as(u32, @intCast(rootpage_val.int));
                }
            }
        }
    }
    return null;
}

fn collectLeafCells(self: *SqliteDb, page_num: u32, cells: *std.ArrayList(Cell)) !void {
    const ph = try self.readPageType(page_num);

    switch (ph.page_type) {
        .leaf_table => {
            const ptrs = try self.readCellPointers(page_num, ph);
            defer self.allocator.free(ptrs);

            for (ptrs) |cell_offset| {
                const cell = try self.readCell(page_num, cell_offset);
                try cells.append(cell);
            }
        },
        .interior_table => {
            const page = try self.getPage(page_num);
            const ptrs = try self.readCellPointers(page_num, ph);
            defer self.allocator.free(ptrs);

            for (ptrs) |cell_offset| {
                // Interior table cell: 4-byte child page number + varint(row_id)
                var pos: usize = cell_offset;
                const child_page = std.mem.readInt(u32, page[pos..][0..4], .big);
                pos += 4;
                try self.collectLeafCells(child_page, cells);
            }

            // Also traverse the right-most pointer
            if (ph.right_most_pointer > 0) {
                try self.collectLeafCells(ph.right_most_pointer, cells);
            }
        },
        else => {},
    }
}

// ── Tests ──

test "SQLite magic constant" {
    try testing.expectEqualSlices(u8, "SQLite format 3\x00", SQLITE_MAGIC);
}

test "readVarint single byte" {
    const v = readVarint(&[_]u8{0x01});
    try testing.expectEqual(@as(u64, 1), v.value);
    try testing.expectEqual(@as(usize, 1), v.bytes_read);
}

test "readVarint multi byte" {
    const v = readVarint(&[_]u8{ 0x81, 0x01 });
    try testing.expectEqual(@as(u64, 129), v.value);
    try testing.expectEqual(@as(usize, 2), v.bytes_read);
}

test "readVarint max value" {
    const v = readVarint(&[_]u8{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F });
    try testing.expectEqual(@as(u64, 0x7FFFFFFFFFFFFFFF), v.value);
    try testing.expectEqual(@as(usize, 9), v.bytes_read);
}

test "SerialType sizes" {
    try testing.expectEqual(@as(usize, 0), SerialType.size(0));
    try testing.expectEqual(@as(usize, 1), SerialType.size(1));
    try testing.expectEqual(@as(usize, 2), SerialType.size(2));
    try testing.expectEqual(@as(usize, 4), SerialType.size(4));
    try testing.expectEqual(@as(usize, 8), SerialType.size(6));
    try testing.expectEqual(@as(usize, 8), SerialType.size(7));
    try testing.expectEqual(@as(usize, 0), SerialType.size(8));
    try testing.expectEqual(@as(usize, 1), SerialType.size(14)); // (14-12)/2 = 1 byte blob
    try testing.expectEqual(@as(usize, 1), SerialType.size(15)); // (15-12)/2 = 1 byte text
}

test "SerialType classification" {
    try testing.expect(SerialType.isBlob(12));
    try testing.expect(!SerialType.isBlob(13));
    try testing.expect(SerialType.isText(13));
    try testing.expect(!SerialType.isText(12));
}

test "open invalid database" {
    const allocator = std.testing.allocator;
    try testing.expectError(error.InvalidDatabase, SqliteDb.open(allocator, ""));

    var buf: [256]u8 = undefined;
    @memset(&buf, 0);
    try testing.expectError(error.NotSQLite, SqliteDb.open(allocator, buf[0..100]));
}

test "open valid header" {
    const allocator = std.testing.allocator;
    var header: [200]u8 = undefined;
    @memcpy(header[0..16], SQLITE_MAGIC);
    std.mem.writeInt(u16, header[16..18], 4096, .big); // page_size = 4096
    for (18..200) |i| {
        header[i] = 0;
    }

    var db = try SqliteDb.open(allocator, &header);
    defer db.deinit();
    try testing.expect(db.header.page_size == 4096);
}

test "readVarint large values" {
    const v1 = readVarint(&[_]u8{ 0x8F, 0x42 });
    try testing.expectEqual(@as(u64, 0xF << 7 | 0x42), v1.value);

    const v2 = readVarint(&[_]u8{ 0x7F });
    try testing.expectEqual(@as(u64, 0x7F), v2.value);

    const v3 = readVarint(&[_]u8{ 0x81, 0x81, 0x00 });
    try testing.expectEqual(@as(u64, 0x4080), v3.value);
}

test "readInt24" {
    var buf: [3]u8 = undefined;
    std.mem.writeInt(i24, &buf, 0x123456, .big);
    try testing.expectEqual(@as(i32, 0x123456), readInt24(&buf));
}

test "parseColumnNames simple" {
    const sql = "CREATE TABLE logins (origin_url TEXT NOT NULL, username_value TEXT NOT NULL, password_value BLOB NOT NULL)";
    const cols = try parseColumnNames(sql, std.testing.allocator);
    defer {
        for (cols) |c| std.testing.allocator.free(c);
        std.testing.allocator.free(cols);
    }
    try testing.expectEqual(@as(usize, 3), cols.len);
    try testing.expectEqualSlices(u8, "origin_url", cols[0]);
    try testing.expectEqualSlices(u8, "username_value", cols[1]);
    try testing.expectEqualSlices(u8, "password_value", cols[2]);
}

test "parseColumnNames with types and constraints" {
    const sql = "CREATE TABLE cookies (host_key TEXT NOT NULL DEFAULT '', name TEXT NOT NULL, value BLOB, encrypted_value BLOB DEFAULT NULL, path TEXT NOT NULL DEFAULT '/')";
    const cols = try parseColumnNames(sql, std.testing.allocator);
    defer {
        for (cols) |c| std.testing.allocator.free(c);
        std.testing.allocator.free(cols);
    }
    try testing.expectEqual(@as(usize, 5), cols.len);
    try testing.expectEqualSlices(u8, "host_key", cols[0]);
    try testing.expectEqualSlices(u8, "encrypted_value", cols[3]);
}

test "parseColumnNames with quoted names" {
    const sql = "CREATE TABLE test (`id` INTEGER, \"name\" TEXT, [value] BLOB)";
    const cols = try parseColumnNames(sql, std.testing.allocator);
    defer {
        for (cols) |c| std.testing.allocator.free(c);
        std.testing.allocator.free(cols);
    }
    try testing.expectEqual(@as(usize, 3), cols.len);
    try testing.expectEqualSlices(u8, "`id`", cols[0]);
    try testing.expectEqualSlices(u8, "\"name\"", cols[1]);
    try testing.expectEqualSlices(u8, "[value]", cols[2]);
}

test "parseColumnNames chrome web data" {
    const sql = "CREATE TABLE credit_cards (guid VARCHAR, name_on_card VARCHAR UNIQUE, expiration_month INTEGER, expiration_year INTEGER, card_number_encrypted BLOB, date_modified INTEGER, origin VARCHAR, use_count INTEGER, use_date INTEGER)";
    const cols = try parseColumnNames(sql, std.testing.allocator);
    defer {
        for (cols) |c| std.testing.allocator.free(c);
        std.testing.allocator.free(cols);
    }
    try testing.expectEqual(@as(usize, 9), cols.len);
    try testing.expectEqualSlices(u8, "card_number_encrypted", cols[4]);
}
