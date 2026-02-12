const std = @import("std");
const Allocator = std.mem.Allocator;

/// Directory Cache
///
/// Caches directory listings with TTL-based expiration.
/// Reduces SFTP readdir calls for frequently accessed directories.

pub const DirCache = struct {
    allocator: Allocator,
    cache: std.StringHashMap(CachedDir),
    ttl_seconds: u64,
    mutex: std.Thread.Mutex,

    const Self = @This();

    /// Directory entry
    pub const DirEntry = struct {
        name: []const u8,
        is_dir: bool,
        size: u64,
        mtime: i64,

        pub fn deinit(self: DirEntry, allocator: Allocator) void {
            allocator.free(self.name);
        }
    };

    /// Cached directory with timestamp
    pub const CachedDir = struct {
        entries: []DirEntry,
        timestamp: i64,
        allocator: Allocator,

        pub fn deinit(self: *CachedDir) void {
            for (self.entries) |entry| {
                entry.deinit(self.allocator);
            }
            self.allocator.free(self.entries);
        }
    };

    /// Default TTL: 5 seconds
    pub const DEFAULT_TTL: u64 = 5;

    pub fn init(allocator: Allocator, ttl_seconds: u64) Self {
        return Self{
            .allocator = allocator,
            .cache = std.StringHashMap(CachedDir).init(allocator),
            .ttl_seconds = if (ttl_seconds > 0) ttl_seconds else DEFAULT_TTL,
            .mutex = .{},
        };
    }

    pub fn deinit(self: *Self) void {
        // Free all cached entries
        var iter = self.cache.iterator();
        while (iter.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit();
        }
        self.cache.deinit();
    }

    /// Get current timestamp in seconds
    fn getCurrentTime() i64 {
        return @divFloor(std.time.timestamp(), 1);
    }

    /// Check if cached entry is still valid
    fn isValid(self: *Self, cached: *const CachedDir) bool {
        const now = getCurrentTime();
        const age = now - cached.timestamp;
        return age >= 0 and age < @as(i64, @intCast(self.ttl_seconds));
    }

    /// Get directory entries from cache
    /// Returns null if not found or expired
    pub fn get(self: *Self, path: []const u8) ?[]const DirEntry {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.cache.getPtr(path)) |cached| {
            if (self.isValid(cached)) {
                return cached.entries;
            } else {
                // Entry expired, remove it
                self.invalidateLocked(path);
            }
        }
        return null;
    }

    /// Put directory entries into cache
    pub fn put(self: *Self, path: []const u8, entries: []const DirEntry) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Remove old entry if exists
        self.invalidateLocked(path);

        // Duplicate path
        const path_copy = try self.allocator.dupe(u8, path);
        errdefer self.allocator.free(path_copy);

        // Duplicate entries
        var entries_copy = try self.allocator.alloc(DirEntry, entries.len);
        errdefer self.allocator.free(entries_copy);

        for (entries, 0..) |entry, i| {
            entries_copy[i] = DirEntry{
                .name = try self.allocator.dupe(u8, entry.name),
                .is_dir = entry.is_dir,
                .size = entry.size,
                .mtime = entry.mtime,
            };
        }

        const cached = CachedDir{
            .entries = entries_copy,
            .timestamp = getCurrentTime(),
            .allocator = self.allocator,
        };

        try self.cache.put(path_copy, cached);
    }

    /// Invalidate (remove) a directory from cache
    pub fn invalidate(self: *Self, path: []const u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        self.invalidateLocked(path);
    }

    /// Invalidate without locking (internal use)
    fn invalidateLocked(self: *Self, path: []const u8) void {
        if (self.cache.fetchRemove(path)) |kv| {
            self.allocator.free(kv.key);
            kv.value.deinit();
        }
    }

    /// Invalidate all entries with path prefix
    /// Useful when a directory is modified
    pub fn invalidatePrefix(self: *Self, prefix: []const u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        var to_remove = std.ArrayList([]const u8).init(self.allocator);
        defer to_remove.deinit();

        // Collect paths to remove
        var iter = self.cache.iterator();
        while (iter.next()) |entry| {
            if (std.mem.startsWith(u8, entry.key_ptr.*, prefix)) {
                to_remove.append(entry.key_ptr.*) catch continue;
            }
        }

        // Remove collected paths
        for (to_remove.items) |path| {
            self.invalidateLocked(path);
        }
    }

    /// Clear all cached entries
    pub fn clear(self: *Self) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        var iter = self.cache.iterator();
        while (iter.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit();
        }

        self.cache.clearRetainingCapacity();
    }

    /// Get number of cached directories
    pub fn count(self: *Self) usize {
        self.mutex.lock();
        defer self.mutex.unlock();

        return self.cache.count();
    }

    /// Remove expired entries
    pub fn cleanExpired(self: *Self) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        var to_remove = std.ArrayList([]const u8).init(self.allocator);
        defer to_remove.deinit();

        // Collect expired paths
        var iter = self.cache.iterator();
        while (iter.next()) |entry| {
            if (!self.isValid(entry.value_ptr)) {
                to_remove.append(entry.key_ptr.*) catch continue;
            }
        }

        // Remove expired entries
        for (to_remove.items) |path| {
            self.invalidateLocked(path);
        }
    }
};

// ============================================================================
// Tests
// ============================================================================

test "DirCache - basic operations" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var cache = DirCache.init(allocator, 10);
    defer cache.deinit();

    // Create test entries
    var entries = [_]DirCache.DirEntry{
        .{ .name = "file1.txt", .is_dir = false, .size = 100, .mtime = 1000 },
        .{ .name = "file2.txt", .is_dir = false, .size = 200, .mtime = 2000 },
        .{ .name = "subdir", .is_dir = true, .size = 0, .mtime = 3000 },
    };

    // Put entries
    try cache.put("/test", &entries);

    // Get entries
    const cached = cache.get("/test");
    try testing.expect(cached != null);
    try testing.expectEqual(@as(usize, 3), cached.?.len);
    try testing.expectEqualStrings("file1.txt", cached.?[0].name);
    try testing.expectEqualStrings("file2.txt", cached.?[1].name);
    try testing.expectEqualStrings("subdir", cached.?[2].name);

    // Check count
    try testing.expectEqual(@as(usize, 1), cache.count());
}

test "DirCache - invalidate" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var cache = DirCache.init(allocator, 10);
    defer cache.deinit();

    var entries = [_]DirCache.DirEntry{
        .{ .name = "test.txt", .is_dir = false, .size = 100, .mtime = 1000 },
    };

    try cache.put("/test", &entries);
    try testing.expect(cache.get("/test") != null);

    cache.invalidate("/test");
    try testing.expect(cache.get("/test") == null);
    try testing.expectEqual(@as(usize, 0), cache.count());
}

test "DirCache - TTL expiration" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Very short TTL for testing
    var cache = DirCache.init(allocator, 1);
    defer cache.deinit();

    var entries = [_]DirCache.DirEntry{
        .{ .name = "test.txt", .is_dir = false, .size = 100, .mtime = 1000 },
    };

    try cache.put("/test", &entries);
    try testing.expect(cache.get("/test") != null);

    // Wait for expiration
    std.time.sleep(1500 * std.time.ns_per_ms);

    // Entry should be expired and removed
    try testing.expect(cache.get("/test") == null);
}

test "DirCache - invalidate prefix" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var cache = DirCache.init(allocator, 10);
    defer cache.deinit();

    var entries = [_]DirCache.DirEntry{
        .{ .name = "test.txt", .is_dir = false, .size = 100, .mtime = 1000 },
    };

    try cache.put("/foo/bar", &entries);
    try cache.put("/foo/baz", &entries);
    try cache.put("/other", &entries);

    try testing.expectEqual(@as(usize, 3), cache.count());

    // Invalidate /foo prefix
    cache.invalidatePrefix("/foo");

    try testing.expect(cache.get("/foo/bar") == null);
    try testing.expect(cache.get("/foo/baz") == null);
    try testing.expect(cache.get("/other") != null);
    try testing.expectEqual(@as(usize, 1), cache.count());
}

test "DirCache - clean expired" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var cache = DirCache.init(allocator, 1);
    defer cache.deinit();

    var entries = [_]DirCache.DirEntry{
        .{ .name = "test.txt", .is_dir = false, .size = 100, .mtime = 1000 },
    };

    try cache.put("/test1", &entries);
    try cache.put("/test2", &entries);

    try testing.expectEqual(@as(usize, 2), cache.count());

    // Wait for expiration
    std.time.sleep(1500 * std.time.ns_per_ms);

    // Clean expired entries
    cache.cleanExpired();

    try testing.expectEqual(@as(usize, 0), cache.count());
}

test "DirCache - clear" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var cache = DirCache.init(allocator, 10);
    defer cache.deinit();

    var entries = [_]DirCache.DirEntry{
        .{ .name = "test.txt", .is_dir = false, .size = 100, .mtime = 1000 },
    };

    try cache.put("/test1", &entries);
    try cache.put("/test2", &entries);
    try cache.put("/test3", &entries);

    try testing.expectEqual(@as(usize, 3), cache.count());

    cache.clear();

    try testing.expectEqual(@as(usize, 0), cache.count());
    try testing.expect(cache.get("/test1") == null);
}
