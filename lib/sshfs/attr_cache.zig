const std = @import("std");
const Allocator = std.mem.Allocator;

/// Attribute Cache
///
/// Caches file attributes (stat information) with TTL-based expiration.
/// Reduces SFTP stat/lstat calls for frequently accessed files.

pub const AttrCache = struct {
    allocator: Allocator,
    cache: std.StringHashMap(CachedAttr),
    ttl_seconds: u64,
    mutex: std.Thread.Mutex,

    const Self = @This();

    /// File attributes (simplified SFTP attributes)
    pub const FileAttributes = struct {
        /// File size in bytes
        size: u64,

        /// User ID
        uid: u32,

        /// Group ID
        gid: u32,

        /// File permissions (mode)
        permissions: u32,

        /// Access time (seconds since epoch)
        atime: i64,

        /// Modification time (seconds since epoch)
        mtime: i64,

        /// File type flags
        is_dir: bool,
        is_regular: bool,
        is_symlink: bool,

        pub fn init() FileAttributes {
            return FileAttributes{
                .size = 0,
                .uid = 0,
                .gid = 0,
                .permissions = 0,
                .atime = 0,
                .mtime = 0,
                .is_dir = false,
                .is_regular = false,
                .is_symlink = false,
            };
        }
    };

    /// Cached attribute with timestamp
    pub const CachedAttr = struct {
        attr: FileAttributes,
        timestamp: i64,
    };

    /// Default TTL: 5 seconds
    pub const DEFAULT_TTL: u64 = 5;

    pub fn init(allocator: Allocator, ttl_seconds: u64) Self {
        return Self{
            .allocator = allocator,
            .cache = std.StringHashMap(CachedAttr).init(allocator),
            .ttl_seconds = if (ttl_seconds > 0) ttl_seconds else DEFAULT_TTL,
            .mutex = .{},
        };
    }

    pub fn deinit(self: *Self) void {
        // Free all path strings
        var iter = self.cache.iterator();
        while (iter.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.cache.deinit();
    }

    /// Get current timestamp in seconds
    fn getCurrentTime() i64 {
        return @divFloor(std.time.timestamp(), 1);
    }

    /// Check if cached entry is still valid
    fn isValid(self: *Self, cached: *const CachedAttr) bool {
        const now = getCurrentTime();
        const age = now - cached.timestamp;
        return age >= 0 and age < @as(i64, @intCast(self.ttl_seconds));
    }

    /// Get file attributes from cache
    /// Returns null if not found or expired
    pub fn get(self: *Self, path: []const u8) ?FileAttributes {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.cache.getPtr(path)) |cached| {
            if (self.isValid(cached)) {
                return cached.attr;
            } else {
                // Entry expired, remove it
                self.invalidateLocked(path);
            }
        }
        return null;
    }

    /// Put file attributes into cache
    pub fn put(self: *Self, path: []const u8, attr: FileAttributes) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Remove old entry if exists
        self.invalidateLocked(path);

        // Duplicate path
        const path_copy = try self.allocator.dupe(u8, path);
        errdefer self.allocator.free(path_copy);

        const cached = CachedAttr{
            .attr = attr,
            .timestamp = getCurrentTime(),
        };

        try self.cache.put(path_copy, cached);
    }

    /// Invalidate (remove) a path from cache
    pub fn invalidate(self: *Self, path: []const u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        self.invalidateLocked(path);
    }

    /// Invalidate without locking (internal use)
    fn invalidateLocked(self: *Self, path: []const u8) void {
        if (self.cache.fetchRemove(path)) |kv| {
            self.allocator.free(kv.key);
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

    /// Update specific attributes without full replacement
    /// Useful for operations that only modify size or mtime
    pub fn updatePartial(
        self: *Self,
        path: []const u8,
        size: ?u64,
        mtime: ?i64,
    ) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.cache.getPtr(path)) |cached| {
            if (size) |s| {
                cached.attr.size = s;
            }
            if (mtime) |m| {
                cached.attr.mtime = m;
            }
            // Update timestamp to keep entry fresh
            cached.timestamp = getCurrentTime();
        }
    }

    /// Clear all cached entries
    pub fn clear(self: *Self) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        var iter = self.cache.iterator();
        while (iter.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }

        self.cache.clearRetainingCapacity();
    }

    /// Get number of cached entries
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

    /// Check if path exists in cache (without checking expiration)
    pub fn hasPath(self: *Self, path: []const u8) bool {
        self.mutex.lock();
        defer self.mutex.unlock();

        return self.cache.contains(path);
    }
};

// ============================================================================
// Tests
// ============================================================================

test "AttrCache - basic operations" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var cache = AttrCache.init(allocator, 10);
    defer cache.deinit();

    // Create test attributes
    const attr = AttrCache.FileAttributes{
        .size = 1024,
        .uid = 1000,
        .gid = 1000,
        .permissions = 0o644,
        .atime = 123456,
        .mtime = 789012,
        .is_dir = false,
        .is_regular = true,
        .is_symlink = false,
    };

    // Put attributes
    try cache.put("/test/file.txt", attr);

    // Get attributes
    const cached = cache.get("/test/file.txt");
    try testing.expect(cached != null);
    try testing.expectEqual(@as(u64, 1024), cached.?.size);
    try testing.expectEqual(@as(u32, 1000), cached.?.uid);
    try testing.expectEqual(@as(u32, 1000), cached.?.gid);
    try testing.expectEqual(@as(u32, 0o644), cached.?.permissions);
    try testing.expectEqual(@as(i64, 123456), cached.?.atime);
    try testing.expectEqual(@as(i64, 789012), cached.?.mtime);
    try testing.expect(cached.?.is_regular);
    try testing.expect(!cached.?.is_dir);

    // Check count
    try testing.expectEqual(@as(usize, 1), cache.count());
}

test "AttrCache - invalidate" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var cache = AttrCache.init(allocator, 10);
    defer cache.deinit();

    const attr = AttrCache.FileAttributes.init();
    try cache.put("/test", attr);
    try testing.expect(cache.get("/test") != null);

    cache.invalidate("/test");
    try testing.expect(cache.get("/test") == null);
    try testing.expectEqual(@as(usize, 0), cache.count());
}

test "AttrCache - TTL expiration" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Very short TTL for testing
    var cache = AttrCache.init(allocator, 1);
    defer cache.deinit();

    const attr = AttrCache.FileAttributes.init();
    try cache.put("/test", attr);
    try testing.expect(cache.get("/test") != null);

    // Wait for expiration
    std.time.sleep(1500 * std.time.ns_per_ms);

    // Entry should be expired and removed
    try testing.expect(cache.get("/test") == null);
}

test "AttrCache - invalidate prefix" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var cache = AttrCache.init(allocator, 10);
    defer cache.deinit();

    const attr = AttrCache.FileAttributes.init();

    try cache.put("/foo/bar/file1.txt", attr);
    try cache.put("/foo/bar/file2.txt", attr);
    try cache.put("/foo/baz/file3.txt", attr);
    try cache.put("/other/file4.txt", attr);

    try testing.expectEqual(@as(usize, 4), cache.count());

    // Invalidate /foo/bar prefix
    cache.invalidatePrefix("/foo/bar");

    try testing.expect(cache.get("/foo/bar/file1.txt") == null);
    try testing.expect(cache.get("/foo/bar/file2.txt") == null);
    try testing.expect(cache.get("/foo/baz/file3.txt") != null);
    try testing.expect(cache.get("/other/file4.txt") != null);
    try testing.expectEqual(@as(usize, 2), cache.count());
}

test "AttrCache - update partial" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var cache = AttrCache.init(allocator, 10);
    defer cache.deinit();

    const attr = AttrCache.FileAttributes{
        .size = 1024,
        .uid = 1000,
        .gid = 1000,
        .permissions = 0o644,
        .atime = 123456,
        .mtime = 789012,
        .is_dir = false,
        .is_regular = true,
        .is_symlink = false,
    };

    try cache.put("/test", attr);

    // Update only size and mtime
    cache.updatePartial("/test", 2048, 999999);

    const cached = cache.get("/test");
    try testing.expect(cached != null);
    try testing.expectEqual(@as(u64, 2048), cached.?.size);
    try testing.expectEqual(@as(i64, 999999), cached.?.mtime);
    // Other fields should remain unchanged
    try testing.expectEqual(@as(u32, 1000), cached.?.uid);
    try testing.expectEqual(@as(u32, 0o644), cached.?.permissions);
}

test "AttrCache - clean expired" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var cache = AttrCache.init(allocator, 1);
    defer cache.deinit();

    const attr = AttrCache.FileAttributes.init();

    try cache.put("/test1", attr);
    try cache.put("/test2", attr);
    try cache.put("/test3", attr);

    try testing.expectEqual(@as(usize, 3), cache.count());

    // Wait for expiration
    std.time.sleep(1500 * std.time.ns_per_ms);

    // Clean expired entries
    cache.cleanExpired();

    try testing.expectEqual(@as(usize, 0), cache.count());
}

test "AttrCache - clear" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var cache = AttrCache.init(allocator, 10);
    defer cache.deinit();

    const attr = AttrCache.FileAttributes.init();

    try cache.put("/test1", attr);
    try cache.put("/test2", attr);
    try cache.put("/test3", attr);

    try testing.expectEqual(@as(usize, 3), cache.count());

    cache.clear();

    try testing.expectEqual(@as(usize, 0), cache.count());
    try testing.expect(cache.get("/test1") == null);
}

test "AttrCache - has path" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var cache = AttrCache.init(allocator, 10);
    defer cache.deinit();

    const attr = AttrCache.FileAttributes.init();
    try cache.put("/test", attr);

    try testing.expect(cache.hasPath("/test"));
    try testing.expect(!cache.hasPath("/nonexistent"));
}
