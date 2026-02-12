const std = @import("std");
const Allocator = std.mem.Allocator;

/// Inode Cache
///
/// Manages bidirectional mapping between paths and inode numbers.
/// In FUSE, we need to maintain consistent inode numbers for paths.

pub const InodeCache = struct {
    allocator: Allocator,
    next_inode: u64,
    path_to_inode: std.StringHashMap(u64),
    inode_to_path: std.AutoHashMap(u64, []const u8),
    mutex: std.Thread.Mutex,

    const Self = @This();

    /// Root inode number
    pub const ROOT_INODE: u64 = 1;

    pub fn init(allocator: Allocator) Self {
        var cache = Self{
            .allocator = allocator,
            .next_inode = ROOT_INODE + 1,
            .path_to_inode = std.StringHashMap(u64).init(allocator),
            .inode_to_path = std.AutoHashMap(u64, []const u8).init(allocator),
            .mutex = .{},
        };

        // Initialize root
        cache.path_to_inode.put("/", ROOT_INODE) catch {};
        cache.inode_to_path.put(ROOT_INODE, "/") catch {};

        return cache;
    }

    pub fn deinit(self: *Self) void {
        // Free all path strings
        var iter = self.inode_to_path.iterator();
        while (iter.next()) |entry| {
            if (!std.mem.eql(u8, entry.value_ptr.*, "/")) {
                self.allocator.free(entry.value_ptr.*);
            }
        }

        self.path_to_inode.deinit();
        self.inode_to_path.deinit();
    }

    /// Get or create inode for path
    pub fn getOrCreateInode(self: *Self, path: []const u8) !u64 {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Check if already exists
        if (self.path_to_inode.get(path)) |inode| {
            return inode;
        }

        // Allocate new inode
        const inode = self.next_inode;
        self.next_inode += 1;

        // Store path (duplicate it)
        const path_copy = try self.allocator.dupe(u8, path);
        errdefer self.allocator.free(path_copy);

        try self.path_to_inode.put(path_copy, inode);
        try self.inode_to_path.put(inode, path_copy);

        return inode;
    }

    /// Get inode for path (without creating)
    pub fn getInode(self: *Self, path: []const u8) ?u64 {
        self.mutex.lock();
        defer self.mutex.unlock();

        return self.path_to_inode.get(path);
    }

    /// Get path for inode
    pub fn getPath(self: *Self, inode: u64) ?[]const u8 {
        self.mutex.lock();
        defer self.mutex.unlock();

        return self.inode_to_path.get(inode);
    }

    /// Invalidate (remove) a path from cache
    pub fn invalidate(self: *Self, path: []const u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.path_to_inode.get(path)) |inode| {
            // Don't invalidate root
            if (inode == ROOT_INODE) return;

            _ = self.path_to_inode.remove(path);

            if (self.inode_to_path.get(inode)) |stored_path| {
                self.allocator.free(stored_path);
                _ = self.inode_to_path.remove(inode);
            }
        }
    }

    /// Rename entry in cache
    pub fn rename(self: *Self, oldpath: []const u8, newpath: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.path_to_inode.get(oldpath)) |inode| {
            // Remove old mapping
            _ = self.path_to_inode.remove(oldpath);

            // Add new mapping
            const newpath_copy = try self.allocator.dupe(u8, newpath);
            errdefer self.allocator.free(newpath_copy);

            try self.path_to_inode.put(newpath_copy, inode);

            // Update reverse mapping
            if (self.inode_to_path.getPtr(inode)) |stored_path_ptr| {
                self.allocator.free(stored_path_ptr.*);
                stored_path_ptr.* = newpath_copy;
            }
        }
    }

    /// Clear all cached entries (except root)
    pub fn clear(self: *Self) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Free all paths except root
        var iter = self.inode_to_path.iterator();
        while (iter.next()) |entry| {
            if (entry.key_ptr.* != ROOT_INODE) {
                self.allocator.free(entry.value_ptr.*);
            }
        }

        self.path_to_inode.clearRetainingCapacity();
        self.inode_to_path.clearRetainingCapacity();

        // Re-add root
        self.path_to_inode.put("/", ROOT_INODE) catch {};
        self.inode_to_path.put(ROOT_INODE, "/") catch {};

        self.next_inode = ROOT_INODE + 1;
    }

    /// Get number of cached entries
    pub fn count(self: *Self) usize {
        self.mutex.lock();
        defer self.mutex.unlock();

        return self.path_to_inode.count();
    }
};

// ============================================================================
// Tests
// ============================================================================

test "InodeCache - basic operations" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var cache = InodeCache.init(allocator);
    defer cache.deinit();

    // Root should exist
    try testing.expectEqual(InodeCache.ROOT_INODE, cache.getInode("/").?);
    try testing.expectEqualStrings("/", cache.getPath(InodeCache.ROOT_INODE).?);

    // Create new inodes
    const inode1 = try cache.getOrCreateInode("/foo");
    const inode2 = try cache.getOrCreateInode("/bar");

    try testing.expect(inode1 != inode2);
    try testing.expect(inode1 > InodeCache.ROOT_INODE);

    // Verify paths
    try testing.expectEqualStrings("/foo", cache.getPath(inode1).?);
    try testing.expectEqualStrings("/bar", cache.getPath(inode2).?);

    // Get existing inode
    const inode1_again = try cache.getOrCreateInode("/foo");
    try testing.expectEqual(inode1, inode1_again);
}

test "InodeCache - invalidate" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var cache = InodeCache.init(allocator);
    defer cache.deinit();

    const inode = try cache.getOrCreateInode("/test");
    try testing.expectEqual(inode, cache.getInode("/test").?);

    cache.invalidate("/test");
    try testing.expect(cache.getInode("/test") == null);
    try testing.expect(cache.getPath(inode) == null);
}

test "InodeCache - rename" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var cache = InodeCache.init(allocator);
    defer cache.deinit();

    const inode = try cache.getOrCreateInode("/old");
    try cache.rename("/old", "/new");

    try testing.expect(cache.getInode("/old") == null);
    try testing.expectEqual(inode, cache.getInode("/new").?);
    try testing.expectEqualStrings("/new", cache.getPath(inode).?);
}

test "InodeCache - clear" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var cache = InodeCache.init(allocator);
    defer cache.deinit();

    _ = try cache.getOrCreateInode("/foo");
    _ = try cache.getOrCreateInode("/bar");
    _ = try cache.getOrCreateInode("/baz");

    try testing.expectEqual(@as(usize, 4), cache.count()); // root + 3

    cache.clear();

    try testing.expectEqual(@as(usize, 1), cache.count()); // only root
    try testing.expectEqual(InodeCache.ROOT_INODE, cache.getInode("/").?);
}
