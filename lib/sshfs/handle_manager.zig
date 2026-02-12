const std = @import("std");
const Allocator = std.mem.Allocator;
const sftp = @import("../sftp/sftp.zig");

/// File Handle Manager
///
/// Manages mapping between FUSE file handles and SFTP handles.
/// Each open file gets a unique handle that tracks the SFTP handle and state.

pub const HandleManager = struct {
    allocator: Allocator,
    next_handle: u64,
    handles: std.AutoHashMap(u64, *HandleInfo),
    mutex: std.Thread.Mutex,

    const Self = @This();

    pub const HandleInfo = struct {
        /// SFTP file handle
        sftp_handle: sftp.client.Handle,

        /// File path
        path: []const u8,

        /// Open flags (O_RDONLY, O_WRONLY, O_RDWR, etc.)
        flags: u32,

        /// Current offset (for sequential access optimization)
        offset: u64,

        /// Allocator for cleanup
        allocator: Allocator,

        pub fn deinit(self: *HandleInfo) void {
            self.allocator.free(self.path);
            self.sftp_handle.deinit(self.allocator);
        }
    };

    pub fn init(allocator: Allocator) Self {
        return Self{
            .allocator = allocator,
            .next_handle = 1, // Start from 1 (0 is invalid)
            .handles = std.AutoHashMap(u64, *HandleInfo).init(allocator),
            .mutex = .{},
        };
    }

    pub fn deinit(self: *Self) void {
        // Clean up all handles
        var iter = self.handles.iterator();
        while (iter.next()) |entry| {
            entry.value_ptr.*.deinit();
            self.allocator.destroy(entry.value_ptr.*);
        }
        self.handles.deinit();
    }

    /// Allocate a new file handle
    pub fn allocateHandle(
        self: *Self,
        sftp_handle: sftp.client.Handle,
        path: []const u8,
        flags: u32,
    ) !u64 {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Allocate handle number
        const fh = self.next_handle;
        self.next_handle += 1;

        // Create handle info
        const info = try self.allocator.create(HandleInfo);
        errdefer self.allocator.destroy(info);

        info.* = HandleInfo{
            .sftp_handle = sftp_handle,
            .path = try self.allocator.dupe(u8, path),
            .flags = flags,
            .offset = 0,
            .allocator = self.allocator,
        };

        try self.handles.put(fh, info);

        return fh;
    }

    /// Get handle info
    pub fn getHandle(self: *Self, fh: u64) ?*HandleInfo {
        self.mutex.lock();
        defer self.mutex.unlock();

        return self.handles.get(fh);
    }

    /// Release (free) a handle
    pub fn releaseHandle(self: *Self, fh: u64) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.handles.fetchRemove(fh)) |entry| {
            entry.value.deinit();
            self.allocator.destroy(entry.value);
        }
    }

    /// Update handle offset
    pub fn updateOffset(self: *Self, fh: u64, offset: u64) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.handles.getPtr(fh)) |info| {
            info.*.offset = offset;
        }
    }

    /// Get number of open handles
    pub fn count(self: *Self) usize {
        self.mutex.lock();
        defer self.mutex.unlock();

        return self.handles.count();
    }

    /// Check if handle exists
    pub fn hasHandle(self: *Self, fh: u64) bool {
        self.mutex.lock();
        defer self.mutex.unlock();

        return self.handles.contains(fh);
    }
};

// ============================================================================
// Tests
// ============================================================================

test "HandleManager - basic operations" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var manager = HandleManager.init(allocator);
    defer manager.deinit();

    // Create mock SFTP handle
    const mock_handle = sftp.client.Handle{
        .data = try allocator.dupe(u8, "mock_handle_123"),
    };

    // Allocate handle
    const fh = try manager.allocateHandle(mock_handle, "/test/file.txt", 0);
    try testing.expect(fh > 0);

    // Get handle info
    const info = manager.getHandle(fh);
    try testing.expect(info != null);
    try testing.expectEqualStrings("/test/file.txt", info.?.path);
    try testing.expectEqual(@as(u32, 0), info.?.flags);
    try testing.expectEqual(@as(u64, 0), info.?.offset);

    // Check count
    try testing.expectEqual(@as(usize, 1), manager.count());

    // Update offset
    manager.updateOffset(fh, 1024);
    const updated_info = manager.getHandle(fh);
    try testing.expectEqual(@as(u64, 1024), updated_info.?.offset);

    // Release handle
    manager.releaseHandle(fh);
    try testing.expect(manager.getHandle(fh) == null);
    try testing.expectEqual(@as(usize, 0), manager.count());
}

test "HandleManager - multiple handles" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var manager = HandleManager.init(allocator);
    defer manager.deinit();

    // Allocate multiple handles
    const mock_handle1 = sftp.client.Handle{
        .data = try allocator.dupe(u8, "handle1"),
    };
    const mock_handle2 = sftp.client.Handle{
        .data = try allocator.dupe(u8, "handle2"),
    };
    const mock_handle3 = sftp.client.Handle{
        .data = try allocator.dupe(u8, "handle3"),
    };

    const fh1 = try manager.allocateHandle(mock_handle1, "/file1", 1);
    const fh2 = try manager.allocateHandle(mock_handle2, "/file2", 2);
    const fh3 = try manager.allocateHandle(mock_handle3, "/file3", 3);

    try testing.expect(fh1 != fh2);
    try testing.expect(fh2 != fh3);
    try testing.expect(fh1 != fh3);

    try testing.expectEqual(@as(usize, 3), manager.count());

    // Verify paths
    try testing.expectEqualStrings("/file1", manager.getHandle(fh1).?.path);
    try testing.expectEqualStrings("/file2", manager.getHandle(fh2).?.path);
    try testing.expectEqualStrings("/file3", manager.getHandle(fh3).?.path);

    // Release middle handle
    manager.releaseHandle(fh2);
    try testing.expectEqual(@as(usize, 2), manager.count());
    try testing.expect(manager.getHandle(fh2) == null);
    try testing.expect(manager.getHandle(fh1) != null);
    try testing.expect(manager.getHandle(fh3) != null);
}

test "HandleManager - has handle" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var manager = HandleManager.init(allocator);
    defer manager.deinit();

    const mock_handle = sftp.client.Handle{
        .data = try allocator.dupe(u8, "test"),
    };

    const fh = try manager.allocateHandle(mock_handle, "/test", 0);

    try testing.expect(manager.hasHandle(fh));
    try testing.expect(!manager.hasHandle(999));

    manager.releaseHandle(fh);
    try testing.expect(!manager.hasHandle(fh));
}
