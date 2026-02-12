const std = @import("std");
const fuse = @import("../fuse/fuse.zig");
const sftp = @import("../sftp/sftp.zig");
const protocol = @import("../sftp/protocol.zig");
const attributes = @import("../sftp/attributes.zig");
const InodeCache = @import("inode_cache.zig").InodeCache;
const HandleManager = @import("handle_manager.zig").HandleManager;
const DirCache = @import("dir_cache.zig").DirCache;
const AttrCache = @import("attr_cache.zig").AttrCache;

/// SSHFS Context
///
/// Global context passed to all FUSE operations.
/// Contains SFTP connection and caching layers.
pub const SshfsContext = struct {
    allocator: std.mem.Allocator,
    sftp_client: *sftp.client.SftpClient,
    inode_cache: *InodeCache,
    handle_manager: *HandleManager,
    dir_cache: *DirCache,
    attr_cache: *AttrCache,

    /// Root path on remote server
    remote_root: []const u8,

    /// Mutex for thread safety
    mutex: std.Thread.Mutex,
};

/// Convert SFTP attributes to FUSE stat structure
fn sftpAttrToStat(attr: attributes.FileAttributes, stbuf: *fuse.Stat) void {
    stbuf.* = std.mem.zeroes(fuse.Stat);

    // File size
    if (attr.size) |size| {
        stbuf.st_size = @intCast(size);
    }

    // Permissions and file type
    if (attr.permissions) |perms| {
        stbuf.st_mode = perms;
    }

    // UID/GID
    if (attr.uid) |uid| {
        stbuf.st_uid = uid;
    }
    if (attr.gid) |gid| {
        stbuf.st_gid = gid;
    }

    // Timestamps
    if (attr.atime) |atime| {
        stbuf.st_atim = .{
            .tv_sec = @intCast(atime),
            .tv_nsec = 0,
        };
    }
    if (attr.mtime) |mtime| {
        stbuf.st_mtim = .{
            .tv_sec = @intCast(mtime),
            .tv_nsec = 0,
        };
        stbuf.st_ctim = stbuf.st_mtim;
    }

    // Block size and blocks
    stbuf.st_blksize = 4096;
    if (attr.size) |size| {
        stbuf.st_blocks = @intCast((size + 511) / 512);
    }
}

/// Convert AttrCache.FileAttributes to FUSE stat
fn cachedAttrToStat(attr: AttrCache.FileAttributes, stbuf: *fuse.Stat, inode: u64) void {
    stbuf.* = std.mem.zeroes(fuse.Stat);

    stbuf.st_ino = inode;
    stbuf.st_size = @intCast(attr.size);
    stbuf.st_mode = attr.permissions;
    stbuf.st_uid = attr.uid;
    stbuf.st_gid = attr.gid;
    stbuf.st_nlink = 1;

    stbuf.st_atim = .{
        .tv_sec = attr.atime,
        .tv_nsec = 0,
    };
    stbuf.st_mtim = .{
        .tv_sec = attr.mtime,
        .tv_nsec = 0,
    };
    stbuf.st_ctim = stbuf.st_mtim;

    stbuf.st_blksize = 4096;
    stbuf.st_blocks = @intCast((attr.size + 511) / 512);
}

/// Get context from FUSE
fn getContext() ?*SshfsContext {
    if (fuse.fuse_get_context()) |ctx| {
        if (ctx.private_data) |data| {
            return @ptrCast(@alignCast(data));
        }
    }
    return null;
}

// ============================================================================
// FUSE Operations - Read-only Operations
// ============================================================================

/// Get file attributes (stat)
export fn sshfs_getattr(path: [*:0]const u8, stbuf: *fuse.Stat) callconv(.c) c_int {
    const ctx = getContext() orelse return -fuse.EIO;
    const path_slice = std.mem.span(path);

    // Get or create inode
    const inode = ctx.inode_cache.getOrCreateInode(path_slice) catch {
        return -fuse.ENOMEM;
    };

    // Check attribute cache first
    if (ctx.attr_cache.get(path_slice)) |cached_attr| {
        cachedAttrToStat(cached_attr, stbuf, inode);
        return 0;
    }

    // Build remote path
    var path_buf: [4096]u8 = undefined;
    const remote_path = std.fmt.bufPrint(&path_buf, "{s}{s}", .{
        ctx.remote_root,
        path_slice,
    }) catch return -fuse.ENAMETOOLONG;

    // Get attributes from SFTP
    const attr = ctx.sftp_client.stat(remote_path) catch |err| {
        return switch (err) {
            error.NoSuchFile => -fuse.ENOENT,
            error.PermissionDenied => -fuse.EACCES,
            else => -fuse.EIO,
        };
    };

    // Convert to stat structure
    sftpAttrToStat(attr, stbuf);
    stbuf.st_ino = inode;
    stbuf.st_nlink = 1;

    // Cache the attributes
    const cache_attr = AttrCache.FileAttributes{
        .size = attr.size orelse 0,
        .uid = attr.uid orelse 0,
        .gid = attr.gid orelse 0,
        .permissions = attr.permissions orelse 0,
        .atime = @intCast(attr.atime orelse 0),
        .mtime = @intCast(attr.mtime orelse 0),
        .is_dir = fuse.S_ISDIR(stbuf.st_mode),
        .is_regular = fuse.S_ISREG(stbuf.st_mode),
        .is_symlink = fuse.S_ISLNK(stbuf.st_mode),
    };
    ctx.attr_cache.put(path_slice, cache_attr) catch {};

    return 0;
}

/// Read directory contents
export fn sshfs_readdir(
    path: [*:0]const u8,
    buf: ?*anyopaque,
    filler: fuse.FuseFillDirT,
    offset: fuse.off_t,
    fi: *fuse.FuseFileInfo,
) callconv(.c) c_int {
    _ = offset;
    _ = fi;

    const ctx = getContext() orelse return -fuse.EIO;
    const path_slice = std.mem.span(path);

    // Check directory cache first
    if (ctx.dir_cache.get(path_slice)) |cached_entries| {
        // Fill from cache
        _ = filler(buf, ".", null, 0);
        _ = filler(buf, "..", null, 0);

        for (cached_entries) |entry| {
            const name_z = ctx.allocator.dupeZ(u8, entry.name) catch {
                continue;
            };
            defer ctx.allocator.free(name_z);

            _ = filler(buf, name_z.ptr, null, 0);
        }

        return 0;
    }

    // Build remote path
    var path_buf: [4096]u8 = undefined;
    const remote_path = std.fmt.bufPrint(&path_buf, "{s}{s}", .{
        ctx.remote_root,
        path_slice,
    }) catch return -fuse.ENAMETOOLONG;

    // Open directory via SFTP
    const handle = ctx.sftp_client.opendir(remote_path) catch |err| {
        return switch (err) {
            error.NoSuchFile => -fuse.ENOENT,
            error.PermissionDenied => -fuse.EACCES,
            else => -fuse.EIO,
        };
    };
    defer ctx.sftp_client.close(handle) catch {};

    // Read directory entries
    // Note: Temporarily not caching directory entries due to ArrayList API issues

    // Add . and ..
    _ = filler(buf, ".", null, 0);
    _ = filler(buf, "..", null, 0);

    // Read all entries from SFTP (readdir returns a slice of all entries)
    const entries = ctx.sftp_client.readdir(handle) catch {
        return -fuse.EIO;
    };
    defer {
        for (entries) |*entry| {
            entry.deinit(ctx.allocator);
        }
        ctx.allocator.free(entries);
    }

    // Add each entry to filler
    for (entries) |entry| {
        // Skip . and ..
        if (std.mem.eql(u8, entry.filename, ".") or
            std.mem.eql(u8, entry.filename, "..")) {
            continue;
        }

        // Add to filler
        const name_z = ctx.allocator.dupeZ(u8, entry.filename) catch continue;
        defer ctx.allocator.free(name_z);

        _ = filler(buf, name_z.ptr, null, 0);
    }

    // TODO: Cache directory listing

    return 0;
}

/// Open a file
export fn sshfs_open(path: [*:0]const u8, fi: *fuse.FuseFileInfo) callconv(.c) c_int {
    const ctx = getContext() orelse return -fuse.EIO;
    const path_slice = std.mem.span(path);

    // Build remote path
    var path_buf: [4096]u8 = undefined;
    const remote_path = std.fmt.bufPrint(&path_buf, "{s}{s}", .{
        ctx.remote_root,
        path_slice,
    }) catch return -fuse.ENAMETOOLONG;

    // Determine SFTP open flags
    var pflags: u32 = protocol.OpenFlags.SSH_FXF_READ;
    if ((fi.flags & fuse.O_WRONLY) != 0 or (fi.flags & fuse.O_RDWR) != 0) {
        pflags = protocol.OpenFlags.SSH_FXF_WRITE;
    }
    if ((fi.flags & fuse.O_RDWR) != 0) {
        pflags = protocol.OpenFlags.SSH_FXF_READ | protocol.OpenFlags.SSH_FXF_WRITE;
    }

    // Open file via SFTP
    const open_flags = protocol.OpenFlags.fromU32(pflags);
    const handle = ctx.sftp_client.open(remote_path, open_flags, attributes.FileAttributes.init()) catch |err| {
        return switch (err) {
            error.NoSuchFile => -fuse.ENOENT,
            error.PermissionDenied => -fuse.EACCES,
            else => -fuse.EIO,
        };
    };

    // Allocate FUSE file handle
    const fh = ctx.handle_manager.allocateHandle(
        handle,
        path_slice,
        @intCast(fi.flags),
    ) catch {
        ctx.sftp_client.close(handle) catch {};
        return -fuse.ENOMEM;
    };

    fi.fh = fh;
    return 0;
}

/// Read file data
export fn sshfs_read(
    path: [*:0]const u8,
    buf: [*]u8,
    size: usize,
    offset: fuse.off_t,
    fi: *fuse.FuseFileInfo,
) callconv(.c) c_int {
    _ = path;

    const ctx = getContext() orelse return -fuse.EIO;

    // Get handle info
    const handle_info = ctx.handle_manager.getHandle(fi.fh) orelse {
        return -fuse.EBADF;
    };

    // Read from SFTP
    const data = ctx.sftp_client.read(
        handle_info.sftp_handle,
        @intCast(offset),
        @intCast(size),
    ) catch |err| {
        return switch (err) {
            error.EndOfFile => 0,
            error.PermissionDenied => -fuse.EACCES,
            else => -fuse.EIO,
        };
    };
    defer ctx.allocator.free(data);

    // Copy to buffer
    const bytes_read = @min(data.len, size);
    @memcpy(buf[0..bytes_read], data[0..bytes_read]);

    // Update offset
    ctx.handle_manager.updateOffset(fi.fh, @intCast(offset + @as(i64, @intCast(bytes_read))));

    return @intCast(bytes_read);
}

/// Release (close) a file
export fn sshfs_release(path: [*:0]const u8, fi: *fuse.FuseFileInfo) callconv(.c) c_int {
    _ = path;

    const ctx = getContext() orelse return -fuse.EIO;

    // Get handle info
    if (ctx.handle_manager.getHandle(fi.fh)) |handle_info| {
        // Close SFTP handle
        ctx.sftp_client.close(handle_info.sftp_handle) catch {};
    }

    // Release FUSE handle
    ctx.handle_manager.releaseHandle(fi.fh);

    return 0;
}

// ============================================================================
// FUSE Operations - Write Operations
// ============================================================================

/// Write file data
export fn sshfs_write(
    path: [*:0]const u8,
    buf: [*]const u8,
    size: usize,
    offset: fuse.off_t,
    fi: *fuse.FuseFileInfo,
) callconv(.c) c_int {
    _ = path;

    const ctx = getContext() orelse return -fuse.EIO;

    // Get handle info
    const handle_info = ctx.handle_manager.getHandle(fi.fh) orelse {
        return -fuse.EBADF;
    };

    // Write to SFTP
    ctx.sftp_client.write(
        handle_info.sftp_handle,
        @intCast(offset),
        buf[0..size],
    ) catch |err| {
        return switch (err) {
            error.PermissionDenied => -fuse.EACCES,
            else => -fuse.EIO,
        };
    };

    // Invalidate attribute cache for this file
    const path_slice = handle_info.path;
    ctx.attr_cache.invalidate(path_slice);

    return @intCast(size);
}

/// Create and open a file
export fn sshfs_create(
    path: [*:0]const u8,
    mode: fuse.mode_t,
    fi: *fuse.FuseFileInfo,
) callconv(.c) c_int {
    const ctx = getContext() orelse return -fuse.EIO;
    const path_slice = std.mem.span(path);

    // Build remote path
    var path_buf: [4096]u8 = undefined;
    const remote_path = std.fmt.bufPrint(&path_buf, "{s}{s}", .{
        ctx.remote_root,
        path_slice,
    }) catch return -fuse.ENAMETOOLONG;

    // Create file via SFTP
    const pflags = protocol.OpenFlags.SSH_FXF_CREAT |
                   protocol.OpenFlags.SSH_FXF_WRITE |
                   protocol.OpenFlags.SSH_FXF_READ;

    var attrs = attributes.FileAttributes.init();
    _ = attrs.withPermissions(mode);

    const open_flags = protocol.OpenFlags.fromU32(pflags);
    const handle = ctx.sftp_client.open(remote_path, open_flags, attrs) catch |err| {
        return switch (err) {
            error.PermissionDenied => -fuse.EACCES,
            else => -fuse.EIO,
        };
    };

    // Allocate FUSE file handle
    const fh = ctx.handle_manager.allocateHandle(
        handle,
        path_slice,
        @intCast(fi.flags),
    ) catch {
        ctx.sftp_client.close(handle) catch {};
        return -fuse.ENOMEM;
    };

    fi.fh = fh;

    // Invalidate caches
    ctx.attr_cache.invalidate(path_slice);
    if (std.mem.lastIndexOf(u8, path_slice, "/")) |idx| {
        const parent = path_slice[0..idx];
        if (parent.len > 0) {
            ctx.dir_cache.invalidate(parent);
        } else {
            ctx.dir_cache.invalidate("/");
        }
    }

    return 0;
}

/// Change file size
export fn sshfs_truncate(path: [*:0]const u8, size: fuse.off_t) callconv(.c) c_int {
    const ctx = getContext() orelse return -fuse.EIO;
    const path_slice = std.mem.span(path);

    // Build remote path
    var path_buf: [4096]u8 = undefined;
    const remote_path = std.fmt.bufPrint(&path_buf, "{s}{s}", .{
        ctx.remote_root,
        path_slice,
    }) catch return -fuse.ENAMETOOLONG;

    // Set size via SFTP setstat
    var attrs = attributes.FileAttributes.init();
    _ = attrs.withSize(@intCast(size));

    ctx.sftp_client.setstat(remote_path, attrs) catch |err| {
        return switch (err) {
            error.NoSuchFile => -fuse.ENOENT,
            error.PermissionDenied => -fuse.EACCES,
            else => -fuse.EIO,
        };
    };

    // Invalidate attribute cache
    ctx.attr_cache.invalidate(path_slice);

    return 0;
}

// ============================================================================
// FUSE Operations - Directory Operations
// ============================================================================

/// Create a directory
export fn sshfs_mkdir(path: [*:0]const u8, mode: fuse.mode_t) callconv(.c) c_int {
    const ctx = getContext() orelse return -fuse.EIO;
    const path_slice = std.mem.span(path);

    // Build remote path
    var path_buf: [4096]u8 = undefined;
    const remote_path = std.fmt.bufPrint(&path_buf, "{s}{s}", .{
        ctx.remote_root,
        path_slice,
    }) catch return -fuse.ENAMETOOLONG;

    // Create directory via SFTP
    var attrs = attributes.FileAttributes.init();
    _ = attrs.withPermissions(mode | fuse.S_IFDIR);

    ctx.sftp_client.mkdir(remote_path, attrs) catch |err| {
        return switch (err) {
            error.NoSuchFile => -fuse.ENOENT,
            error.PermissionDenied => -fuse.EACCES,
            else => -fuse.EIO,
        };
    };

    // Invalidate parent directory cache
    if (std.mem.lastIndexOf(u8, path_slice, "/")) |idx| {
        const parent = path_slice[0..idx];
        if (parent.len > 0) {
            ctx.dir_cache.invalidate(parent);
        } else {
            ctx.dir_cache.invalidate("/");
        }
    }

    return 0;
}

/// Remove a directory
export fn sshfs_rmdir(path: [*:0]const u8) callconv(.c) c_int {
    const ctx = getContext() orelse return -fuse.EIO;
    const path_slice = std.mem.span(path);

    // Build remote path
    var path_buf: [4096]u8 = undefined;
    const remote_path = std.fmt.bufPrint(&path_buf, "{s}{s}", .{
        ctx.remote_root,
        path_slice,
    }) catch return -fuse.ENAMETOOLONG;

    // Remove directory via SFTP
    ctx.sftp_client.rmdir(remote_path) catch |err| {
        return switch (err) {
            error.NoSuchFile => -fuse.ENOENT,
            error.PermissionDenied => -fuse.EACCES,
            else => -fuse.EIO,
        };
    };

    // Invalidate caches
    ctx.dir_cache.invalidate(path_slice);
    ctx.attr_cache.invalidate(path_slice);
    if (std.mem.lastIndexOf(u8, path_slice, "/")) |idx| {
        const parent = path_slice[0..idx];
        if (parent.len > 0) {
            ctx.dir_cache.invalidate(parent);
        } else {
            ctx.dir_cache.invalidate("/");
        }
    }

    return 0;
}

/// Remove a file
export fn sshfs_unlink(path: [*:0]const u8) callconv(.c) c_int {
    const ctx = getContext() orelse return -fuse.EIO;
    const path_slice = std.mem.span(path);

    // Build remote path
    var path_buf: [4096]u8 = undefined;
    const remote_path = std.fmt.bufPrint(&path_buf, "{s}{s}", .{
        ctx.remote_root,
        path_slice,
    }) catch return -fuse.ENAMETOOLONG;

    // Remove file via SFTP
    ctx.sftp_client.remove(remote_path) catch |err| {
        return switch (err) {
            error.NoSuchFile => -fuse.ENOENT,
            error.PermissionDenied => -fuse.EACCES,
            else => -fuse.EIO,
        };
    };

    // Invalidate caches
    ctx.attr_cache.invalidate(path_slice);
    if (std.mem.lastIndexOf(u8, path_slice, "/")) |idx| {
        const parent = path_slice[0..idx];
        if (parent.len > 0) {
            ctx.dir_cache.invalidate(parent);
        } else {
            ctx.dir_cache.invalidate("/");
        }
    }

    return 0;
}

/// Rename/move a file or directory
export fn sshfs_rename(oldpath: [*:0]const u8, newpath: [*:0]const u8) callconv(.c) c_int {
    const ctx = getContext() orelse return -fuse.EIO;
    const old_slice = std.mem.span(oldpath);
    const new_slice = std.mem.span(newpath);

    // Build remote paths
    var old_buf: [4096]u8 = undefined;
    var new_buf: [4096]u8 = undefined;
    const remote_old = std.fmt.bufPrint(&old_buf, "{s}{s}", .{
        ctx.remote_root,
        old_slice,
    }) catch return -fuse.ENAMETOOLONG;
    const remote_new = std.fmt.bufPrint(&new_buf, "{s}{s}", .{
        ctx.remote_root,
        new_slice,
    }) catch return -fuse.ENAMETOOLONG;

    // Rename via SFTP
    ctx.sftp_client.rename(remote_old, remote_new) catch |err| {
        return switch (err) {
            error.NoSuchFile => -fuse.ENOENT,
            error.PermissionDenied => -fuse.EACCES,
            else => -fuse.EIO,
        };
    };

    // Update inode cache
    ctx.inode_cache.rename(old_slice, new_slice) catch {};

    // Invalidate all affected caches
    ctx.attr_cache.invalidate(old_slice);
    ctx.attr_cache.invalidate(new_slice);
    ctx.dir_cache.invalidate(old_slice);

    // Invalidate parent directories
    if (std.mem.lastIndexOf(u8, old_slice, "/")) |idx| {
        const parent = old_slice[0..idx];
        if (parent.len > 0) {
            ctx.dir_cache.invalidate(parent);
        } else {
            ctx.dir_cache.invalidate("/");
        }
    }
    if (std.mem.lastIndexOf(u8, new_slice, "/")) |idx| {
        const parent = new_slice[0..idx];
        if (parent.len > 0) {
            ctx.dir_cache.invalidate(parent);
        } else {
            ctx.dir_cache.invalidate("/");
        }
    }

    return 0;
}

// ============================================================================
// FUSE Operations - Attribute Operations
// ============================================================================

/// Change file permissions
export fn sshfs_chmod(path: [*:0]const u8, mode: fuse.mode_t) callconv(.c) c_int {
    const ctx = getContext() orelse return -fuse.EIO;
    const path_slice = std.mem.span(path);

    // Build remote path
    var path_buf: [4096]u8 = undefined;
    const remote_path = std.fmt.bufPrint(&path_buf, "{s}{s}", .{
        ctx.remote_root,
        path_slice,
    }) catch return -fuse.ENAMETOOLONG;

    // Set permissions via SFTP
    var attrs = attributes.FileAttributes.init();
    _ = attrs.withPermissions(mode);

    ctx.sftp_client.setstat(remote_path, attrs) catch |err| {
        return switch (err) {
            error.NoSuchFile => -fuse.ENOENT,
            error.PermissionDenied => -fuse.EACCES,
            else => -fuse.EIO,
        };
    };

    // Invalidate attribute cache
    ctx.attr_cache.invalidate(path_slice);

    return 0;
}

/// Change file owner
export fn sshfs_chown(
    path: [*:0]const u8,
    uid: fuse.uid_t,
    gid: fuse.gid_t,
) callconv(.c) c_int {
    const ctx = getContext() orelse return -fuse.EIO;
    const path_slice = std.mem.span(path);

    // Build remote path
    var path_buf: [4096]u8 = undefined;
    const remote_path = std.fmt.bufPrint(&path_buf, "{s}{s}", .{
        ctx.remote_root,
        path_slice,
    }) catch return -fuse.ENAMETOOLONG;

    // Set ownership via SFTP
    var attrs = attributes.FileAttributes.init();
    _ = attrs.withUidGid(uid, gid);

    ctx.sftp_client.setstat(remote_path, attrs) catch |err| {
        return switch (err) {
            error.NoSuchFile => -fuse.ENOENT,
            error.PermissionDenied => -fuse.EACCES,
            else => -fuse.EIO,
        };
    };

    // Invalidate attribute cache
    ctx.attr_cache.invalidate(path_slice);

    return 0;
}

/// Change file timestamps
export fn sshfs_utimens(
    path: [*:0]const u8,
    tv: [*]const fuse.timespec,
) callconv(.c) c_int {
    const ctx = getContext() orelse return -fuse.EIO;
    const path_slice = std.mem.span(path);

    // Build remote path
    var path_buf: [4096]u8 = undefined;
    const remote_path = std.fmt.bufPrint(&path_buf, "{s}{s}", .{
        ctx.remote_root,
        path_slice,
    }) catch return -fuse.ENAMETOOLONG;

    // Extract timestamps
    const atime = tv[0];
    const mtime = tv[1];

    // Set timestamps via SFTP
    var attrs = attributes.FileAttributes.init();
    _ = attrs.withTimes(@intCast(atime.tv_sec), @intCast(mtime.tv_sec));

    ctx.sftp_client.setstat(remote_path, attrs) catch |err| {
        return switch (err) {
            error.NoSuchFile => -fuse.ENOENT,
            error.PermissionDenied => -fuse.EACCES,
            else => -fuse.EIO,
        };
    };

    // Invalidate attribute cache
    ctx.attr_cache.invalidate(path_slice);

    return 0;
}

// ============================================================================
// FUSE Operations Structure
// ============================================================================

/// Complete FUSE operations for read-write SSHFS
pub const sshfs_operations = fuse.FuseOperations{
    // Attribute operations
    .getattr = sshfs_getattr,
    .chmod = sshfs_chmod,
    .chown = sshfs_chown,
    .utimens = sshfs_utimens,
    .truncate = sshfs_truncate,

    // Directory operations
    .readdir = sshfs_readdir,
    .mkdir = sshfs_mkdir,
    .rmdir = sshfs_rmdir,

    // File operations
    .open = sshfs_open,
    .create = sshfs_create,
    .read = sshfs_read,
    .write = sshfs_write,
    .release = sshfs_release,
    .unlink = sshfs_unlink,
    .rename = sshfs_rename,
};
