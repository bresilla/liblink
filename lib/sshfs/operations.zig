const std = @import("std");
const fuse = @import("../fuse/fuse.zig");
const sftp = @import("../sftp/sftp.zig");
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
fn sftpAttrToStat(attr: sftp.protocol.FileAttributes, stbuf: *fuse.Stat) void {
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
export fn sshfs_getattr(path: [*:0]const u8, stbuf: *fuse.Stat) callconv(.C) c_int {
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
) callconv(.C) c_int {
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
            error.NotDirectory => -fuse.ENOTDIR,
            else => -fuse.EIO,
        };
    };
    defer ctx.sftp_client.close(handle) catch {};

    // Read directory entries
    var entries = std.ArrayList(DirCache.DirEntry).init(ctx.allocator);
    defer {
        for (entries.items) |entry| {
            entry.deinit(ctx.allocator);
        }
        entries.deinit();
    }

    // Add . and ..
    _ = filler(buf, ".", null, 0);
    _ = filler(buf, "..", null, 0);

    // Read all entries
    while (true) {
        const entry = ctx.sftp_client.readdir(handle) catch |err| {
            if (err == error.EndOfFile) break;
            return -fuse.EIO;
        };
        defer ctx.allocator.free(entry.filename);
        if (entry.attrs.longname) |ln| {
            ctx.allocator.free(ln);
        }

        // Skip . and ..
        if (std.mem.eql(u8, entry.filename, ".") or
            std.mem.eql(u8, entry.filename, "..")) {
            continue;
        }

        // Add to filler
        const name_z = ctx.allocator.dupeZ(u8, entry.filename) catch {
            continue;
        };
        defer ctx.allocator.free(name_z);

        _ = filler(buf, name_z.ptr, null, 0);

        // Cache entry
        const is_dir = if (entry.attrs.permissions) |perms|
            fuse.S_ISDIR(perms)
        else
            false;

        const cache_entry = DirCache.DirEntry{
            .name = ctx.allocator.dupe(u8, entry.filename) catch continue,
            .is_dir = is_dir,
            .size = entry.attrs.size orelse 0,
            .mtime = @intCast(entry.attrs.mtime orelse 0),
        };
        entries.append(cache_entry) catch continue;
    }

    // Cache directory listing
    ctx.dir_cache.put(path_slice, entries.items) catch {};

    return 0;
}

/// Open a file
export fn sshfs_open(path: [*:0]const u8, fi: *fuse.FuseFileInfo) callconv(.C) c_int {
    const ctx = getContext() orelse return -fuse.EIO;
    const path_slice = std.mem.span(path);

    // Build remote path
    var path_buf: [4096]u8 = undefined;
    const remote_path = std.fmt.bufPrint(&path_buf, "{s}{s}", .{
        ctx.remote_root,
        path_slice,
    }) catch return -fuse.ENAMETOOLONG;

    // Determine SFTP open flags
    var pflags: u32 = sftp.protocol.SSH_FXF_READ;
    if ((fi.flags & fuse.O_WRONLY) != 0 or (fi.flags & fuse.O_RDWR) != 0) {
        pflags = sftp.protocol.SSH_FXF_WRITE;
    }
    if ((fi.flags & fuse.O_RDWR) != 0) {
        pflags = sftp.protocol.SSH_FXF_READ | sftp.protocol.SSH_FXF_WRITE;
    }

    // Open file via SFTP
    const handle = ctx.sftp_client.open(remote_path, pflags, .{}) catch |err| {
        return switch (err) {
            error.NoSuchFile => -fuse.ENOENT,
            error.PermissionDenied => -fuse.EACCES,
            error.IsDirectory => -fuse.EISDIR,
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
) callconv(.C) c_int {
    _ = path;

    const ctx = getContext() orelse return -fuse.EIO;

    // Get handle info
    const handle_info = ctx.handle_manager.getHandle(fi.fh) orelse {
        return -fuse.EBADF;
    };

    // Read from SFTP
    const bytes_read = ctx.sftp_client.read(
        handle_info.sftp_handle,
        @intCast(offset),
        buf[0..size],
    ) catch |err| {
        return switch (err) {
            error.EndOfFile => 0,
            error.PermissionDenied => -fuse.EACCES,
            else => -fuse.EIO,
        };
    };

    // Update offset
    ctx.handle_manager.updateOffset(fi.fh, @intCast(offset + bytes_read));

    return @intCast(bytes_read);
}

/// Release (close) a file
export fn sshfs_release(path: [*:0]const u8, fi: *fuse.FuseFileInfo) callconv(.C) c_int {
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
// FUSE Operations Structure
// ============================================================================

/// FUSE operations for read-only SSHFS
pub const sshfs_operations = fuse.FuseOperations{
    .getattr = sshfs_getattr,
    .readdir = sshfs_readdir,
    .open = sshfs_open,
    .read = sshfs_read,
    .release = sshfs_release,

    // TODO: Add write operations
    // .write = sshfs_write,
    // .mkdir = sshfs_mkdir,
    // .unlink = sshfs_unlink,
    // .rmdir = sshfs_rmdir,
    // .rename = sshfs_rename,
    // .truncate = sshfs_truncate,
    // .chmod = sshfs_chmod,
    // .chown = sshfs_chown,
    // .utimens = sshfs_utimens,
};
