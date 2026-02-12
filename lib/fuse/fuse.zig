const std = @import("std");
const types = @import("types.zig");

pub const Stat = types.Stat;
pub const Statvfs = types.Statvfs;
pub const FuseFileInfo = types.FuseFileInfo;
pub const FuseFillDirT = types.FuseFillDirT;
pub const FuseConnInfo = types.FuseConnInfo;
pub const FuseContext = types.FuseContext;
pub const timespec = types.timespec;
pub const mode_t = types.mode_t;
pub const uid_t = types.uid_t;
pub const gid_t = types.gid_t;
pub const off_t = types.off_t;

// Re-export all constants
pub usingnamespace types;

/// FUSE operations structure
///
/// This structure contains function pointers for all filesystem operations.
/// Operations that are not implemented should be set to null.
pub const FuseOperations = extern struct {
    /// Get file attributes (like stat)
    getattr: ?*const fn (
        path: [*:0]const u8,
        stbuf: *Stat,
    ) callconv(.C) c_int = null,

    /// Read symbolic link
    readlink: ?*const fn (
        path: [*:0]const u8,
        buf: [*]u8,
        size: usize,
    ) callconv(.C) c_int = null,

    /// Create a file node (deprecated, use mknod + open + release)
    mknod: ?*const fn (
        path: [*:0]const u8,
        mode: mode_t,
        dev: types.dev_t,
    ) callconv(.C) c_int = null,

    /// Create a directory
    mkdir: ?*const fn (
        path: [*:0]const u8,
        mode: mode_t,
    ) callconv(.C) c_int = null,

    /// Remove a file
    unlink: ?*const fn (
        path: [*:0]const u8,
    ) callconv(.C) c_int = null,

    /// Remove a directory
    rmdir: ?*const fn (
        path: [*:0]const u8,
    ) callconv(.C) c_int = null,

    /// Create a symbolic link
    symlink: ?*const fn (
        target: [*:0]const u8,
        linkpath: [*:0]const u8,
    ) callconv(.C) c_int = null,

    /// Rename a file
    rename: ?*const fn (
        oldpath: [*:0]const u8,
        newpath: [*:0]const u8,
    ) callconv(.C) c_int = null,

    /// Create a hard link
    link: ?*const fn (
        oldpath: [*:0]const u8,
        newpath: [*:0]const u8,
    ) callconv(.C) c_int = null,

    /// Change file permissions
    chmod: ?*const fn (
        path: [*:0]const u8,
        mode: mode_t,
    ) callconv(.C) c_int = null,

    /// Change file owner
    chown: ?*const fn (
        path: [*:0]const u8,
        uid: uid_t,
        gid: gid_t,
    ) callconv(.C) c_int = null,

    /// Change file size
    truncate: ?*const fn (
        path: [*:0]const u8,
        size: off_t,
    ) callconv(.C) c_int = null,

    /// Open a file
    open: ?*const fn (
        path: [*:0]const u8,
        fi: *FuseFileInfo,
    ) callconv(.C) c_int = null,

    /// Read data from a file
    read: ?*const fn (
        path: [*:0]const u8,
        buf: [*]u8,
        size: usize,
        offset: off_t,
        fi: *FuseFileInfo,
    ) callconv(.C) c_int = null,

    /// Write data to a file
    write: ?*const fn (
        path: [*:0]const u8,
        buf: [*]const u8,
        size: usize,
        offset: off_t,
        fi: *FuseFileInfo,
    ) callconv(.C) c_int = null,

    /// Get filesystem statistics
    statfs: ?*const fn (
        path: [*:0]const u8,
        stbuf: *Statvfs,
    ) callconv(.C) c_int = null,

    /// Flush cached data
    flush: ?*const fn (
        path: [*:0]const u8,
        fi: *FuseFileInfo,
    ) callconv(.C) c_int = null,

    /// Release (close) a file
    release: ?*const fn (
        path: [*:0]const u8,
        fi: *FuseFileInfo,
    ) callconv(.C) c_int = null,

    /// Synchronize file contents
    fsync: ?*const fn (
        path: [*:0]const u8,
        datasync: c_int,
        fi: *FuseFileInfo,
    ) callconv(.C) c_int = null,

    /// Set extended attributes
    setxattr: ?*const fn (
        path: [*:0]const u8,
        name: [*:0]const u8,
        value: [*]const u8,
        size: usize,
        flags: c_int,
    ) callconv(.C) c_int = null,

    /// Get extended attributes
    getxattr: ?*const fn (
        path: [*:0]const u8,
        name: [*:0]const u8,
        value: [*]u8,
        size: usize,
    ) callconv(.C) c_int = null,

    /// List extended attributes
    listxattr: ?*const fn (
        path: [*:0]const u8,
        list: [*]u8,
        size: usize,
    ) callconv(.C) c_int = null,

    /// Remove extended attributes
    removexattr: ?*const fn (
        path: [*:0]const u8,
        name: [*:0]const u8,
    ) callconv(.C) c_int = null,

    /// Open a directory
    opendir: ?*const fn (
        path: [*:0]const u8,
        fi: *FuseFileInfo,
    ) callconv(.C) c_int = null,

    /// Read directory contents
    readdir: ?*const fn (
        path: [*:0]const u8,
        buf: ?*anyopaque,
        filler: FuseFillDirT,
        offset: off_t,
        fi: *FuseFileInfo,
    ) callconv(.C) c_int = null,

    /// Release (close) a directory
    releasedir: ?*const fn (
        path: [*:0]const u8,
        fi: *FuseFileInfo,
    ) callconv(.C) c_int = null,

    /// Synchronize directory contents
    fsyncdir: ?*const fn (
        path: [*:0]const u8,
        datasync: c_int,
        fi: *FuseFileInfo,
    ) callconv(.C) c_int = null,

    /// Initialize filesystem
    init: ?*const fn (
        conn: *FuseConnInfo,
    ) callconv(.C) ?*anyopaque = null,

    /// Clean up filesystem
    destroy: ?*const fn (
        private_data: ?*anyopaque,
    ) callconv(.C) void = null,

    /// Check file access permissions
    access: ?*const fn (
        path: [*:0]const u8,
        mask: c_int,
    ) callconv(.C) c_int = null,

    /// Create and open a file
    create: ?*const fn (
        path: [*:0]const u8,
        mode: mode_t,
        fi: *FuseFileInfo,
    ) callconv(.C) c_int = null,

    /// Change file size (with file handle)
    ftruncate: ?*const fn (
        path: [*:0]const u8,
        size: off_t,
        fi: *FuseFileInfo,
    ) callconv(.C) c_int = null,

    /// Get file attributes (with file handle)
    fgetattr: ?*const fn (
        path: [*:0]const u8,
        stbuf: *Stat,
        fi: *FuseFileInfo,
    ) callconv(.C) c_int = null,

    /// Perform POSIX file locking
    lock: ?*const fn (
        path: [*:0]const u8,
        fi: *FuseFileInfo,
        cmd: c_int,
        lock: ?*anyopaque,
    ) callconv(.C) c_int = null,

    /// Change file timestamps
    utimens: ?*const fn (
        path: [*:0]const u8,
        tv: [*]const timespec,
    ) callconv(.C) c_int = null,

    /// Map block index to device block
    bmap: ?*const fn (
        path: [*:0]const u8,
        blocksize: usize,
        idx: *u64,
    ) callconv(.C) c_int = null,

    /// I/O control
    ioctl: ?*const fn (
        path: [*:0]const u8,
        cmd: c_int,
        arg: ?*anyopaque,
        fi: *FuseFileInfo,
        flags: c_uint,
        data: ?*anyopaque,
    ) callconv(.C) c_int = null,

    /// Poll for I/O readiness
    poll: ?*const fn (
        path: [*:0]const u8,
        fi: *FuseFileInfo,
        ph: ?*anyopaque,
        reventsp: *c_uint,
    ) callconv(.C) c_int = null,

    /// Write buffer
    write_buf: ?*const fn (
        path: [*:0]const u8,
        buf: ?*anyopaque,
        offset: off_t,
        fi: *FuseFileInfo,
    ) callconv(.C) c_int = null,

    /// Read buffer
    read_buf: ?*const fn (
        path: [*:0]const u8,
        bufp: ?*anyopaque,
        size: usize,
        offset: off_t,
        fi: *FuseFileInfo,
    ) callconv(.C) c_int = null,

    /// Perform BSD file locking
    flock: ?*const fn (
        path: [*:0]const u8,
        fi: *FuseFileInfo,
        op: c_int,
    ) callconv(.C) c_int = null,

    /// Allocate space for a file
    fallocate: ?*const fn (
        path: [*:0]const u8,
        mode: c_int,
        offset: off_t,
        length: off_t,
        fi: *FuseFileInfo,
    ) callconv(.C) c_int = null,
};

/// FUSE main function
///
/// This is the main entry point for a FUSE filesystem.
/// It parses command-line arguments, mounts the filesystem, and enters the main loop.
pub extern fn fuse_main_real(
    argc: c_int,
    argv: [*c][*c]u8,
    op: *const FuseOperations,
    op_size: usize,
    user_data: ?*anyopaque,
) c_int;

/// Simplified fuse_main wrapper
pub fn fuse_main(
    argc: c_int,
    argv: [*c][*c]u8,
    op: *const FuseOperations,
    user_data: ?*anyopaque,
) c_int {
    return fuse_main_real(argc, argv, op, @sizeOf(FuseOperations), user_data);
}

/// Get the current FUSE context
pub extern fn fuse_get_context() ?*FuseContext;

/// FUSE arguments structure
pub const FuseArgs = extern struct {
    argc: c_int,
    argv: [*c][*c]u8,
    allocated: c_int,
};

/// FUSE option parsing
pub extern fn fuse_opt_parse(
    args: *FuseArgs,
    data: ?*anyopaque,
    opts: ?*const anyopaque,
    proc: ?*const anyopaque,
) c_int;

/// Add argument to FUSE args
pub extern fn fuse_opt_add_arg(args: *FuseArgs, arg: [*:0]const u8) c_int;

/// Free FUSE args
pub extern fn fuse_opt_free_args(args: *FuseArgs) void;
