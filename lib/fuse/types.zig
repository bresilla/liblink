const std = @import("std");

/// FUSE types and constants
///
/// Low-level bindings for FUSE (Filesystem in Userspace)
/// Compatible with libfuse3

// POSIX types
pub const mode_t = u32;
pub const dev_t = u64;
pub const ino_t = u64;
pub const nlink_t = u64;
pub const uid_t = u32;
pub const gid_t = u32;
pub const off_t = i64;
pub const blksize_t = i64;
pub const blkcnt_t = i64;
pub const time_t = i64;

/// File statistics
pub const Stat = extern struct {
    st_dev: dev_t,
    st_ino: ino_t,
    st_nlink: nlink_t,
    st_mode: mode_t,
    st_uid: uid_t,
    st_gid: gid_t,
    __pad0: c_int = 0,
    st_rdev: dev_t,
    st_size: off_t,
    st_blksize: blksize_t,
    st_blocks: blkcnt_t,
    st_atim: timespec,
    st_mtim: timespec,
    st_ctim: timespec,
    __unused: [3]i64 = [_]i64{0} ** 3,

    pub fn init() Stat {
        return std.mem.zeroes(Stat);
    }
};

/// Timespec structure
pub const timespec = extern struct {
    tv_sec: time_t,
    tv_nsec: c_long,
};

/// Filesystem statistics
pub const Statvfs = extern struct {
    f_bsize: c_ulong,
    f_frsize: c_ulong,
    f_blocks: u64,
    f_bfree: u64,
    f_bavail: u64,
    f_files: u64,
    f_ffree: u64,
    f_favail: u64,
    f_fsid: c_ulong,
    f_flag: c_ulong,
    f_namemax: c_ulong,
};

/// File information passed to open/release
pub const FuseFileInfo = extern struct {
    /// Open flags (O_RDONLY, O_WRONLY, O_RDWR)
    flags: c_int,

    /// Old file handle (deprecated)
    fh_old: c_ulong = 0,

    /// Writepage flag
    writepage: c_int = 0,

    /// Direct I/O flag
    direct_io: c_uint = 0,

    /// Keep cache flag
    keep_cache: c_uint = 0,

    /// Flush flag
    flush: c_uint = 0,

    /// Non-seekable flag
    nonseekable: c_uint = 0,

    /// Flock release flag
    flock_release: c_uint = 0,

    /// Padding
    padding: c_uint = 0,

    /// File handle (set by open, used by read/write/release)
    fh: u64 = 0,

    /// Lock owner ID
    lock_owner: u64 = 0,

    /// Requested poll events
    poll_events: u32 = 0,
};

/// Directory entry filler function type
pub const FuseFillDirT = *const fn (
    buf: ?*anyopaque,
    name: [*:0]const u8,
    stbuf: ?*const Stat,
    off: off_t,
) callconv(.C) c_int;

/// Directory entry with offset
pub const FuseDirHandle = opaque {};

/// Connection information
pub const FuseConnInfo = extern struct {
    proto_major: c_uint,
    proto_minor: c_uint,
    max_write: c_uint,
    max_read: c_uint,
    max_readahead: c_uint,
    capable: c_uint,
    want: c_uint,
    max_background: c_uint,
    congestion_threshold: c_uint,
    time_gran: c_uint,
    reserved: [22]u32,
};

/// FUSE context
pub const FuseContext = extern struct {
    fuse: ?*anyopaque,
    uid: uid_t,
    gid: gid_t,
    pid: i32,
    private_data: ?*anyopaque,
    umask: mode_t,
};

// File mode constants
pub const S_IFMT: mode_t = 0o170000;
pub const S_IFSOCK: mode_t = 0o140000;
pub const S_IFLNK: mode_t = 0o120000;
pub const S_IFREG: mode_t = 0o100000;
pub const S_IFBLK: mode_t = 0o060000;
pub const S_IFDIR: mode_t = 0o040000;
pub const S_IFCHR: mode_t = 0o020000;
pub const S_IFIFO: mode_t = 0o010000;

pub const S_ISUID: mode_t = 0o4000;
pub const S_ISGID: mode_t = 0o2000;
pub const S_ISVTX: mode_t = 0o1000;

pub const S_IRWXU: mode_t = 0o0700;
pub const S_IRUSR: mode_t = 0o0400;
pub const S_IWUSR: mode_t = 0o0200;
pub const S_IXUSR: mode_t = 0o0100;

pub const S_IRWXG: mode_t = 0o0070;
pub const S_IRGRP: mode_t = 0o0040;
pub const S_IWGRP: mode_t = 0o0020;
pub const S_IXGRP: mode_t = 0o0010;

pub const S_IRWXO: mode_t = 0o0007;
pub const S_IROTH: mode_t = 0o0004;
pub const S_IWOTH: mode_t = 0o0002;
pub const S_IXOTH: mode_t = 0o0001;

// Mode checking macros as functions
pub fn S_ISREG(m: mode_t) bool {
    return (m & S_IFMT) == S_IFREG;
}

pub fn S_ISDIR(m: mode_t) bool {
    return (m & S_IFMT) == S_IFDIR;
}

pub fn S_ISCHR(m: mode_t) bool {
    return (m & S_IFMT) == S_IFCHR;
}

pub fn S_ISBLK(m: mode_t) bool {
    return (m & S_IFMT) == S_IFBLK;
}

pub fn S_ISFIFO(m: mode_t) bool {
    return (m & S_IFMT) == S_IFIFO;
}

pub fn S_ISLNK(m: mode_t) bool {
    return (m & S_IFMT) == S_IFLNK;
}

pub fn S_ISSOCK(m: mode_t) bool {
    return (m & S_IFMT) == S_IFSOCK;
}

// Errno constants
pub const EPERM: c_int = 1;
pub const ENOENT: c_int = 2;
pub const EIO: c_int = 5;
pub const EBADF: c_int = 9;
pub const ENOMEM: c_int = 12;
pub const EACCES: c_int = 13;
pub const EBUSY: c_int = 16;
pub const EEXIST: c_int = 17;
pub const ENOTDIR: c_int = 20;
pub const EISDIR: c_int = 21;
pub const EINVAL: c_int = 22;
pub const ENOSPC: c_int = 28;
pub const EROFS: c_int = 30;
pub const ENOSYS: c_int = 38;
pub const ENOTEMPTY: c_int = 39;
pub const ENOTSUP: c_int = 95;

// Open flags
pub const O_RDONLY: c_int = 0o0;
pub const O_WRONLY: c_int = 0o1;
pub const O_RDWR: c_int = 0o2;
pub const O_CREAT: c_int = 0o100;
pub const O_EXCL: c_int = 0o200;
pub const O_TRUNC: c_int = 0o1000;
pub const O_APPEND: c_int = 0o2000;

// Access mode flags
pub const R_OK: c_int = 4;
pub const W_OK: c_int = 2;
pub const X_OK: c_int = 1;
pub const F_OK: c_int = 0;

/// Get current timestamp
pub fn getCurrentTime() timespec {
    const ns = std.time.nanoTimestamp();
    return .{
        .tv_sec = @divFloor(ns, std.time.ns_per_s),
        .tv_nsec = @mod(ns, std.time.ns_per_s),
    };
}

/// Convert timestamp to seconds
pub fn timespecToSeconds(ts: timespec) f64 {
    return @as(f64, @floatFromInt(ts.tv_sec)) +
           @as(f64, @floatFromInt(ts.tv_nsec)) / @as(f64, std.time.ns_per_s);
}
