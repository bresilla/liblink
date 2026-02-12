const std = @import("std");
const fuse = @import("../fuse/fuse.zig");
const sftp = @import("../sftp/sftp.zig");
const connection = @import("../connection.zig");
const InodeCache = @import("inode_cache.zig").InodeCache;
const HandleManager = @import("handle_manager.zig").HandleManager;
const DirCache = @import("dir_cache.zig").DirCache;
const AttrCache = @import("attr_cache.zig").AttrCache;
const operations = @import("operations.zig");

/// SSH Filesystem
///
/// Main SSHFS implementation that mounts a remote directory via SFTP.
pub const SshFilesystem = struct {
    allocator: std.mem.Allocator,
    connection: *connection.ClientConnection,
    sftp_client: sftp.client.SftpClient,
    inode_cache: InodeCache,
    handle_manager: HandleManager,
    dir_cache: DirCache,
    attr_cache: AttrCache,
    context: operations.SshfsContext,

    /// Remote root path
    remote_root: []const u8,

    /// Local mount point
    mount_point: []const u8,

    const Self = @This();

    /// Configuration options
    pub const Options = struct {
        /// Cache TTL in seconds (default: 5)
        cache_ttl: u64 = 5,

        /// Remote root directory (default: "/")
        remote_root: []const u8 = "/",

        /// FUSE options
        allow_other: bool = false,
        allow_root: bool = false,
        debug: bool = false,
    };

    /// Initialize SSHFS filesystem
    pub fn init(
        allocator: std.mem.Allocator,
        conn: *connection.ClientConnection,
        mount_point: []const u8,
        opts: Options,
    ) !Self {
        // Duplicate paths for storage
        const remote_root = try allocator.dupe(u8, opts.remote_root);
        errdefer allocator.free(remote_root);

        const mount_point_copy = try allocator.dupe(u8, mount_point);
        errdefer allocator.free(mount_point_copy);

        // Open SFTP channel and initialize client
        const sftp_channel = try conn.openSftp();
        const sftp_client = try sftp.client.SftpClient.init(allocator, sftp_channel);
        errdefer sftp_client.deinit();

        // Initialize caching layers
        const inode_cache = InodeCache.init(allocator);
        const handle_manager = HandleManager.init(allocator);
        const dir_cache = DirCache.init(allocator, opts.cache_ttl);
        const attr_cache = AttrCache.init(allocator, opts.cache_ttl);

        var self = Self{
            .allocator = allocator,
            .connection = conn,
            .sftp_client = sftp_client,
            .inode_cache = inode_cache,
            .handle_manager = handle_manager,
            .dir_cache = dir_cache,
            .attr_cache = attr_cache,
            .context = undefined,
            .remote_root = remote_root,
            .mount_point = mount_point_copy,
        };

        // Initialize context
        self.context = operations.SshfsContext{
            .allocator = allocator,
            .sftp_client = &self.sftp_client,
            .inode_cache = &self.inode_cache,
            .handle_manager = &self.handle_manager,
            .dir_cache = &self.dir_cache,
            .attr_cache = &self.attr_cache,
            .remote_root = self.remote_root,
            .mutex = .{},
        };

        return self;
    }

    pub fn deinit(self: *Self) void {
        self.allocator.free(self.remote_root);
        self.allocator.free(self.mount_point);
        self.attr_cache.deinit();
        self.dir_cache.deinit();
        self.handle_manager.deinit();
        self.inode_cache.deinit();
        self.sftp_client.deinit();
    }

    /// Mount the filesystem
    pub fn mount(self: *Self, opts: Options) !void {
        // Build FUSE arguments
        var args = std.ArrayListUnmanaged([]const u8){};
        defer args.deinit(self.allocator);

        // Program name
        try args.append(self.allocator, "sshfs");

        // Mount point
        try args.append(self.allocator, self.mount_point);

        // FUSE options
        try args.append(self.allocator, "-f"); // Foreground

        if (opts.debug) {
            try args.append(self.allocator, "-d"); // Debug
        }

        if (opts.allow_other) {
            try args.append(self.allocator, "-o");
            try args.append(self.allocator, "allow_other");
        }

        if (opts.allow_root) {
            try args.append(self.allocator, "-o");
            try args.append(self.allocator, "allow_root");
        }

        // Convert to C-style argv
        var argv = try self.allocator.alloc([*c]u8, args.items.len);
        defer self.allocator.free(argv);

        for (args.items, 0..) |arg, i| {
            const arg_z = try self.allocator.dupeZ(u8, arg);
            argv[i] = @constCast(arg_z.ptr);
        }
        defer {
            for (argv) |arg| {
                self.allocator.free(std.mem.span(arg));
            }
        }

        // Call fuse_main
        const argc: c_int = @intCast(args.items.len);
        const result = fuse.fuse_main(
            argc,
            @ptrCast(argv.ptr),
            &operations.sshfs_operations,
            &self.context,
        );

        if (result != 0) {
            return error.FuseMountFailed;
        }
    }

    /// Unmount the filesystem
    pub fn unmount(self: *Self) !void {
        // Build fusermount command
        var argv = [_][]const u8{
            "fusermount",
            "-u",
            self.mount_point,
        };

        var child = std.process.Child.init(&argv, self.allocator);
        const result = try child.spawnAndWait();

        if (result.Exited != 0) {
            return error.UnmountFailed;
        }
    }

    /// Clean expired cache entries
    pub fn cleanCaches(self: *Self) void {
        self.dir_cache.cleanExpired();
        self.attr_cache.cleanExpired();
    }

    /// Invalidate all caches
    pub fn invalidateCaches(self: *Self) void {
        self.dir_cache.clear();
        self.attr_cache.clear();
    }

    /// Get filesystem statistics
    pub fn getStats(self: *Self) Stats {
        return Stats{
            .cached_inodes = self.inode_cache.count(),
            .open_handles = self.handle_manager.count(),
            .cached_dirs = self.dir_cache.count(),
            .cached_attrs = self.attr_cache.count(),
        };
    }

    pub const Stats = struct {
        cached_inodes: usize,
        open_handles: usize,
        cached_dirs: usize,
        cached_attrs: usize,
    };
};

// ============================================================================
// Convenience Functions
// ============================================================================

/// Mount remote directory over SSH
pub fn mount(
    allocator: std.mem.Allocator,
    hostname: []const u8,
    port: u16,
    username: []const u8,
    password: []const u8,
    remote_path: []const u8,
    mount_point: []const u8,
    opts: SshFilesystem.Options,
) !void {
    // Create SSH connection
    const random = std.crypto.random;
    var conn = try connection.connectClient(
        allocator,
        hostname,
        port,
        random,
    );
    defer conn.deinit();

    // Authenticate
    const auth_success = try conn.authenticatePassword(username, password);
    if (!auth_success) {
        return error.AuthenticationFailed;
    }

    // Create filesystem
    var fs_opts = opts;
    fs_opts.remote_root = remote_path;

    var fs = try SshFilesystem.init(allocator, &conn, mount_point, fs_opts);
    defer fs.deinit();

    // Mount
    try fs.mount(opts);
}

// TODO: Implement public key authentication
// Need to parse SSH key file format and call authenticatePublicKey with:
// - algorithm_name (e.g. "ssh-ed25519")
// - public_key_blob
// - private_key (64 bytes for Ed25519)
