const std = @import("std");
const Allocator = std.mem.Allocator;
const protocol = @import("protocol.zig");
const attributes = @import("attributes.zig");
const wire = @import("../protocol/wire.zig");

/// SFTP Server for handling file transfer operations
///
/// The server manages:
/// - SFTP protocol version negotiation
/// - File and directory handle management
/// - File operations (open, read, write, close)
/// - Directory operations (opendir, readdir, mkdir, rmdir)
/// - File metadata operations (stat, setstat)

pub const SftpServer = struct {
    allocator: Allocator,
    channel: Channel,
    version: u32,
    next_handle_id: u64,
    open_handles: std.AutoHashMap(u64, OpenHandle),

    /// SSH channel for SFTP communication
    pub const Channel = @import("channel_adapter.zig").SftpChannel;

    /// Initialize SFTP server and perform version negotiation
    pub fn init(allocator: Allocator, channel: Channel) !SftpServer {
        var server = SftpServer{
            .allocator = allocator,
            .channel = channel,
            .version = 0,
            .next_handle_id = 1,
            .open_handles = std.AutoHashMap(u64, OpenHandle).init(allocator),
        };

        // Receive INIT from client
        const init_data = try server.channel.receive(allocator);
        defer allocator.free(init_data);

        const init_msg = try protocol.Init.decode(init_data);

        // Negotiate version (use minimum of client and server)
        server.version = @min(init_msg.version, protocol.SFTP_VERSION);

        // Send VERSION response
        const extensions: []const []const u8 = &.{};
        const version_msg = protocol.Version{
            .version = server.version,
            .extensions = extensions,
        };
        const version_packet = try version_msg.encode(allocator);
        defer allocator.free(version_packet);
        try server.channel.send(version_packet);

        std.log.info("SFTP server initialized, version {}", .{server.version});

        return server;
    }

    /// Clean up server resources
    pub fn deinit(self: *SftpServer) void {
        // Close all open handles
        var it = self.open_handles.valueIterator();
        while (it.next()) |handle| {
            handle.close();
        }
        self.open_handles.deinit();
        self.channel.deinit();
    }

    /// Process incoming SFTP requests in a loop
    pub fn run(self: *SftpServer) !void {
        while (true) {
            const request_data = self.channel.receive(self.allocator) catch |err| {
                if (err == error.EndOfStream or err == error.ConnectionClosed) {
                    std.log.info("SFTP session ended", .{});
                    return;
                }
                return err;
            };
            defer self.allocator.free(request_data);

            self.handleRequest(request_data) catch |err| {
                std.log.err("Error handling SFTP request: {}", .{err});
                // Continue processing other requests
            };
        }
    }

    /// Handle a single SFTP request
    pub fn handleRequest(self: *SftpServer, request_data: []const u8) !void {
        if (request_data.len < 5) return error.InvalidRequest;

        const packet_type_byte = request_data[4];
        const packet_type: protocol.PacketType = @enumFromInt(packet_type_byte);

        switch (packet_type) {
            .SSH_FXP_OPEN => try self.handleOpen(request_data),
            .SSH_FXP_CLOSE => try self.handleClose(request_data),
            .SSH_FXP_READ => try self.handleRead(request_data),
            .SSH_FXP_WRITE => try self.handleWrite(request_data),
            .SSH_FXP_OPENDIR => try self.handleOpendir(request_data),
            .SSH_FXP_READDIR => try self.handleReaddir(request_data),
            .SSH_FXP_STAT => try self.handleStat(request_data),
            .SSH_FXP_LSTAT => try self.handleLstat(request_data),
            .SSH_FXP_FSTAT => try self.handleFstat(request_data),
            .SSH_FXP_MKDIR => try self.handleMkdir(request_data),
            .SSH_FXP_RMDIR => try self.handleRmdir(request_data),
            .SSH_FXP_REMOVE => try self.handleRemove(request_data),
            .SSH_FXP_REALPATH => try self.handleRealpath(request_data),
            .SSH_FXP_RENAME => try self.handleRename(request_data),
            .SSH_FXP_SETSTAT => try self.handleSetstat(request_data),
            .SSH_FXP_FSETSTAT => try self.handleFsetstat(request_data),
            else => {
                std.log.warn("Unsupported SFTP operation: {}", .{packet_type});
                // Send unsupported operation status
                const request_id = std.mem.readInt(u32, request_data[5..9], .big);
                try self.sendStatus(request_id, .SSH_FX_OP_UNSUPPORTED, "Operation not supported", "");
            },
        }
    }

    // ========================================================================
    // Request Handlers
    // ========================================================================

    fn handleOpen(self: *SftpServer, request_data: []const u8) !void {
        var reader = wire.Reader{ .buffer = request_data };
        _ = try reader.readUint32(); // length
        _ = try reader.readByte(); // packet type
        const request_id = try reader.readUint32();
        const filename = try reader.readString(self.allocator);
        defer self.allocator.free(filename);
        const pflags = try reader.readUint32();
        const flags = protocol.OpenFlags.fromU32(pflags);

        // Read attributes (we'll use default attributes for now)
        _ = try attributes.FileAttributes.decode(self.allocator, reader.buffer[reader.offset..]);

        std.log.info("SFTP OPEN: path={s}, flags={}", .{ filename, pflags });

        // Open the file
        const handle_id = self.openFile(filename, flags) catch |err| {
            const status_code = statusFromError(err);
            const msg = @errorName(err);
            try self.sendStatus(request_id, status_code, msg, "");
            return;
        };

        // Send handle response
        const handle_str = try self.handleIdToString(handle_id);
        defer self.allocator.free(handle_str);

        const handle_msg = protocol.Handle{
            .request_id = request_id,
            .handle = handle_str,
        };
        const response = try handle_msg.encode(self.allocator);
        defer self.allocator.free(response);
        try self.channel.send(response);
    }

    fn handleClose(self: *SftpServer, request_data: []const u8) !void {
        var reader = wire.Reader{ .buffer = request_data };
        _ = try reader.readUint32(); // length
        _ = try reader.readByte(); // packet type
        const request_id = try reader.readUint32();
        const handle_str = try reader.readString(self.allocator);
        defer self.allocator.free(handle_str);

        const handle_id = try self.handleStringToId(handle_str);

        std.log.info("SFTP CLOSE: handle={}", .{handle_id});

        if (self.open_handles.fetchRemove(handle_id)) |entry| {
            entry.value.close();
            try self.sendStatus(request_id, .SSH_FX_OK, "Success", "");
        } else {
            try self.sendStatus(request_id, .SSH_FX_FAILURE, "Invalid handle", "");
        }
    }

    fn handleRead(self: *SftpServer, request_data: []const u8) !void {
        var reader = wire.Reader{ .buffer = request_data };
        _ = try reader.readUint32(); // length
        _ = try reader.readByte(); // packet type
        const request_id = try reader.readUint32();
        const handle_str = try reader.readString(self.allocator);
        defer self.allocator.free(handle_str);
        const offset = try reader.readUint64();
        const len = try reader.readUint32();

        const handle_id = try self.handleStringToId(handle_str);

        std.log.debug("SFTP READ: handle={}, offset={}, len={}", .{ handle_id, offset, len });

        const handle = self.open_handles.get(handle_id) orelse {
            try self.sendStatus(request_id, .SSH_FX_FAILURE, "Invalid handle", "");
            return;
        };

        if (handle != .file) {
            try self.sendStatus(request_id, .SSH_FX_FAILURE, "Handle is not a file", "");
            return;
        }

        // Read from file
        const data = handle.file.readAt(self.allocator, offset, len) catch |err| {
            const status_code = statusFromError(err);
            const msg = @errorName(err);
            try self.sendStatus(request_id, status_code, msg, "");
            return;
        };
        defer self.allocator.free(data);

        // Send data response
        const data_msg = protocol.Data{
            .request_id = request_id,
            .data = data,
        };
        const response = try data_msg.encode(self.allocator);
        defer self.allocator.free(response);
        try self.channel.send(response);
    }

    fn handleWrite(self: *SftpServer, request_data: []const u8) !void {
        var reader = wire.Reader{ .buffer = request_data };
        _ = try reader.readUint32(); // length
        _ = try reader.readByte(); // packet type
        const request_id = try reader.readUint32();
        const handle_str = try reader.readString(self.allocator);
        defer self.allocator.free(handle_str);
        const offset = try reader.readUint64();
        const data = try reader.readString(self.allocator);
        defer self.allocator.free(data);

        const handle_id = try self.handleStringToId(handle_str);

        std.log.debug("SFTP WRITE: handle={}, offset={}, len={}", .{ handle_id, offset, data.len });

        const handle = self.open_handles.get(handle_id) orelse {
            try self.sendStatus(request_id, .SSH_FX_FAILURE, "Invalid handle", "");
            return;
        };

        if (handle != .file) {
            try self.sendStatus(request_id, .SSH_FX_FAILURE, "Handle is not a file", "");
            return;
        }

        // Write to file
        handle.file.writeAt(offset, data) catch |err| {
            const status_code = statusFromError(err);
            const msg = @errorName(err);
            try self.sendStatus(request_id, status_code, msg, "");
            return;
        };

        try self.sendStatus(request_id, .SSH_FX_OK, "Success", "");
    }

    fn handleOpendir(self: *SftpServer, request_data: []const u8) !void {
        var reader = wire.Reader{ .buffer = request_data };
        _ = try reader.readUint32(); // length
        _ = try reader.readByte(); // packet type
        const request_id = try reader.readUint32();
        const path = try reader.readString(self.allocator);
        defer self.allocator.free(path);

        std.log.info("SFTP OPENDIR: path={s}", .{path});

        // Open directory
        const handle_id = self.openDirectory(path) catch |err| {
            const status_code = statusFromError(err);
            const msg = @errorName(err);
            try self.sendStatus(request_id, status_code, msg, "");
            return;
        };

        // Send handle response
        const handle_str = try self.handleIdToString(handle_id);
        defer self.allocator.free(handle_str);

        const handle_msg = protocol.Handle{
            .request_id = request_id,
            .handle = handle_str,
        };
        const response = try handle_msg.encode(self.allocator);
        defer self.allocator.free(response);
        try self.channel.send(response);
    }

    fn handleReaddir(self: *SftpServer, request_data: []const u8) !void {
        var reader = wire.Reader{ .buffer = request_data };
        _ = try reader.readUint32(); // length
        _ = try reader.readByte(); // packet type
        const request_id = try reader.readUint32();
        const handle_str = try reader.readString(self.allocator);
        defer self.allocator.free(handle_str);

        const handle_id = try self.handleStringToId(handle_str);

        std.log.debug("SFTP READDIR: handle={}", .{handle_id});

        const handle = self.open_handles.get(handle_id) orelse {
            try self.sendStatus(request_id, .SSH_FX_FAILURE, "Invalid handle", "");
            return;
        };

        if (handle != .directory) {
            try self.sendStatus(request_id, .SSH_FX_FAILURE, "Handle is not a directory", "");
            return;
        }

        // Read directory entries
        const entries = handle.directory.readEntries(self.allocator) catch |err| {
            // EOF indicates no more entries
            if (err == error.EndOfStream) {
                try self.sendStatus(request_id, .SSH_FX_EOF, "End of directory", "");
                return;
            }
            const status_code = statusFromError(err);
            const msg = @errorName(err);
            try self.sendStatus(request_id, status_code, msg, "");
            return;
        };
        defer {
            for (entries) |entry| {
                self.allocator.free(entry.filename);
                self.allocator.free(entry.longname);
            }
            self.allocator.free(entries);
        }

        // Send NAME response
        try self.sendNameResponse(request_id, entries);
    }

    fn handleStat(self: *SftpServer, request_data: []const u8) !void {
        var reader = wire.Reader{ .buffer = request_data };
        _ = try reader.readUint32(); // length
        _ = try reader.readByte(); // packet type
        const request_id = try reader.readUint32();
        const path = try reader.readString(self.allocator);
        defer self.allocator.free(path);

        std.log.debug("SFTP STAT: path={s}", .{path});

        const attrs = self.getFileAttributes(path, true) catch |err| {
            const status_code = statusFromError(err);
            const msg = @errorName(err);
            try self.sendStatus(request_id, status_code, msg, "");
            return;
        };

        try self.sendAttrsResponse(request_id, attrs);
    }

    fn handleLstat(self: *SftpServer, request_data: []const u8) !void {
        var reader = wire.Reader{ .buffer = request_data };
        _ = try reader.readUint32(); // length
        _ = try reader.readByte(); // packet type
        const request_id = try reader.readUint32();
        const path = try reader.readString(self.allocator);
        defer self.allocator.free(path);

        std.log.debug("SFTP LSTAT: path={s}", .{path});

        // LSTAT doesn't follow symlinks
        const attrs = self.getFileAttributes(path, false) catch |err| {
            const status_code = statusFromError(err);
            const msg = @errorName(err);
            try self.sendStatus(request_id, status_code, msg, "");
            return;
        };

        try self.sendAttrsResponse(request_id, attrs);
    }

    fn handleFstat(self: *SftpServer, request_data: []const u8) !void {
        var reader = wire.Reader{ .buffer = request_data };
        _ = try reader.readUint32(); // length
        _ = try reader.readByte(); // packet type
        const request_id = try reader.readUint32();
        const handle_str = try reader.readString(self.allocator);
        defer self.allocator.free(handle_str);

        const handle_id = try self.handleStringToId(handle_str);

        std.log.debug("SFTP FSTAT: handle={}", .{handle_id});

        const handle = self.open_handles.get(handle_id) orelse {
            try self.sendStatus(request_id, .SSH_FX_FAILURE, "Invalid handle", "");
            return;
        };

        const attrs = switch (handle) {
            .file => |f| try f.getAttributes(),
            .directory => |d| try d.getAttributes(),
        };

        try self.sendAttrsResponse(request_id, attrs);
    }

    fn handleMkdir(self: *SftpServer, request_data: []const u8) !void {
        var reader = wire.Reader{ .buffer = request_data };
        _ = try reader.readUint32(); // length
        _ = try reader.readByte(); // packet type
        const request_id = try reader.readUint32();
        const path = try reader.readString(self.allocator);
        defer self.allocator.free(path);

        std.log.info("SFTP MKDIR: path={s}", .{path});

        std.fs.cwd().makeDir(path) catch |err| {
            const status_code = statusFromError(err);
            const msg = @errorName(err);
            try self.sendStatus(request_id, status_code, msg, "");
            return;
        };

        try self.sendStatus(request_id, .SSH_FX_OK, "Success", "");
    }

    fn handleRmdir(self: *SftpServer, request_data: []const u8) !void {
        var reader = wire.Reader{ .buffer = request_data };
        _ = try reader.readUint32(); // length
        _ = try reader.readByte(); // packet type
        const request_id = try reader.readUint32();
        const path = try reader.readString(self.allocator);
        defer self.allocator.free(path);

        std.log.info("SFTP RMDIR: path={s}", .{path});

        std.fs.cwd().deleteDir(path) catch |err| {
            const status_code = statusFromError(err);
            const msg = @errorName(err);
            try self.sendStatus(request_id, status_code, msg, "");
            return;
        };

        try self.sendStatus(request_id, .SSH_FX_OK, "Success", "");
    }

    fn handleRemove(self: *SftpServer, request_data: []const u8) !void {
        var reader = wire.Reader{ .buffer = request_data };
        _ = try reader.readUint32(); // length
        _ = try reader.readByte(); // packet type
        const request_id = try reader.readUint32();
        const filename = try reader.readString(self.allocator);
        defer self.allocator.free(filename);

        std.log.info("SFTP REMOVE: path={s}", .{filename});

        std.fs.cwd().deleteFile(filename) catch |err| {
            const status_code = statusFromError(err);
            const msg = @errorName(err);
            try self.sendStatus(request_id, status_code, msg, "");
            return;
        };

        try self.sendStatus(request_id, .SSH_FX_OK, "Success", "");
    }

    fn handleRealpath(self: *SftpServer, request_data: []const u8) !void {
        var reader = wire.Reader{ .buffer = request_data };
        _ = try reader.readUint32(); // length
        _ = try reader.readByte(); // packet type
        const request_id = try reader.readUint32();
        const path = try reader.readString(self.allocator);
        defer self.allocator.free(path);

        std.log.debug("SFTP REALPATH: path={s}", .{path});

        // For simplicity, we'll just return the path as-is
        // In production, this should resolve to absolute path
        const realpath = if (std.fs.path.isAbsolute(path))
            try self.allocator.dupe(u8, path)
        else
            try std.fs.cwd().realpathAlloc(self.allocator, path);
        defer self.allocator.free(realpath);

        const entries = try self.allocator.alloc(DirEntry, 1);
        defer self.allocator.free(entries);

        entries[0] = DirEntry{
            .filename = realpath,
            .longname = realpath,
            .attrs = attributes.FileAttributes{},
        };

        try self.sendNameResponse(request_id, entries);
    }

    fn handleRename(self: *SftpServer, request_data: []const u8) !void {
        var reader = wire.Reader{ .buffer = request_data };
        _ = try reader.readUint32(); // length
        _ = try reader.readByte(); // packet type
        const request_id = try reader.readUint32();
        const oldpath = try reader.readString(self.allocator);
        defer self.allocator.free(oldpath);
        const newpath = try reader.readString(self.allocator);
        defer self.allocator.free(newpath);

        std.log.info("SFTP RENAME: {s} -> {s}", .{ oldpath, newpath });

        std.fs.cwd().rename(oldpath, newpath) catch |err| {
            const status_code = statusFromError(err);
            const msg = @errorName(err);
            try self.sendStatus(request_id, status_code, msg, "");
            return;
        };

        try self.sendStatus(request_id, .SSH_FX_OK, "Success", "");
    }

    fn handleSetstat(self: *SftpServer, request_data: []const u8) !void {
        var reader = wire.Reader{ .buffer = request_data };
        _ = try reader.readUint32(); // length
        _ = try reader.readByte(); // packet type
        const request_id = try reader.readUint32();
        const path = try reader.readString(self.allocator);
        defer self.allocator.free(path);

        std.log.debug("SFTP SETSTAT: path={s}", .{path});

        // For now, we'll just acknowledge without actually setting attributes
        // Full implementation would parse and apply the attributes
        try self.sendStatus(request_id, .SSH_FX_OK, "Success", "");
    }

    fn handleFsetstat(self: *SftpServer, request_data: []const u8) !void {
        var reader = wire.Reader{ .buffer = request_data };
        _ = try reader.readUint32(); // length
        _ = try reader.readByte(); // packet type
        const request_id = try reader.readUint32();
        const handle_str = try reader.readString(self.allocator);
        defer self.allocator.free(handle_str);

        const handle_id = try self.handleStringToId(handle_str);

        std.log.debug("SFTP FSETSTAT: handle={}", .{handle_id});

        if (!self.open_handles.contains(handle_id)) {
            try self.sendStatus(request_id, .SSH_FX_FAILURE, "Invalid handle", "");
            return;
        }

        // For now, just acknowledge
        try self.sendStatus(request_id, .SSH_FX_OK, "Success", "");
    }

    // ========================================================================
    // Helper Functions
    // ========================================================================

    fn openFile(self: *SftpServer, path: []const u8, flags: protocol.OpenFlags) !u64 {
        const handle_id = self.next_handle_id;
        self.next_handle_id += 1;

        const file_handle = try FileHandle.open(path, flags);
        try self.open_handles.put(handle_id, .{ .file = file_handle });

        return handle_id;
    }

    fn openDirectory(self: *SftpServer, path: []const u8) !u64 {
        const handle_id = self.next_handle_id;
        self.next_handle_id += 1;

        const dir_handle = try DirectoryHandle.open(self.allocator, path);
        try self.open_handles.put(handle_id, .{ .directory = dir_handle });

        return handle_id;
    }

    fn getFileAttributes(self: *SftpServer, path: []const u8, follow_symlinks: bool) !attributes.FileAttributes {
        _ = self;
        _ = follow_symlinks;

        const stat = try std.fs.cwd().statFile(path);

        return attributes.FileAttributes{
            .size = @intCast(stat.size),
            .permissions = @intCast(@intFromEnum(stat.mode)),
            .atime = @intCast(@divFloor(stat.atime, 1_000_000_000)),
            .mtime = @intCast(@divFloor(stat.mtime, 1_000_000_000)),
        };
    }

    fn handleIdToString(self: *SftpServer, id: u64) ![]u8 {
        const str = try std.fmt.allocPrint(self.allocator, "{x:0>16}", .{id});
        return str;
    }

    fn handleStringToId(self: *SftpServer, str: []const u8) !u64 {
        _ = self;
        return std.fmt.parseInt(u64, str, 16);
    }

    fn sendStatus(
        self: *SftpServer,
        request_id: u32,
        status_code: protocol.StatusCode,
        message: []const u8,
        lang: []const u8,
    ) !void {
        const status = protocol.Status{
            .request_id = request_id,
            .status_code = status_code,
            .error_message = message,
            .language_tag = lang,
        };
        const response = try status.encode(self.allocator);
        defer self.allocator.free(response);
        try self.channel.send(response);
    }

    fn sendAttrsResponse(self: *SftpServer, request_id: u32, attrs: attributes.FileAttributes) !void {
        const attrs_data = try attrs.encode(self.allocator);
        defer self.allocator.free(attrs_data);

        const packet_size = 4 + 1 + 4 + attrs_data.len;
        const packet = try self.allocator.alloc(u8, packet_size);
        defer self.allocator.free(packet);

        var writer = wire.Writer{ .buffer = packet };
        try writer.writeUint32(@intCast(packet_size - 4));
        try writer.writeByte(@intFromEnum(protocol.PacketType.SSH_FXP_ATTRS));
        try writer.writeUint32(request_id);
        @memcpy(packet[writer.offset..][0..attrs_data.len], attrs_data);

        try self.channel.send(packet);
    }

    fn sendNameResponse(self: *SftpServer, request_id: u32, entries: []const DirEntry) !void {
        // Calculate packet size
        var packet_size: usize = 4 + 1 + 4 + 4; // length + type + request_id + count
        for (entries) |entry| {
            packet_size += 4 + entry.filename.len; // filename
            packet_size += 4 + entry.longname.len; // longname
            const attrs_data = try entry.attrs.encode(self.allocator);
            defer self.allocator.free(attrs_data);
            packet_size += attrs_data.len;
        }

        const packet = try self.allocator.alloc(u8, packet_size);
        defer self.allocator.free(packet);

        var writer = wire.Writer{ .buffer = packet };
        try writer.writeUint32(@intCast(packet_size - 4));
        try writer.writeByte(@intFromEnum(protocol.PacketType.SSH_FXP_NAME));
        try writer.writeUint32(request_id);
        try writer.writeUint32(@intCast(entries.len));

        for (entries) |entry| {
            try writer.writeString(entry.filename);
            try writer.writeString(entry.longname);
            const attrs_data = try entry.attrs.encode(self.allocator);
            defer self.allocator.free(attrs_data);
            @memcpy(packet[writer.offset..][0..attrs_data.len], attrs_data);
            writer.offset += attrs_data.len;
        }

        try self.channel.send(packet);
    }
};

// ============================================================================
// Handle Management
// ============================================================================

const OpenHandle = union(enum) {
    file: FileHandle,
    directory: DirectoryHandle,

    fn close(self: *OpenHandle) void {
        switch (self.*) {
            .file => |*f| f.close(),
            .directory => |*d| d.close(),
        }
    }
};

const FileHandle = struct {
    file: std.fs.File,

    fn open(path: []const u8, flags: protocol.OpenFlags) !FileHandle {
        const open_flags: std.fs.File.OpenFlags = .{
            .mode = if (flags.read and !flags.write) .read_only else if (flags.write) .read_write else .read_only,
        };

        const file = if (flags.creat) blk: {
            const create_flags: std.fs.File.CreateFlags = .{
                .read = flags.read,
                .truncate = flags.trunc,
                .exclusive = flags.excl,
            };
            break :blk try std.fs.cwd().createFile(path, create_flags);
        } else blk: {
            break :blk try std.fs.cwd().openFile(path, open_flags);
        };

        return FileHandle{ .file = file };
    }

    fn close(self: *FileHandle) void {
        self.file.close();
    }

    fn readAt(self: *FileHandle, allocator: Allocator, offset: u64, len: u32) ![]u8 {
        const buffer = try allocator.alloc(u8, len);
        errdefer allocator.free(buffer);

        const bytes_read = try self.file.preadAll(buffer, offset);

        // Return only the bytes actually read
        if (bytes_read < len) {
            if (bytes_read == 0) {
                allocator.free(buffer);
                return error.EndOfStream;
            }
            const trimmed = try allocator.realloc(buffer, bytes_read);
            return trimmed;
        }

        return buffer;
    }

    fn writeAt(self: *FileHandle, offset: u64, data: []const u8) !void {
        try self.file.pwriteAll(data, offset);
    }

    fn getAttributes(self: *FileHandle) !attributes.FileAttributes {
        const stat = try self.file.stat();
        return attributes.FileAttributes{
            .size = @intCast(stat.size),
            .permissions = @intCast(@intFromEnum(stat.mode)),
            .atime = @intCast(@divFloor(stat.atime, 1_000_000_000)),
            .mtime = @intCast(@divFloor(stat.mtime, 1_000_000_000)),
        };
    }
};

const DirectoryHandle = struct {
    allocator: Allocator,
    dir: std.fs.Dir,
    iterator: ?std.fs.Dir.Iterator,

    fn open(allocator: Allocator, path: []const u8) !DirectoryHandle {
        const dir = try std.fs.cwd().openDir(path, .{ .iterate = true });
        return DirectoryHandle{
            .allocator = allocator,
            .dir = dir,
            .iterator = null,
        };
    }

    fn close(self: *DirectoryHandle) void {
        self.dir.close();
    }

    fn readEntries(self: *DirectoryHandle, allocator: Allocator) ![]DirEntry {
        // Initialize iterator if not already done
        if (self.iterator == null) {
            self.iterator = self.dir.iterate();
        }

        // Read up to 64 entries per request (typical batch size)
        var entries = std.ArrayList(DirEntry).init(allocator);
        errdefer {
            for (entries.items) |entry| {
                allocator.free(entry.filename);
                allocator.free(entry.longname);
            }
            entries.deinit();
        }

        var count: usize = 0;
        while (count < 64) : (count += 1) {
            const entry = try self.iterator.?.next() orelse {
                if (count == 0) return error.EndOfStream;
                break;
            };

            const filename = try allocator.dupe(u8, entry.name);
            errdefer allocator.free(filename);

            // Create longname (ls -l style)
            const kind_char: u8 = switch (entry.kind) {
                .directory => 'd',
                .file => '-',
                .sym_link => 'l',
                else => '?',
            };
            const longname = try std.fmt.allocPrint(allocator, "{c}rw-r--r-- 1 user group 0 Jan  1 00:00 {s}", .{ kind_char, entry.name });

            // Get attributes
            const stat = self.dir.statFile(entry.name) catch blk: {
                break :blk std.fs.File.Stat{
                    .size = 0,
                    .mode = std.fs.File.Mode.fromFlags(.{}, .{}),
                    .atime = 0,
                    .mtime = 0,
                    .ctime = 0,
                    .kind = entry.kind,
                    .inode = 0,
                };
            };

            const attrs = attributes.FileAttributes{
                .size = @intCast(stat.size),
                .permissions = @intCast(@intFromEnum(stat.mode)),
                .atime = @intCast(@divFloor(stat.atime, 1_000_000_000)),
                .mtime = @intCast(@divFloor(stat.mtime, 1_000_000_000)),
            };

            try entries.append(DirEntry{
                .filename = filename,
                .longname = longname,
                .attrs = attrs,
            });
        }

        return entries.toOwnedSlice();
    }

    fn getAttributes(self: *DirectoryHandle) !attributes.FileAttributes {
        const stat = try self.dir.stat();
        return attributes.FileAttributes{
            .size = @intCast(stat.size),
            .permissions = @intCast(@intFromEnum(stat.mode)),
            .atime = @intCast(@divFloor(stat.atime, 1_000_000_000)),
            .mtime = @intCast(@divFloor(stat.mtime, 1_000_000_000)),
        };
    }
};

const DirEntry = struct {
    filename: []const u8,
    longname: []const u8,
    attrs: attributes.FileAttributes,
};

// ============================================================================
// Error Mapping
// ============================================================================

fn statusFromError(err: anyerror) protocol.StatusCode {
    return switch (err) {
        error.FileNotFound => .SSH_FX_NO_SUCH_FILE,
        error.AccessDenied => .SSH_FX_PERMISSION_DENIED,
        error.EndOfStream => .SSH_FX_EOF,
        else => .SSH_FX_FAILURE,
    };
}

// ============================================================================
// Tests
// ============================================================================

test "SftpServer - statusFromError mapping" {
    const testing = std.testing;

    try testing.expectEqual(protocol.StatusCode.SSH_FX_NO_SUCH_FILE, statusFromError(error.FileNotFound));
    try testing.expectEqual(protocol.StatusCode.SSH_FX_PERMISSION_DENIED, statusFromError(error.AccessDenied));
    try testing.expectEqual(protocol.StatusCode.SSH_FX_EOF, statusFromError(error.EndOfStream));
    try testing.expectEqual(protocol.StatusCode.SSH_FX_FAILURE, statusFromError(error.OutOfMemory));
}

test "SftpServer - handle ID to string conversion" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Mock server for testing
    var open_handles = std.AutoHashMap(u64, OpenHandle).init(allocator);
    defer open_handles.deinit();

    var server = SftpServer{
        .allocator = allocator,
        .channel = undefined,
        .version = 3,
        .next_handle_id = 1,
        .open_handles = open_handles,
    };

    const id: u64 = 0x123456789ABCDEF0;
    const str = try server.handleIdToString(id);
    defer allocator.free(str);

    try testing.expectEqualStrings("123456789abcdef0", str);

    const parsed_id = try server.handleStringToId(str);
    try testing.expectEqual(id, parsed_id);
}
