const std = @import("std");
const c = @cImport({
    @cInclude("fcntl.h");
    @cInclude("sys/stat.h");
    @cInclude("unistd.h");
});

pub fn pidFilePath(allocator: std.mem.Allocator) ![]u8 {
    const uid = std.posix.getuid();
    const runtime_dir = std.process.getEnvVarOwned(allocator, "XDG_RUNTIME_DIR") catch |err| switch (err) {
        error.EnvironmentVariableNotFound => null,
        else => return err,
    };
    defer if (runtime_dir) |dir| allocator.free(dir);

    if (runtime_dir) |dir| {
        return std.fmt.allocPrint(allocator, "{s}/syslink-server-{}.pid", .{ dir, uid });
    }
    return std.fmt.allocPrint(allocator, "/tmp/syslink-server-{}.pid", .{uid});
}

pub fn writePidFile(allocator: std.mem.Allocator, pid: std.process.Child.Id) !void {
    const pid_file = try pidFilePath(allocator);
    defer allocator.free(pid_file);

    var file = try std.fs.cwd().createFile(pid_file, .{ .truncate = true, .mode = 0o600 });
    defer file.close();

    var buffer: [32]u8 = undefined;
    const pid_text = try std.fmt.bufPrint(&buffer, "{}\n", .{pid});
    try file.writeAll(pid_text);
}

fn validatePidFile(path: []const u8, allocator: std.mem.Allocator) !void {
    const path_z = try allocator.dupeZ(u8, path);
    defer allocator.free(path_z);

    const fd = c.open(path_z.ptr, c.O_RDONLY | c.O_NOFOLLOW | c.O_CLOEXEC);
    if (fd < 0) return error.FileNotFound;
    defer _ = c.close(fd);

    var st: c.struct_stat = undefined;
    if (c.fstat(fd, &st) != 0) return error.FileNotFound;

    if (st.st_uid != std.posix.getuid()) {
        return error.InvalidPidFileOwner;
    }

    if ((st.st_mode & 0o022) != 0) {
        return error.InsecurePidFilePermissions;
    }
}

pub fn readPidFile(allocator: std.mem.Allocator) !std.posix.pid_t {
    const pid_file = try pidFilePath(allocator);
    defer allocator.free(pid_file);

    try validatePidFile(pid_file, allocator);

    const file = try std.fs.cwd().openFile(pid_file, .{});
    defer file.close();

    const content = try file.readToEndAlloc(allocator, 64);
    defer allocator.free(content);

    const trimmed = std.mem.trim(u8, content, &std.ascii.whitespace);
    return try std.fmt.parseInt(std.posix.pid_t, trimmed, 10);
}

pub fn removePidFile(allocator: std.mem.Allocator) void {
    const pid_file = pidFilePath(allocator) catch return;
    defer allocator.free(pid_file);
    std.fs.cwd().deleteFile(pid_file) catch {};
}

pub fn processAlive(pid: std.posix.pid_t) bool {
    std.posix.kill(pid, 0) catch |err| {
        return err == error.PermissionDenied;
    };
    return true;
}
