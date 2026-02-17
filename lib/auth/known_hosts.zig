const std = @import("std");

pub fn defaultPath(allocator: std.mem.Allocator) ![]u8 {
    const home = std.process.getEnvVarOwned(allocator, "HOME") catch |err| switch (err) {
        error.EnvironmentVariableNotFound => return error.HomeNotSet,
        else => return err,
    };
    defer allocator.free(home);

    return std.fmt.allocPrint(allocator, "{s}/.ssh/syslink_known_hosts", .{home});
}

pub fn loadFingerprintsForHost(allocator: std.mem.Allocator, host_key: []const u8) ![][]u8 {
    const path = try defaultPath(allocator);
    defer allocator.free(path);

    const file = std.fs.cwd().openFile(path, .{}) catch |err| switch (err) {
        error.FileNotFound => return allocator.alloc([]u8, 0),
        else => return err,
    };
    defer file.close();

    const content = try file.readToEndAlloc(allocator, 512 * 1024);
    defer allocator.free(content);

    var list = std.ArrayListUnmanaged([]u8){};
    errdefer {
        for (list.items) |fp| allocator.free(fp);
        list.deinit(allocator);
    }

    var lines = std.mem.splitScalar(u8, content, '\n');
    while (lines.next()) |line_raw| {
        const line = std.mem.trim(u8, line_raw, &std.ascii.whitespace);
        if (line.len == 0 or line[0] == '#') continue;

        var parts = std.mem.tokenizeScalar(u8, line, ' ');
        const host = parts.next() orelse continue;
        const fingerprint = parts.next() orelse continue;
        if (!std.mem.eql(u8, host, host_key)) continue;

        try list.append(allocator, try allocator.dupe(u8, fingerprint));
    }

    return list.toOwnedSlice(allocator);
}

pub fn freeFingerprints(allocator: std.mem.Allocator, fingerprints: [][]u8) void {
    for (fingerprints) |fp| allocator.free(fp);
    allocator.free(fingerprints);
}

pub fn addFingerprint(allocator: std.mem.Allocator, host_key: []const u8, fingerprint: []const u8) !void {
    const existing = try loadFingerprintsForHost(allocator, host_key);
    defer freeFingerprints(allocator, existing);

    for (existing) |fp| {
        if (std.mem.eql(u8, fp, fingerprint)) return;
    }

    const path = try defaultPath(allocator);
    defer allocator.free(path);

    if (std.fs.path.dirname(path)) |dir| {
        try std.fs.cwd().makePath(dir);
    }

    const file = try std.fs.cwd().createFile(path, .{ .read = true, .truncate = false });
    defer file.close();
    try file.seekFromEnd(0);

    const line = try std.fmt.allocPrint(allocator, "{s} {s}\n", .{ host_key, fingerprint });
    defer allocator.free(line);
    try file.writeAll(line);
}
