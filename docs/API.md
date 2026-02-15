# SysLink API Reference

This reference covers the active public API areas: connection, authentication, channels, and SFTP.

## Connection

```zig
pub fn connectClient(
    allocator: Allocator,
    host: []const u8,
    port: u16,
    random: std.Random,
) !ClientConnection
```

```zig
pub fn startServer(
    allocator: Allocator,
    listen_addr: []const u8,
    listen_port: u16,
    host_key: []const u8,
    host_private_key: *const [64]u8,
    random: std.Random,
) !ConnectionListener
```

## Authentication

- `ClientConnection.authenticatePassword`
- `ClientConnection.authenticatePublicKey`
- `ServerConnection.handleAuthentication`

## Channels

- `ClientConnection.openSession`
- `ClientConnection.requestShell`
- `ClientConnection.requestExec`
- `ClientConnection.requestSubsystem`

## SFTP Client API

Initialize client:

```zig
pub fn init(allocator: Allocator, channel: SftpChannel) !SftpClient
```

Main operations:

- `open`, `close`, `read`, `write`
- `opendir`, `readdir`
- `mkdir`, `rmdir`, `remove`, `rename`
- `stat`, `lstat`, `setstat`, `fsetstat`
- `realpath`, `readlink`, `symlink`

## SFTP Server API

Initialize server:

```zig
pub fn init(allocator: Allocator, channel: Channel) !SftpServer
```

Initialize with root jail:

```zig
pub fn initWithOptions(
    allocator: Allocator,
    channel: Channel,
    options: SftpServer.Options,
) !SftpServer
```

```zig
pub const Options = struct {
    remote_root: []const u8 = ".",
};
```

Request processing:

```zig
pub fn run(self: *SftpServer) !void
pub fn handleRequest(self: *SftpServer, request_data: []const u8) !void
```
