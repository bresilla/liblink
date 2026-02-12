# SysLink API Reference

Complete API documentation for the SysLink SSH/QUIC library.

## Table of Contents

- [Connection API](#connection-api)
- [Authentication API](#authentication-api)
- [Channel API](#channel-api)
- [SFTP Client API](#sftp-client-api)
- [SFTP Server API](#sftp-server-api)
- [SSHFS API](#sshfs-api)
- [Cryptography API](#cryptography-api)
- [Protocol Types](#protocol-types)

---

## Connection API

### Client Connection

#### `connectClient`

Connect to an SSH/QUIC server.

```zig
pub fn connectClient(
    allocator: Allocator,
    host: []const u8,
    port: u16,
    random: std.Random,
) !ClientConnection
```

**Parameters:**
- `allocator` - Memory allocator
- `host` - Server hostname or IP address
- `port` - Server port (default: 22, recommended: 2222 for SSH/QUIC)
- `random` - Random number generator for key generation

**Returns:** `ClientConnection` instance

**Example:**
```zig
var prng = std.Random.DefaultPrng.init(12345);
var conn = try syslink.connection.connectClient(
    allocator,
    "server.example.com",
    2222,
    prng.random(),
);
defer conn.deinit();
```

#### `ClientConnection.deinit`

Clean up connection resources.

```zig
pub fn deinit(self: *Self) void
```

**Example:**
```zig
defer conn.deinit();
```

### Server Connection

#### `startServer`

Start an SSH/QUIC server.

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

**Parameters:**
- `allocator` - Memory allocator
- `listen_addr` - Address to bind to (e.g., "0.0.0.0", "::")
- `listen_port` - Port to listen on
- `host_key` - Server's public host key (SSH format string)
- `host_private_key` - Server's private key (64 bytes for Ed25519)
- `random` - Random number generator

**Returns:** `ConnectionListener` instance

**Example:**
```zig
var listener = try syslink.connection.startServer(
    allocator,
    "0.0.0.0",
    2222,
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5...",
    &host_private_key,
    random,
);
defer listener.deinit();
```

#### `ConnectionListener.acceptConnection`

Accept a new client connection.

```zig
pub fn acceptConnection(self: *Self) !*ServerConnection
```

**Returns:** Pointer to accepted connection

**Example:**
```zig
const client = try listener.acceptConnection();
// Handle client...
listener.removeConnection(client);
```

#### `ConnectionListener.shutdown`

Initiate graceful server shutdown.

```zig
pub fn shutdown(self: *Self) void
```

---

## Authentication API

### Client Authentication

#### `authenticatePassword`

Authenticate using username and password.

```zig
pub fn authenticatePassword(
    self: *Self,
    username: []const u8,
    password: []const u8,
) !bool
```

**Returns:** `true` if authentication succeeded

**Example:**
```zig
const authed = try conn.authenticatePassword("user", "password");
if (!authed) return error.AuthenticationFailed;
```

#### `authenticatePublicKey`

Authenticate using SSH public key.

```zig
pub fn authenticatePublicKey(
    self: *Self,
    username: []const u8,
    algorithm_name: []const u8,
    public_key: []const u8,
    private_key: []const u8,
) !bool
```

**Parameters:**
- `username` - Username to authenticate as
- `algorithm_name` - Key algorithm (e.g., "ssh-ed25519")
- `public_key` - Public key bytes
- `private_key` - Private key bytes (64 bytes for Ed25519)

**Example:**
```zig
const authed = try conn.authenticatePublicKey(
    "user",
    "ssh-ed25519",
    &public_key_bytes,
    &private_key_bytes,
);
```

### Server Authentication

#### `handleAuthentication`

Handle client authentication request (server-side).

```zig
pub fn handleAuthentication(
    self: *Self,
    password_validator: ?PasswordValidator,
    publickey_validator: ?PublicKeyValidator,
) !bool
```

**Callback Types:**
```zig
const PasswordValidator = fn(username: []const u8, password: []const u8) bool;
const PublicKeyValidator = fn(
    username: []const u8,
    algorithm: []const u8,
    public_key_blob: []const u8,
) bool;
```

**Example:**
```zig
const authed = try server_conn.handleAuthentication(
    validatePassword,
    validatePublicKey,
);

fn validatePassword(username: []const u8, password: []const u8) bool {
    return std.mem.eql(u8, username, "testuser") and
           std.mem.eql(u8, password, "testpass");
}
```

---

## Channel API

### Opening Channels

#### `openChannel`

Open a new channel (client-side).

```zig
pub fn openChannel(
    self: *Self,
    channel_type: []const u8,
    type_specific_data: []const u8,
) !u64
```

**Returns:** Stream ID of the opened channel

**Common channel types:**
- `"session"` - Interactive session
- `"direct-tcpip"` - TCP forwarding (not yet implemented)

#### `acceptChannel`

Accept incoming channel (server-side).

```zig
pub fn acceptChannel(self: *Self) !u64
```

**Returns:** Stream ID of the accepted channel

### Channel Operations

#### `sendData`

Send data on a channel.

```zig
pub fn sendData(self: *Self, channel_id: u64, data: []const u8) !void
```

#### `receiveData`

Receive data from a channel.

```zig
pub fn receiveData(self: *Self, channel_id: u64, buffer: []u8) !usize
```

**Returns:** Number of bytes received

---

## SFTP Client API

### Initialization

#### `SftpClient.init`

Initialize SFTP client over a channel.

```zig
pub fn init(allocator: Allocator, channel: Channel) !SftpClient
```

**Example:**
```zig
var sftp_channel = try conn.openSftp();
var sftp = try syslink.sftp.SftpClient.init(allocator, sftp_channel);
defer sftp.deinit();
```

### File Operations

#### `open`

Open a file.

```zig
pub fn open(
    self: *SftpClient,
    path: []const u8,
    flags: OpenFlags,
    attrs: FileAttributes,
) !Handle
```

**Example:**
```zig
const flags = syslink.sftp.protocol.OpenFlags{ .read = true };
const handle = try sftp.open("/remote/file.txt", flags, .{});
defer sftp.close(handle) catch {};
```

#### `read`

Read from a file.

```zig
pub fn read(
    self: *SftpClient,
    handle: Handle,
    offset: u64,
    len: u32,
) ![]u8
```

**Returns:** Allocated buffer with file data (caller must free)

#### `write`

Write to a file.

```zig
pub fn write(
    self: *SftpClient,
    handle: Handle,
    offset: u64,
    data: []const u8,
) !void
```

#### `close`

Close a file or directory handle.

```zig
pub fn close(self: *SftpClient, handle: Handle) !void
```

### Directory Operations

#### `opendir`

Open a directory for listing.

```zig
pub fn opendir(self: *SftpClient, path: []const u8) !Handle
```

#### `readdir`

Read directory entries.

```zig
pub fn readdir(self: *SftpClient, handle: Handle) ![]DirEntry
```

**Returns:** Allocated array of directory entries (caller must free)

#### `mkdir`

Create a directory.

```zig
pub fn mkdir(self: *SftpClient, path: []const u8, attrs: FileAttributes) !void
```

#### `rmdir`

Remove a directory.

```zig
pub fn rmdir(self: *SftpClient, path: []const u8) !void
```

#### `remove`

Remove a file.

```zig
pub fn remove(self: *SftpClient, path: []const u8) !void
```

### File Metadata

#### `stat`

Get file attributes (follows symlinks).

```zig
pub fn stat(self: *SftpClient, path: []const u8) !FileAttributes
```

#### `lstat`

Get file attributes (doesn't follow symlinks).

```zig
pub fn lstat(self: *SftpClient, path: []const u8) !FileAttributes
```

---

## SFTP Server API

### Initialization

#### `SftpServer.init`

Initialize SFTP server over a channel.

```zig
pub fn init(allocator: Allocator, channel: Channel) !SftpServer
```

**Example:**
```zig
var sftp_server = try syslink.sftp.SftpServer.init(allocator, channel);
defer sftp_server.deinit();
```

### Request Processing

#### `run`

Process SFTP requests in a loop (blocking).

```zig
pub fn run(self: *SftpServer) !void
```

**Example:**
```zig
try sftp_server.run(); // Blocks until connection closes
```

#### `handleRequest`

Handle a single SFTP request.

```zig
pub fn handleRequest(self: *SftpServer, request_data: []const u8) !void
```

---

## SSHFS API

### Filesystem Mounting

#### `SshfsFilesystem.init`

Initialize SSHFS filesystem.

```zig
pub fn init(
    allocator: Allocator,
    conn: *connection.ClientConnection,
    mount_point: []const u8,
    opts: Options,
) !SshfsFilesystem
```

**Options:**
```zig
pub const Options = struct {
    remote_root: []const u8 = "/",
    cache_ttl: u64 = 5, // seconds
    debug: bool = false,
    allow_other: bool = false,
};
```

**Example:**
```zig
var fs = try syslink.sshfs.filesystem.SshfsFilesystem.init(
    allocator,
    &conn,
    "/mnt/remote",
    .{ .remote_root = "/home/user", .cache_ttl = 10 },
);
defer fs.deinit();
```

#### `mount`

Mount the filesystem (blocking).

```zig
pub fn mount(self: *Self, opts: Options) !void
```

#### `connectWithPublicKey`

Authenticate SSHFS connection with public key.

```zig
pub fn connectWithPublicKey(
    conn: *connection.ClientConnection,
    username: []const u8,
    key_path: []const u8,
) !bool
```

**Example:**
```zig
const authed = try syslink.sshfs.filesystem.connectWithPublicKey(
    &conn,
    "username",
    "/home/user/.ssh/id_ed25519",
);
```

---

## Cryptography API

### Key Exchange

See `lib/kex/exchange.zig` for:
- `ClientKeyExchange` - Client-side key exchange
- `ServerKeyExchange` - Server-side key exchange

### Signatures

```zig
// Sign data with Ed25519
pub fn signEd25519(data: []const u8, private_key: *const [64]u8) [64]u8

// Verify Ed25519 signature
pub fn verifyEd25519(
    data: []const u8,
    signature: *const [64]u8,
    public_key: *const [32]u8,
) bool
```

### Key Derivation

```zig
// HKDF-SHA256 key derivation
pub fn hkdfSha256(
    ikm: []const u8,
    salt: []const u8,
    info: []const u8,
    out: []u8,
) !void
```

---

## Protocol Types

### OpenFlags (SFTP)

```zig
pub const OpenFlags = packed struct(u32) {
    read: bool = false,
    write: bool = false,
    append: bool = false,
    creat: bool = false,
    trunc: bool = false,
    excl: bool = false,
};
```

### FileAttributes (SFTP)

```zig
pub const FileAttributes = struct {
    size: ?u64 = null,
    uid: ?u32 = null,
    gid: ?u32 = null,
    permissions: ?u32 = null,
    atime: ?u32 = null,
    mtime: ?u32 = null,
    flags: AttrFlags = .{},
};
```

### Handle (SFTP)

```zig
pub const Handle = struct {
    data: []const u8,
};
```

### StatusCode (SFTP)

```zig
pub const StatusCode = enum(u32) {
    SSH_FX_OK = 0,
    SSH_FX_EOF = 1,
    SSH_FX_NO_SUCH_FILE = 2,
    SSH_FX_PERMISSION_DENIED = 3,
    SSH_FX_FAILURE = 4,
    // ...
};
```

---

## Error Handling

All API functions return Zig error unions. Common errors:

```zig
// Connection errors
error.ConnectionFailed
error.Timeout
error.NetworkUnreachable

// Authentication errors
error.AuthenticationFailed
error.InvalidCredentials

// SFTP errors
error.NoSuchFile
error.PermissionDenied
error.FileAlreadyExists

// General errors
error.OutOfMemory
error.InvalidArgument
error.NotImplemented
```

**Example:**
```zig
const result = sftp.open("/path/to/file", flags, .{}) catch |err| {
    switch (err) {
        error.NoSuchFile => std.debug.print("File not found\n", .{}),
        error.PermissionDenied => std.debug.print("Access denied\n", .{}),
        else => return err,
    }
};
```

---

## Best Practices

### Resource Management

Always use `defer` for cleanup:

```zig
var conn = try syslink.connection.connectClient(...);
defer conn.deinit();

var sftp = try syslink.sftp.SftpClient.init(...);
defer sftp.deinit();

const handle = try sftp.open(...);
defer sftp.close(handle) catch {};
```

### Error Handling

Check authentication results:

```zig
const authed = try conn.authenticatePassword("user", "pass");
if (!authed) {
    std.log.err("Authentication failed", .{});
    return error.AuthenticationFailed;
}
```

### Memory Safety

Free allocated buffers:

```zig
const data = try sftp.read(handle, 0, 1024);
defer allocator.free(data);

const entries = try sftp.readdir(dir_handle);
defer {
    for (entries) |*entry| {
        entry.deinit(allocator);
    }
    allocator.free(entries);
}
```

### Concurrent Operations

For multiple concurrent operations, spawn threads or use async:

```zig
// Spawn thread for background server
const thread = try std.Thread.spawn(.{}, serverLoop, .{&listener});
thread.detach();
```

---

## Complete Examples

See `examples/` directory for complete working examples:
- `client_demo.zig` - Client connection and SFTP usage
- `server_demo.zig` - Server implementation with authentication

## Further Reading

- [Protocol Specification](../SPEC.md)
- [Implementation Status](../IMPLEMENTATION_STATUS.md)
- [Testing Guide](../TESTING.md)
- [README](../README.md)
