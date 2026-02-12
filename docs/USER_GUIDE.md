# SysLink User Guide

A practical guide to using SysLink for SSH/QUIC connections and file transfers.

## Table of Contents

- [Getting Started](#getting-started)
- [Client Usage](#client-usage)
- [Server Setup](#server-setup)
- [SFTP File Transfer](#sftp-file-transfer)
- [SSHFS Mounting](#sshfs-mounting)
- [Troubleshooting](#troubleshooting)
- [FAQ](#faq)

---

## Getting Started

### Installation

1. **Install Zig 0.15.2+**
   ```bash
   # Download from https://ziglang.org/download/
   wget https://ziglang.org/download/0.15.2/zig-linux-x86_64-0.15.2.tar.xz
   tar xf zig-linux-x86_64-0.15.2.tar.xz
   export PATH=$PATH:$PWD/zig-linux-x86_64-0.15.2
   ```

2. **Clone and Build**
   ```bash
   git clone https://github.com/yourusername/syslink.git
   cd syslink
   zig build
   ```

3. **Verify Installation**
   ```bash
   ./zig-out/bin/sl --version
   ```

### Quick Test

Start a server and connect to it:

```bash
# Terminal 1: Start server
./zig-out/bin/server_demo

# Terminal 2: Connect as client
./zig-out/bin/client_demo
```

---

## Client Usage

### Connecting to a Server

**Password Authentication:**
```bash
./zig-out/bin/sl shell user@hostname:2222
# Enter password when prompted
```

**Public Key Authentication:**
```bash
# Ensure your key is loaded
./zig-out/bin/sl shell -i ~/.ssh/id_ed25519 user@hostname:2222
```

### Running Remote Commands

**Single Command:**
```bash
./zig-out/bin/sl exec user@host "uptime"
./zig-out/bin/sl exec user@host "ls -la /var/log"
```

**Command with Output Redirect:**
```bash
./zig-out/bin/sl exec user@host "cat /etc/hostname" > local_file.txt
```

### Interactive Shell

```bash
./zig-out/bin/sl shell user@host
```

**Note:** Full interactive terminal support (PTY) is not yet implemented. Commands can be executed one at a time.

---

## Server Setup

### Generate Host Key

```bash
# Generate Ed25519 host key
ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ""

# Or use existing OpenSSH host key
ls /etc/ssh/ssh_host_ed25519_key
```

### Start Server

**Using Demo Server:**
```zig
// See examples/server_demo.zig for complete example
var listener = try syslink.connection.startServer(
    allocator,
    "0.0.0.0",      // Listen on all interfaces
    2222,           // Port
    host_key_str,   // Public key string
    &private_key,   // Private key bytes
    random,
);

while (listener.running) {
    const client = try listener.acceptConnection();
    // Handle client in separate thread or sequentially
    handleClient(allocator, client, &listener) catch continue;
}
```

### Configure Authentication

**Password Authentication:**
```zig
fn validatePassword(username: []const u8, password: []const u8) bool {
    // Check against password database
    // Example: simple comparison
    return std.mem.eql(u8, username, "testuser") and
           std.mem.eql(u8, password, "testpass");
}
```

**Public Key Authentication:**
```zig
fn validatePublicKey(
    username: []const u8,
    algorithm: []const u8,
    public_key_blob: []const u8,
) bool {
    // Load authorized_keys and verify
    // Example: allow specific key
    const authorized_key = "AAAAC3NzaC1lZDI1NTE5...";
    return std.mem.eql(u8, algorithm, "ssh-ed25519") and
           std.mem.eql(u8, public_key_blob, authorized_key);
}
```

### Handle Client Sessions

```zig
fn handleClient(
    allocator: std.mem.Allocator,
    connection: *syslink.connection.ServerConnection,
    listener: *syslink.connection.ConnectionListener,
) !void {
    defer listener.removeConnection(connection);

    // Authenticate
    const authed = try connection.handleAuthentication(
        validatePassword,
        validatePublicKey,
    );
    if (!authed) return error.AuthenticationFailed;

    // Create session server
    var session_server = connection.createSessionServer();

    // Accept session channel
    const stream_id: u64 = 4; // First client stream
    try session_server.acceptSession(stream_id);

    // Handle requests
    try session_server.handleRequest(
        stream_id,
        request_data,
        handleShellRequest,
        handleExecRequest,
        handleSubsystemRequest,
    );
}
```

---

## SFTP File Transfer

### Interactive SFTP Session

```bash
./zig-out/bin/sl sftp user@hostname
```

**Common Commands:**
```
sftp> ls /remote/path          # List directory
sftp> cd /remote/path          # Change directory
sftp> pwd                      # Print working directory
sftp> get remote.txt           # Download file
sftp> get remote.txt local.txt # Download with rename
sftp> put local.txt            # Upload file
sftp> put local.txt remote.txt # Upload with rename
sftp> mkdir newdir             # Create directory
sftp> rmdir olddir             # Remove directory
sftp> rm file.txt              # Delete file
sftp> exit                     # Quit
```

### Programmatic SFTP

```zig
// Open SFTP channel
var sftp_channel = try conn.openSftp();
var sftp = try syslink.sftp.SftpClient.init(allocator, sftp_channel);
defer sftp.deinit();

// Upload file
const flags = syslink.sftp.protocol.OpenFlags{
    .write = true,
    .creat = true,
    .trunc = true,
};
const handle = try sftp.open("/remote/file.txt", flags, .{});
defer sftp.close(handle) catch {};

const data = "Hello, SFTP!";
try sftp.write(handle, 0, data);

// Download file
const read_flags = syslink.sftp.protocol.OpenFlags{ .read = true };
const read_handle = try sftp.open("/remote/file.txt", read_flags, .{});
defer sftp.close(read_handle) catch {};

const content = try sftp.read(read_handle, 0, 4096);
defer allocator.free(content);

std.debug.print("File contents: {s}\n", .{content});
```

### Batch File Operations

```zig
// List and process directory
const dir_handle = try sftp.opendir("/remote/path");
defer sftp.close(dir_handle) catch {};

const entries = try sftp.readdir(dir_handle);
defer {
    for (entries) |*entry| {
        entry.deinit(allocator);
    }
    allocator.free(entries);
}

for (entries) |entry| {
    std.debug.print("{s} - {} bytes\n", .{
        entry.filename,
        entry.attrs.size orelse 0,
    });
}
```

---

## SSHFS Mounting

### Mount Remote Filesystem

**Command Line:**
```bash
./zig-out/bin/sshfs user@host:/remote/path /local/mountpoint
```

**With Options:**
```bash
./zig-out/bin/sshfs \
    -o cache_timeout=30 \
    -o allow_other \
    user@host:/remote/path /local/mountpoint
```

**Unmount:**
```bash
fusermount -u /local/mountpoint
# Or on macOS:
umount /local/mountpoint
```

### Programmatic Mounting

```zig
// Connect to server
var conn = try syslink.connection.connectClient(
    allocator,
    "server.example.com",
    2222,
    random,
);
defer conn.deinit();

// Authenticate with public key
const authed = try syslink.sshfs.filesystem.connectWithPublicKey(
    &conn,
    "username",
    "/home/user/.ssh/id_ed25519",
);
if (!authed) return error.AuthenticationFailed;

// Create and mount filesystem
var fs = try syslink.sshfs.filesystem.SshfsFilesystem.init(
    allocator,
    &conn,
    "/mnt/remote",
    .{
        .remote_root = "/home/user",
        .cache_ttl = 10, // 10 second cache
        .allow_other = false,
        .debug = false,
    },
);
defer fs.deinit();

// Mount (blocks until unmounted)
try fs.mount(.{});
```

### Performance Tips

1. **Increase Cache TTL** for read-heavy workloads:
   ```bash
   ./zig-out/bin/sshfs -o cache_timeout=60 user@host:/path /mnt
   ```

2. **Use Local Disk** for temporary files instead of SSHFS

3. **Batch Operations** when possible instead of many small operations

4. **Close Handles** promptly to free resources

---

## Troubleshooting

### Connection Issues

**Problem: "Connection refused"**
```
Solution:
1. Check server is running: netstat -ln | grep 2222
2. Check firewall: sudo ufw allow 2222/udp
3. Verify host/port are correct
```

**Problem: "Connection timeout"**
```
Solution:
1. Check network connectivity: ping server.example.com
2. Verify UDP port 2222 is accessible
3. Check for NAT/firewall blocking UDP
```

### Authentication Issues

**Problem: "Authentication failed"**
```
Solution:
1. Verify credentials are correct
2. Check server logs for auth attempts
3. Ensure password/key validator is configured
4. Verify key format (Ed25519 vs RSA)
```

**Problem: "Public key not accepted"**
```
Solution:
1. Verify key algorithm matches (ssh-ed25519)
2. Check key file permissions (chmod 600 ~/.ssh/id_ed25519)
3. Ensure public key is in authorized_keys on server
4. Use ssh-keygen -l to verify key fingerprint
```

### SFTP Issues

**Problem: "File not found"**
```
Solution:
1. Check path is absolute: /home/user/file.txt
2. Verify remote_root setting if using SSHFS
3. List directory to confirm file exists: sftp> ls
```

**Problem: "Permission denied"**
```
Solution:
1. Check file permissions on server
2. Verify user has access to parent directory
3. Try with sudo on server side if needed
```

### SSHFS Issues

**Problem: "Transport endpoint not connected"**
```
Solution:
1. Unmount first: fusermount -u /mnt/remote
2. Kill stale processes: killall sshfs
3. Remount with debug: sshfs -d user@host:/path /mnt
```

**Problem: "Slow performance"**
```
Solution:
1. Increase cache timeout: -o cache_timeout=60
2. Check network latency: ping server
3. Use compression if available
4. Consider rsync for large transfers
```

### Debug Mode

Enable debug logging:

```zig
// Set log level
std.log.default_level = .debug;

// Or from command line
./zig-out/bin/sl -v shell user@host  // Verbose
./zig-out/bin/sl -vv shell user@host // Very verbose
```

---

## FAQ

**Q: What ports does SSH/QUIC use?**

A: SSH/QUIC uses UDP instead of TCP. Default port is 22, but 2222 is recommended to avoid conflicts with traditional SSH.

**Q: Can I use SSH/QUIC with existing SSH clients?**

A: No, SSH/QUIC uses a different transport (QUIC over UDP) and requires a compatible client. Traditional SSH uses TCP.

**Q: Does SSH/QUIC support port forwarding?**

A: Not yet. TCP forwarding (direct-tcpip) is planned for a future release.

**Q: How do I generate an Ed25519 key?**

A: Use `ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519`

**Q: Can I connect to a traditional SSH server?**

A: No, the server must support SSH/QUIC protocol. This implementation only supports SSH/QUIC servers.

**Q: What's the difference between SFTP and SSHFS?**

A: SFTP is a file transfer protocol (like FTP but over SSH). SSHFS mounts a remote filesystem locally using FUSE, allowing you to use regular file operations (cp, mv, etc.) on remote files.

**Q: Is SSH/QUIC more secure than traditional SSH?**

A: Both provide strong security. SSH/QUIC inherits QUIC's built-in encryption (TLS 1.3) and adds SSH's authentication layer. The main advantage is performance and connection migration, not security.

**Q: Why use SSH/QUIC instead of regular SSH?**

A: Benefits include:
- Faster connection establishment (one-RTT key exchange)
- Better performance over lossy networks
- Connection migration (survives network changes)
- No head-of-line blocking between channels
- Better support for mobile clients

**Q: How do I report bugs?**

A: Open an issue at https://github.com/yourusername/syslink/issues with:
- Zig version (`zig version`)
- OS and version
- Complete error message
- Minimal reproduction steps

---

## Additional Resources

- [API Reference](API.md) - Complete API documentation
- [Architecture](../SPEC.md) - Protocol specification
- [Examples](../examples/) - Code examples
- [README](../README.md) - Project overview

## Getting Help

- GitHub Issues: https://github.com/yourusername/syslink/issues
- Email: [Add contact email]
- Community: [Add Discord/forum link if available]
