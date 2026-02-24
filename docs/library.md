# liblink Library API

liblink is a Zig library implementing the SSH/QUIC protocol stack. It can be used as a dependency in other Zig projects to build custom SSH clients, servers, or tools.

## Adding as a Dependency

In your `build.zig.zon`:

```zig
.dependencies = .{
    .liblink = .{
        .url = "https://github.com/bresilla/liblink/archive/refs/tags/0.0.6.tar.gz",
        .hash = "...",
    },
},
```

In your `build.zig`:

```zig
const liblink_dep = b.dependency("liblink", .{ .target = target, .optimize = optimize });
exe.root_module.addImport("liblink", liblink_dep.module("liblink"));
```

## Modules

```
liblink
  .connection    High-level client/server connection API
  .auth          Authentication (public key, system users)
  .channels      SSH session channels (shell, exec, subsystem)
  .sftp          SFTP v3 client and server
  .crypto        Cryptographic primitives
  .kex           Key exchange state machines
  .protocol      Wire format encoding/decoding
  .network       UDP and QUIC transport
  .platform      Platform-specific (PTY, user lookup)
  .server        Server daemon and session runtime
  .common        Constants and error types
```

## Client Connection

### Basic Connection

```zig
const liblink = @import("liblink");

var prng = std.Random.DefaultPrng.init(@intCast(std.time.milliTimestamp()));

var conn = try liblink.connection.connectClient(
    allocator,
    "192.168.1.10",
    2222,
    prng.random(),
);
defer conn.deinit();
```

### Connection with Host Key Trust

```zig
// Trust-on-first-use (saves fingerprint to ~/.ssh/known_hosts)
var conn = try liblink.connection.connectClientTrusted(
    allocator,
    "192.168.1.10",
    2222,
    prng.random(),
    .accept_new,  // or .strict to require known host
);
defer conn.deinit();
```

### Authentication

```zig
const authenticated = try liblink.auth.workflow.authenticateClient(
    allocator,
    &conn,
    "username",
    .{ .identity_path = "/home/user/.ssh/id_ed25519" },
);
```

## Remote Execution

```zig
// Execute a command
const result = try conn.requestExec("uptime");

// Read output
var buf: [4096]u8 = undefined;
const n = try conn.receiveData(&buf);
std.debug.print("{s}\n", .{buf[0..n]});
```

## Interactive Shell

```zig
// Open session channel
const stream_id = try conn.openSessionChannel();

// Request PTY and shell
try conn.channel_manager.sendRequest(stream_id, "pty-req", pty_data);
try conn.channel_manager.sendRequest(stream_id, "shell", "");

// Send/receive data
try conn.channel_manager.sendData(stream_id, input);
const n = try conn.receiveChannelData(stream_id, &buf);
```

## SFTP

```zig
// Open SFTP subsystem
var sftp_channel = try conn.openSftp();
var sftp = try liblink.sftp.SftpClient.init(allocator, sftp_channel);
defer sftp.deinit();

// List directory
const entries = try liblink.sftp.workflow.listDirectory(allocator, &sftp, "/home/user");
defer allocator.free(entries);

// Download file
try liblink.sftp.workflow.downloadFile(allocator, &sftp, "/remote/file.txt", "/local/file.txt");

// Upload file
try liblink.sftp.workflow.uploadFile(allocator, &sftp, "/local/file.txt", "/remote/file.txt");
```

## Server

### Basic Server

```zig
const host_key_blob = try encodeHostKeyBlob(allocator, &host_public_key);

var listener = try liblink.connection.ConnectionListener.init(
    allocator,
    "0.0.0.0",
    2222,
    host_key_blob,
    &host_private_key,
    random,
);
defer listener.deinit();

// Accept connections
var server_conn = try listener.acceptConnection();
defer server_conn.deinit();

// Authenticate
const auth_ok = try server_conn.handleAuthentication(publickey_validator);
```

### Public Key Validator

The server validates client public keys via a callback:

```zig
fn myValidator(username: []const u8, algorithm: []const u8, public_key_blob: []const u8) bool {
    // Check against authorized_keys, database, etc.
    return liblink.auth.system.validatePublicKey(username, algorithm, public_key_blob);
}
```

`system.validatePublicKey` reads `~/.ssh/authorized_keys` for the given system user, matching the OpenSSH behavior.

## Cryptography

All cryptographic operations use Zig's standard library implementations:

| Operation | Algorithm | Usage |
|-----------|-----------|-------|
| Key exchange | X25519 ECDH | Derive shared secret |
| Signatures | Ed25519 | Host key proof, user auth |
| Encryption | AES-256-GCM | QUIC packet protection |
| Hashing | SHA-256 | Fingerprints, key derivation |
| KDF | HKDF-SHA256 | Derive session keys |

## Architecture

```
Application (sl CLI or custom)
        |
  liblink.connection        ← High-level API
    ├── kex/exchange        ← Key exchange (UDP phase)
    ├── auth/               ← Authentication (QUIC phase)
    ├── channels/manager    ← Channel multiplexing
    ├── sftp/               ← File transfer
    └── network/
        ├── udp             ← Initial handshake
        └── quic_transport  ← Encrypted data (wraps libfast)
                |
            libfast         ← QUIC transport engine
```

## Platform Requirements

- Linux only (uses POSIX PTY, `getpwnam`, `fork`)
- Zig 0.15+
- No external C dependencies beyond libc
