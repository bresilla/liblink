# SysLink - SSH/QUIC Implementation

A complete implementation of the SSH/QUIC protocol in Zig, providing secure remote access and file transfer over QUIC transport.

## Features

- ✅ **SSH/QUIC Protocol** - Full implementation of draft-denis-ssh-quic
- ✅ **Modern Cryptography** - Ed25519 signatures, X25519 key exchange, HKDF-SHA256
- ✅ **QUIC Transport** - UDP-based multiplexed transport via zquic
- ✅ **SSH Authentication** - Password and public key authentication
- ✅ **Session Channels** - Shell, command execution, and subsystems
- ✅ **SFTP v3** - Complete file transfer protocol implementation
- ✅ **CLI Tool** - Command-line interface for SSH/SFTP operations

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/syslink.git
cd syslink

# Build the project
zig build

# Run tests
zig build test
```

### Usage

**Connect to SSH server:**
```bash
./zig-out/bin/sl shell user@example.com:2222
```

**Execute remote command:**
```bash
./zig-out/bin/sl exec user@host "ls -la"
```

**Transfer files with SFTP:**
```bash
./zig-out/bin/sl sftp user@example.com
sftp> ls /home/user
sftp> get remote.txt local.txt
sftp> put local.txt remote.txt
```

## Library Usage

### Basic Connection

```zig
const std = @import("std");
const syslink = @import("voidbox");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var prng = std.Random.DefaultPrng.init(12345);
    const random = prng.random();

    // Connect to server
    var conn = try syslink.connection.connectClient(
        allocator,
        "server.example.com",
        2222,
        random,
    );
    defer conn.deinit();

    // Authenticate
    const authed = try conn.authenticatePassword("username", "password");
    if (!authed) return error.AuthenticationFailed;

    std.debug.print("Connected and authenticated!\n", .{});
}
```

### Command Execution

```zig
// Execute remote command
var session = try conn.requestExec("uptime");
defer session.close() catch {};

// Read output
const output = try session.receiveData();
defer allocator.free(output);

std.debug.print("Output: {s}\n", .{output});
```

### SFTP File Operations

```zig
// Open SFTP session
var sftp_channel = try conn.openSftp();
defer sftp_channel.deinit();

var sftp = try syslink.sftp.SftpClient.init(allocator, sftp_channel);
defer sftp.deinit();

// List directory
const dir_handle = try sftp.opendir("/home/user");
defer sftp.close(dir_handle) catch {};

const entries = try sftp.readdir(dir_handle);
defer {
    for (entries) |*entry| {
        entry.deinit(allocator);
    }
    allocator.free(entries);
}

for (entries) |entry| {
    std.debug.print("{s}\n", .{entry.filename});
}

// Read file
const flags = syslink.sftp.protocol.OpenFlags{ .read = true };
const handle = try sftp.open("/remote/file.txt", flags, .{});
defer sftp.close(handle) catch {};

const data = try sftp.read(handle, 0, 1024);
defer allocator.free(data);

std.debug.print("File contents: {s}\n", .{data});
```

## Architecture

```
┌─────────────────────────────────────────────┐
│           Application Layer                 │
│  (CLI Tool, SFTP Client, Shell Session)    │
└─────────────────┬───────────────────────────┘
                  │
┌─────────────────┴───────────────────────────┐
│            SSH Channels                     │
│  (Session, Shell, Exec, Subsystem)         │
└─────────────────┬───────────────────────────┘
                  │
┌─────────────────┴───────────────────────────┐
│        SSH Authentication                   │
│  (Password, Public Key, None)              │
└─────────────────┬───────────────────────────┘
                  │
┌─────────────────┴───────────────────────────┐
│         QUIC Transport                      │
│  (Stream multiplexing, Flow control)       │
└─────────────────┬───────────────────────────┘
                  │
┌─────────────────┴───────────────────────────┐
│      SSH/QUIC Key Exchange                  │
│  (SSH_QUIC_INIT/REPLY over UDP)           │
└─────────────────┬───────────────────────────┘
                  │
┌─────────────────┴───────────────────────────┐
│          UDP Transport                      │
│  (Datagram send/receive)                   │
└─────────────────────────────────────────────┘
```

## Protocol Compliance

### SSH/QUIC (draft-denis-ssh-quic)

- **Key Exchange** - SSH_QUIC_INIT/REPLY messages over UDP
- **Secret Derivation** - HKDF-based QUIC secret derivation from SSH exchange hash
- **Channel Mapping** - QUIC streams map directly to SSH channels
- **Modified Messages** - Channel IDs removed (stream ID serves this purpose)
- **Flow Control** - Delegated to QUIC (no SSH_MSG_CHANNEL_WINDOW_ADJUST)

### SSH Protocol Suite

- **Authentication (RFC 4252)** - Password and public key methods
- **Connection Protocol (RFC 4254)** - Session channels, shell, exec, subsystem
- **File Transfer (draft-ietf-secsh-filexfer)** - SFTP v3 complete implementation

### Cryptography

- **Signatures** - Ed25519 (RFC 8032)
- **Key Exchange** - X25519 (RFC 7748)
- **Hashing** - SHA-256
- **Key Derivation** - HKDF-SHA256 (RFC 5869)

## Project Structure

```
syslink/
├── lib/                    # Library implementation
│   ├── voidbox.zig        # Main entry point
│   ├── connection.zig     # Connection management
│   ├── auth/              # Authentication
│   ├── channels/          # SSH channels
│   ├── crypto/            # Cryptographic primitives
│   ├── kex/               # Key exchange
│   ├── network/           # Networking (UDP)
│   ├── protocol/          # Protocol messages
│   ├── sftp/              # SFTP implementation
│   └── transport/         # QUIC transport
├── bin/                   # Executables
│   └── sl.zig            # CLI tool
├── examples/              # Example programs
│   ├── client_demo.zig   # Client demonstration
│   └── server_demo.zig   # Server demonstration
├── tests/                 # Test suite
├── build.zig             # Build configuration
├── SPEC.md               # Protocol specification
├── IMPLEMENTATION_STATUS.md  # Current status
├── TESTING.md            # Testing guide
└── README.md             # This file
```

## Documentation

- [SPEC.md](SPEC.md) - SSH/QUIC protocol specification
- [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md) - Implementation progress
- [TESTING.md](TESTING.md) - Testing and debugging guide
- [API Documentation](docs/api/) - Generated API docs (TODO)

## Development

### Prerequisites

- Zig 0.15.2 or later
- zquic library
- zcrypto library

### Building

```bash
# Debug build
zig build

# Release build
zig build -Doptimize=ReleaseFast

# Run tests
zig build test

# Build and run examples
zig build
./zig-out/bin/client_demo
./zig-out/bin/server_demo
```

### Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes with tests
4. Run `zig fmt` on all files
5. Submit a pull request

### Code Style

- Follow Zig standard library conventions
- Use meaningful variable names
- Add documentation comments for public APIs
- Include tests for new features
- Run `zig fmt` before committing

## Performance

### Benchmarks

(Benchmarks to be added)

Expected performance characteristics:
- **Latency** - Low overhead due to QUIC multiplexing
- **Throughput** - Limited by underlying QUIC implementation
- **Memory** - Efficient allocation, minimal copying

### Optimization Opportunities

- Zero-copy buffer handling
- Connection pooling
- Parallel file transfers
- Async I/O integration

## Security Considerations

### Implemented Security Features

- ✅ Authenticated encryption (via QUIC/TLS 1.3)
- ✅ Forward secrecy (X25519 ephemeral keys)
- ✅ Strong authentication (Ed25519 signatures)
- ✅ Secure random number generation

### Security Limitations

- ⚠️ No host key verification implementation
- ⚠️ No known_hosts file support
- ⚠️ No certificate pinning
- ⚠️ Limited error handling for attacks

### Future Security Work

- Add host key verification
- Implement known_hosts management
- Add support for hardware security keys
- Comprehensive security audit
- Fuzzing tests

## Known Issues

1. **CLI Tool** - Interactive terminal I/O not fully implemented
2. **Server** - Production server features incomplete
3. **SFTP Server** - Server-side SFTP not implemented
4. **Platform Support** - Primarily tested on Linux
5. **Error Messages** - Could be more user-friendly

See [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md) for detailed status.

## Roadmap

### Phase 1-8: ✅ Complete
- Foundation & protocol implementation
- Authentication & channels
- SFTP client

### Phase 9: 🚧 In Progress
- CLI tool polish
- Integration testing
- Documentation

### Phase 10: 📋 Planned
- Production hardening
- Performance optimization
- Platform compatibility
- SFTP server implementation

## License

[Add license information]

## References

- [SSH/QUIC Draft](https://datatracker.ietf.org/doc/html/draft-denis-ssh-quic)
- [SSH Protocol (RFC 4251-4254)](https://www.rfc-editor.org/rfc/rfc4251.html)
- [SFTP Protocol](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02)
- [QUIC Protocol (RFC 9000)](https://www.rfc-editor.org/rfc/rfc9000.html)
- [Ed25519 (RFC 8032)](https://www.rfc-editor.org/rfc/rfc8032.html)
- [X25519 (RFC 7748)](https://www.rfc-editor.org/rfc/rfc7748.html)

## Acknowledgments

- Zig programming language and community
- zquic - QUIC implementation for Zig
- zcrypto - Cryptographic primitives for Zig
- OpenSSH project for SSH protocol reference

## Contact

[Add contact information]

---

**Status**: 🚧 Active Development
**Version**: 0.1.0
**Last Updated**: 2025-01-XX
