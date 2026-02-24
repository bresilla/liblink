# liblink

SSH/QUIC protocol implementation in Zig. Secure remote access and file transfer over QUIC transport.

## Build

```bash
zig build
zig build test
```

## Quick Start

```bash
# Generate server host key
ssh-keygen -t ed25519 -f ~/.ssh/sl_host_key -N ""

# Start server
sl server start -k ~/.ssh/sl_host_key

# Remote shell
sl shell -i ~/.ssh/id_ed25519 user@host:2222

# Execute command
sl exec -i ~/.ssh/id_ed25519 user@host "ls -la"

# SFTP session
sl sftp -i ~/.ssh/id_ed25519 user@host
```

## Library

```zig
const liblink = @import("liblink");

// Connect
var conn = try liblink.connection.connectClientTrusted(allocator, "host", 2222, random, .accept_new);
defer conn.deinit();

// Authenticate
try liblink.auth.workflow.authenticateClient(allocator, &conn, "user", .{
    .identity_path = "/home/user/.ssh/id_ed25519",
});

// Execute
var session = try conn.requestExec("uptime");

// SFTP
var sftp_channel = try conn.openSftp();
var sftp = try liblink.sftp.SftpClient.init(allocator, sftp_channel);
```

## Project Structure

```
lib/
  liblink.zig        Entry point
  connection.zig     Client/server connection API
  auth/              Authentication (public key, system users)
  channels/          SSH session channels (shell, exec, subsystem)
  crypto/            Cryptographic primitives (Ed25519, X25519, AES-GCM)
  kex/               Key exchange state machines
  network/           UDP and QUIC transport
  protocol/          Wire format encoding/decoding
  platform/          PTY allocation, user lookup
  server/            Server daemon and session runtime
  sftp/              SFTP v3 client and server
bin/
  sl.zig             CLI tool
examples/
  client_demo.zig    Client usage example
  server_demo.zig    Server usage example
```

## Documentation

- **[CLI Reference](bin/README.md)** - `sl` command usage, server setup, client options
- **[Library API](docs/library.md)** - Using liblink as a Zig dependency
- **[Protocol](docs/protocol.md)** - SSH/QUIC protocol details, key exchange, authentication flow

## Protocol

Implements [draft-bider-ssh-quic](https://datatracker.ietf.org/doc/draft-bider-ssh-quic/):

- Key exchange over UDP, then encrypted QUIC transport
- Ed25519 signatures, X25519 ECDH, AES-256-GCM, HKDF-SHA256
- SSH channels map 1:1 to QUIC streams (no head-of-line blocking)
- Public key authentication against `~/.ssh/authorized_keys`
- SFTP v3 file transfer
- Session channels (interactive shell, remote exec, subsystem)

## References

- [draft-bider-ssh-quic](https://datatracker.ietf.org/doc/draft-bider-ssh-quic/)
- [SSH Protocol (RFC 4251-4254)](https://www.rfc-editor.org/rfc/rfc4251.html)
- [SFTP Protocol](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02)
- [QUIC (RFC 9000)](https://www.rfc-editor.org/rfc/rfc9000.html)
