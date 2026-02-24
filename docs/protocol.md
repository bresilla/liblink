# SSH/QUIC Protocol

liblink implements the [draft-bider-ssh-quic](https://datatracker.ietf.org/doc/draft-bider-ssh-quic/) protocol, which adapts SSH to run over QUIC instead of TCP.

## Overview

```
Traditional SSH:    TCP → SSH transport → SSH channels
liblink:            UDP (KEX) → QUIC → SSH channels on QUIC streams
```

SSH channels map directly to QUIC streams instead of being multiplexed inside a single TCP connection. This gives each channel independent flow control and eliminates head-of-line blocking.

## Connection Phases

### Phase 1: Key Exchange (UDP)

Before QUIC is established, client and server perform a single UDP round-trip to exchange keys and derive QUIC encryption secrets.

```
CLIENT                                    SERVER
  |                                         |
  |  SSH_QUIC_INIT (UDP)                    |
  |  ├── client ephemeral public key (Q_C)  |
  |  ├── supported algorithms               |
  |  ├── client connection ID               |
  |  └── padding to 1200 bytes (DDoS)       |
  |  ─────────────────────────────────────►  |
  |                                         |
  |                    generate Q_S         |
  |                    K = X25519(q_s, Q_C) |
  |                    H = SHA256(...)      |
  |                    sig = Ed25519(H, host_private_key)
  |                                         |
  |  SSH_QUIC_REPLY (UDP)                   |
  |  ├── server host public key (K_S)       |
  |  ├── server ephemeral public key (Q_S)  |
  |  └── signature over exchange hash       |
  |  ◄─────────────────────────────────────  |
  |                                         |
  |  K = X25519(q_c, Q_S)                  |
  |  verify sig with K_S                    |
  |  check known_hosts                      |
  |                                         |
  |  Both sides derive:                     |
  |    client_secret = HMAC-SHA256("ssh/quic client", K || H)
  |    server_secret = HMAC-SHA256("ssh/quic server", K || H)
  |                                         |
```

The exchange hash `H` is computed over:
```
SHA-256(
    "SSH/QUIC"          magic
    SSH_QUIC_INIT       full client init
    SSH_QUIC_REPLY      reply without signature
    0x1f                KEX_ECDH_REPLY marker
    K_S                 server host key blob
    Q_C                 client ephemeral
    Q_S                 server ephemeral
    K                   shared secret (mpint)
)
```

### Phase 2: QUIC Connection

With `client_secret` and `server_secret`, both sides initialize QUIC packet protection. All subsequent communication is encrypted QUIC.

Stream 0 is reserved for SSH authentication and control messages.

### Phase 3: User Authentication (QUIC Stream 0)

Standard SSH public key authentication (RFC 4252 Section 7) over QUIC:

```
CLIENT                                    SERVER
  |                                         |
  |  SSH_MSG_USERAUTH_REQUEST               |
  |  ├── username                           |
  |  ├── "ssh-connection"                   |
  |  ├── "publickey"                        |
  |  ├── has_signature = false              |
  |  ├── "ssh-ed25519"                      |
  |  └── public_key_blob                    |
  |  ─────────────────────────────────────►  |
  |                          check authorized_keys
  |  SSH_MSG_USERAUTH_PK_OK                 |
  |  ◄─────────────────────────────────────  |
  |                                         |
  |  SSH_MSG_USERAUTH_REQUEST               |
  |  ├── (same fields)                      |
  |  ├── has_signature = true               |
  |  └── signature = Ed25519(               |
  |        session_id || msg_type ||        |
  |        username || service ||            |
  |        "publickey" || algorithm ||       |
  |        public_key_blob,                 |
  |        client_private_key)              |
  |  ─────────────────────────────────────►  |
  |                          verify signature
  |  SSH_MSG_USERAUTH_SUCCESS               |
  |  ◄─────────────────────────────────────  |
```

### Phase 4: Session Channels (QUIC Streams)

Each SSH channel maps to a QUIC stream. Opening a channel opens a new stream:

```
Stream 0:  Authentication + control
Stream 4:  Session channel (shell/exec)
Stream 8:  SFTP subsystem
Stream 12: Another session (if needed)
```

## Key Material

| Key | Type | Size | Purpose |
|-----|------|------|---------|
| Server host key | Ed25519 | 64B private, 32B public | Server identity |
| Client identity key | Ed25519 | 64B private, 32B public | User authentication |
| Ephemeral keys | X25519 | 32B each | Forward-secret key agreement |
| Shared secret (K) | X25519 result | 32B | Input to session key derivation |
| Exchange hash (H) | SHA-256 | 32B | Session ID, binds auth to KEX |
| Client QUIC secret | HMAC-SHA256 | 32B | Client-to-server encryption |
| Server QUIC secret | HMAC-SHA256 | 32B | Server-to-client encryption |

## Authentication Flow

Server validates clients using the same mechanism as OpenSSH:

1. Client presents its public key
2. Server looks up `~/.ssh/authorized_keys` for the connecting user
3. If the key is found, server asks client to prove ownership
4. Client signs a challenge with its private key
5. Server verifies the signature

Keys are installed on the server the same way as OpenSSH:
```bash
ssh-copy-id -i ~/.ssh/id_ed25519.pub user@server
# or manually append to ~/.ssh/authorized_keys
```

## Flow Control

QUIC stream-level flow control replaces SSH's channel window mechanism:

- Each stream has an independent send/receive window (2MB default, matching OpenSSH)
- Receiver sends `MAX_STREAM_DATA` frames to slide the window forward
- Sender blocks when the window is full, polling for window updates
- No head-of-line blocking between channels (unlike TCP-based SSH)

## Packet Format

SSH messages are framed inside QUIC STREAM frames:

```
QUIC Packet:
  Short Header (1 + conn_id_len + 1 bytes)
  Encrypted Payload:
    STREAM frame:
      stream_id (varint)
      offset (varint)
      data: SSH message bytes
```

## Supported Algorithms

| Category | Algorithm |
|----------|-----------|
| Key exchange | curve25519-sha256 |
| Host key | ssh-ed25519 |
| Encryption | aes256-gcm (QUIC packet protection) |
| MAC | implicit in GCM |
| Compression | none |

## References

- [draft-bider-ssh-quic](https://datatracker.ietf.org/doc/draft-bider-ssh-quic/) - SSH over QUIC
- [RFC 4251](https://www.rfc-editor.org/rfc/rfc4251.html) - SSH Protocol Architecture
- [RFC 4252](https://www.rfc-editor.org/rfc/rfc4252.html) - SSH Authentication Protocol
- [RFC 4253](https://www.rfc-editor.org/rfc/rfc4253.html) - SSH Transport Layer Protocol
- [RFC 4254](https://www.rfc-editor.org/rfc/rfc4254.html) - SSH Connection Protocol
- [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000.html) - QUIC Transport Protocol
- [SFTP v3](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02) - SSH File Transfer Protocol
