# SysLink Implementation Plan

## Current Status (As of 2026-02-12)

✅ **Completed:**
- SSH/QUIC protocol foundation
- Client-side implementation (connection, authentication, channels)
- SFTP client for file operations
- SSHFS filesystem integration
- Interactive CLI tools (sl, sshfs)
- 136/139 tests passing

🔧 **In Progress:**
- Server-side implementation
- Bug fixes and TODO resolution
- Production hardening

---

## Phase A: Server Implementation (HIGH PRIORITY)

**Goal:** Implement SSH/QUIC server to enable real client-server connections

**Timeline:** 1-2 weeks

### A1. Server Key Exchange Handler (3-4 days)

**Files to modify/create:**
- `lib/kex/exchange.zig` - Extend `ServerKeyExchange`
- `lib/network/udp.zig` - Server UDP listener

**Tasks:**
- [ ] Implement proper connection ID generation (replace "server-conn-id" TODO)
- [ ] Implement Ed25519 signature over exchange hash (replace TODO)
- [ ] Verify client's SSH_QUIC_INIT message validation
- [ ] Handle multiple concurrent key exchanges
- [ ] Add rate limiting for DoS protection

**Acceptance Criteria:**
```zig
// Server can:
var listener = try KeyExchangeListener.listen(allocator, "0.0.0.0", 2222);
const init_data = try listener.receiveInit(timeout);
const reply_data = try server_kex.createReply(init_data);
try listener.sendReply(reply_data);
```

### A2. Server Authentication Handler (2-3 days)

**Files to modify/create:**
- `lib/auth/server.zig` - Already exists, needs integration
- `lib/connection.zig` - Add server connection wrapper

**Tasks:**
- [ ] Integrate `AuthServer` with connection lifecycle
- [ ] Implement password validation callback system
- [ ] Implement public key validation (authorized_keys lookup)
- [ ] Add authentication logging
- [ ] Handle authentication failures gracefully

**Acceptance Criteria:**
```zig
// Server can:
var auth_server = AuthServer.init(allocator);
auth_server.setPasswordValidator(validatePassword);
auth_server.setPublicKeyValidator(validatePublicKey);

const response = try auth_server.processRequest(auth_request, exchange_hash);
// response is .success or .failure
```

### A3. Server Channel Management (2-3 days)

**Files to modify/create:**
- `lib/channels/manager.zig` - Server-side channel acceptance
- `lib/channels/session.zig` - Extend `SessionServer`
- `lib/connection.zig` - Add channel event loop

**Tasks:**
- [ ] Implement server-side channel acceptance workflow
- [ ] Handle channel open requests from clients
- [ ] Dispatch channel requests to handlers (shell, exec, subsystem)
- [ ] Implement shell request handler (spawn PTY)
- [ ] Implement exec request handler (run command)
- [ ] Implement subsystem request handler (SFTP)

**Acceptance Criteria:**
```zig
// Server can:
var session_server = SessionServer.init(allocator, &channel_manager);
try session_server.acceptSession(stream_id);
try session_server.handleRequest(stream_id, data,
    shellHandler, execHandler, subsystemHandler);
```

### A4. Server Main Loop & Connection Handling (2-3 days)

**Files to modify/create:**
- `lib/connection.zig` - Add `ServerConnection.listen()`
- `examples/server_demo.zig` - Complete server example
- `bin/sl-server.zig` - Optional: dedicated server binary

**Tasks:**
- [ ] Implement server accept loop (UDP listener → key exchange → QUIC connection)
- [ ] Handle multiple concurrent client connections
- [ ] Add graceful shutdown handling
- [ ] Implement connection cleanup on client disconnect
- [ ] Add server configuration (host keys, auth methods, etc.)

**Acceptance Criteria:**
```zig
// Server can:
var server = try connection.startServer(
    allocator, "0.0.0.0", 2222,
    host_key, host_private_key, random
);
defer server.deinit();

while (server.running) {
    const client = try server.acceptConnection();
    // Handle client in separate task/thread
}
```

### A5. SFTP Server (3-4 days)

**Files to modify/create:**
- `lib/sftp/server.zig` - Create SFTP server
- `lib/sftp/sftp.zig` - Export server types

**Tasks:**
- [ ] Implement SFTP server request processing
- [ ] Handle SSH_FXP_OPEN, SSH_FXP_READ, SSH_FXP_WRITE
- [ ] Handle SSH_FXP_OPENDIR, SSH_FXP_READDIR
- [ ] Handle SSH_FXP_STAT, SSH_FXP_MKDIR, SSH_FXP_REMOVE
- [ ] Implement file handle management
- [ ] Add filesystem access controls

**Acceptance Criteria:**
```zig
// SFTP server can:
var sftp_server = try SftpServer.init(allocator, session_channel);
defer sftp_server.deinit();

const request = try sftp_server.receiveRequest();
try sftp_server.handleRequest(request);
// Processes file operations and sends responses
```

### A6. Integration & Testing (2-3 days)

**Tasks:**
- [ ] Test full client-server connection flow
- [ ] Test authentication (password + public key)
- [ ] Test shell sessions
- [ ] Test exec commands
- [ ] Test SFTP file transfers
- [ ] Test multiple concurrent clients
- [ ] Add integration tests for client-server scenarios

**Deliverables:**
- Working SSH/QUIC server binary
- Client can connect, authenticate, and use shell/SFTP
- Integration tests pass

---

## Phase B: Fix Critical TODOs (QUICK WINS)

**Goal:** Resolve all TODO/FIXME items in codebase

**Timeline:** 2-3 days

### B1. Connection ID Generation (1 day)

**File:** `lib/kex/exchange.zig`

**Current TODO:**
```zig
.server_connection_id = "server-conn-id", // TODO: Generate properly
```

**Tasks:**
- [ ] Implement cryptographically random connection ID generation
- [ ] Use std.crypto.random for randomness
- [ ] Ensure uniqueness across connections
- [ ] Follow QUIC connection ID format (4-20 bytes)

**Implementation:**
```zig
fn generateConnectionId(random: std.Random) ![20]u8 {
    var conn_id: [20]u8 = undefined;
    random.bytes(&conn_id);
    return conn_id;
}
```

### B2. Server Signature Verification (1 day)

**File:** `lib/kex/exchange.zig`

**Current TODO:**
```zig
// TODO: Verify server signature over exchange hash
```

**Tasks:**
- [ ] Extract server signature from SSH_QUIC_REPLY
- [ ] Reconstruct exchange hash H on client side
- [ ] Verify signature using server's host key
- [ ] Return error if verification fails
- [ ] Add test for signature verification

**Implementation:**
```zig
pub fn verifyServerSignature(
    self: *ClientKeyExchange,
    server_sig: []const u8,
    server_host_key: []const u8,
) !void {
    const exchange_hash = self.getExchangeHash();
    if (!crypto.signature.verify(exchange_hash, server_sig, server_host_key)) {
        return error.InvalidServerSignature;
    }
}
```

### B3. Channel Open Message Handling (half day)

**File:** `lib/connection.zig`

**Current TODO:**
```zig
// TODO: Wait for channel open message on next available stream
```

**Tasks:**
- [ ] Implement channel open confirmation waiting
- [ ] Handle SSH_MSG_CHANNEL_OPEN_CONFIRMATION
- [ ] Handle SSH_MSG_CHANNEL_OPEN_FAILURE
- [ ] Add timeout for channel open response

**Implementation:**
```zig
pub fn waitForChannelOpen(self: *Self, stream_id: u64) !void {
    var buffer: [4096]u8 = undefined;
    const len = try self.transport.receiveFromStream(stream_id, &buffer);

    const msg_type = buffer[0];
    if (msg_type != 91) { // SSH_MSG_CHANNEL_OPEN_CONFIRMATION
        return error.ChannelOpenFailed;
    }
}
```

### B4. SSHFS Public Key Authentication (half day)

**File:** `lib/sshfs/filesystem.zig`

**Current TODO:**
```zig
// TODO: Implement public key authentication
```

**Tasks:**
- [ ] Add public key auth support to SSHFS
- [ ] Load SSH key from file (id_ed25519)
- [ ] Parse OpenSSH key format
- [ ] Call connection.authenticatePublicKey()

**Implementation:**
```zig
pub fn connectWithPublicKey(
    self: *SshfsFilesystem,
    username: []const u8,
    key_path: []const u8,
) !void {
    const key_data = try self.loadPrivateKey(key_path);
    defer self.allocator.free(key_data);

    const authed = try self.conn.authenticatePublicKey(
        username, "ssh-ed25519", key_data.public, &key_data.private
    );
    if (!authed) return error.AuthenticationFailed;
}
```

### B5. Directory Caching (half day)

**File:** `lib/sshfs/operations.zig`

**Current TODO:**
```zig
// TODO: Cache directory listing
```

**Tasks:**
- [ ] Implement simple TTL-based directory cache
- [ ] Cache directory entries for 30 seconds
- [ ] Invalidate cache on write operations
- [ ] Add cache statistics

**Implementation:**
```zig
const DirCache = struct {
    entries: std.StringHashMap([]DirEntry),
    timestamps: std.StringHashMap(i64),
    ttl_seconds: i64 = 30,

    pub fn get(self: *Self, path: []const u8) ?[]DirEntry {
        const now = std.time.timestamp();
        if (self.timestamps.get(path)) |ts| {
            if (now - ts < self.ttl_seconds) {
                return self.entries.get(path);
            }
        }
        return null;
    }
};
```

### B6. Ed25519 Signature Implementation (half day)

**File:** `lib/kex/exchange.zig`

**Current TODO:**
```zig
// TODO: Implement Ed25519 signature
```

**Tasks:**
- [ ] Implement Ed25519 signing in key exchange
- [ ] Use crypto.signature.sign() (already implemented)
- [ ] Sign exchange hash with server's private key
- [ ] Include signature in SSH_QUIC_REPLY

**Implementation:**
```zig
pub fn signExchangeHash(
    self: *ServerKeyExchange,
    private_key: *const [64]u8,
) ![64]u8 {
    const exchange_hash = self.getExchangeHash();
    return crypto.signature.sign(exchange_hash, private_key);
}
```

---

## Phase C: Testing & Documentation (POLISH)

**Goal:** Make project production-ready with comprehensive docs and tests

**Timeline:** 1-2 weeks

### C1. Integration Testing (3-4 days)

**Files to create:**
- `tests/integration/client_server_test.zig`
- `tests/integration/sftp_test.zig`
- `tests/integration/sshfs_test.zig`
- `tests/integration/stress_test.zig`

**Tasks:**

#### Client-Server Tests
- [ ] Test basic connection establishment
- [ ] Test authentication (password, public key, failure)
- [ ] Test shell session (send commands, receive output)
- [ ] Test exec command
- [ ] Test subsystem request (SFTP)
- [ ] Test graceful disconnect
- [ ] Test connection timeout

#### SFTP Integration Tests
- [ ] Test file upload (small, medium, large files)
- [ ] Test file download
- [ ] Test directory listing
- [ ] Test directory creation/removal
- [ ] Test file removal
- [ ] Test file rename
- [ ] Test concurrent file operations

#### SSHFS Tests
- [ ] Test filesystem mount
- [ ] Test file read operations
- [ ] Test file write operations
- [ ] Test directory browsing
- [ ] Test file metadata (stat)
- [ ] Test unmount

#### Stress Tests
- [ ] Test 100 concurrent connections
- [ ] Test large file transfers (1GB+)
- [ ] Test sustained connection duration (1+ hour)
- [ ] Test rapid connect/disconnect cycles
- [ ] Measure memory usage under load
- [ ] Measure CPU usage under load

**Acceptance Criteria:**
- All integration tests pass
- No memory leaks detected
- Performance meets targets:
  - Connection establishment: <100ms
  - File transfer: >50 MB/s
  - Concurrent connections: 100+

### C2. Security Testing (2-3 days)

**Tasks:**

#### Cryptographic Validation
- [ ] Verify Ed25519 signature generation/verification
- [ ] Verify X25519 key exchange produces correct secrets
- [ ] Verify HKDF derivation matches test vectors
- [ ] Verify no key material leaks in logs/errors

#### Attack Scenarios
- [ ] Test invalid SSH_QUIC_INIT messages
- [ ] Test malformed SSH packets
- [ ] Test authentication brute force (rate limiting)
- [ ] Test DoS protection (connection limits)
- [ ] Test packet injection/replay attacks
- [ ] Test man-in-the-middle detection

#### Code Review
- [ ] Review all error handling paths
- [ ] Review all buffer operations for overflows
- [ ] Review all crypto operations for constant-time
- [ ] Review all input validation
- [ ] Review resource cleanup (no leaks)

**Deliverables:**
- Security audit report
- List of vulnerabilities (if any) with fixes
- Hardening recommendations

### C3. Documentation (3-4 days)

#### README.md Updates
- [ ] Fix "voidbox" → "syslink" references
- [ ] Add server usage examples
- [ ] Add SSHFS mounting instructions
- [ ] Add troubleshooting section
- [ ] Add FAQ section

#### Architecture Documentation
**File:** `docs/ARCHITECTURE.md`
- [ ] Overall system architecture diagram
- [ ] Protocol flow diagrams (key exchange, auth, channels)
- [ ] Module dependency graph
- [ ] Data flow diagrams
- [ ] Sequence diagrams for key operations

#### API Reference
**File:** `docs/API.md`
- [ ] Client API documentation
- [ ] Server API documentation
- [ ] SFTP API documentation
- [ ] Common types and structures
- [ ] Error handling guide
- [ ] Code examples for each API

#### Protocol Documentation
**File:** `docs/PROTOCOL.md`
- [ ] SSH/QUIC protocol overview
- [ ] Differences from standard SSH
- [ ] Obfuscated envelope format
- [ ] Key exchange details
- [ ] Channel mapping to QUIC streams
- [ ] SFTP adaptations

#### Deployment Guide
**File:** `docs/DEPLOYMENT.md`
- [ ] Server deployment instructions
- [ ] Configuration options
- [ ] Host key generation
- [ ] User management (authorized_keys)
- [ ] Systemd service file example
- [ ] Docker container setup
- [ ] Security best practices
- [ ] Monitoring and logging

#### Developer Guide
**File:** `docs/CONTRIBUTING.md`
- [ ] Code style guidelines
- [ ] Build system overview
- [ ] Testing procedures
- [ ] Debugging tips
- [ ] How to add new features
- [ ] Pull request process

### C4. Examples & Demos (2-3 days)

**Files to create/update:**
- `examples/client_demo.zig` - Update with server support
- `examples/server_demo.zig` - Complete implementation
- `examples/sftp_demo.zig` - Complete SFTP client/server demo
- `examples/sshfs_demo.zig` - SSHFS mounting demo
- `examples/benchmark.zig` - Performance benchmarking

**Tasks:**

#### Client Demo
- [ ] Show basic connection
- [ ] Show authentication methods
- [ ] Show shell session
- [ ] Show exec command
- [ ] Show SFTP file transfer
- [ ] Add comments explaining each step

#### Server Demo
- [ ] Show server setup
- [ ] Show host key loading
- [ ] Show authentication configuration
- [ ] Show handler registration
- [ ] Show graceful shutdown
- [ ] Add extensive comments

#### SFTP Demo
- [ ] Show SFTP client operations
- [ ] Show SFTP server operations
- [ ] Show file upload/download
- [ ] Show directory operations

#### Benchmark
- [ ] Connection throughput (connections/sec)
- [ ] Data throughput (MB/s)
- [ ] Latency measurements
- [ ] Memory usage profiling
- [ ] CPU usage profiling

### C5. Production Hardening (2-3 days)

**Tasks:**

#### Error Handling Review
- [ ] Audit all error returns
- [ ] Ensure proper error context
- [ ] Add error logging where appropriate
- [ ] Ensure no silent failures
- [ ] Test all error paths

#### Resource Management
- [ ] Audit all allocations
- [ ] Verify all defer/errdefer usage
- [ ] Test for memory leaks (valgrind/sanitizers)
- [ ] Test file descriptor leaks
- [ ] Test with resource limits (ulimit)

#### Configuration
- [ ] Add server configuration file support
- [ ] Add client configuration file support
- [ ] Environment variable support
- [ ] Command-line flag parsing
- [ ] Configuration validation

#### Logging & Monitoring
- [ ] Add structured logging
- [ ] Add log levels (debug, info, warn, error)
- [ ] Add performance metrics
- [ ] Add connection statistics
- [ ] Add health check endpoint (for server)

#### Build & Packaging
- [ ] Add release build configuration
- [ ] Add install target
- [ ] Create man pages
- [ ] Create shell completions (bash, zsh, fish)
- [ ] Package for common distros (deb, rpm)

---

## Success Criteria

### Phase A Complete When:
- ✅ Server binary accepts SSH/QUIC connections
- ✅ Client can authenticate to server (password + public key)
- ✅ Client can open shell session and execute commands
- ✅ Client can use SFTP for file transfers
- ✅ Multiple concurrent clients work correctly

### Phase B Complete When:
- ✅ All TODO/FIXME comments resolved
- ✅ Connection IDs generated properly
- ✅ Server signatures verified
- ✅ Channel open messages handled
- ✅ SSHFS supports public key auth
- ✅ All changes tested and working

### Phase C Complete When:
- ✅ Integration test suite passes
- ✅ Security audit completed
- ✅ All documentation written
- ✅ Examples working and documented
- ✅ Production hardening complete
- ✅ Ready for 1.0 release

---

## Timeline Summary

| Phase | Duration | Key Deliverable |
|-------|----------|----------------|
| **A: Server** | 1-2 weeks | Working SSH/QUIC server |
| **B: TODOs** | 2-3 days | All critical TODOs fixed |
| **C: Testing** | 1-2 weeks | Production-ready release |
| **TOTAL** | 3-4 weeks | Complete SSH/QUIC stack |

---

## Notes

- Each phase builds on the previous
- Testing should be done incrementally (not just at end)
- Documentation should be written as code is implemented
- Security considerations should be addressed throughout

---

## Getting Started

To begin Phase A:
```bash
# Create new branch
git checkout -b feature/server-implementation

# Start with A1: Server Key Exchange Handler
vim lib/kex/exchange.zig

# Run tests frequently
zig build test

# Commit often
git add -p
git commit -m "feat(server): implement connection ID generation"
```
