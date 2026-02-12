const std = @import("std");

/// SSH Authentication Layer
///
/// Provides both client and server authentication implementations
/// supporting password and public key authentication methods.

pub const AuthClient = @import("client.zig").AuthClient;
pub const AuthResult = @import("client.zig").AuthResult;
pub const AuthServer = @import("server.zig").AuthServer;
pub const AuthResponse = @import("server.zig").AuthResponse;

test {
    std.testing.refAllDecls(@This());
}
