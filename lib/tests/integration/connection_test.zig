const std = @import("std");
const testing = std.testing;
const syslink = @import("../../syslink.zig");

// Integration test: Full client-server connection flow components

test "Integration: Server components available" {
    std.log.info("=== Integration Test: Server Components ===", .{});

    // Verify server components exist
    _ = syslink.connection.ServerConnection;
    _ = syslink.connection.ConnectionListener;
    _ = syslink.connection.ServerConfig;

    std.log.info("✓ Server connection components available", .{});
}

test "Integration: Client components available" {
    std.log.info("=== Integration Test: Client Components ===", .{});

    // Verify client components exist
    _ = syslink.connection.ClientConnection;
    _ = syslink.connection.ConnectionConfig;

    std.log.info("✓ Client connection components available", .{});
}

test "Integration: Authentication components available" {
    std.log.info("=== Integration Test: Authentication ===", .{});

    // Verify auth components exist
    _ = syslink.auth.dispatcher.AuthServer;
    _ = syslink.auth.client.AuthClient;

    std.log.info("✓ Authentication components validated", .{});
}

test "Integration: All required components available" {
    // Verify all required components for integration are available

    // Connection layer
    _ = syslink.connection.ClientConnection;
    _ = syslink.connection.ServerConnection;
    _ = syslink.connection.ConnectionListener;

    // Authentication layer
    _ = syslink.auth.client.AuthClient;
    _ = syslink.auth.dispatcher.AuthServer;

    // Channel layer
    _ = syslink.channels.ChannelManager;
    _ = syslink.channels.SessionServer;

    // SFTP layer
    _ = syslink.sftp.SftpClient;
    _ = syslink.sftp.SftpServer;

    std.log.info("✓ All integration components available", .{});
}
