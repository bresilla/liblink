const std = @import("std");

// Although this function looks imperative, note that its job is to
// declaratively construct a build graph that will be executed by an external
// runner.
pub fn build(b: *std.Build) !void {
    // Standard target options allows the person running `zig build` to choose
    // what target to build for. Here we do not override the defaults, which
    // means any target is allowed, and the default is native. Other options
    // for restricting supported target set are available.
    const target = b.standardTargetOptions(.{});

    if (target.result.os.tag != .linux) {
        return error.InvalidOS;
    }

    // Standard optimization options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall. Here we do not
    // set a preferred release mode, allowing the user to decide how to optimize.
    const optimize = b.standardOptimizeOption(.{});

    // Get dependencies
    const zcrypto = b.dependency("zcrypto", .{
        .target = target,
        .optimize = optimize,
    });
    const zquic = b.dependency("zquic", .{
        .target = target,
        .optimize = optimize,
    });

    const voidbox_module = b.createModule(.{
        .root_source_file = b.path("lib/voidbox.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    voidbox_module.addImport("zcrypto", zcrypto.module("zcrypto"));
    voidbox_module.addImport("zquic", zquic.module("zquic"));

    _ = b.addModule("voidbox", .{
        .root_source_file = b.path("lib/voidbox.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });

    const lib = b.addLibrary(.{
        .name = "voidbox",
        .root_module = voidbox_module,
        .linkage = .static,
    });

    b.installArtifact(lib);

    const exe_unit_tests = b.addTest(.{
        .root_module = voidbox_module,
    });

    const run_exe_unit_tests = b.addRunArtifact(exe_unit_tests);

    // Similar to creating the run step earlier, this exposes a `test` step to
    // the `zig build --help` menu, providing a way for the user to request
    // running the unit tests.
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_exe_unit_tests.step);

    const ex_shell_module = b.createModule(.{
        .root_source_file = b.path("examples/embedder_launch_shell.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    ex_shell_module.addImport("voidbox", voidbox_module);

    const ex_shell = b.addExecutable(.{
        .name = "example_embedder_launch_shell",
        .root_module = ex_shell_module,
    });

    const ex_events_module = b.createModule(.{
        .root_source_file = b.path("examples/embedder_events.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    ex_events_module.addImport("voidbox", voidbox_module);

    const ex_events = b.addExecutable(.{
        .name = "example_embedder_events",
        .root_module = ex_events_module,
    });

    const sl_module = b.createModule(.{
        .root_source_file = b.path("bin/sl.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    sl_module.addImport("voidbox", voidbox_module);

    const sl_unit_tests = b.addTest(.{
        .root_module = sl_module,
    });
    const run_sl_unit_tests = b.addRunArtifact(sl_unit_tests);
    test_step.dependOn(&run_sl_unit_tests.step);

    const sl = b.addExecutable(.{
        .name = "sl",
        .root_module = sl_module,
    });
    b.installArtifact(sl);

    const sl_step = b.step("sl", "Compile sl CLI binary");
    sl_step.dependOn(&sl.step);

    // SSHFS executable
    const sshfs_module = b.createModule(.{
        .root_source_file = b.path("bin/sshfs.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    sshfs_module.addImport("voidbox", voidbox_module);

    const sshfs = b.addExecutable(.{
        .name = "sshfs",
        .root_module = sshfs_module,
    });

    // Link FUSE3 library
    sshfs.addLibraryPath(.{ .cwd_relative = "/usr/lib/x86_64-linux-gnu" });
    sshfs.addIncludePath(.{ .cwd_relative = "/usr/include/fuse3" });
    sshfs.linkSystemLibrary("fuse3");
    sshfs.linkLibC();

    b.installArtifact(sshfs);

    const sshfs_step = b.step("sshfs", "Compile sshfs CLI binary");
    sshfs_step.dependOn(&b.addInstallArtifact(sshfs, .{}).step);

    const examples_step = b.step("examples", "Compile embedder examples");
    examples_step.dependOn(&ex_shell.step);
    examples_step.dependOn(&ex_events.step);
}
