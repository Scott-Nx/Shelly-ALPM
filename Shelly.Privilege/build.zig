const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const user_account = b.addModule("user_account", .{
        .root_source_file = b.path("src/user_account.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    const privilege = b.addModule("privilege", .{
        .root_source_file = b.path("src/privilege.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    privilege.addImport("user_account", user_account);

    const tests = b.addTest(.{ .root_module = privilege });
    b.step("test", "Test privilege providers and invoking-user identity")
        .dependOn(&b.addRunArtifact(tests).step);
}
