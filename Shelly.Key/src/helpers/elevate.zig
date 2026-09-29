const std = @import("std");
const privilege = @import("privilege");

const ElevatedCommand = struct {
    provider: privilege.Provider,
    executable: []u8,
    argv: []const []const u8,

    fn deinit(self: ElevatedCommand, allocator: std.mem.Allocator) void {
        allocator.free(self.argv);
        self.provider.deinit(allocator);
        allocator.free(self.executable);
    }
};

pub fn ensureRoot(
    io: std.Io,
    allocator: std.mem.Allocator,
    args: []const []const u8,
    environment: *const std.process.Environ.Map,
) !void {
    if (std.os.linux.getuid() == 0) return;

    const command = try buildElevatedCommand(io, allocator, args, environment);
    defer command.deinit(allocator);
    var child = try std.process.spawn(io, .{
        .argv = command.argv,
        .stdin = .inherit,
        .stdout = .inherit,
        .stderr = .inherit,
    });
    errdefer child.kill(io);
    try handleTerm(try child.wait(io));
}

fn buildElevatedCommand(
    io: std.Io,
    allocator: std.mem.Allocator,
    args: []const []const u8,
    environment: *const std.process.Environ.Map,
) !ElevatedCommand {
    const provider = try privilege.select(allocator, io, environment, .elevate_root);
    errdefer provider.deinit(allocator);
    const executable = try std.process.executablePathAlloc(io, allocator);
    errdefer allocator.free(executable);
    const arguments = if (args.len > 0) args[1..] else args;
    const argv = try privilege.buildRootCommand(allocator, provider, executable, arguments);
    return .{ .provider = provider, .executable = executable, .argv = argv };
}

fn handleTerm(term: std.process.Child.Term) error{ExecFailed}!noreturn {
    switch (term) {
        .exited => |code| std.process.exit(code),
        .signal => |sig| std.process.exit(@truncate(128 + @intFromEnum(sig))),
        .stopped => |sig| {
            std.log.err("The authorization helper was stopped by signal {0f}. Retry the operation if it was interrupted unintentionally.", .{@import("diagnostics").safe(@tagName(sig))});
            return error.ExecFailed;
        },
        .unknown => |status| {
            std.log.err("The authorization helper returned an unrecognized process status. Review the technical details before retrying.\n\nTechnical details: {0x}", .{status});
            return error.ExecFailed;
        },
    }
}

fn createExecutable(dir: std.Io.Dir, io: std.Io, name: []const u8) !void {
    var fixture = try dir.createFile(io, name, .{ .permissions = .executable_file });
    fixture.close(io);
}

test "shelly-key builds direct run0 elevation through shared provider policy" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    try createExecutable(temporary.dir, std.testing.io, "run0");
    const path = try temporary.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(path);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var environment = std.process.Environ.Map.init(arena.allocator());
    try environment.put("PATH", path);

    const command = try buildElevatedCommand(
        std.testing.io,
        arena.allocator(),
        &.{ "shelly-key", "--init" },
        &environment,
    );
    defer command.deinit(arena.allocator());
    try std.testing.expectEqualStrings(try std.fs.path.join(arena.allocator(), &.{ path, "run0" }), command.argv[0]);
    try std.testing.expectEqualStrings("--init", command.argv[2]);
}

test "shelly-key returns common NoElevator for empty PATH" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var environment = std.process.Environ.Map.init(arena.allocator());
    try environment.put("PATH", "");
    try std.testing.expectError(
        error.NoElevator,
        buildElevatedCommand(std.testing.io, arena.allocator(), &.{"shelly-key"}, &environment),
    );
}
