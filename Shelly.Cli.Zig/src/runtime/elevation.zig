const std = @import("std");
const builtin = @import("builtin");
const Zigalpm = @import("Zigalpm");
const privilege = @import("privilege");
const context_module = @import("context.zig");
const signals = @import("signals.zig");

pub const Error = error{
    UnsupportedPlatform,
    ElevationFailed,
};

pub fn isRoot() bool {
    return builtin.os.tag == .linux and std.os.linux.geteuid() == 0;
}

/// Relaunches the current executable through the configured privilege
/// elevator when the process is not already root. A non-null result is the
/// elevated child's exit code and must be returned by the caller immediately.
pub fn relaunchIfNeeded(
    context: *context_module.RuntimeContext,
    arguments: []const []const u8,
) !?u8 {
    if (builtin.os.tag != .linux) return error.UnsupportedPlatform;
    if (isRoot()) return null;

    const executable = try std.process.executablePathAlloc(context.io, context.allocator);
    const safe_executable: []const u8 = executableWithoutDeletedSuffix(executable);
    defer context.allocator.free(executable);
    const provider = try privilege.select(
        context.allocator,
        context.io,
        context.environment,
        .elevate_root,
    );
    defer provider.deinit(context.allocator);
    const elevated_arguments = try privilege.buildRootCommand(
        context.allocator,
        provider,
        safe_executable,
        arguments,
    );
    defer context.allocator.free(elevated_arguments);

    var child = try std.process.spawn(context.io, .{
        .argv = elevated_arguments,
        .stdin = .inherit,
        .stdout = .inherit,
        .stderr = .inherit,
    });
    errdefer child.kill(context.io);

    return @as(?u8, try exitCode(try child.wait(context.io)));
}

pub const CancellableRelaunchResult = struct {
    exit_code: u8,
    stdout: ?[]u8,
    cancelled: bool,

    pub fn deinit(self: CancellableRelaunchResult, allocator: std.mem.Allocator) void {
        if (self.stdout) |output| allocator.free(output);
    }
};

/// Relaunches Shelly through the configured elevator while supervising the
/// complete elevator process group. This is used by isolated builds because
/// their signal handler must be allowed to unwind the elevated coordinator
/// and remove its operation root instead of terminating the original process
/// immediately.
pub fn relaunchIfNeededCancellable(
    context: *context_module.RuntimeContext,
    arguments: []const []const u8,
    capture_stdout: bool,
) !?CancellableRelaunchResult {
    if (builtin.os.tag != .linux) return error.UnsupportedPlatform;
    if (isRoot()) return null;

    const executable = try std.process.executablePathAlloc(context.io, context.allocator);
    const safe_executable: []const u8 = executableWithoutDeletedSuffix(executable);
    defer context.allocator.free(executable);
    const provider = try privilege.select(
        context.allocator,
        context.io,
        context.environment,
        .elevate_root,
    );
    defer provider.deinit(context.allocator);
    const elevated_arguments = try privilege.buildRootCommand(
        context.allocator,
        provider,
        safe_executable,
        arguments,
    );
    defer context.allocator.free(elevated_arguments);
    return try runCancellableProcess(context, elevated_arguments, .{
        .capture_stdout = capture_stdout,
        // Moving a process that reads a controlling terminal into a
        // background process group can trigger SIGTTIN during an interactive
        // authentication prompt. Unattended invocations get an owned group;
        // interactive elevators retain their foreground group and are
        // expected to forward the signal to their privileged command.
        .own_process_group = !context.stdin_is_tty,
    });
}

const CancellableProcessOptions = struct {
    capture_stdout: bool = false,
    own_process_group: bool = true,
    interrupt_grace_polls: usize = 80,
    terminate_grace_polls: usize = 120,
    kill_reap_polls: usize = 80,
};

const ElevationCancellationSupervisor = struct {
    io: std.Io,
    process_id: std.posix.pid_t,
    options: CancellableProcessOptions,
    leader_reaped: std.atomic.Value(bool) = .init(false),
    cancelled: std.atomic.Value(bool) = .init(false),
    future: ?std.Io.Future(void) = null,

    fn start(self: *ElevationCancellationSupervisor) !void {
        self.future = try self.io.concurrent(watch, .{self});
    }

    fn finish(self: *ElevationCancellationSupervisor) void {
        self.leader_reaped.store(true, .release);
        if (self.future) |*future| future.await(self.io);
        self.future = null;
    }

    fn watch(self: *ElevationCancellationSupervisor) void {
        while (!self.leader_reaped.load(.acquire) and !signals.wasInterrupted())
            self.io.sleep(.fromMilliseconds(25), .awake) catch return;
        if (!signals.wasInterrupted()) return;

        self.cancelled.store(true, .release);
        const initial_count = signals.interruptionCount();
        signalProcessGroup(
            self.process_id,
            self.options.own_process_group,
            signals.receivedSignal() orelse .TERM,
        );
        if (self.waitForExit(self.options.interrupt_grace_polls, initial_count, true)) return;

        signalProcessGroup(self.process_id, self.options.own_process_group, .TERM);
        if (self.waitForExit(self.options.terminate_grace_polls, initial_count, true)) return;

        signalProcessGroup(self.process_id, self.options.own_process_group, .KILL);
        _ = self.waitForExit(self.options.kill_reap_polls, initial_count, false);
    }

    fn waitForExit(
        self: *ElevationCancellationSupervisor,
        polls: usize,
        initial_signal_count: u8,
        second_signal_escalates: bool,
    ) bool {
        var attempt: usize = 0;
        while (attempt < polls) : (attempt += 1) {
            if (!processTargetExists(self.process_id, self.options.own_process_group)) return true;
            if (second_signal_escalates and signals.interruptionCount() > initial_signal_count)
                return false;
            self.io.sleep(.fromMilliseconds(25), .awake) catch return false;
        }
        return !processTargetExists(self.process_id, self.options.own_process_group);
    }
};

fn runCancellableProcess(
    context: *context_module.RuntimeContext,
    arguments: []const []const u8,
    options: CancellableProcessOptions,
) !CancellableRelaunchResult {
    var child = try std.process.spawn(context.io, .{
        .argv = arguments,
        .stdin = .inherit,
        .stdout = if (options.capture_stdout) .pipe else .inherit,
        .stderr = .inherit,
        .pgid = if (options.own_process_group) 0 else null,
    });
    const process_group = child.id.?;
    errdefer {
        signalProcessGroup(process_group, options.own_process_group, .KILL);
        child.kill(context.io);
    }

    var supervisor: ElevationCancellationSupervisor = .{
        .io = context.io,
        .process_id = process_group,
        .options = options,
    };
    try supervisor.start();
    defer supervisor.finish();

    var captured: ?[]u8 = null;
    errdefer if (captured) |output| context.allocator.free(output);
    if (options.capture_stdout) {
        var output: std.Io.Writer.Allocating = .init(context.allocator);
        errdefer output.deinit();
        var read_buffer: [64 * 1024]u8 = undefined;
        var reader = child.stdout.?.reader(context.io, &read_buffer);
        if (reader.interface.streamRemaining(&output.writer)) |_| {} else |err| {
            if (!signals.wasInterrupted()) return err;
        }
        captured = try output.toOwnedSlice();
    }

    const term = try child.wait(context.io);
    supervisor.leader_reaped.store(true, .release);
    const cancelled = supervisor.cancelled.load(.acquire) or signals.wasInterrupted();
    return .{
        .exit_code = if (cancelled) 130 else try exitCode(term),
        .stdout = captured,
        .cancelled = cancelled,
    };
}

fn signalProcessGroup(process_id: std.posix.pid_t, owns_group: bool, signal: std.posix.SIG) void {
    std.posix.kill(if (owns_group) -process_id else process_id, signal) catch {};
}

fn processTargetExists(process_id: std.posix.pid_t, owns_group: bool) bool {
    const probe: std.posix.SIG = @enumFromInt(0);
    std.posix.kill(if (owns_group) -process_id else process_id, probe) catch |err| return switch (err) {
        error.ProcessNotFound => false,
        error.PermissionDenied => true,
        else => true,
    };
    return true;
}

fn processExists(pid: std.posix.pid_t) bool {
    const probe: std.posix.SIG = @enumFromInt(0);
    std.posix.kill(pid, probe) catch |err| return switch (err) {
        error.ProcessNotFound => false,
        error.PermissionDenied => true,
        else => true,
    };
    return true;
}

/// Runs the current executable as the user who invoked Shelly with elevated
/// privileges. This keeps per-user package stores (notably Flatpak) attached to the calling
/// user when an aggregate command is already running as root. The child also
/// receives the calling user's runtime directory and session bus address so
/// system-scope Flatpak operations can authenticate through the Flatpak
/// helper. Returns null when the process was not elevated by a supported
/// caller-preserving tool.
pub fn runAsInvokingUser(
    context: *context_module.RuntimeContext,
    arguments: []const []const u8,
) !?u8 {
    var arena = std.heap.ArenaAllocator.init(context.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const child_arguments = (try buildCurrentInvokingUserCommand(context, allocator, arguments)) orelse return null;

    var child = try std.process.spawn(context.io, .{
        .argv = child_arguments,
        .stdin = .inherit,
        .stdout = .inherit,
        .stderr = .inherit,
    });
    errdefer child.kill(context.io);
    return @as(?u8, try exitCode(try child.wait(context.io)));
}

pub const CapturedRun = struct {
    exit_code: u8,
    stdout: []u8,

    pub fn deinit(self: CapturedRun, allocator: std.mem.Allocator) void {
        allocator.free(self.stdout);
    }
};

/// Runs Shelly as the original user while retaining its stdout. Stderr stays
/// inherited so a coordinator can forward progress without contaminating a
/// machine-readable result document.
pub fn runAsInvokingUserCapture(
    context: *context_module.RuntimeContext,
    arguments: []const []const u8,
    operation_context: *Zigalpm.OperationContext,
) !?CapturedRun {
    var arena = std.heap.ArenaAllocator.init(context.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const child_arguments = (try buildCurrentInvokingUserCommand(context, allocator, arguments)) orelse return null;

    var child = try std.process.spawn(context.io, .{
        .argv = child_arguments,
        .stdin = .inherit,
        .stdout = .pipe,
        .stderr = .inherit,
    });
    errdefer child.kill(context.io);
    const Cancellation = struct {
        child: *std.process.Child,
        io: std.Io,
        cancelled: std.atomic.Value(bool) = .init(false),

        fn cancel(data: ?*anyopaque) void {
            const self: *@This() = @ptrCast(@alignCast(data.?));
            self.cancelled.store(true, .release);
            self.child.kill(self.io);
        }
    };
    var cancellation: Cancellation = .{ .child = &child, .io = context.io };
    const subscription = try operation_context.subscribeCancellation(.{
        .function = Cancellation.cancel,
        .data = &cancellation,
    });
    defer {
        _ = operation_context.unsubscribeCancellation(subscription);
        operation_context.waitForCancellationCallbacks();
    }
    if (operation_context.isCancelled()) Cancellation.cancel(&cancellation);
    var buffered: std.Io.Writer.Allocating = .init(context.allocator);
    errdefer buffered.deinit();
    var read_buffer: [64 * 1024]u8 = undefined;
    var reader = child.stdout.?.reader(context.io, &read_buffer);
    _ = try reader.interface.streamRemaining(&buffered.writer);
    const code = try exitCode(try child.wait(context.io));
    if (cancellation.cancelled.load(.acquire)) return error.Cancelled;
    return .{ .exit_code = code, .stdout = try buffered.toOwnedSlice() };
}

pub const UserIds = struct {
    uid: std.Io.File.Uid,
    gid: std.Io.File.Gid,
};

pub fn invokingUserIds(context: *const context_module.RuntimeContext) !?UserIds {
    const identity = (try invokingUser(context)) orelse return null;
    defer identity.deinit(context.allocator);
    return .{
        .uid = try std.fmt.parseInt(std.Io.File.Uid, identity.uid, 10),
        .gid = try std.fmt.parseInt(std.Io.File.Gid, identity.gid, 10),
    };
}

pub const InvokingIdentity = privilege.InvokingIdentity;

pub fn invokingUser(context: *const context_module.RuntimeContext) !?InvokingIdentity {
    return privilege.invokingUser(context.allocator, context.environment);
}

fn buildCurrentInvokingUserCommand(
    context: *const context_module.RuntimeContext,
    allocator: std.mem.Allocator,
    arguments: []const []const u8,
) !?[]const []const u8 {
    const environment = context.environment orelse return null;
    const executable_allocated = try std.process.executablePathAlloc(context.io, allocator);
    const executable = executableWithoutDeletedSuffix(executable_allocated);
    return privilege.buildDropToInvokingUserCommand(
        allocator,
        environment,
        .{ .path = Zigalpm.process_runner.build_path.baseline },
        executable,
        arguments,
    );
}

fn executableWithoutDeletedSuffix(path: []const u8) []const u8 {
    const suffix = " (deleted)";
    return if (std.mem.endsWith(u8, path, suffix)) path[0 .. path.len - suffix.len] else path;
}

fn exitCode(term: std.process.Child.Term) Error!u8 {
    return switch (term) {
        .exited => |code| code,
        .signal => |signal| @truncate(128 + @intFromEnum(signal)),
        .stopped, .unknown => error.ElevationFailed,
    };
}

fn expectCancellableProcessTreeStops(
    signal: std.posix.SIG,
    ignore_signals: bool,
    own_process_group: bool,
) !void {
    const allocator = std.testing.allocator;
    var threaded: std.Io.Threaded = .init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const directory = try temporary.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(directory);
    const pid_path = try std.fs.path.join(allocator, &.{ directory, "processes" });
    defer allocator.free(pid_path);
    const cleanup_path = try std.fs.path.join(allocator, &.{ directory, "cleaned" });
    defer allocator.free(cleanup_path);
    const script = if (ignore_signals)
        // Retain the ignored dispositions across exec, but keep the
        // uncooperative process as our direct child. A force-killed grandchild
        // would become PID 1's responsibility and make this unit test depend
        // on the CI container's orphan-reaping policy.
        "trap '' INT TERM; printf '%s %s\\n' \"$$\" \"$$\" > \"$1\"; exec sleep 30"
    else
        "trap 'kill -TERM \"$descendant\" 2>/dev/null; wait \"$descendant\" 2>/dev/null; printf cleaned > \"$2\"; exit 0' INT TERM; sleep 30 & descendant=$!; printf '%s %s\\n' \"$$\" \"$descendant\" > \"$1\"; wait \"$descendant\"";

    var stdout = std.Io.Writer.Discarding.init(&.{});
    var stderr = std.Io.Writer.Discarding.init(&.{});
    var context: context_module.RuntimeContext = .{
        .allocator = allocator,
        .io = io,
        .stdout = &stdout.writer,
        .stderr = &stderr.writer,
    };
    signals.installInterruptHandler(true);
    defer signals.installInterruptHandler(false);
    var future = try io.concurrent(runCancellableProcess, .{
        &context,
        &.{ "sh", "-c", script, "sh", pid_path, cleanup_path },
        CancellableProcessOptions{
            .own_process_group = own_process_group,
            .interrupt_grace_polls = 8,
            .terminate_grace_polls = 12,
            .kill_reap_polls = 20,
        },
    });

    var attempts: usize = 0;
    while (attempts < 200) : (attempts += 1) {
        temporary.dir.access(io, "processes", .{}) catch {
            io.sleep(.fromMilliseconds(5), .awake) catch {};
            continue;
        };
        break;
    }
    if (attempts == 200) {
        signals.installInterruptHandler(true);
        try std.posix.raise(.TERM);
        _ = future.await(io) catch {};
        return error.TestUnexpectedResult;
    }

    try std.posix.raise(signal);
    const result = try future.await(io);
    defer result.deinit(allocator);
    try std.testing.expect(result.cancelled);
    try std.testing.expectEqual(@as(u8, 130), result.exit_code);
    const pid_contents = try temporary.dir.readFileAlloc(
        io,
        "processes",
        allocator,
        .limited(128),
    );
    defer allocator.free(pid_contents);
    var pids = std.mem.tokenizeAny(u8, pid_contents, " \t\r\n");
    const leader = try std.fmt.parseInt(std.posix.pid_t, pids.next() orelse return error.InvalidPid, 10);
    const descendant = try std.fmt.parseInt(std.posix.pid_t, pids.next() orelse return error.InvalidPid, 10);
    // The direct child must have been waited and fully reaped. Graceful cases
    // additionally prove that the simulated elevator reaped its descendant.
    try std.testing.expect(!processExists(leader));
    if (descendant != leader) try std.testing.expect(!processExists(descendant));
    if (!ignore_signals)
        try temporary.dir.access(io, "cleaned", .{});
}

test "targeted SIGINT crosses the cancellable elevation process boundary" {
    try expectCancellableProcessTreeStops(.INT, false, true);
}

test "targeted SIGTERM crosses the cancellable elevation process boundary" {
    try expectCancellableProcessTreeStops(.TERM, false, true);
}

test "interactive elevation preserves its process group and forwards cancellation" {
    try expectCancellableProcessTreeStops(.TERM, false, false);
}

test "cancellable elevation forcibly reaps a child that ignores termination" {
    try expectCancellableProcessTreeStops(.TERM, true, true);
}

test "elevation child status maps to shell exit codes" {
    try std.testing.expectEqual(@as(u8, 7), try exitCode(.{ .exited = 7 }));
    try std.testing.expectError(error.ElevationFailed, exitCode(.{ .unknown = 1 }));
}

test "invoking-user CLI relaunch uses a root-local switch without an elevator" {
    var tc: @import("../commands/test_support.zig").TestContext = .{};
    tc.init();
    defer tc.deinit();
    const allocator = tc.context.allocator;
    const account = (try Zigalpm.user_account.byName(allocator, "nobody")) orelse return error.SkipZigTest;
    const uid = try std.fmt.allocPrint(allocator, "{d}", .{account.uid});
    for ([_][]const u8{ "SUDO_USER", "DOAS_USER", "PKEXEC_UID" }) |marker| {
        var environment = std.process.Environ.Map.init(allocator);
        try environment.put("PATH", "");
        try environment.put("SHELLY_ELEVATOR", "/missing/pkexec");
        try environment.put(marker, if (std.mem.eql(u8, marker, "PKEXEC_UID")) uid else account.username);
        tc.context.environment = &environment;
        const command = (try buildCurrentInvokingUserCommand(&tc.context, allocator, &.{ "upgrade", "flatpak" })).?;
        try std.testing.expectEqualStrings("/usr/bin/runuser", command[0]);
        try std.testing.expectEqualStrings("-u", command[1]);
        try std.testing.expectEqualStrings(account.username, command[2]);
        try std.testing.expectEqualStrings("--", command[3]);
        try std.testing.expectEqualStrings("/usr/bin/env", command[4]);
        try std.testing.expectEqualStrings("-i", command[5]);
        try std.testing.expectEqualStrings("upgrade", command[command.len - 2]);
        try std.testing.expectEqualStrings("flatpak", command[command.len - 1]);
    }
}

test "executable path strips only the exact Linux deleted suffix" {
    for ([_][]const u8{ "/usr/bin/shelly", "/usr/bin/renamed", "/tmp/test", "/tmp/deleted", "/tmp/helper (delete)" }) |path|
        try std.testing.expectEqualStrings(path, executableWithoutDeletedSuffix(path));
    try std.testing.expectEqualStrings("/usr/bin/renamed", executableWithoutDeletedSuffix("/usr/bin/renamed (deleted)"));
}
