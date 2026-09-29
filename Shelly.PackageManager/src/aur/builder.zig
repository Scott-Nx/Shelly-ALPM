const std = @import("std");
pub const build_path = @import("build_path.zig");
const privilege = @import("privilege");
const operation_api = @import("operation_context");

pub const ProcessResult = struct {
    exit_code: u8,
    stdout: []u8,
    stderr: []u8,

    pub fn deinit(self: *ProcessResult, allocator: std.mem.Allocator) void {
        allocator.free(self.stdout);
        allocator.free(self.stderr);
        self.* = undefined;
    }
};

pub const StreamKind = enum {
    stdout,
    stderr,
};

pub const LineHandler = struct {
    function: *const fn (data: ?*anyopaque, stream: StreamKind, line: []const u8) void,
    data: ?*anyopaque = null,

    fn call(self: LineHandler, stream: StreamKind, line: []const u8) void {
        self.function(self.data, stream, line);
    }
};

pub const BuildEnvironment = struct {
    cppflags: ?[]const []const u8 = null,
    cflags: ?[]const []const u8 = null,
    cxxflags: ?[]const []const u8 = null,
    ldflags: ?[]const []const u8 = null,
    ltoflags: ?[]const []const u8 = null,
    makeflags: ?[]const []const u8 = null,
    chost: ?[]const u8 = null,
    distcc_hosts: ?[]const []const u8 = null,
    /// One build-scoped timestamp shared with every PKGBUILD subprocess and
    /// package metadata writer, matching makepkg's SOURCE_DATE_EPOCH model.
    source_date_epoch: ?i64 = null,
    ccache: bool = false,
    distcc: bool = false,
};

pub const OwnedCommand = struct {
    argv: [][]u8,

    pub fn deinit(self: *OwnedCommand, allocator: std.mem.Allocator) void {
        for (self.argv) |argument| allocator.free(argument);
        allocator.free(self.argv);
        self.* = undefined;
    }

    pub fn asConst(self: *const OwnedCommand) []const []const u8 {
        return @ptrCast(self.argv);
    }
};

pub fn directCommand(
    allocator: std.mem.Allocator,
    command: []const u8,
    arguments: []const []const u8,
) !OwnedCommand {
    var argv: std.ArrayList([]u8) = .empty;
    errdefer {
        for (argv.items) |argument| allocator.free(argument);
        argv.deinit(allocator);
    }
    try appendOwned(allocator, &argv, &.{command});
    try appendOwned(allocator, &argv, arguments);
    return .{ .argv = try argv.toOwnedSlice(allocator) };
}

fn appendOwned(
    allocator: std.mem.Allocator,
    list: *std.ArrayList([]u8),
    values: []const []const u8,
) !void {
    for (values) |value| {
        const owned = try allocator.dupe(u8, value);
        errdefer allocator.free(owned);
        try list.append(allocator, owned);
    }
}

pub fn run(
    allocator: std.mem.Allocator,
    io: std.Io,
    argv: []const []const u8,
    working_directory: ?[]const u8,
    timeout_seconds: ?u32,
) !ProcessResult {
    return runWithEnvironmentMap(allocator, io, argv, working_directory, timeout_seconds, null);
}

pub fn runWithEnvironment(
    allocator: std.mem.Allocator,
    io: std.Io,
    environ: std.process.Environ,
    argv: []const []const u8,
    working_directory: ?[]const u8,
    timeout_seconds: ?u32,
) !ProcessResult {
    var environ_map = try executionEnvironment(allocator, environ);
    defer environ_map.deinit();
    return runWithEnvironmentMap(allocator, io, argv, working_directory, timeout_seconds, &environ_map);
}

/// Runs a native build helper with executable lookup using the build PATH.
pub fn runWithBuildEnvironment(
    allocator: std.mem.Allocator,
    io: std.Io,
    environ: std.process.Environ,
    argv: []const []const u8,
    working_directory: ?[]const u8,
    timeout_seconds: ?u32,
) !ProcessResult {
    var environment = try environ.createMap(allocator);
    defer environment.deinit();
    const command = try buildHelperCommand(allocator, argv);
    defer allocator.free(command);
    return runWithEnvironmentMap(allocator, io, command, working_directory, timeout_seconds, &environment);
}

// Zig searches argv[0] using the Io parent's PATH, not environ_map. env
// performs that lookup after receiving the native build's environment.
fn buildHelperCommand(allocator: std.mem.Allocator, argv: []const []const u8) ![][]const u8 {
    return std.mem.concat(allocator, []const u8, &.{ &.{ "/usr/bin/env", "--" }, argv });
}

pub fn runStreamingWithEnvironment(
    allocator: std.mem.Allocator,
    io: std.Io,
    environ: std.process.Environ,
    argv: []const []const u8,
    working_directory: ?[]const u8,
    timeout_seconds: ?u32,
    line_handler: LineHandler,
) !u8 {
    return runStreamingWithEnvironmentOperation(
        allocator,
        io,
        environ,
        argv,
        working_directory,
        timeout_seconds,
        line_handler,
        null,
    );
}

pub fn runStreamingWithEnvironmentOperation(
    allocator: std.mem.Allocator,
    io: std.Io,
    environ: std.process.Environ,
    argv: []const []const u8,
    working_directory: ?[]const u8,
    timeout_seconds: ?u32,
    line_handler: LineHandler,
    operation: ?*const operation_api.Operation,
) !u8 {
    return runStreamingWithBuildEnvironmentOperation(
        allocator,
        io,
        environ,
        null,
        argv,
        working_directory,
        timeout_seconds,
        line_handler,
        operation,
    );
}

pub fn runStreamingWithBuildEnvironmentOperation(
    allocator: std.mem.Allocator,
    io: std.Io,
    environ: std.process.Environ,
    build_environment: ?BuildEnvironment,
    argv: []const []const u8,
    working_directory: ?[]const u8,
    timeout_seconds: ?u32,
    line_handler: LineHandler,
    operation: ?*const operation_api.Operation,
) !u8 {
    var environ_map = if (build_environment) |build|
        try executionEnvironmentWithBuild(allocator, environ, build)
    else
        try executionEnvironment(allocator, environ);
    defer environ_map.deinit();
    const build_command = if (build_environment != null) try buildHelperCommand(allocator, argv) else null;
    defer if (build_command) |command| allocator.free(command);
    var child = try std.process.spawn(io, .{
        .argv = build_command orelse argv,
        .cwd = if (working_directory) |path| .{ .path = path } else .inherit,
        .environ_map = &environ_map,
        .stdin = .ignore,
        .stdout = .pipe,
        .stderr = .pipe,
    });
    defer child.kill(io);

    var multi_reader_buffer: std.Io.File.MultiReader.Buffer(2) = undefined;
    var multi_reader: std.Io.File.MultiReader = undefined;
    multi_reader.init(allocator, io, multi_reader_buffer.toStreams(), &.{ child.stdout.?, child.stderr.? });
    defer multi_reader.deinit();

    const poll_for_cancellation = operation != null;
    const timeout: std.Io.Timeout = if (poll_for_cancellation)
        .{ .duration = .{ .clock = .awake, .raw = .fromMilliseconds(250) } }
    else if (timeout_seconds) |seconds|
        .{ .duration = .{ .clock = .awake, .raw = .fromSeconds(seconds) } }
    else
        .none;
    const start = std.Io.Timestamp.now(io, .awake).nanoseconds;
    read_loop: while (true) {
        multi_reader.fill(4096, timeout) catch |err| switch (err) {
            error.EndOfStream => break :read_loop,
            error.Timeout => {
                if (operation) |active_operation| {
                    if (active_operation.isCancelled()) {
                        child.kill(io);
                        return error.Cancelled;
                    }
                    if (timeout_seconds) |seconds| {
                        const elapsed = std.Io.Timestamp.now(io, .awake).nanoseconds - start;
                        if (elapsed >= @as(i96, seconds) * std.time.ns_per_s) return error.Timeout;
                    }
                    continue :read_loop;
                }
                return error.Timeout;
            },
            else => |other| return other,
        };
        if (operation) |active_operation| {
            if (active_operation.isCancelled()) {
                child.kill(io);
                return error.Cancelled;
            }
        }
        drainLines(multi_reader.reader(0), .stdout, false, line_handler);
        drainLines(multi_reader.reader(1), .stderr, false, line_handler);
    }
    try multi_reader.checkAnyError();
    drainLines(multi_reader.reader(0), .stdout, true, line_handler);
    drainLines(multi_reader.reader(1), .stderr, true, line_handler);

    if (operation) |active_operation| {
        if (active_operation.isCancelled()) {
            child.kill(io);
            return error.Cancelled;
        }
    }
    return switch ((try child.wait(io))) {
        .exited => |code| code,
        else => 255,
    };
}

fn drainLines(reader: *std.Io.Reader, stream: StreamKind, flush_tail: bool, line_handler: LineHandler) void {
    while (std.mem.indexOfAny(u8, reader.buffered(), "\r\n")) |line_end| {
        const line = reader.buffered()[0..line_end];

        if (std.mem.trim(u8, line, " \t").len != 0) {
            line_handler.call(stream, line);
        }

        reader.toss(line_end + 1);
    }

    if (flush_tail and reader.bufferedLen() != 0) {
        const len = reader.bufferedLen();
        const line = std.mem.trimEnd(u8, reader.buffered(), "\r");
        if (line.len != 0) line_handler.call(stream, line);
        reader.toss(len);
    }
}

fn runWithEnvironmentMap(
    allocator: std.mem.Allocator,
    io: std.Io,
    argv: []const []const u8,
    working_directory: ?[]const u8,
    timeout_seconds: ?u32,
    environ_map: ?*const std.process.Environ.Map,
) !ProcessResult {
    const result = try std.process.run(allocator, io, .{
        .argv = argv,
        .cwd = if (working_directory) |path| .{ .path = path } else .inherit,
        .environ_map = environ_map,
        .stdout_limit = .limited(16 * 1024 * 1024),
        .stderr_limit = .limited(16 * 1024 * 1024),
        .timeout = if (timeout_seconds) |seconds|
            .{ .duration = .{ .clock = .awake, .raw = .fromSeconds(seconds) } }
        else
            .none,
    });
    return .{
        .exit_code = switch (result.term) {
            .exited => |code| code,
            else => 255,
        },
        .stdout = result.stdout,
        .stderr = result.stderr,
    };
}

pub fn executionEnvironment(allocator: std.mem.Allocator, environ: std.process.Environ) !std.process.Environ.Map {
    var environ_map = try environ.createMap(allocator);
    errdefer environ_map.deinit();
    const path = try buildExecutionPath(allocator, environ);
    defer allocator.free(path);
    try environ_map.put("PATH", path);
    return environ_map;
}

pub fn executionEnvironmentWithBuild(
    allocator: std.mem.Allocator,
    environ: std.process.Environ,
    build: BuildEnvironment,
) !std.process.Environ.Map {
    var environ_map = try environ.createMap(allocator);
    errdefer environ_map.deinit();

    try putJoinedOrRemove(allocator, &environ_map, "CPPFLAGS", build.cppflags);
    try putJoinedOrRemove(allocator, &environ_map, "CFLAGS", build.cflags);
    try putJoinedOrRemove(allocator, &environ_map, "CXXFLAGS", build.cxxflags);
    try putJoinedOrRemove(allocator, &environ_map, "LDFLAGS", build.ldflags);
    try putJoinedOrRemove(allocator, &environ_map, "LTOFLAGS", build.ltoflags);
    try putJoinedOrRemove(allocator, &environ_map, "MAKEFLAGS", build.makeflags);
    try putScalarOrRemove(&environ_map, "CHOST", build.chost);
    try putJoinedOrRemove(
        allocator,
        &environ_map,
        "DISTCC_HOSTS",
        if (build.distcc) build.distcc_hosts else null,
    );
    if (build.source_date_epoch) |epoch| {
        var epoch_buffer: [20]u8 = undefined;
        const epoch_text = try std.fmt.bufPrint(&epoch_buffer, "{d}", .{epoch});
        try environ_map.put("SOURCE_DATE_EPOCH", epoch_text);
    }

    const path = try build_path.withWrappers(allocator, environ_map.get("PATH") orelse build_path.baseline, build.ccache, build.distcc);
    defer allocator.free(path);
    try environ_map.put("PATH", path);
    return environ_map;
}

fn putJoinedOrRemove(
    allocator: std.mem.Allocator,
    environ_map: *std.process.Environ.Map,
    name: []const u8,
    values: ?[]const []const u8,
) !void {
    if (values) |configured| {
        const joined = try std.mem.join(allocator, " ", configured);
        defer allocator.free(joined);
        try environ_map.put(name, joined);
    } else {
        _ = environ_map.swapRemove(name);
    }
}

fn putScalarOrRemove(
    environ_map: *std.process.Environ.Map,
    name: []const u8,
    value: ?[]const u8,
) !void {
    if (value) |configured|
        try environ_map.put(name, configured)
    else
        _ = environ_map.swapRemove(name);
}

pub fn buildExecutionPath(allocator: std.mem.Allocator, environ: std.process.Environ) ![]u8 {
    const default_path = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/bin";
    const path = environ.getPosix("PATH") orelse default_path;
    if (std.mem.indexOf(u8, path, "core_perl") != null) return allocator.dupe(u8, path);
    return std.fmt.allocPrint(
        allocator,
        "/usr/bin/core_perl:/usr/bin/vendor_perl:/usr/bin/site_perl:{s}",
        .{path},
    );
}

pub fn resolveInvokingUserHome(
    allocator: std.mem.Allocator,
    _: std.Io,
    environ: std.process.Environ,
) ![]u8 {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    var environment = try environ.createMap(arena.allocator());
    defer environment.deinit();
    return privilege.invokingUserHome(allocator, &environment);
}

pub fn invokingUserCommand(
    allocator: std.mem.Allocator,
    _: std.Io,
    environ: std.process.Environ,
    command: []const u8,
    arguments: []const []const u8,
) !OwnedCommand {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const scratch = arena.allocator();
    var environment = try environ.createMap(scratch);
    defer environment.deinit();
    const child_arguments = (try privilege.buildDropToInvokingUserCommand(
        scratch,
        &environment,
        .{ .path = environment.get("PATH") orelse build_path.baseline },
        command,
        arguments,
    )) orelse return directCommand(allocator, command, arguments);
    var owned: std.ArrayList([]u8) = .empty;
    errdefer {
        for (owned.items) |argument| allocator.free(argument);
        owned.deinit(allocator);
    }
    try appendOwned(allocator, &owned, child_arguments);
    return .{ .argv = try owned.toOwnedSlice(allocator) };
}

/// Runs reviewed PKGBUILD code with only the invoking user's safe environment.
pub fn invokingUserCleanCommand(
    allocator: std.mem.Allocator,
    _: std.Io,
    environ: std.process.Environ,
    command: []const u8,
    arguments: []const []const u8,
) !OwnedCommand {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const scratch = arena.allocator();
    var environment = try environ.createMap(scratch);
    defer environment.deinit();
    const child_arguments = (try privilege.buildDropToInvokingUserCommand(
        scratch,
        &environment,
        .{
            .path = build_path.baseline,
            .preserve_locale = true,
            .preserve_source_date_epoch = true,
        },
        command,
        arguments,
    )) orelse return error.InvokingUserUnavailable;
    var owned: std.ArrayList([]u8) = .empty;
    errdefer {
        for (owned.items) |argument| allocator.free(argument);
        owned.deinit(allocator);
    }
    try appendOwned(allocator, &owned, child_arguments);
    return .{ .argv = try owned.toOwnedSlice(allocator) };
}

pub fn makechrootpkgCommand(
    allocator: std.mem.Allocator,
    _: std.Io,
    environ: std.process.Environ,
    chroot_path: []const u8,
) !OwnedCommand {
    var argv: std.ArrayList([]u8) = .empty;
    errdefer {
        for (argv.items) |argument| allocator.free(argument);
        argv.deinit(allocator);
    }
    try appendOwned(allocator, &argv, &.{ "makechrootpkg", "-c", "-r", chroot_path });
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    var environment = try environ.createMap(arena.allocator());
    defer environment.deinit();
    if (try privilege.invokingUser(arena.allocator(), &environment)) |identity| {
        try appendOwned(allocator, &argv, &.{ "-U", identity.username });
    } else if (privilege.hasInvokingUserMarker(&environment)) {
        return error.InvokingUserUnavailable;
    }
    return .{ .argv = try argv.toOwnedSlice(allocator) };
}

pub const BuildProgress = struct {
    percent: u8,
    message: []const u8,
};

pub fn parseBuildProgress(line: []const u8) ?BuildProgress {
    const open = std.mem.indexOfScalar(u8, line, '[') orelse return null;
    const percent_sign = std.mem.indexOfPos(u8, line, open + 1, "%") orelse return null;
    const close = std.mem.indexOfPos(u8, line, percent_sign + 1, "]") orelse return null;
    const percent_text = std.mem.trim(u8, line[open + 1 .. percent_sign], " \t");
    const percent = std.fmt.parseInt(u8, percent_text, 10) catch return null;
    if (percent > 100) return null;
    return .{
        .percent = percent,
        .message = std.mem.trim(u8, line[close + 1 ..], " \t"),
    };
}

pub fn selectBuiltPackageFiles(
    allocator: std.mem.Allocator,
    io: std.Io,
    directory_path: []const u8,
    package_name: []const u8,
) ![][]u8 {
    return selectBuiltPackageFilesForNames(
        allocator,
        io,
        directory_path,
        &.{package_name},
        &.{package_name},
    );
}

pub fn selectBuiltPackageFilesForNames(
    allocator: std.mem.Allocator,
    io: std.Io,
    directory_path: []const u8,
    requested_names: []const []const u8,
    package_names: []const []const u8,
) ![][]u8 {
    var directory = std.Io.Dir.cwd().openDir(io, directory_path, .{ .iterate = true }) catch |err| switch (err) {
        error.FileNotFound => return allocator.alloc([]u8, 0),
        else => return err,
    };
    defer directory.close(io);
    var iterator = directory.iterate();
    var paths: std.ArrayList([]u8) = .empty;
    errdefer {
        for (paths.items) |path| allocator.free(path);
        paths.deinit(allocator);
    }
    while (try iterator.next(io)) |entry| {
        if (entry.kind != .file) continue;
        if (!isBuiltPackageFile(entry.name)) continue;

        // Split-package names may prefix one another (for example `demo` and
        // `demo-docs`). Classifying against the longest known package name
        // prevents selecting an unrequested sibling as `demo`.
        var matched_name: ?[]const u8 = null;
        for (package_names) |name| {
            if (entry.name.len <= name.len or entry.name[name.len] != '-' or
                !std.mem.startsWith(u8, entry.name, name)) continue;
            if (matched_name == null or name.len > matched_name.?.len) matched_name = name;
        }
        const package = matched_name orelse continue;
        var requested = false;
        for (requested_names) |name| {
            if (std.mem.eql(u8, name, package)) {
                requested = true;
                break;
            }
        }
        if (!requested) continue;
        try paths.append(allocator, try std.fs.path.join(allocator, &.{ directory_path, entry.name }));
    }
    return paths.toOwnedSlice(allocator);
}

pub fn isBuiltPackageFile(file_name: []const u8) bool {
    return isPackageArchiveArtifact(file_name) and
        !std.mem.endsWith(u8, file_name, ".sig");
}

pub fn isPackageArchiveArtifact(file_name: []const u8) bool {
    return std.mem.indexOf(u8, file_name, ".pkg.tar.") != null;
}

pub fn deinitPaths(allocator: std.mem.Allocator, paths: []const []u8) void {
    for (paths) |path| allocator.free(path);
    allocator.free(paths);
}

test "build progress parser recognizes makepkg percentage lines" {
    const progress = parseBuildProgress("[ 42%] Compiling source files").?;
    try std.testing.expectEqual(@as(u8, 42), progress.percent);
    try std.testing.expectEqualStrings("Compiling source files", progress.message);
    try std.testing.expect(parseBuildProgress("ordinary output") == null);
}

test "execution PATH adds Arch Perl paths exactly once" {
    const path = try buildExecutionPath(std.testing.allocator, std.testing.environ);
    defer std.testing.allocator.free(path);
    try std.testing.expect(std.mem.indexOf(u8, path, "/usr/bin/core_perl") != null);

    var environ_map = try executionEnvironment(std.testing.allocator, std.testing.environ);
    defer environ_map.deinit();
    try std.testing.expectEqualStrings(path, environ_map.get("PATH").?);
}

test "build environment exports flags hosts and compiler wrapper paths" {
    var environ_map = std.process.Environ.Map.init(std.testing.allocator);
    defer environ_map.deinit();
    try environ_map.put("PATH", "/usr/bin:/bin");
    const environ: std.process.Environ = .{
        .block = try environ_map.createPosixBlock(std.testing.allocator, .{}),
    };
    defer environ.block.deinit(std.testing.allocator);

    var effective = try executionEnvironmentWithBuild(std.testing.allocator, environ, .{
        .cppflags = &.{"-D_FORTIFY_SOURCE=3"},
        .cflags = &.{ "-O3", "-pipe" },
        .cxxflags = &.{"-O3"},
        .ldflags = &.{"-Wl,-z,now"},
        .ltoflags = &.{"-flto=auto"},
        .makeflags = &.{"-j8"},
        .chost = "x86_64-pc-linux-gnu",
        .distcc_hosts = &.{ "builder/8", "localhost/2" },
        .source_date_epoch = 1_700_000_000,
        .ccache = true,
        .distcc = true,
    });
    defer effective.deinit();

    try std.testing.expectEqualStrings("-D_FORTIFY_SOURCE=3", effective.get("CPPFLAGS").?);
    try std.testing.expectEqualStrings("-O3 -pipe", effective.get("CFLAGS").?);
    try std.testing.expectEqualStrings("-j8", effective.get("MAKEFLAGS").?);
    try std.testing.expectEqualStrings("builder/8 localhost/2", effective.get("DISTCC_HOSTS").?);
    try std.testing.expectEqualStrings("1700000000", effective.get("SOURCE_DATE_EPOCH").?);
    try std.testing.expect(std.mem.startsWith(u8, effective.get("PATH").?, "/usr/lib/ccache/bin:/usr/lib/distcc/bin:"));
}

test "disabled build environment removes inherited flags and hosts" {
    var environ_map = std.process.Environ.Map.init(std.testing.allocator);
    defer environ_map.deinit();
    try environ_map.put("CFLAGS", "ambient flags");
    try environ_map.put("MAKEFLAGS", "ambient make flags");
    try environ_map.put("DISTCC_HOSTS", "ambient host");
    const environ: std.process.Environ = .{
        .block = try environ_map.createPosixBlock(std.testing.allocator, .{}),
    };
    defer environ.block.deinit(std.testing.allocator);

    var effective = try executionEnvironmentWithBuild(std.testing.allocator, environ, .{
        .chost = "x86_64-pc-linux-gnu",
    });
    defer effective.deinit();
    try std.testing.expect(effective.get("CFLAGS") == null);
    try std.testing.expect(effective.get("MAKEFLAGS") == null);
    try std.testing.expect(effective.get("DISTCC_HOSTS") == null);
    try std.testing.expectEqualStrings("x86_64-pc-linux-gnu", effective.get("CHOST").?);
}

test "VCS build commands replicate invoking-user behavior" {
    var command = try makechrootpkgCommand(
        std.testing.allocator,
        std.testing.io,
        std.testing.environ,
        "/var/lib/shelly/chroot",
    );
    defer command.deinit(std.testing.allocator);
    var command_index: ?usize = null;
    for (command.argv, 0..) |argument, index| {
        if (std.mem.eql(u8, argument, "makechrootpkg")) command_index = index;
    }
    const index = command_index orelse return error.MissingMakechrootpkgCommand;
    try std.testing.expectEqualStrings("-c", command.argv[index + 1]);
    try std.testing.expectEqualStrings("-r", command.argv[index + 2]);
    try std.testing.expectEqualStrings("/var/lib/shelly/chroot", command.argv[index + 3]);
}

test "invoking-user command stays direct when caller identity is absent" {
    var environment = std.process.Environ.Map.init(std.testing.allocator);
    defer environment.deinit();
    const environ: std.process.Environ = .{ .block = try environment.createPosixBlock(std.testing.allocator, .{}) };
    defer environ.block.deinit(std.testing.allocator);

    var command = try invokingUserCommand(std.testing.allocator, std.testing.io, environ, "/usr/bin/git", &.{ "status", "--short" });
    defer command.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("/usr/bin/git", command.argv[0]);
    try std.testing.expectEqualStrings("status", command.argv[1]);
    try std.testing.expectEqualStrings("--short", command.argv[2]);
}

test "clean invoking-user command rejects missing caller identity" {
    var environment = std.process.Environ.Map.init(std.testing.allocator);
    defer environment.deinit();
    const environ: std.process.Environ = .{ .block = try environment.createPosixBlock(std.testing.allocator, .{}) };
    defer environ.block.deinit(std.testing.allocator);
    try std.testing.expectError(
        error.InvokingUserUnavailable,
        invokingUserCleanCommand(std.testing.allocator, std.testing.io, environ, "/usr/bin/shelly", &.{"build"}),
    );
}

test "built package selection mirrors split-package and stale-output safeguards" {
    var matching = std.testing.tmpDir(.{});
    defer matching.cleanup();
    try matching.dir.writeFile(std.testing.io, .{ .sub_path = "demo-1-1-x86_64.pkg.tar.zst", .data = "" });
    try matching.dir.writeFile(std.testing.io, .{ .sub_path = "demo-docs-1-1-any.pkg.tar.zst", .data = "" });
    try matching.dir.writeFile(std.testing.io, .{ .sub_path = "demo-1-1-x86_64.pkg.tar.zst.sig", .data = "" });
    const matching_path = try matching.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(matching_path);
    const split_files = try selectBuiltPackageFilesForNames(
        std.testing.allocator,
        std.testing.io,
        matching_path,
        &.{"demo"},
        &.{ "demo", "demo-docs" },
    );
    defer deinitPaths(std.testing.allocator, split_files);
    try std.testing.expectEqual(@as(usize, 1), split_files.len);
    try std.testing.expect(std.mem.endsWith(u8, split_files[0], "demo-1-1-x86_64.pkg.tar.zst"));

    const all_split_files = try selectBuiltPackageFilesForNames(
        std.testing.allocator,
        std.testing.io,
        matching_path,
        &.{ "demo", "demo-docs" },
        &.{ "demo", "demo-docs" },
    );
    defer deinitPaths(std.testing.allocator, all_split_files);
    try std.testing.expectEqual(@as(usize, 2), all_split_files.len);

    var ambiguous = std.testing.tmpDir(.{});
    defer ambiguous.cleanup();
    try ambiguous.dir.writeFile(std.testing.io, .{ .sub_path = "one-1-1-any.pkg.tar.zst", .data = "" });
    try ambiguous.dir.writeFile(std.testing.io, .{ .sub_path = "two-1-1-any.pkg.tar.zst", .data = "" });
    const ambiguous_path = try ambiguous.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(ambiguous_path);
    const no_match = try selectBuiltPackageFiles(std.testing.allocator, std.testing.io, ambiguous_path, "demo");
    defer deinitPaths(std.testing.allocator, no_match);
    try std.testing.expectEqual(@as(usize, 0), no_match.len);

    try std.testing.expect(isBuiltPackageFile("demo.pkg.tar.zst"));
    try std.testing.expect(!isBuiltPackageFile("demo.pkg.tar.zst.sig"));
    try std.testing.expect(isPackageArchiveArtifact("demo.pkg.tar.zst.sig"));
}

test "streaming process execution forwards stdout stderr and a final unterminated line" {
    const Capture = struct {
        stdout_buffer: [64]u8 = undefined,
        stdout_len: usize = 0,
        stderr_buffer: [64]u8 = undefined,
        stderr_len: usize = 0,

        fn append(target: []u8, len: *usize, line: []const u8) void {
            if (len.* != 0 and len.* < target.len) {
                target[len.*] = '|';
                len.* += 1;
            }
            const amount = @min(line.len, target.len - len.*);
            @memcpy(target[len.*..][0..amount], line[0..amount]);
            len.* += amount;
        }

        fn onLine(data: ?*anyopaque, stream: StreamKind, line: []const u8) void {
            const self: *@This() = @ptrCast(@alignCast(data));
            switch (stream) {
                .stdout => append(&self.stdout_buffer, &self.stdout_len, line),
                .stderr => append(&self.stderr_buffer, &self.stderr_len, line),
            }
        }
    };

    var capture = Capture{};
    const exit_code = try runStreamingWithEnvironment(
        std.testing.allocator,
        std.testing.io,
        std.testing.environ,
        &.{ "sh", "-c", "printf 'first\\nlast'; printf 'problem\\n' >&2" },
        null,
        null,
        .{ .function = Capture.onLine, .data = &capture },
    );
    try std.testing.expectEqual(@as(u8, 0), exit_code);
    try std.testing.expectEqualStrings("first|last", capture.stdout_buffer[0..capture.stdout_len]);
    try std.testing.expectEqualStrings("problem", capture.stderr_buffer[0..capture.stderr_len]);
}

test "streaming process execution delivers output before the child exits" {
    const Capture = struct {
        io: std.Io,
        acknowledgement_path: []const u8,
        saw_first: bool = false,
        saw_second: bool = false,

        fn onLine(data: ?*anyopaque, stream: StreamKind, line: []const u8) void {
            const self: *@This() = @ptrCast(@alignCast(data));
            if (stream != .stdout) return;
            if (std.mem.eql(u8, line, "first")) {
                self.saw_first = true;
                var acknowledgement = std.Io.Dir.cwd().createFile(
                    self.io,
                    self.acknowledgement_path,
                    .{},
                ) catch return;
                acknowledgement.close(self.io);
            } else if (std.mem.eql(u8, line, "second")) {
                self.saw_second = true;
            }
        }
    };

    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const temporary_path = try temporary.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(temporary_path);
    const acknowledgement_path = try std.fs.path.join(std.testing.allocator, &.{ temporary_path, "acknowledged" });
    defer std.testing.allocator.free(acknowledgement_path);

    var capture = Capture{
        .io = std.testing.io,
        .acknowledgement_path = acknowledgement_path,
    };
    const exit_code = try runStreamingWithEnvironment(
        std.testing.allocator,
        std.testing.io,
        std.testing.environ,
        &.{
            "sh",
            "-c",
            "printf 'first\\n'; i=0; while [ ! -e \"$1\" ] && [ \"$i\" -lt 100 ]; do sleep 0.01; i=$((i + 1)); done; [ -e \"$1\" ] || exit 9; printf 'second\\n'",
            "sh",
            acknowledgement_path,
        },
        null,
        null,
        .{ .function = Capture.onLine, .data = &capture },
    );

    try std.testing.expectEqual(@as(u8, 0), exit_code);
    try std.testing.expect(capture.saw_first);
    try std.testing.expect(capture.saw_second);
}

test "streaming process execution terminates when the shared operation is cancelled" {
    const Capture = struct {
        fn onLine(_: ?*anyopaque, _: StreamKind, _: []const u8) void {}
    };

    var threaded: std.Io.Threaded = .init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const directory = try temporary.dir.realPathFileAlloc(io, ".", std.testing.allocator);
    defer std.testing.allocator.free(directory);
    const marker = try std.fs.path.join(std.testing.allocator, &.{ directory, "child-started" });
    defer std.testing.allocator.free(marker);

    var context = operation_api.OperationContext.init(std.testing.allocator, io);
    defer context.deinit();
    var operation = context.begin(.{ .backend = .aur, .kind = .build, .subject = "cancelled-build" });
    defer operation.finish(.cancelled);
    var future = try io.concurrent(runStreamingWithEnvironmentOperation, .{
        std.testing.allocator,
        io,
        std.testing.environ,
        &.{ "sh", "-c", "touch \"$1\"; exec sleep 30", "sh", marker },
        null,
        null,
        LineHandler{ .function = Capture.onLine },
        &operation,
    });
    var attempts: usize = 0;
    while (attempts < 200) : (attempts += 1) {
        std.Io.Dir.cwd().access(io, marker, .{}) catch {
            io.sleep(.fromMilliseconds(5), .awake) catch {};
            continue;
        };
        break;
    }
    try std.testing.expect(attempts < 200);
    context.cancel();
    try std.testing.expectError(error.Cancelled, future.await(io));
}

test "NSS invoking-user AUR and VCS commands use root-local switching without an elevator" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const account = (try @import("user_account").byName(allocator, "nobody")) orelse return error.SkipZigTest;
    const uid = try std.fmt.allocPrint(allocator, "{d}", .{account.uid});
    for ([_][]const u8{ "SUDO_USER", "DOAS_USER", "PKEXEC_UID" }) |marker| {
        var environment = std.process.Environ.Map.init(allocator);
        try environment.put("PATH", "");
        try environment.put("SHELLY_ELEVATOR", "/missing/pkexec");
        try environment.put(marker, if (std.mem.eql(u8, marker, "PKEXEC_UID")) uid else account.username);
        const environ: std.process.Environ = .{ .block = try environment.createPosixBlock(allocator, .{}) };
        const clean = try invokingUserCleanCommand(allocator, std.testing.io, environ, "/usr/bin/shelly", &.{ "build", "--coordinator-child" });
        const vcs = try invokingUserCommand(allocator, std.testing.io, environ, "/usr/bin/git", &.{"status"});
        for ([_]OwnedCommand{ clean, vcs }) |command| {
            try std.testing.expectEqualStrings("/usr/bin/runuser", command.argv[0]);
            try std.testing.expectEqualStrings("-u", command.argv[1]);
            try std.testing.expectEqualStrings(account.username, command.argv[2]);
            try std.testing.expectEqualStrings("--", command.argv[3]);
            try std.testing.expectEqualStrings("/usr/bin/env", command.argv[4]);
            try std.testing.expectEqualStrings("-i", command.argv[5]);
        }
        try std.testing.expectEqualStrings("--coordinator-child", clean.argv[clean.argv.len - 1]);
        try std.testing.expectEqualStrings("status", vcs.argv[vcs.argv.len - 1]);
        const chroot = try makechrootpkgCommand(allocator, std.testing.io, environ, "/var/lib/shelly/chroot");
        try std.testing.expectEqualStrings("-U", chroot.argv[chroot.argv.len - 2]);
        try std.testing.expectEqualStrings(account.username, chroot.argv[chroot.argv.len - 1]);
    }
}

test "NSS invoking-user home propagates invalid authoritative identity errors" {
    for ([_][]const u8{ "SUDO_USER", "DOAS_USER", "PKEXEC_UID" }) |marker| {
        var environment = std.process.Environ.Map.init(std.testing.allocator);
        defer environment.deinit();
        try environment.put("HOME", "/root");
        try environment.put(marker, if (std.mem.eql(u8, marker, "PKEXEC_UID")) "invalid" else "root");
        const environ: std.process.Environ = .{ .block = try environment.createPosixBlock(std.testing.allocator, .{}) };
        defer environ.block.deinit(std.testing.allocator);
        try std.testing.expectError(error.InvokingUserUnavailable, resolveInvokingUserHome(std.testing.allocator, std.testing.io, environ));
    }
}

test "invoking-user command argument copies are freed on allocation failure" {
    const Check = struct {
        fn run(allocator: std.mem.Allocator) !void {
            var command = try directCommand(allocator, "/usr/bin/git", &.{ "status", "--short" });
            defer command.deinit(allocator);
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Check.run, .{});
}
