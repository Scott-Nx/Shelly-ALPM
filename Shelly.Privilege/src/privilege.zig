const std = @import("std");
const user_account = @import("user_account");

pub const ProviderKind = enum {
    sudo,
    doas,
    run0,
    pkexec,
};

pub const Requirement = enum {
    elevate_root,
    run_as_user,
};

pub const Capabilities = packed struct {
    elevate_root: bool = false,
    run_as_user: bool = false,
    invoking_user_identity: bool = false,
};

const ProviderDefinition = struct {
    kind: ProviderKind,
    name: []const u8,
    capabilities: Capabilities,
    caller_name_variable: ?[]const u8 = null,
    caller_uid_variable: ?[]const u8 = null,
    environment_prefix: ?[]const u8 = null,
};

const registry = [_]ProviderDefinition{
    .{
        .kind = .sudo,
        .name = "sudo",
        .capabilities = .{ .elevate_root = true, .run_as_user = true, .invoking_user_identity = true },
        .caller_name_variable = "SUDO_USER",
        .environment_prefix = "SUDO_",
    },
    .{
        .kind = .doas,
        .name = "doas",
        .capabilities = .{ .elevate_root = true, .run_as_user = true, .invoking_user_identity = true },
        .caller_name_variable = "DOAS_USER",
        .environment_prefix = "DOAS_",
    },
    .{
        .kind = .run0,
        .name = "run0",
        .capabilities = .{ .elevate_root = true, .run_as_user = true, .invoking_user_identity = true },
        .caller_name_variable = "SUDO_USER",
        .environment_prefix = "SUDO_",
    },
    .{
        .kind = .pkexec,
        .name = "pkexec",
        .capabilities = .{ .elevate_root = true, .invoking_user_identity = true },
        .caller_uid_variable = "PKEXEC_UID",
        .environment_prefix = "PKEXEC_",
    },
};

const automatic_priority = [_]ProviderKind{ .doas, .sudo, .run0 };
// run0 shares SUDO_USER; each identity source appears only once.
const identity_priority = [_]ProviderKind{ .sudo, .doas, .pkexec };

pub const Provider = struct {
    kind: ProviderKind,
    executable: []const u8,

    pub fn deinit(self: Provider, allocator: std.mem.Allocator) void {
        allocator.free(self.executable);
    }
};

pub const InvokingUserCommandOptions = struct {
    path: []const u8,
    preserve_locale: bool = false,
    preserve_source_date_epoch: bool = false,
};

pub fn select(
    allocator: std.mem.Allocator,
    io: std.Io,
    environment: ?*const std.process.Environ.Map,
    requirement: Requirement,
) !Provider {
    const variables = environment orelse return error.NoElevator;
    const path = variables.get("PATH") orelse "";

    if (variables.get("SHELLY_ELEVATOR")) |configured| {
        const executable = std.mem.trim(u8, configured, " \t\r\n");
        if (executable.len > 0) {
            const kind = providerKind(std.fs.path.basename(executable)) orelse
                return error.UnsupportedElevator;
            const resolved = try resolveConfigured(allocator, io, path, executable);
            errdefer allocator.free(resolved);
            if (!supports(kind, requirement)) return error.ElevatorOperationUnsupported;
            return .{ .kind = kind, .executable = resolved };
        }
    }

    for (automatic_priority) |kind| {
        if (!supports(kind, requirement)) continue;
        const definition = providerDefinition(kind);
        if (try findExecutable(allocator, io, path, definition.name)) |resolved|
            return .{ .kind = kind, .executable = resolved };
    }
    return error.NoElevator;
}

pub fn capabilities(kind: ProviderKind) Capabilities {
    return providerDefinition(kind).capabilities;
}

pub fn buildRootCommand(
    allocator: std.mem.Allocator,
    provider: Provider,
    executable: []const u8,
    arguments: []const []const u8,
) ![]const []const u8 {
    if (!supports(provider.kind, .elevate_root)) return error.ElevatorOperationUnsupported;
    var result: std.ArrayList([]const u8) = .empty;
    errdefer result.deinit(allocator);
    try result.appendSlice(allocator, &.{ provider.executable, executable });
    try result.appendSlice(allocator, arguments);
    return result.toOwnedSlice(allocator);
}

/// Builds a helper-mediated command for the validated invoking user.
/// For an already-root process, use buildDropToInvokingUserCommand instead.
/// Returns null when there is no supported caller marker.
pub fn buildInvokingUserCommand(
    allocator: std.mem.Allocator,
    io: std.Io,
    environment: *const std.process.Environ.Map,
    options: InvokingUserCommandOptions,
    executable: []const u8,
    arguments: []const []const u8,
) !?[]const []const u8 {
    return buildInvokingUserCommandWithAccounts(
        allocator,
        .{ .helper = io },
        environment,
        options,
        executable,
        arguments,
        user_account,
    );
}

/// Builds a root-local command that drops to the validated invoking user.
/// The caller must already be root to execute it. No elevator is selected and
/// SHELLY_ELEVATOR has no effect. Returns null when no caller marker exists.
pub fn buildDropToInvokingUserCommand(
    allocator: std.mem.Allocator,
    environment: *const std.process.Environ.Map,
    options: InvokingUserCommandOptions,
    executable: []const u8,
    arguments: []const []const u8,
) !?[]const []const u8 {
    return buildInvokingUserCommandWithAccounts(
        allocator,
        .drop_to_user,
        environment,
        options,
        executable,
        arguments,
        user_account,
    );
}

const InvokingUserExecution = union(enum) {
    drop_to_user,
    helper: std.Io,
};

fn buildInvokingUserCommandWithAccounts(
    allocator: std.mem.Allocator,
    execution: InvokingUserExecution,
    environment: *const std.process.Environ.Map,
    options: InvokingUserCommandOptions,
    executable: []const u8,
    arguments: []const []const u8,
    comptime accounts: type,
) !?[]const []const u8 {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const scratch = arena.allocator();

    const identity = (try invokingIdentity(scratch, environment, accounts)) orelse {
        if (hasInvokingUserMarker(environment)) return error.InvokingUserUnavailable;
        return null;
    };
    if (identity.home.len == 0 or !std.fs.path.isAbsolute(identity.home))
        return error.InvokingUserUnavailable;

    const user_environment = try invokingUserEnvironment(scratch, environment, identity, options);
    const path_environment = try std.fmt.allocPrint(scratch, "PATH={s}", .{options.path});
    const child_arguments = switch (execution) {
        .drop_to_user => local: {
            var command: std.ArrayList([]const u8) = .empty;
            try command.appendSlice(scratch, &.{ "/usr/bin/runuser", "-u", identity.username, "--", "/usr/bin/env", "-i" });
            try command.appendSlice(scratch, user_environment);
            try command.appendSlice(scratch, &.{ path_environment, executable });
            try command.appendSlice(scratch, arguments);
            break :local try command.toOwnedSlice(scratch);
        },
        .helper => |io| try buildProviderInvokingUserCommand(
            scratch,
            try select(scratch, io, environment, .run_as_user),
            identity.username,
            user_environment,
            path_environment,
            executable,
            arguments,
        ),
    };
    return try duplicateArguments(allocator, child_arguments);
}

fn invokingUserEnvironment(
    allocator: std.mem.Allocator,
    environment: *const std.process.Environ.Map,
    identity: InvokingIdentity,
    options: InvokingUserCommandOptions,
) ![]const []const u8 {
    var entries: std.ArrayList([]const u8) = .empty;
    try entries.appendSlice(allocator, &.{
        try std.fmt.allocPrint(allocator, "HOME={s}", .{identity.home}),
        try std.fmt.allocPrint(allocator, "XDG_CONFIG_HOME={s}/.config", .{identity.home}),
        try std.fmt.allocPrint(allocator, "XDG_DATA_HOME={s}/.local/share", .{identity.home}),
        try std.fmt.allocPrint(allocator, "XDG_CACHE_HOME={s}/.cache", .{identity.home}),
        try std.fmt.allocPrint(allocator, "XDG_BIN_HOME={s}/.local/bin", .{identity.home}),
        try std.fmt.allocPrint(allocator, "XDG_RUNTIME_DIR=/run/user/{s}", .{identity.uid}),
        try std.fmt.allocPrint(allocator, "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{s}/bus", .{identity.uid}),
    });
    if (options.preserve_source_date_epoch) {
        if (environment.get("SOURCE_DATE_EPOCH")) |epoch|
            try entries.append(allocator, try std.fmt.allocPrint(allocator, "SOURCE_DATE_EPOCH={s}", .{epoch}));
    }
    if (options.preserve_locale) {
        const lang = environment.get("LANG") orelse "";
        try entries.append(allocator, try std.fmt.allocPrint(allocator, "LANG={s}", .{if (lang.len == 0) "C.UTF-8" else lang}));
        for (locale_variables) |name| {
            if (environment.get(name)) |value|
                try entries.append(allocator, try std.fmt.allocPrint(allocator, "{s}={s}", .{ name, value }));
        }
    }
    return entries.toOwnedSlice(allocator);
}

fn buildProviderInvokingUserCommand(
    allocator: std.mem.Allocator,
    provider: Provider,
    user: []const u8,
    environment: []const []const u8,
    path_environment: []const u8,
    executable: []const u8,
    arguments: []const []const u8,
) ![]const []const u8 {
    if (!supports(provider.kind, .run_as_user)) return error.ElevatorOperationUnsupported;

    var result: std.ArrayList([]const u8) = .empty;
    errdefer result.deinit(allocator);
    if (provider.kind == .run0) {
        try result.appendSlice(allocator, &.{ provider.executable, "--user", user });
        for (environment) |entry| try result.appendSlice(allocator, &.{ "--setenv", entry });
        try result.appendSlice(allocator, &.{ "--setenv", path_environment, executable });
    } else {
        try result.appendSlice(allocator, &.{ provider.executable, "-u", user, "/usr/bin/env", "-i" });
        try result.appendSlice(allocator, environment);
        try result.appendSlice(allocator, &.{ path_environment, executable });
    }
    try result.appendSlice(allocator, arguments);
    return result.toOwnedSlice(allocator);
}

fn duplicateArguments(allocator: std.mem.Allocator, arguments: []const []const u8) ![]const []const u8 {
    const result = try allocator.alloc([]const u8, arguments.len);
    errdefer allocator.free(result);
    var copied: usize = 0;
    errdefer for (result[0..copied]) |argument| allocator.free(argument);
    for (arguments, 0..) |argument, index| {
        result[index] = try allocator.dupe(u8, argument);
        copied += 1;
    }
    return result;
}

const locale_variables = [_][]const u8{
    "LANGUAGE",
    "LC_ALL",
    "LC_CTYPE",
    "LC_NUMERIC",
    "LC_TIME",
    "LC_COLLATE",
    "LC_MONETARY",
    "LC_MESSAGES",
    "LC_PAPER",
    "LC_NAME",
    "LC_ADDRESS",
    "LC_TELEPHONE",
    "LC_MEASUREMENT",
    "LC_IDENTIFICATION",
};

pub const InvokingIdentity = struct {
    username: []u8,
    uid: []u8,
    gid: []u8,
    home: []u8,

    pub fn deinit(self: InvokingIdentity, allocator: std.mem.Allocator) void {
        allocator.free(self.username);
        allocator.free(self.uid);
        allocator.free(self.gid);
        allocator.free(self.home);
    }
};

pub fn invokingUser(
    allocator: std.mem.Allocator,
    environment: ?*const std.process.Environ.Map,
) !?InvokingIdentity {
    const variables = environment orelse return null;
    return invokingIdentity(allocator, variables, user_account);
}

pub fn invokingUserHome(
    allocator: std.mem.Allocator,
    environment: ?*const std.process.Environ.Map,
) ![]u8 {
    return invokingUserHomeWithAccounts(allocator, environment, user_account);
}

fn invokingUserHomeWithAccounts(
    allocator: std.mem.Allocator,
    environment: ?*const std.process.Environ.Map,
    comptime accounts: type,
) ![]u8 {
    if (environment) |variables| {
        if (try invokingIdentity(allocator, variables, accounts)) |identity| {
            defer identity.deinit(allocator);
            if (identity.home.len > 0) return allocator.dupe(u8, identity.home);
            return error.InvokingUserUnavailable;
        }
        if (hasInvokingUserMarker(variables)) return error.InvokingUserUnavailable;
        if (variables.get("HOME")) |home| return allocator.dupe(u8, home);
    }
    return error.HomeNotSet;
}

pub fn hasInvokingUserMarker(environment: ?*const std.process.Environ.Map) bool {
    const variables = environment orelse return false;
    for (registry) |definition| {
        if (!definition.capabilities.invoking_user_identity) continue;
        if (definition.caller_name_variable) |marker| {
            if (variables.get(marker) != null) return true;
        }
        if (definition.caller_uid_variable) |marker| {
            if (variables.get(marker) != null) return true;
        }
    }
    return false;
}

pub fn isProviderEnvironmentVariable(name: []const u8) bool {
    for (registry) |definition| {
        if (definition.environment_prefix) |prefix| {
            if (std.mem.startsWith(u8, name, prefix)) return true;
        }
    }
    return false;
}

fn invokingIdentity(
    allocator: std.mem.Allocator,
    environment: *const std.process.Environ.Map,
    comptime accounts: type,
) !?InvokingIdentity {
    for (identity_priority) |kind| {
        const definition = providerDefinition(kind);
        if (!definition.capabilities.invoking_user_identity) continue;
        if (definition.caller_name_variable) |marker| {
            const user = environment.get(marker) orelse continue;
            if (!validInvokingUser(user)) return null;
            const account = (try accounts.byName(allocator, user)) orelse return null;
            defer account.deinit(allocator);
            return identityFromAccount(allocator, account);
        }
        if (definition.caller_uid_variable) |marker| {
            const uid = environment.get(marker) orelse continue;
            const account = (try accounts.byUidText(allocator, uid)) orelse return null;
            defer account.deinit(allocator);
            return identityFromAccount(allocator, account);
        }
    }
    return null;
}

fn identityFromAccount(
    allocator: std.mem.Allocator,
    account: user_account.Account,
) !?InvokingIdentity {
    if (account.uid == 0 or !validInvokingUser(account.username)) return null;
    const uid = try std.fmt.allocPrint(allocator, "{d}", .{account.uid});
    errdefer allocator.free(uid);
    const gid = try std.fmt.allocPrint(allocator, "{d}", .{account.gid});
    errdefer allocator.free(gid);
    const home = try allocator.dupe(u8, account.home);
    errdefer allocator.free(home);
    return .{
        .username = try allocator.dupe(u8, account.username),
        .uid = uid,
        .gid = gid,
        .home = home,
    };
}

fn validInvokingUser(user: []const u8) bool {
    return user.len > 0 and !std.mem.eql(u8, user, "root") and !std.mem.eql(u8, user, "0");
}

fn supports(kind: ProviderKind, requirement: Requirement) bool {
    const provider_capabilities = providerDefinition(kind).capabilities;
    return switch (requirement) {
        .elevate_root => provider_capabilities.elevate_root,
        .run_as_user => provider_capabilities.run_as_user,
    };
}

fn providerDefinition(kind: ProviderKind) ProviderDefinition {
    for (registry) |definition| if (definition.kind == kind) return definition;
    unreachable;
}

fn providerKind(name: []const u8) ?ProviderKind {
    for (registry) |definition| if (std.mem.eql(u8, definition.name, name)) return definition.kind;
    return null;
}

fn resolveConfigured(
    allocator: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
    configured: []const u8,
) ![]u8 {
    if (configured.len == 0) return error.UnsupportedElevator;
    if (std.mem.indexOfScalar(u8, configured, '/') == null) {
        return (try findExecutable(allocator, io, path, configured)) orelse error.ElevatorUnavailable;
    }
    if (!executableAvailable(io, configured)) return error.ElevatorUnavailable;
    return allocator.dupe(u8, configured);
}

fn findExecutable(
    allocator: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
    name: []const u8,
) !?[]u8 {
    if (path.len == 0) return null;
    var directories = std.mem.splitScalar(u8, path, ':');
    while (directories.next()) |directory| {
        if (directory.len == 0) continue;
        const candidate = try std.fs.path.join(allocator, &.{ directory, name });
        errdefer allocator.free(candidate);
        if (!executableAvailable(io, candidate)) {
            allocator.free(candidate);
            continue;
        }
        return candidate;
    }
    return null;
}

fn executableAvailable(io: std.Io, path: []const u8) bool {
    const stat = std.Io.Dir.cwd().statFile(io, path, .{}) catch return false;
    if (stat.kind != .file) return false;
    std.Io.Dir.cwd().access(io, path, .{ .execute = true }) catch return false;
    return true;
}

const TestAccounts = struct {
    fn byName(allocator: std.mem.Allocator, name: []const u8) !?user_account.Account {
        const uid: std.c.uid_t = if (std.mem.eql(u8, name, "tester")) 60123 else if (std.mem.eql(u8, name, "other")) 60124 else if (std.mem.eql(u8, name, "0")) 60125 else if (std.mem.eql(u8, name, "root") or std.mem.eql(u8, name, "root-alias")) 0 else return null;
        const username = try allocator.dupe(u8, name);
        errdefer allocator.free(username);
        return .{
            .username = username,
            .home = try allocator.dupe(u8, "/home/custom-home"),
            .uid = uid,
            .gid = uid + 1,
        };
    }

    fn byUidText(allocator: std.mem.Allocator, uid: []const u8) !?user_account.Account {
        return byName(
            allocator,
            if (std.mem.eql(u8, uid, "60123")) "tester" else if (std.mem.eql(u8, uid, "60124")) "other" else if (std.mem.eql(u8, uid, "0")) "root" else return null,
        );
    }
};

fn createExecutable(dir: std.Io.Dir, io: std.Io, name: []const u8) !void {
    var fixture = try dir.createFile(io, name, .{ .permissions = .executable_file });
    fixture.close(io);
}

test "automatic selection follows provider priority, independent of PATH order" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    try temporary.dir.createDir(std.testing.io, "run0", .default_dir);
    try temporary.dir.createDir(std.testing.io, "sudo", .default_dir);
    try temporary.dir.createDir(std.testing.io, "doas", .default_dir);
    try temporary.dir.createDir(std.testing.io, "pkexec", .default_dir);
    var run0_dir = try temporary.dir.openDir(std.testing.io, "run0", .{});
    defer run0_dir.close(std.testing.io);
    var sudo_dir = try temporary.dir.openDir(std.testing.io, "sudo", .{});
    defer sudo_dir.close(std.testing.io);
    var doas_dir = try temporary.dir.openDir(std.testing.io, "doas", .{});
    defer doas_dir.close(std.testing.io);
    var pkexec_dir = try temporary.dir.openDir(std.testing.io, "pkexec", .{});
    defer pkexec_dir.close(std.testing.io);
    try createExecutable(run0_dir, std.testing.io, "run0");
    try createExecutable(sudo_dir, std.testing.io, "sudo");
    try createExecutable(doas_dir, std.testing.io, "doas");
    try createExecutable(pkexec_dir, std.testing.io, "pkexec");

    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const root_length = try temporary.dir.realPath(std.testing.io, &path_buffer);
    const root = path_buffer[0..root_length];
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var environment = std.process.Environ.Map.init(arena.allocator());
    const path = try std.fmt.allocPrint(arena.allocator(), "{s}/run0:{s}/sudo:{s}/pkexec:{s}/doas", .{ root, root, root, root });
    try environment.put("PATH", path);

    const doas = try select(arena.allocator(), std.testing.io, &environment, .elevate_root);
    try std.testing.expectEqual(ProviderKind.doas, doas.kind);
    const doas_path = try std.fs.path.join(arena.allocator(), &.{ root, "doas", "doas" });
    try std.testing.expectEqualStrings(doas_path, doas.executable);

    for ([_][]const u8{ "", "   ", "\t\n" }) |empty_override| {
        try environment.put("SHELLY_ELEVATOR", empty_override);
        const automatic = try select(arena.allocator(), std.testing.io, &environment, .elevate_root);
        try std.testing.expectEqual(ProviderKind.doas, automatic.kind);
        try std.testing.expectEqualStrings(doas_path, automatic.executable);
    }
    _ = environment.swapRemove("SHELLY_ELEVATOR");

    try temporary.dir.deleteTree(std.testing.io, "doas");
    const sudo = try select(arena.allocator(), std.testing.io, &environment, .elevate_root);
    try std.testing.expectEqual(ProviderKind.sudo, sudo.kind);

    try temporary.dir.deleteTree(std.testing.io, "sudo");
    const run0 = try select(arena.allocator(), std.testing.io, &environment, .elevate_root);
    try std.testing.expectEqual(ProviderKind.run0, run0.kind);

    try temporary.dir.deleteTree(std.testing.io, "run0");
    try std.testing.expectError(error.NoElevator, select(arena.allocator(), std.testing.io, &environment, .elevate_root));
}

test "explicit provider wins and unavailable override never falls back" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    try temporary.dir.createDir(std.testing.io, "auto", .default_dir);
    try temporary.dir.createDir(std.testing.io, "configured", .default_dir);
    var auto_dir = try temporary.dir.openDir(std.testing.io, "auto", .{});
    defer auto_dir.close(std.testing.io);
    var configured_dir = try temporary.dir.openDir(std.testing.io, "configured", .{});
    defer configured_dir.close(std.testing.io);
    try createExecutable(auto_dir, std.testing.io, "doas");
    try createExecutable(configured_dir, std.testing.io, "sudo");
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const root_length = try temporary.dir.realPath(std.testing.io, &path_buffer);
    const root = path_buffer[0..root_length];
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var environment = std.process.Environ.Map.init(arena.allocator());
    const path = try std.fs.path.join(arena.allocator(), &.{ root, "auto" });
    const explicit = try std.fs.path.join(arena.allocator(), &.{ root, "configured", "sudo" });
    try environment.put("PATH", path);
    try environment.put("SHELLY_ELEVATOR", try std.fmt.allocPrint(arena.allocator(), " \t{s}\n ", .{explicit}));
    const selected = try select(arena.allocator(), std.testing.io, &environment, .elevate_root);
    try std.testing.expectEqual(ProviderKind.sudo, selected.kind);
    try std.testing.expectEqualStrings(explicit, selected.executable);

    const missing = try std.fs.path.join(arena.allocator(), &.{ root, "missing", "sudo" });
    try environment.put("SHELLY_ELEVATOR", missing);
    try std.testing.expectError(error.ElevatorUnavailable, select(arena.allocator(), std.testing.io, &environment, .elevate_root));
}

test "selection rejects unsupported overrides and unsupported requested operations" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    try temporary.dir.createDir(std.testing.io, "bin", .default_dir);
    var bin_dir = try temporary.dir.openDir(std.testing.io, "bin", .{});
    defer bin_dir.close(std.testing.io);
    try createExecutable(bin_dir, std.testing.io, "pkexec");
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const root_length = try temporary.dir.realPath(std.testing.io, &path_buffer);
    const root = path_buffer[0..root_length];
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var environment = std.process.Environ.Map.init(arena.allocator());
    try environment.put("PATH", root);
    try environment.put("SHELLY_ELEVATOR", "unknown");
    try std.testing.expectError(error.UnsupportedElevator, select(arena.allocator(), std.testing.io, &environment, .elevate_root));

    const pkexec = try std.fs.path.join(arena.allocator(), &.{ root, "bin", "pkexec" });
    try environment.put("SHELLY_ELEVATOR", pkexec);
    try std.testing.expectError(error.ElevatorOperationUnsupported, select(arena.allocator(), std.testing.io, &environment, .run_as_user));
}

test "empty and missing PATH and pkexec-only PATH have no automatic provider" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var environment = std.process.Environ.Map.init(arena.allocator());
    try environment.put("PATH", "");
    try std.testing.expectError(error.NoElevator, select(arena.allocator(), std.testing.io, &environment, .elevate_root));

    var missing_path = std.process.Environ.Map.init(arena.allocator());
    try std.testing.expectError(error.NoElevator, select(arena.allocator(), std.testing.io, &missing_path, .elevate_root));
}

test "root command construction supports all registered providers" {
    const executable = "/usr/bin/shelly";
    const arguments = [_][]const u8{ "sync", "--force" };
    inline for (.{ ProviderKind.sudo, .doas, .run0, .pkexec }) |kind| {
        const provider: Provider = .{ .kind = kind, .executable = @tagName(kind) };
        const actual = try buildRootCommand(std.testing.allocator, provider, executable, &arguments);
        defer std.testing.allocator.free(actual);
        try std.testing.expectEqualStrings(@tagName(kind), actual[0]);
        try std.testing.expectEqualStrings(executable, actual[1]);
        try std.testing.expectEqualStrings("sync", actual[2]);
        try std.testing.expectEqualStrings("--force", actual[3]);
    }
}

test "sudo and doas run as invoking user with a clean baseline environment" {
    const environment = [_][]const u8{ "HOME=/home/tester", "XDG_RUNTIME_DIR=/run/user/60123" };
    const arguments = [_][]const u8{ "upgrade", "flatpak" };
    inline for (.{ ProviderKind.sudo, .doas }) |kind| {
        const provider: Provider = .{ .kind = kind, .executable = @tagName(kind) };
        const actual = try buildProviderInvokingUserCommand(
            std.testing.allocator,
            provider,
            "tester",
            &environment,
            "PATH=/usr/bin:/bin",
            "/usr/bin/shelly",
            &arguments,
        );
        defer std.testing.allocator.free(actual);
        const expected = [_][]const u8{
            @tagName(kind),      "-u",                              "tester",             "/usr/bin/env",    "-i",
            "HOME=/home/tester", "XDG_RUNTIME_DIR=/run/user/60123", "PATH=/usr/bin:/bin", "/usr/bin/shelly", "upgrade",
            "flatpak",
        };
        try std.testing.expectEqual(expected.len, actual.len);
        for (expected, actual) |wanted, value| try std.testing.expectEqualStrings(wanted, value);
    }
}

test "run0 runs as invoking user with native user and setenv options" {
    const environment = [_][]const u8{ "HOME=/home/tester", "XDG_RUNTIME_DIR=/run/user/60123" };
    const arguments = [_][]const u8{ "upgrade", "flatpak" };
    const provider: Provider = .{ .kind = .run0, .executable = "/usr/bin/run0" };
    const actual = try buildProviderInvokingUserCommand(
        std.testing.allocator,
        provider,
        "tester",
        &environment,
        "PATH=/usr/bin:/bin",
        "/usr/bin/shelly",
        &arguments,
    );
    defer std.testing.allocator.free(actual);
    const expected = [_][]const u8{
        "/usr/bin/run0",                   "--user",            "tester",
        "--setenv",                        "HOME=/home/tester", "--setenv",
        "XDG_RUNTIME_DIR=/run/user/60123", "--setenv",          "PATH=/usr/bin:/bin",
        "/usr/bin/shelly",                 "upgrade",           "flatpak",
    };
    try std.testing.expectEqual(expected.len, actual.len);
    for (expected, actual) |wanted, value| try std.testing.expectEqualStrings(wanted, value);
}

test "pkexec cannot run as invoking user" {
    const provider: Provider = .{ .kind = .pkexec, .executable = "pkexec" };
    try std.testing.expectError(
        error.ElevatorOperationUnsupported,
        buildProviderInvokingUserCommand(std.testing.allocator, provider, "tester", &.{}, "PATH=/usr/bin:/bin", "/usr/bin/shelly", &.{}),
    );
}

test "high-level caller command builds a clean environment with selected provider" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    try createExecutable(temporary.dir, std.testing.io, "doas");
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const root_length = try temporary.dir.realPath(std.testing.io, &path_buffer);
    const root = path_buffer[0..root_length];

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var environment = std.process.Environ.Map.init(allocator);
    try environment.put("PATH", root);
    try environment.put("DOAS_USER", "tester");
    try environment.put("LD_PRELOAD", "/untrusted/library.so");
    try environment.put("BASH_ENV", "/untrusted/startup");
    try environment.put("SOURCE_DATE_EPOCH", "1700000000");
    try environment.put("LANG", "en_US.UTF-8");
    try environment.put("LC_TIME", "C");

    const command = (try buildInvokingUserCommandWithAccounts(
        allocator,
        .{ .helper = std.testing.io },
        &environment,
        .{ .path = "/usr/bin:/bin", .preserve_locale = true, .preserve_source_date_epoch = true },
        "/usr/bin/shelly",
        &.{ "build", "--coordinator-child" },
        TestAccounts,
    )).?;
    const expected = [_][]const u8{
        try std.fs.path.join(allocator, &.{ root, "doas" }),
        "-u",
        "tester",
        "/usr/bin/env",
        "-i",
        "HOME=/home/custom-home",
        "XDG_CONFIG_HOME=/home/custom-home/.config",
        "XDG_DATA_HOME=/home/custom-home/.local/share",
        "XDG_CACHE_HOME=/home/custom-home/.cache",
        "XDG_BIN_HOME=/home/custom-home/.local/bin",
        "XDG_RUNTIME_DIR=/run/user/60123",
        "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/60123/bus",
        "SOURCE_DATE_EPOCH=1700000000",
        "LANG=en_US.UTF-8",
        "LC_TIME=C",
        "PATH=/usr/bin:/bin",
        "/usr/bin/shelly",
        "build",
        "--coordinator-child",
    };
    try std.testing.expectEqual(expected.len, command.len);
    for (expected, command) |wanted, actual| try std.testing.expectEqualStrings(wanted, actual);
    for (command) |argument| try std.testing.expect(std.mem.indexOf(u8, argument, "LD_PRELOAD") == null);
}

test "high-level caller command selects run0 natively and rejects pkexec run-as" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    try createExecutable(temporary.dir, std.testing.io, "run0");
    try createExecutable(temporary.dir, std.testing.io, "doas");
    try createExecutable(temporary.dir, std.testing.io, "pkexec");
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const root_length = try temporary.dir.realPath(std.testing.io, &path_buffer);
    const root = path_buffer[0..root_length];

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var environment = std.process.Environ.Map.init(allocator);
    try environment.put("PATH", root);
    try environment.put("SUDO_USER", "tester");
    try environment.put("SHELLY_ELEVATOR", "run0");
    const command = (try buildInvokingUserCommandWithAccounts(
        allocator,
        .{ .helper = std.testing.io },
        &environment,
        .{ .path = "/usr/bin:/bin" },
        "/usr/bin/shelly",
        &.{"sync"},
        TestAccounts,
    )).?;
    try std.testing.expectEqualStrings(try std.fs.path.join(allocator, &.{ root, "run0" }), command[0]);
    try std.testing.expectEqualStrings("--user", command[1]);
    try std.testing.expectEqualStrings("tester", command[2]);
    try std.testing.expectEqualStrings("--setenv", command[3]);
    try std.testing.expectEqualStrings("HOME=/home/custom-home", command[4]);
    try std.testing.expectEqualStrings("--setenv", command[5]);
    try std.testing.expectEqualStrings("PATH=/usr/bin:/bin", command[18]);

    try environment.put("SHELLY_ELEVATOR", "pkexec");
    try std.testing.expectError(
        error.ElevatorOperationUnsupported,
        buildInvokingUserCommandWithAccounts(
            allocator,
            .{ .helper = std.testing.io },
            &environment,
            .{ .path = "/usr/bin:/bin" },
            "/usr/bin/shelly",
            &.{"sync"},
            TestAccounts,
        ),
    );
}

test "NSS caller identity supports sudo, doas, run0, and pkexec markers" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var environment = std.process.Environ.Map.init(allocator);
    for ([_][]const u8{ "SUDO_USER", "DOAS_USER" }) |marker| {
        try environment.put(marker, "tester");
        const identity = (try invokingIdentity(std.testing.allocator, &environment, TestAccounts)).?;
        defer identity.deinit(std.testing.allocator);
        try std.testing.expectEqualStrings("tester", identity.username);
        try std.testing.expectEqualStrings("60123", identity.uid);
        try std.testing.expectEqualStrings("60124", identity.gid);
        _ = environment.swapRemove(marker);
    }
    try environment.put("PKEXEC_UID", "60124");
    const pkexec = (try invokingIdentity(std.testing.allocator, &environment, TestAccounts)).?;
    defer pkexec.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("other", pkexec.username);

    try environment.put("SUDO_USER", "tester");
    try environment.put("PKEXEC_UID", "60124");
    const preferred = (try invokingIdentity(std.testing.allocator, &environment, TestAccounts)).?;
    defer preferred.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("tester", preferred.username);
}

test "caller identity rejects root, aliases for UID zero, and missing accounts" {
    var environment = std.process.Environ.Map.init(std.testing.allocator);
    defer environment.deinit();
    try environment.put("SUDO_USER", "root");
    try environment.put("PKEXEC_UID", "0");
    try std.testing.expect(try invokingIdentity(std.testing.allocator, &environment, TestAccounts) == null);

    try environment.put("SUDO_USER", "root-alias");
    try std.testing.expect(try invokingIdentity(std.testing.allocator, &environment, TestAccounts) == null);
    try environment.put("SUDO_USER", "0");
    try std.testing.expect(try invokingIdentity(std.testing.allocator, &environment, TestAccounts) == null);
    try environment.put("SUDO_USER", "missing");
    try std.testing.expect(try invokingIdentity(std.testing.allocator, &environment, TestAccounts) == null);
}

test "caller identity needs an elevation marker" {
    var environment = std.process.Environ.Map.init(std.testing.allocator);
    defer environment.deinit();
    try std.testing.expect(try invokingIdentity(std.testing.allocator, &environment, TestAccounts) == null);
}

test "provider environment variables are recognized centrally" {
    for ([_][]const u8{ "SUDO_USER", "SUDO_UID", "DOAS_USER", "PKEXEC_UID" }) |name|
        try std.testing.expect(isProviderEnvironmentVariable(name));
    for ([_][]const u8{ "SHELLY_ELEVATOR", "XDG_CONFIG_HOME", "PATH" }) |name|
        try std.testing.expect(!isProviderEnvironmentVariable(name));
}

test "authoritative invalid identity never falls through to a valid lower marker" {
    for ([_][]const u8{ "SUDO_USER", "DOAS_USER" }) |marker| {
        for ([_][]const u8{ "missing", "root", "root-alias", "", "0", "bad\x00name" }) |invalid| {
            var environment = std.process.Environ.Map.init(std.testing.allocator);
            defer environment.deinit();
            try environment.put(marker, invalid);
            try environment.put("PKEXEC_UID", "60124");
            // Also reject fallback to doas when SUDO_USER is present.
            if (std.mem.eql(u8, marker, "SUDO_USER")) try environment.put("DOAS_USER", "tester");
            try std.testing.expect(try invokingIdentity(std.testing.allocator, &environment, TestAccounts) == null);
            try std.testing.expectError(error.InvokingUserUnavailable, buildInvokingUserCommandWithAccounts(
                std.testing.allocator,
                .drop_to_user,
                &environment,
                .{ .path = "/usr/bin:/bin" },
                "/usr/bin/env",
                &.{},
                TestAccounts,
            ));
        }
    }
}

// Execute only the generated env -i section, without a privilege helper or PAM.
fn runCleanEnvironment(
    allocator: std.mem.Allocator,
    environment: *std.process.Environ.Map,
    options: InvokingUserCommandOptions,
    executable: []const u8,
    arguments: []const []const u8,
    directory: ?[]const u8,
) !std.process.RunResult {
    try environment.put("PATH", "");
    try environment.put("DOAS_USER", "tester");
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const command = (try buildInvokingUserCommandWithAccounts(
        arena.allocator(),
        .drop_to_user,
        environment,
        options,
        executable,
        arguments,
        TestAccounts,
    )).?;
    try std.testing.expectEqualStrings("/usr/bin/env", command[4]);
    return std.process.run(allocator, std.testing.io, .{
        .argv = command[4..],
        .cwd = if (directory) |path_value| .{ .path = path_value } else .inherit,
        .environ_map = environment,
        .timeout = .{ .duration = .{ .clock = .awake, .raw = .fromSeconds(10) } },
    });
}

test "clean invoking-user execution drops unsafe variables and preserves epoch only when requested" {
    var environment = std.process.Environ.Map.init(std.testing.allocator);
    defer environment.deinit();
    try environment.put("SOURCE_DATE_EPOCH", "1700000000");
    // Empty LD_PRELOAD still tests filtering without loading an untrusted library.
    try environment.put("LD_PRELOAD", "");
    for ([_][]const u8{ "BASH_ENV", "LOCPATH", "LC_UNRECOGNIZED", "UNRELATED", "SUDO_UID", "PKEXEC_EXTRA" }) |name|
        try environment.put(name, "/untrusted");
    for ([_]bool{ false, true }) |preserve_epoch| {
        // Exercise both absent and empty LANG defaults at execution time.
        if (preserve_epoch) try environment.put("LANG", "");
        const result = try runCleanEnvironment(std.testing.allocator, &environment, .{ .path = "/usr/bin:/bin", .preserve_locale = true, .preserve_source_date_epoch = preserve_epoch }, "/usr/bin/env", &.{}, null);
        defer std.testing.allocator.free(result.stdout);
        defer std.testing.allocator.free(result.stderr);
        try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
        try std.testing.expect(std.mem.indexOf(u8, result.stdout, "LANG=C.UTF-8\n") != null);
        try std.testing.expectEqual(preserve_epoch, std.mem.indexOf(u8, result.stdout, "SOURCE_DATE_EPOCH=1700000000\n") != null);
        for ([_][]const u8{ "LD_PRELOAD=", "BASH_ENV=", "LOCPATH=", "LC_UNRECOGNIZED=", "UNRELATED=", "SUDO_", "DOAS_", "PKEXEC_" }) |name|
            try std.testing.expect(std.mem.indexOf(u8, result.stdout, name) == null);
    }
}

test "clean invoking-user build command preserves explicit locale settings" {
    const allocator = std.testing.allocator;
    var environment = std.process.Environ.Map.init(allocator);
    defer environment.deinit();
    try environment.put("LANG", "en_US.UTF-8");
    const overrides = .{
        .{ "LANGUAGE", "en:de with spaces; $(false)" },
        .{ "LC_ALL", "" },
        .{ "LC_CTYPE", "C.UTF-8" },
        .{ "LC_NUMERIC", "C" },
        .{ "LC_TIME", "C" },
        .{ "LC_COLLATE", "C" },
        .{ "LC_MONETARY", "C" },
        .{ "LC_MESSAGES", "C" },
        .{ "LC_PAPER", "C" },
        .{ "LC_NAME", "C" },
        .{ "LC_ADDRESS", "C" },
        .{ "LC_TELEPHONE", "C" },
        .{ "LC_MEASUREMENT", "C" },
        .{ "LC_IDENTIFICATION", "C" },
    };
    inline for (overrides) |entry| try environment.put(entry[0], entry[1]);
    const result = try runCleanEnvironment(allocator, &environment, .{ .path = "/usr/bin:/bin", .preserve_locale = true }, "/usr/bin/env", &.{}, null);
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
    try std.testing.expect(std.mem.indexOf(u8, result.stdout, "\nLANG=en_US.UTF-8\n") != null);
    inline for (overrides) |entry|
        try std.testing.expect(std.mem.indexOf(u8, result.stdout, "\n" ++ entry[0] ++ "=" ++ entry[1] ++ "\n") != null);
}

test "clean invoking-user build command supports Unicode filenames and locale precedence" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var fixture = std.testing.tmpDir(.{});
    defer fixture.cleanup();
    try fixture.dir.writeFile(io, .{ .sub_path = "∂-unicode.txt", .data = "unicode resource\n" });
    const directory = try fixture.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(directory);
    const Case = struct { lang: ?[]const u8 = null, ctype: ?[]const u8 = null, all: ?[]const u8 = null, characters: u8 = 1 };
    for ([_]Case{
        .{},
        .{ .lang = "" },
        .{ .lang = "C.UTF-8" },
        .{ .lang = "C", .characters = 3 },
        .{ .lang = "C", .ctype = "C.UTF-8" },
        .{ .lang = "C", .ctype = "C", .all = "C.UTF-8" },
        .{ .lang = "C.UTF-8", .ctype = "C.UTF-8", .all = "C", .characters = 3 },
        .{ .all = "C", .characters = 3 },
        .{ .ctype = "", .all = "" },
    }) |case| {
        var environment = std.process.Environ.Map.init(allocator);
        defer environment.deinit();
        if (case.lang) |value| try environment.put("LANG", value);
        if (case.ctype) |value| try environment.put("LC_CTYPE", value);
        if (case.all) |value| try environment.put("LC_ALL", value);
        const result = try runCleanEnvironment(allocator, &environment, .{ .path = "/usr/bin:/bin", .preserve_locale = true }, "/bin/bash", &.{
            "--noprofile", "--norc", "-c",
            "set -eu; character='∂'; printf '%s\\n' \"${#character}\"; cat -- \"${character}-unicode.txt\"",
        }, directory);
        defer allocator.free(result.stdout);
        defer allocator.free(result.stderr);
        try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
        try std.testing.expectEqualStrings("", result.stderr);
        try std.testing.expectEqualStrings(if (case.characters == 1) "1\nunicode resource\n" else "3\nunicode resource\n", result.stdout);
    }
}

test "root-local drop accepts each invoking marker without an elevator and ignores its override" {
    const Source = struct { marker: []const u8, value: []const u8, user: []const u8, uid: []const u8 };
    for ([_]Source{
        .{ .marker = "SUDO_USER", .value = "tester", .user = "tester", .uid = "60123" },
        .{ .marker = "DOAS_USER", .value = "tester", .user = "tester", .uid = "60123" },
        .{ .marker = "PKEXEC_UID", .value = "60124", .user = "other", .uid = "60124" },
    }) |source| {
        for ([_]?[]const u8{ null, "", " \t\n", "pkexec", "sudo", "doas", "run0", "unsupported", "/missing/pkexec" }) |override| {
            var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
            defer arena.deinit();
            const allocator = arena.allocator();
            var environment = std.process.Environ.Map.init(allocator);
            try environment.put("PATH", "");
            try environment.put(source.marker, source.value);
            if (override) |value| try environment.put("SHELLY_ELEVATOR", value);
            try environment.put("LANG", "C.UTF-8");
            try environment.put("SOURCE_DATE_EPOCH", "1700000000");
            try environment.put("LD_PRELOAD", "/untrusted/library.so");
            const command = (try buildInvokingUserCommandWithAccounts(
                allocator,
                .drop_to_user,
                &environment,
                .{ .path = "/usr/bin:/bin", .preserve_locale = true, .preserve_source_date_epoch = true },
                "/usr/bin/shelly",
                &.{ "build", "--coordinator-child" },
                TestAccounts,
            )).?;
            const expected = [_][]const u8{
                "/usr/bin/runuser",                                                                                       "-u",                                        source.user,                                    "--",                                      "/usr/bin/env",                              "-i",
                "HOME=/home/custom-home",                                                                                 "XDG_CONFIG_HOME=/home/custom-home/.config", "XDG_DATA_HOME=/home/custom-home/.local/share", "XDG_CACHE_HOME=/home/custom-home/.cache", "XDG_BIN_HOME=/home/custom-home/.local/bin", try std.fmt.allocPrint(allocator, "XDG_RUNTIME_DIR=/run/user/{s}", .{source.uid}),
                try std.fmt.allocPrint(allocator, "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{s}/bus", .{source.uid}), "SOURCE_DATE_EPOCH=1700000000",              "LANG=C.UTF-8",                                 "PATH=/usr/bin:/bin",                      "/usr/bin/shelly",                           "build",
                "--coordinator-child",
            };
            try std.testing.expectEqual(expected.len, command.len);
            for (expected, command) |wanted, actual| try std.testing.expectEqualStrings(wanted, actual);
        }
    }
}

test "root-local drop rejects invalid pkexec identities and needs an invoking marker" {
    var environment = std.process.Environ.Map.init(std.testing.allocator);
    defer environment.deinit();
    try std.testing.expect(try buildInvokingUserCommandWithAccounts(
        std.testing.allocator,
        .drop_to_user,
        &environment,
        .{ .path = "/usr/bin:/bin" },
        "/usr/bin/env",
        &.{},
        TestAccounts,
    ) == null);
    for ([_][]const u8{ "0", "invalid", "99999", "", "-1", "60123x" }) |invalid| {
        try environment.put("PKEXEC_UID", invalid);
        try std.testing.expectError(error.InvokingUserUnavailable, buildInvokingUserCommandWithAccounts(
            std.testing.allocator,
            .drop_to_user,
            &environment,
            .{ .path = "/usr/bin:/bin" },
            "/usr/bin/env",
            &.{},
            TestAccounts,
        ));
    }
}

test "invoking-user home rejects invalid authoritative identities despite HOME or a valid lower marker" {
    const Case = struct { marker: []const u8, value: []const u8 };
    for ([_]Case{
        .{ .marker = "SUDO_USER", .value = "missing" },
        .{ .marker = "SUDO_USER", .value = "root" },
        .{ .marker = "SUDO_USER", .value = "root-alias" },
        .{ .marker = "DOAS_USER", .value = "missing" },
        .{ .marker = "PKEXEC_UID", .value = "invalid" },
        .{ .marker = "PKEXEC_UID", .value = "0" },
    }) |case| {
        var environment = std.process.Environ.Map.init(std.testing.allocator);
        defer environment.deinit();
        try environment.put("HOME", "/root");
        try environment.put(case.marker, case.value);
        try std.testing.expectError(error.InvokingUserUnavailable, invokingUserHomeWithAccounts(std.testing.allocator, &environment, TestAccounts));
        if (!std.mem.eql(u8, case.marker, "PKEXEC_UID")) {
            try environment.put("PKEXEC_UID", "60124");
            try std.testing.expectError(error.InvokingUserUnavailable, invokingUserHomeWithAccounts(std.testing.allocator, &environment, TestAccounts));
        }
    }
}

test "invoking-user home uses NSS for valid markers and HOME only without markers" {
    for ([_][]const u8{ "SUDO_USER", "DOAS_USER", "PKEXEC_UID" }) |marker| {
        var environment = std.process.Environ.Map.init(std.testing.allocator);
        defer environment.deinit();
        try environment.put("HOME", "/root");
        try environment.put(marker, if (std.mem.eql(u8, marker, "PKEXEC_UID")) "60123" else "tester");
        const home = try invokingUserHomeWithAccounts(std.testing.allocator, &environment, TestAccounts);
        defer std.testing.allocator.free(home);
        try std.testing.expectEqualStrings("/home/custom-home", home);
    }
    var environment = std.process.Environ.Map.init(std.testing.allocator);
    defer environment.deinit();
    try std.testing.expectError(error.HomeNotSet, invokingUserHomeWithAccounts(std.testing.allocator, &environment, TestAccounts));
    try std.testing.expectError(error.HomeNotSet, invokingUserHomeWithAccounts(std.testing.allocator, null, TestAccounts));
    try environment.put("HOME", "/home/tester");
    const home = try invokingUserHomeWithAccounts(std.testing.allocator, &environment, TestAccounts);
    defer std.testing.allocator.free(home);
    try std.testing.expectEqualStrings("/home/tester", home);
}

test "invoking-user home rejects an NSS account without a home" {
    const EmptyHomeAccounts = struct {
        fn byName(allocator: std.mem.Allocator, name: []const u8) !?user_account.Account {
            var account = (try TestAccounts.byName(allocator, name)) orelse return null;
            errdefer account.deinit(allocator);
            const home = try allocator.dupe(u8, "");
            allocator.free(account.home);
            account.home = home;
            return account;
        }
        const byUidText = TestAccounts.byUidText;
    };
    var environment = std.process.Environ.Map.init(std.testing.allocator);
    defer environment.deinit();
    try environment.put("HOME", "/root");
    try environment.put("SUDO_USER", "tester");
    try std.testing.expectError(error.InvokingUserUnavailable, invokingUserHomeWithAccounts(std.testing.allocator, &environment, EmptyHomeAccounts));
}

test "provider discovery rejects executable directories and accepts executable symlinks" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    try temporary.dir.createDir(std.testing.io, "doas", .default_dir);
    try createExecutable(temporary.dir, std.testing.io, "sudo");
    try temporary.dir.symLink(std.testing.io, "sudo", "run0", .{});
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const path = try temporary.dir.realPathFileAlloc(std.testing.io, ".", allocator);
    var environment = std.process.Environ.Map.init(allocator);
    try environment.put("PATH", path);
    const selected = try select(allocator, std.testing.io, &environment, .elevate_root);
    try std.testing.expectEqual(ProviderKind.sudo, selected.kind);
    try environment.put("SHELLY_ELEVATOR", "doas");
    try std.testing.expectError(error.ElevatorUnavailable, select(allocator, std.testing.io, &environment, .elevate_root));
    try environment.put("SHELLY_ELEVATOR", try std.fs.path.join(allocator, &.{ path, "doas" }));
    try std.testing.expectError(error.ElevatorUnavailable, select(allocator, std.testing.io, &environment, .elevate_root));
    try environment.put("SHELLY_ELEVATOR", "run0");
    try std.testing.expectEqual(ProviderKind.run0, (try select(allocator, std.testing.io, &environment, .elevate_root)).kind);
}
