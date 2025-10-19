const std: type = @import("std");
const builtin: type = @import("builtin");

const APP_VERSION: []const u8 = "v1.1.0";
const VERSION_INFO: type = struct {
    app_version: []const u8 = APP_VERSION,
    install_cpu: []const u8,
    install_os: []const u8,
    install_optimise_mode: []const u8,
    zig_build_version: []const u8,
};

pub fn build(b: *std.Build) !void {

    // defining default build args
    const def_target: std.Build.ResolvedTarget = b.standardTargetOptions(.{});
    const def_optimise: std.builtin.OptimizeMode = b.standardOptimizeOption(.{});

    // capture versioning info for capture and parse to main
    const version_info: VERSION_INFO = VERSION_INFO {
        .install_cpu = @tagName(def_target.result.cpu.arch),
        .install_os = @tagName(def_target.result.os.tag),
        .install_optimise_mode = @tagName(def_optimise),
        .zig_build_version = builtin.zig_version_string,
    };

    // EXECUTABLE BUILDING //
    
    // module for capturing main entry (main.zig)
    const root_exe_module: *std.Build.Module = b.createModule(.{
        .root_source_file = b.path("./src/main.zig"),
        .strip = false,
        .optimize = def_optimise,
        .target = def_target,
    });
    
    // parsing versioning info to main (for version print)
    const version_info_step: *std.Build.Step.Options = b.addOptions();
    version_info_step.addOption([]const u8, "APP_VERSION", version_info.app_version);
    version_info_step.addOption([]const u8, "INSTALL_CPU", version_info.install_cpu);
    version_info_step.addOption([]const u8, "INSTALL_OS", version_info.install_os);
    version_info_step.addOption([]const u8, "OPTIMISE_MODE", version_info.install_optimise_mode);
    version_info_step.addOption([]const u8, "ZIG_VERSION", version_info.zig_build_version);
    root_exe_module.addOptions("build_version_info", version_info_step);

    // compiler for building executable
    const root_exe_compiler: *std.Build.Step.Compile = b.addExecutable(.{
        .name = "zenc",
        .root_module = root_exe_module,
        .use_llvm = true,
    });
    b.installArtifact(root_exe_compiler); // creating binary on system

    // TESTING //
    const test_build_step: *std.Build.Step = b.step("test", "Run all tests.");

    // capture REAL path of ./src folder for Dir iteration
    const root_lazypath: std.Build.LazyPath = b.path(".");
    const src_lazypath: std.Build.LazyPath = try root_lazypath.join(b.allocator, "src");
    const src_cache_path: std.Build.Cache.Path = src_lazypath.getPath3(b, null);
    const src_realpath: []const u8 = try src_cache_path.toString(b.allocator);

    // capture files from ./src dir (for testing)
    const src_dir: std.fs.Dir = try std.fs.openDirAbsolute(src_realpath, .{ .iterate = true });
    var src_dir_iterator: std.fs.Dir.Iterator = src_dir.iterate();

    // loop for testing all files that have tests in the ./src dir
    while (try src_dir_iterator.next()) |src_entry| {

        // building lazypath for current file
        const curr_entry_realpath: []const u8 = try std.fs.path.join(b.allocator, &.{ "src", src_entry.name });
        const curr_lazypath: std.Build.LazyPath = b.path(curr_entry_realpath);

        // creating module for building test step
        const curr_file_module = b.createModule(.{
            .root_source_file = curr_lazypath,
            .strip = false,
            .optimize = def_optimise,
            .target = def_target,
            .error_tracing = true,
        });

        // creating test step from current file
        const zenc_test_step: *std.Build.Step.Compile = b.addTest(.{
            .root_module = curr_file_module,
            .use_llvm = true,
        });

        // adding run test step to build process
        const run_zenc_tests: *std.Build.Step.Run = b.addRunArtifact(zenc_test_step);
        test_build_step.dependOn(&run_zenc_tests.step); // adding test to fleet of tests

    }
}
