const std: type = @import("std");
const builtin: type = @import("builtin");

const APP_VERSION: []const u8 = "v1.2.0";
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

    // EXECUTABLE BUILDING //
    
    // module for capturing main entry (main.zig)
    const root_exe_module: *std.Build.Module = b.createModule(.{
        .root_source_file = b.path("./src/main.zig"),
        .strip = false,
        .optimize = def_optimise,
        .target = def_target,
    });

    // capturing the versioning options for building the default executable
    const def_v_options: *std.Build.Step.Options = create_version_options(b, def_target, def_optimise);
    root_exe_module.addOptions("build_version_info", def_v_options);

    // compiler for building executable
    const arch_str: []const u8 = @tagName(def_target.result.cpu.arch);
    const os_str: []const u8 = @tagName(def_target.result.os.tag);
    const root_exe_compiler: *std.Build.Step.Compile = b.addExecutable(.{
        .name = b.fmt("zenc_{s}-{s}", .{ arch_str, os_str }),
        .root_module = root_exe_module,
        .use_llvm = true,
    });
    b.installArtifact(root_exe_compiler); // creating binary on system

    // BUILD ALL ARCH + OS STEP //
    const build_all_step: *std.Build.Step = b.step("all", "Build all executable types.");
    const arch_to_build: []const std.Target.Cpu.Arch = &.{ std.Target.Cpu.Arch.aarch64, std.Target.Cpu.Arch.x86_64 };
    const os_to_build: []const std.Target.Os.Tag = &.{ std.Target.Os.Tag.windows, std.Target.Os.Tag.linux };

    // building for all targets (will repeat regular install artefact)
    for (arch_to_build) |curr_arch| {
        for (os_to_build) |curr_os| {
            
            // get target from current CPU and OS
            const target_query: std.Target.Query = .{ 
                .cpu_arch = curr_arch, 
                .os_tag = curr_os, 
            };
            const curr_target: std.Build.ResolvedTarget = b.resolveTargetQuery(target_query);

            // create a module from the resolved target
            const cross_exe_module: *std.Build.Module = b.createModule(.{
                .root_source_file = b.path("./src/main.zig"),
                .strip = false,
                .optimize = def_optimise,
                .target = curr_target,
            });

            // capturing the version options for the current executable
            const curr_v_options: *std.Build.Step.Options = create_version_options(b, curr_target, def_optimise);
            cross_exe_module.addOptions("build_version_info", curr_v_options);

            // create an exe compiler obj from the cross-compile module
            const cross_exe_compiler: *std.Build.Step.Compile = b.addExecutable(.{
                .name = b.fmt("zenc_{s}-{s}", .{ @tagName(curr_arch), @tagName(curr_os) }),
                .root_module = cross_exe_module,
                .use_llvm = true,
            });

            // install the current exe to system
            const cross_exe_installer: *std.Build.Step.InstallArtifact = b.addInstallArtifact(cross_exe_compiler, .{});
            build_all_step.dependOn(&cross_exe_installer.step);
        }
    }

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

//////////////////////////////////
// HELPER FUNCTION DECLARATIONS //
//////////////////////////////////

/// DESCRIPTION
/// A helper function to increase readability of the main build script. Used for both native and cross compiling executable options.
///
/// PARAMETERS
/// `b` - A ptr to the main build object
/// `target` - The target to create the version options against
/// `optimise` - The optimisation settings to create the version options against
fn create_version_options(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimise: std.builtin.OptimizeMode,
) *std.Build.Step.Options {

    // capture versioning info for capture and parse to main
    const version_info: VERSION_INFO = VERSION_INFO {
        .install_cpu = @tagName(target.result.cpu.arch),
        .install_os = @tagName(target.result.os.tag),
        .install_optimise_mode = @tagName(optimise),
        .zig_build_version = builtin.zig_version_string,
    };

    // parsing versioning info to main (for version print)
    const version_info_step: *std.Build.Step.Options = b.addOptions();
    version_info_step.addOption([]const u8, "APP_VERSION", version_info.app_version);
    version_info_step.addOption([]const u8, "INSTALL_CPU", version_info.install_cpu);
    version_info_step.addOption([]const u8, "INSTALL_OS", version_info.install_os);
    version_info_step.addOption([]const u8, "OPTIMISE_MODE", version_info.install_optimise_mode);
    version_info_step.addOption([]const u8, "ZIG_VERSION", version_info.zig_build_version);

    return version_info_step;
}
