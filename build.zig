const std = @import("std");

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
