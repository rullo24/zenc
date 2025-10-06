const std = @import("std");

pub fn build(b: *std.Build) !void {

    // allocator for concatenating strings
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const alloc: std.mem.Allocator = gpa.allocator();
    _ = alloc;
    defer _ = gpa.deinit();

    // defining default build args
    const def_target: std.Build.ResolvedTarget = b.standardTargetOptions(.{});
    const def_optimise: std.builtin.OptimizeMode = b.standardOptimizeOption(.{});

    // EXECUTABLE BUILDING //
    const exe = b.addExecutable(.{
        .name = "zenc",
        .root_module = b.createModule(.{
            .root_source_file = b.path("./src/main.zig"),
            .strip = false,
            .optimize = def_optimise,
            .target = def_target,
        }),
        .use_llvm = true,
    });
    b.installArtifact(exe); // creating binary on system

    // --- CUSTOM RUN STEP FOR DEBUGGING --- ///

    // const lldb_install_loc: []const u8 = "\"C:\\Program Files\\LLVM\\bin\\lldb.exe\"";
    // const debug_test_file: []const u8 = "-e=\"./test/file1.txt\"";
    // const debug_command_arr: []const []const u8 = &[_][]const u8{ "cmd", "/c", lldb_install_loc, ".\\zig-out\\bin\\zenc.exe", "--", debug_test_file};

    // const debug_cmd: *std.Build.Step.Run = b.addSystemCommand(debug_command_arr);
    // const debug_step: *std.Build.Step = b.step("debug", "Runs the exe under lldb w/ specified argument");
    // debug_step.dependOn(&debug_cmd.step); // ensure that the debug step calls the debug_cmd

    // TESTING //
    
    // TODO: add test cases

}
