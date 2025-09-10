const std = @import("std");

pub fn build(b: *std.Build) !void {
    const def_target = b.standardTargetOptions(.{});
    const def_optimise = b.standardOptimizeOption(.{});

    // EXECUTABLE BUILDING //

    const exe = b.addExecutable(.{
        .name = "Zenc",
        .root_module = b.createModule(.{
            .root_source_file = b.path("./src/main.zig"),
            .strip = true, // remove all debug symbols
            .optimize = def_optimise,
            .target = def_target,
        })
    });
    b.installArtifact(exe);

    // TESTING //
    
    // TODO: add test cases

}
