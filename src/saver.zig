const std: type = @import("std");
const tac: type = @import("types_and_constants.zig");

/// handles the final file path logic and writes the output buffer to the new file.
///
/// PARAMETERS:
/// - alloc: Allocator used for path string creation.
/// - p_args_obj: Argument struct with file locations.
/// - s_opt_output_data: The final data slice to be written to disk.
/// - io_stdout_writer: Writer for logging output.
pub fn saveOutput(
    alloc: std.mem.Allocator,
    p_args_obj: *tac.ARGUMENT_STRUCT,
    s_opt_output_data: ?[]const u8,
    io_stdout_writer: *std.Io.Writer,
) !void {

    if (p_args_obj.opt_enc_file_loc == null and p_args_obj.opt_dec_file_loc == null) return error.NULL_ENC_AND_DEC_FILE;

    // get basename of parsed file for adding enc or dec extension to
    const s_encdec_basename: []const u8 =
        if (p_args_obj.opt_enc_file_loc != null) std.fs.path.basename(p_args_obj.opt_enc_file_loc.?)
        else if (p_args_obj.opt_dec_file_loc != null) std.fs.path.basename(p_args_obj.opt_dec_file_loc.?) 
        else return error.ENC_OR_DEC_FILE_DNE;

    // create buffer for new basename w/ replaced "ezenc"
    const s_new_basename: []u8 = try alloc.alloc(u8, s_encdec_basename.len + (".dzenc".len));
    defer alloc.free(s_new_basename);
    for (s_new_basename) |*p_c| p_c.* = 0x0; // zero all bytes in slice just created
    @memcpy(s_new_basename[0..s_encdec_basename.len], s_encdec_basename); // copy current basename to buffer
    var basename_size: usize = s_encdec_basename.len; // mimics copied parent at start

    // replace last ezenc w/ dzenc (if avail), otherwise concatenate dzenc to end of basename
    if (p_args_obj.opt_enc_file_loc != null) {

        @memmove(s_new_basename[s_encdec_basename.len..(s_encdec_basename.len + ".ezenc".len)], ".ezenc");
        basename_size += ".ezenc".len; // add extra characters for concatenation

    } else { // act on decryption logic

        const opt_i_last_ezenc: ?usize = std.mem.lastIndexOf(u8, s_new_basename[0..basename_size], ".ezenc");
        if (opt_i_last_ezenc) |i_last_ezenc| { // act when .ezenc IS IN basename
            @memmove(s_new_basename[ i_last_ezenc..i_last_ezenc+(".ezenc".len) ], ".dzenc"); // in-position replacement
        } else { // act when .ezenc IS NOT IN basename
            @memmove(s_new_basename[s_encdec_basename.len..(s_encdec_basename.len + ".dzenc".len)], ".dzenc");
            basename_size += ".dzenc".len; // add extra characters for concatenation
        }

    }
    
    // get file directory from path
    const s_opt_encdec_file_dir_loc: ?[]const u8 = 
        if (p_args_obj.opt_enc_file_loc != null) std.fs.path.dirname(p_args_obj.opt_enc_file_loc.?) 
        else if (p_args_obj.opt_dec_file_loc != null) std.fs.path.dirname(p_args_obj.opt_dec_file_loc.?) 
        else return error.ENC_OR_DEC_FILE_DNE;
    if (s_opt_encdec_file_dir_loc == null) return error.NULL_FILE_DIRECTORY_CANNOT_SAVE;
 
    // capturing new save location from parsed directory and filename
    const s_new_save_loc: []const u8 = 
        if (p_args_obj.opt_enc_file_loc != null) try std.fs.path.join(alloc, &[_][]const u8{s_opt_encdec_file_dir_loc.?, s_new_basename})
        else if (p_args_obj.opt_dec_file_loc != null) try std.fs.path.join(alloc, &[_][]const u8{s_opt_encdec_file_dir_loc.?, s_new_basename})
        else return error.ENC_OR_DEC_FILE_DNE;
    defer alloc.free(s_new_save_loc); // free heaped memory on program close

    // saving cipher calculated text to a file
    if (s_opt_output_data) |s_output_data| {
        const p_out_file: std.fs.File = try std.fs.cwd().createFile(s_new_save_loc, .{}); // overwrites prev file if exists 
        defer p_out_file.close(); // close after local scope finishes

        // writing to output file using Io.Writer
        var b_file_out_write: [tac.WRITE_TO_FILE_WRITER_BUF_SIZE]u8 = undefined;
        var fs_file_out_writer: std.fs.File.Writer = p_out_file.writer(&b_file_out_write);
        var io_file_out_writer: *std.Io.Writer = &fs_file_out_writer.interface;
        try io_file_out_writer.writeAll(s_output_data); // b_file_out_write buf flushed WHEN FULL ONLY
        try io_file_out_writer.flush(); // ensure all, final data is moved to the file (REQUIRED)

    } else return error.NO_OUTPUT_DATA_TO_WRITE_TO_NEW_FILE;
    _ = try io_stdout_writer.writeAll("\tSUCCESS: Ciphertext written to file (");
    _ = try io_stdout_writer.writeAll(s_new_save_loc);
    _ = try io_stdout_writer.writeAll(")\n");
    try io_stdout_writer.flush();

}


