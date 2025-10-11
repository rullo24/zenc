const std: type = @import("std");
const tac: type = @import("types_and_constants.zig");
const testing: type = std.testing;

////////////////////////////////////
/// PUBLIC FUNCTION DECLARATIONS ///
////////////////////////////////////

/// DESCRIPTION
/// Parses and validates cli args to determine the action to be performed on data.
///
/// PARAMETERS
/// `p_arg_struct` - Stack defined variable to store the captured arguments in a struct-like format
/// `args` - Sentinel arguments captured using std.process.argsAlloc
pub fn parseArgs(p_arg_struct: *tac.ARGUMENT_STRUCT, args: []const [:0]u8) !void {
    // iterate over each parameter
    for (0..args.len) |i| {

        // skip the program name (argument 0)       
        if (i == 0) continue;

        // converting sentinel slice --> regular slice w/ len
        const arg_non_sentinel: []const u8 = std.mem.span(args[i].ptr);

        // check if help argument available
        if (std.mem.eql(u8, arg_non_sentinel, "-h") or std.mem.eql(u8, arg_non_sentinel, "--help")) {

            p_arg_struct.has_help = true;

        } else if(std.mem.eql(u8, arg_non_sentinel, "-v") or std.mem.eql(u8, arg_non_sentinel, "--verbose")) {

            p_arg_struct.verbose_print = true;

        } else if(std.mem.eql(u8, arg_non_sentinel, "--dont_check_enc")) {

            p_arg_struct.should_check_enc_data = false;

        } else if (arg_non_sentinel.len > tac.MIN_OTHER_FLAG_AVAILABLE_LEN) { // only check for file flags are definitely available (larger than prerequisite size)

            // capturing letter that tells whether to perform encryption or decryption i.e. 'e'
            const req_behaviour_letter: u8 = arg_non_sentinel[tac.ARGUMENT_BEHAVIOUR_LETTER_INDEX];

            // capturing file string after behaviour letter
            const file_starting_index = tac.MIN_OTHER_FLAG_AVAILABLE_LEN; 
            const file_string_parsed: []const u8 = arg_non_sentinel[file_starting_index..arg_non_sentinel.len];

            // add encryption file from arguments
            if (req_behaviour_letter == 'e') { 

                // check if file string is larger than buffer size available
                if (file_string_parsed.len > p_arg_struct.enc_buf.len) return error.FILE_STRING_TOO_LARGE;
                
                // copy file string into encryption buffer in struct
                @memcpy(p_arg_struct.enc_buf[0..file_string_parsed.len], file_string_parsed); // copy into buffer

                // set slice in struct to resemble valid part of buffer
                p_arg_struct.opt_enc_file_loc = p_arg_struct.enc_buf[0..file_string_parsed.len]; // update struct slice to reflect new buffer addition

            // add decryption file from arguments
            } else if (req_behaviour_letter == 'd') { 

                // check if file string is larger than buffer size available
                if (file_string_parsed.len > p_arg_struct.dec_buf.len) return error.FILE_STRING_TOO_LARGE;

                // copy file string into encryption buffer in struct
                @memcpy(p_arg_struct.dec_buf[0..file_string_parsed.len], file_string_parsed); // copy into buffer

                // set slice in struct to resemble valid part of buffer
                p_arg_struct.opt_dec_file_loc = p_arg_struct.dec_buf[0..file_string_parsed.len]; // update struct slice to reflect new buffer addition
                
            } else { // argument has been parsed but is not VALID

                return error.INVALID_BEHAVIOUR_LETTER; 

            }

        }
    }
    
}

/// DESCRIPTION
/// Displays the usage instructions and a list of available commands
///
/// PARAMETERS
/// `p_file_handle` - File to print to (this should usually be stdout)
pub fn printHelp(p_file_handle: *std.Io.Writer) !void {
    const help_menu: []const u8 = 
    \\ === USAGE ===
    \\ ./zenc [OPTIONS]
    \\ NOTE: Always captures relative paths from cwd.
    \\ 
    \\ === OPTIONS ===
    \\ -h OR --help -> Prints this help menu
    \\ -e=<file_to_encrypt> -> Encrypt file
    \\ -d=<file_to_decrypt> -> Decrypt file
    \\ --dont_check_enc -> Stop immediate encrypted file decryption check (increase speed).
    \\ -v OR --verbose -> Prints extra stdout information
    ;

    try p_file_handle.writeAll(help_menu);
    try p_file_handle.flush();
}

/// DESCRIPTION
/// Checks if sufficient arguments were parsed to allow to program to perform some operation.
///
/// PARAMETERS
/// `p_args_obj` - ptr to arguments struct for processing
pub fn validateArgsObj(p_args_obj: *tac.ARGUMENT_STRUCT) !void {
    // Error Check - ONE OF -e or -d 
    if ( p_args_obj.opt_enc_file_loc == null and p_args_obj.opt_dec_file_loc == null) {
        return error.NO_ENC_OR_DEC_FILE;
    }
    // Error Check - NOT BOTH -e and -d
    if ( p_args_obj.opt_dec_file_loc != null and p_args_obj.opt_enc_file_loc != null) {
        return error.PROVIDED_ENC_AND_DEC_FILE;
    }

    // check if file to enc or dec file exists
    if ( p_args_obj.opt_enc_file_loc != null) std.fs.cwd().access( p_args_obj.opt_enc_file_loc.?, .{}) catch return error.ENC_FILE_LOC_NOT_REAL
    else if ( p_args_obj.opt_dec_file_loc != null) std.fs.cwd().access( p_args_obj.opt_dec_file_loc.?, .{}) catch return error.DEC_FILE_LOC_NOT_REAL
    else return error.ENC_OR_DEC_FILE_DNE;
}

/// DESCRIPTION
/// Reads a password from the cli without echoing characters to the screen (toggle this option).
///
/// PARAMETERS
/// `stdout` - The file pointer to print to the console
/// `stdin` - The file pointer to read from the console
pub fn getPassword(w: *std.Io.Writer, r: *std.Io.Reader) ![]const u8 {

    // print to writer (console)
    _ = try w.writeAll("Enter Password: "); 
    try w.flush();

    // read from user (stdin)
    return try r.takeDelimiterExclusive('\n');
}

///////////////////////////
// --- BEGIN TESTING --- //
///////////////////////////

// -- START parseArgs -- //

test "parseArgs - parse nothing" {

    // init vars
    var args_obj: tac.ARGUMENT_STRUCT = .{};
    const test_args: []const [:0]u8 = &.{ @constCast("./example_program"), };

    // run w/ no args
    try parseArgs(&args_obj, test_args );
    try testing.expect(args_obj.has_help == false);
    try testing.expect(args_obj.should_check_enc_data == true);
    try testing.expect(args_obj.opt_enc_file_loc == null);
    try testing.expect(args_obj.opt_dec_file_loc == null);
}

test "parseArgs - both help versions" {

    // init vars
    var args_obj_h: tac.ARGUMENT_STRUCT = .{};
    const test_args_h: []const [:0]u8 = &.{ @constCast("./example_program"), @constCast("-h")};
    var args_obj_help: tac.ARGUMENT_STRUCT = .{};
    const test_args_help: []const [:0]u8 = &.{ @constCast("./example_program"), @constCast("--help")};

    // -h
    try parseArgs(&args_obj_h, test_args_h);
    try testing.expect(args_obj_h.has_help == true);
    try testing.expect(args_obj_h.should_check_enc_data == true);
    try testing.expect(args_obj_h.opt_enc_file_loc == null);
    try testing.expect(args_obj_h.opt_dec_file_loc == null);

    // --help
    try parseArgs(&args_obj_help, test_args_help);
    try testing.expect(args_obj_help.has_help == true);
    try testing.expect(args_obj_help.should_check_enc_data == true);
    try testing.expect(args_obj_help.opt_enc_file_loc == null);
    try testing.expect(args_obj_help.opt_dec_file_loc == null);

}

test "parseArgs - parse just --dont_check_enc" {

    // init vars
    var args_obj: tac.ARGUMENT_STRUCT = .{};
    const test_args: []const [:0]u8 = &.{ @constCast("./example_program"), @constCast("--dont_check_enc")};

    // run w/ --dont_check_enc arg ONLY
    try parseArgs(&args_obj, test_args);
    try testing.expect(args_obj.has_help == false);
    try testing.expect(args_obj.should_check_enc_data == false);
    try testing.expect(args_obj.opt_enc_file_loc == null);
    try testing.expect(args_obj.opt_dec_file_loc == null);

}

test "parseArgs - parse just enc w/ no file" {

    // init vars
    var args_obj: tac.ARGUMENT_STRUCT = .{};
    const test_args: []const [:0]u8 = &.{ @constCast("./example_program"), @constCast("-e=")};

    // run w/ enc file (no file string) arg ONLY
    try parseArgs(&args_obj, test_args);
    try testing.expect(args_obj.has_help == false);
    try testing.expect(args_obj.should_check_enc_data == true);
    try testing.expect(args_obj.opt_enc_file_loc == null); // should not change
    try testing.expect(args_obj.opt_dec_file_loc == null);

}

test "parseArgs - parse just enc file" {

    // init vars
    var args_obj: tac.ARGUMENT_STRUCT = .{};
    const test_args: []const [:0]u8 = &.{ @constCast("./example_program"), @constCast("-e=jeff")};

    // run w/ enc file arg ONLY
    try parseArgs(&args_obj, test_args);
    try testing.expect(args_obj.has_help == false);
    try testing.expect(args_obj.should_check_enc_data == true);
    if (args_obj.opt_enc_file_loc) |enc_file_loc| {
        try testing.expectEqualStrings(enc_file_loc, "jeff");
    } else return error.OPT_ENC_FILE_LOC_IS_STILL_NULL;
    try testing.expect(args_obj.opt_dec_file_loc == null);

}

test "parseArgs - parse just dec w/ no file" {

    // init vars
    var args_obj: tac.ARGUMENT_STRUCT = .{};
    const test_args: []const [:0]u8 = &.{ @constCast("./example_program"), @constCast("-d=")};

    // run w/ dec file arg ONLY
    try parseArgs(&args_obj, test_args);
    try testing.expect(args_obj.has_help == false);
    try testing.expect(args_obj.should_check_enc_data == true);
    try testing.expect(args_obj.opt_enc_file_loc == null);
    try testing.expect(args_obj.opt_dec_file_loc == null); // should not change

}

test "parseArgs - parse just dec file" {

    // init vars
    var args_obj: tac.ARGUMENT_STRUCT = .{};
    const test_args: []const [:0]u8 = &.{ @constCast("./example_program"), @constCast("-d=jeff")};

    // run w/ dec file arg ONLY
    try parseArgs(&args_obj, test_args);
    try testing.expect(args_obj.has_help == false);
    try testing.expect(args_obj.should_check_enc_data == true);
    try testing.expect(args_obj.opt_enc_file_loc == null);
    try testing.expect(args_obj.opt_dec_file_loc != null);
    try testing.expectEqualStrings(args_obj.opt_dec_file_loc.?, "jeff");

}

test "parseArgs - parse invalid letter through -<letter>= syntax NO filepath" {

    // init vars
    var args_obj: tac.ARGUMENT_STRUCT = .{};
    const test_args: []const [:0]u8 = &.{ @constCast("./example_program"), @constCast("-x=")};

    // run w/ bad syntax
    try parseArgs(&args_obj, test_args); // ignore -x=
    try testing.expect(args_obj.has_help == false);
    try testing.expect(args_obj.should_check_enc_data == true);
    try testing.expect(args_obj.opt_enc_file_loc == null);
    try testing.expect(args_obj.opt_dec_file_loc == null);

}

test "parseArgs - parse invalid letter through -<letter>= syntax w/ filepath" {

    // init vars
    var args_obj: tac.ARGUMENT_STRUCT = .{};
    const test_args: []const [:0]u8 = &.{ @constCast("./example_program"), @constCast("-x=jeff")};

    // run w/ bad syntax
    const parse_args_res = parseArgs(&args_obj, test_args);
    try testing.expectError(error.INVALID_BEHAVIOUR_LETTER, parse_args_res);
    try testing.expect(args_obj.has_help == false);
    try testing.expect(args_obj.should_check_enc_data == true);
    try testing.expect(args_obj.opt_enc_file_loc == null);
    try testing.expect(args_obj.opt_dec_file_loc == null);

}

test "parseArgs - parse all" {

    // init vars
    var args_obj: tac.ARGUMENT_STRUCT = .{};
    const test_args: []const [:0]u8 = &.{ 
        @constCast("./example_program"), 
        @constCast("-e=jeff"), 
        @constCast("-d=jeff"),
        @constCast("-h"),
        @constCast("--help"),
        @constCast("--dont_check_enc")
    };

    // run w/ all args
    try parseArgs(&args_obj, test_args);
    try testing.expect(args_obj.has_help == true);
    try testing.expect(args_obj.should_check_enc_data == false);
    try testing.expect(args_obj.opt_enc_file_loc != null);
    try testing.expectEqualStrings(args_obj.opt_enc_file_loc.?, "jeff");
    try testing.expect(args_obj.opt_dec_file_loc != null);
    try testing.expectEqualStrings(args_obj.opt_dec_file_loc.?, "jeff");

}

// -- END parseArgs -- //

// -- START printHelp -- //

test "printHelp - general print" {

    // taken from printHelp
    const help_menu: []const u8 = 
    \\ === USAGE ===
    \\ ./zenc [OPTIONS]
    \\ NOTE: Always captures relative paths from cwd.
    \\ 
    \\ === OPTIONS ===
    \\ -h OR --help -> Prints this help menu
    \\ -e=<file_to_encrypt> -> Encrypt file
    \\ -d=<file_to_decrypt> -> Decrypt file
    \\ --dont_check_enc -> Stop immediate encrypted file decryption check (increase speed).
    \\ -v OR --verbose -> Prints extra stdout information
    ;

    // creating buffer w/ std.Io.Writer to mimic stdout
    var buf: [help_menu.len]u8 = std.mem.zeroes([help_menu.len]u8);
    try testing.expectStringStartsWith(&buf, "\x00");
    try testing.expectStringEndsWith(&buf, "\x00");
    var b_writer: std.Io.Writer = .fixed(&buf);

    // check if any data is printed to stdout
    try printHelp(&b_writer);
    const zero_term_output: [*:0]u8 = @ptrCast(&buf);
    const true_output: []const u8 = std.mem.span(zero_term_output);
    try testing.expectEqualStrings(help_menu, true_output);

}

// -- END printHelp -- //

// -- START validateArgsObj -- //

test "validateArgsObj - both null" {

    // init vars
    var args_obj: tac.ARGUMENT_STRUCT = .{}; // init all to null

    // run testing on data
    const resp = validateArgsObj(&args_obj);
    try testing.expectError(error.NO_ENC_OR_DEC_FILE, resp);

}

test "validateArgsObj - both NOT null but invalid" {

    // init vars
    var args_obj: tac.ARGUMENT_STRUCT = .{}; // init all to null
    @memcpy(args_obj.enc_buf[0..3], "abc");
    args_obj.opt_enc_file_loc = args_obj.enc_buf[0..3];
    @memcpy(args_obj.dec_buf[0..3], "abc");
    args_obj.opt_dec_file_loc = args_obj.dec_buf[0..3];

    // run testing on data
    const resp = validateArgsObj(&args_obj);
    try testing.expectError(error.PROVIDED_ENC_AND_DEC_FILE, resp);

}

test "validateArgsObj - invalid path on enc (no dec)" {

    // init vars
    var args_obj: tac.ARGUMENT_STRUCT = .{}; // init all to null
    @memcpy(args_obj.enc_buf[0..3], "abc");
    args_obj.opt_enc_file_loc = args_obj.enc_buf[0..3];

    // run testing on data
    const resp = validateArgsObj(&args_obj);
    try testing.expectError(error.ENC_FILE_LOC_NOT_REAL, resp);

}

test "validateArgsObj - invalid path on dec (no enc)" {

    // init vars
    var args_obj: tac.ARGUMENT_STRUCT = .{}; // init all to null
    @memcpy(args_obj.dec_buf[0..3], "abc");
    args_obj.opt_dec_file_loc = args_obj.dec_buf[0..3];

    // run testing on data
    const resp = validateArgsObj(&args_obj);
    try testing.expectError(error.DEC_FILE_LOC_NOT_REAL, resp);

}

test "validateArgsObj - one valid path" {

    // init vars
    const alloc: std.mem.Allocator = testing.allocator; // creating allocator for file movement
    var args_obj: tac.ARGUMENT_STRUCT = .{}; // init all to null
    var tmp_dir: std.testing.TmpDir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const tmp_dir_loc: []const u8 = try tmp_dir.dir.realpathAlloc(alloc, ".");
    defer alloc.free(tmp_dir_loc);

    @memcpy(args_obj.dec_buf[0..tmp_dir_loc.len], tmp_dir_loc);
    args_obj.opt_dec_file_loc = args_obj.dec_buf[0..tmp_dir_loc.len];

    // run testing on data
    try validateArgsObj(&args_obj);

}

// -- END validateArgsObj -- //

// -- START getPassword -- //

test "getPassword - capture password from reader & print prompt to writer" {

    // create writer
    var b_write: [tac.MAX_PASSWORD_SIZE_BYTES]u8 = std.mem.zeroes([tac.MAX_PASSWORD_SIZE_BYTES]u8);
    var writer: std.Io.Writer = .fixed(&b_write);

    // create reader
    var b_read: [tac.MAX_PASSWORD_SIZE_BYTES]u8 = std.mem.zeroes([tac.MAX_PASSWORD_SIZE_BYTES]u8);
    const makeshift_read: []const u8 = "abcdefg";
    const makeshift_read_w_newline: []const u8 = makeshift_read ++ "\n";
    @memcpy(b_read[0..makeshift_read_w_newline.len], makeshift_read_w_newline);
    var reader: std.Io.Reader = .fixed(&b_read);

    // capture password from reader feed and compare against expected
    const resp: []const u8 = try getPassword(&writer, &reader);
    try testing.expectEqualStrings(makeshift_read, resp);

}

test "getPassword - handle empty password read" {

    // create writer
    var b_write: [tac.MAX_PASSWORD_SIZE_BYTES]u8 = std.mem.zeroes([tac.MAX_PASSWORD_SIZE_BYTES]u8);
    var writer: std.Io.Writer = .fixed(&b_write);

    // create reader
    var b_read: [tac.MAX_PASSWORD_SIZE_BYTES]u8 = std.mem.zeroes([tac.MAX_PASSWORD_SIZE_BYTES]u8);
    const makeshift_read: []const u8 = "";
    const makeshift_read_w_newline: []const u8 = makeshift_read ++ "\n";
    @memcpy(b_read[0..makeshift_read_w_newline.len], makeshift_read_w_newline);
    var reader: std.Io.Reader = .fixed(&b_read);

    // capture password from reader feed and compare against expected
    const resp: []const u8 = try getPassword(&writer, &reader);
    try testing.expectEqualStrings(makeshift_read, resp);

}

// -- END getPassword -- //

/////////////////////////
// --- END TESTING --- //
/////////////////////////


