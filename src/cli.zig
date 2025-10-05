const std: type = @import("std");
const tac: type = @import("types_and_constants.zig");

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
                std.mem.copyForwards(u8, &p_arg_struct.enc_buf, file_string_parsed); // copy into buffer

                // set slice in struct to resemble valid part of buffer
                p_arg_struct.opt_enc_file_loc = p_arg_struct.enc_buf[0..file_string_parsed.len]; // update struct slice to reflect new buffer addition

            // add decryption file from arguments
            } else if (req_behaviour_letter == 'd') { 

                // check if file string is larger than buffer size available
                if (file_string_parsed.len > p_arg_struct.dec_buf.len) return error.FILE_STRING_TOO_LARGE;

                // copy file string into encryption buffer in struct
                std.mem.copyForwards(u8, &p_arg_struct.dec_buf, file_string_parsed); // copy into buffer

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
/// `p_pass_v1_buf` - Buffer to hold the captured password
/// `stdout` - The file pointer to print to the console
pub fn getPassword(p_pass_buf: *[tac.MAX_PASSWORD_SIZE_BYTES]u8, stdout: *std.Io.Writer) ![]const u8 {

    // creating stdin reader and prompting user for password
    var password_stdin_reader: std.fs.File.Reader = std.fs.File.stdin().reader(p_pass_buf);
    const stdin: *std.Io.Reader = &password_stdin_reader.interface;
    _ = try stdout.writeAll("Enter Password: "); // print to console
    try stdout.flush();

    // reading from the user (stdin)
    const s_password: []const u8 = try stdin.takeDelimiterExclusive('\n'); // read from user in console

    return s_password;
}

/// DESCRIPTION
/// Clear the terminal history of the PC
///
/// PARAMETERS
/// TBD
// TODO: Add parameters to comment
pub fn cleanTerminalHistory() !void {
    // TODO: implement this
}
