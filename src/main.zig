const std = @import("std");

// IMPORT LOCAL PACKAGES //
const cipher: type = @import("cipher.zig");
const cli: type = @import("cli.zig");
const tac: type = @import("types_and_constants.zig");
const err: type = @import("err.zig");

/// DESCRIPTION
/// The entry point of the program
///
/// PARAMETERS
/// N/A
pub fn main() !void {
    // init allocator + writers
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const alloc: std.mem.Allocator = gpa.allocator();
    defer _ = gpa.deinit();
    const stdout: std.fs.File = std.fs.File.stdout();

    // capture args from user --> move args into zenc variables
    var args_obj: tac.ARGUMENT_STRUCT = tac.ARGUMENT_STRUCT{}; // to store arguments in easy-to-read format
    const args: []const [:0]u8 = try std.process.argsAlloc(alloc); // capturing args from console
    defer std.process.argsFree(alloc, args);
    try cli.parseArgs(&args_obj, args); // capture arguments into ARGUMENT_STRUCT for easier use

    // check if help flag is in captured args
    if (args_obj.has_help == true) {
        try cli.printHelp(stdout);
        return; // end program after printing help
    }

    // check args are valid 
    // Error Check - ONE OF -e or -d 
    if ( !args_obj.opt_enc_file_loc and !args_obj.opt_dec_file_loc ) {
        return error.NO_ENC_OR_DEC_FILE;
    }
    // Error Check - NOT BOTH -e and -d
    if ( args_obj.opt_dec_file_loc and args_obj.opt_enc_file_loc ) {
        return error.PROVIDED_ENC_AND_DEC_FILE;
    }
    
    // check if file to enc or dec exists
    if (args_obj.opt_enc_file_loc) std.fs.cwd().access(args_obj.opt_enc_file_loc.?, .{}) catch return error.ENC_FILE_LOC_NOT_REAL
    else if (args_obj.opt_dec_file_loc) try std.fs.cwd().access(args_obj.opt_dec_file_loc.?, .{}) catch return error.DEC_FILE_LOC_NOT_REAL
    else return error.ENC_OR_DEC_FILE_DNE;

    // get file directory from path
    const opt_encdec_file_dir: ?[]const u8 = 
    if (args_obj.opt_enc_file_loc) std.fs.path.dirname(args_obj.opt_enc_file_loc.?) 
    else if (args_obj.opt_dec_file_loc) std.fs.path.dirname(args_obj.opt_dec_file_loc) 
    else return error.ENC_OR_DEC_FILE_DNE;
    
    // capture password from stdin (user input)
    
    // derive crypto key from password

    // read unchanged file contents into buffer
        
    // if encrypting 
        // reconfirm entered password

        // generate nonce and salt from password

        // use salt and none to encrypt the file

        // add auth tag to enc output (at start of file)

    // if decrypting
        // verify entered file starts with ZENC_MAGIC_NUMBER
    
        //  extract nonce and salt from file
    
        // use derived key, nonce and salt to decrypt file contents into second buffer

        // verify auth tag to confirm data is valid (at start of file)

    // generate output file name (extension changing)
    
    // save data to the new file

    // cleanup password RAM memory (avoid leaving password in RAM)
    
}

/// DESCRIPTION
/// A security function that securely overwrites sensitive data in memory i.e. passwords
///
/// PARAMETERS
/// N/A
fn cleanup() !void {
    // TODO: implement this

}
