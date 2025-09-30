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
    if ( args_obj.opt_enc_file_loc == null and args_obj.opt_dec_file_loc == null) {
        return error.NO_ENC_OR_DEC_FILE;
    }
    // Error Check - NOT BOTH -e and -d
    if ( args_obj.opt_dec_file_loc != null and args_obj.opt_enc_file_loc != null) {
        return error.PROVIDED_ENC_AND_DEC_FILE;
    }
    
    // check if file to enc or dec exists
    {
        if (args_obj.opt_enc_file_loc != null) std.fs.cwd().access(args_obj.opt_enc_file_loc.?, .{}) catch return error.ENC_FILE_LOC_NOT_REAL
        else if (args_obj.opt_dec_file_loc != null) std.fs.cwd().access(args_obj.opt_dec_file_loc.?, .{}) catch return error.DEC_FILE_LOC_NOT_REAL
        else return error.ENC_OR_DEC_FILE_DNE;
    }

    // get file directory from path
    const opt_encdec_file_dir: ?[]const u8 = 
        if (args_obj.opt_enc_file_loc != null) std.fs.path.dirname(args_obj.opt_enc_file_loc.?) 
        else if (args_obj.opt_dec_file_loc != null) std.fs.path.dirname(args_obj.opt_dec_file_loc.?) 
        else return error.ENC_OR_DEC_FILE_DNE;
 
    // capture password from stdin (user input)
    var pass_v1_buf: [tac.MAX_PASSWORD_SIZE_BYTES]u8 = std.mem.zeroes([tac.MAX_PASSWORD_SIZE_BYTES]u8);
    var stdin_reader: std.fs.File.Reader = std.fs.File.stdin().reader(&pass_v1_buf);
    _ = try stdout.write("Enter Password: "); // print to console
    const pass_v1_len: usize = try stdin_reader.read(&pass_v1_buf); // read from user in console
    const password_v1: []const u8 = pass_v1_buf[0..pass_v1_len];

    // capture file object from available item
    const p_file: std.fs.File = 
        if (args_obj.opt_enc_file_loc != null) try std.fs.cwd().openFile(args_obj.opt_enc_file_loc.?, .{.mode = .read_only})
        else if (args_obj.opt_dec_file_loc != null) try std.fs.cwd().openFile(args_obj.opt_dec_file_loc.?, .{.mode = .read_only})
        else return error.ENC_OR_DEC_FILE_DNE;
    defer p_file.close(); // free file descriptor memory

    // read file contents into buffer (heaped)
    const file_size: u64 = try p_file.getEndPos();
    const raw_buf: []u8 = try alloc.alloc(u8, file_size); // heap buffer to store file bytes
    defer alloc.free(raw_buf); // free copied file bytes on program exit
    _ = try p_file.read(raw_buf); // reading unencrypted file data into raw buf

    // building buf for cipher text (encrypted)
    const ciphertext_buf: []u8 = try alloc.alloc(u8, file_size); // to be parsed to encrypt method for capturing contents
    defer alloc.free(ciphertext_buf);

    // building buf for output file text (NONCE + ciphertext + AUTH_TAG)
    const output_size: usize = (@sizeOf(tac.ZENC_MAGIC_NUM) + tac.NONCE_SIZE + ciphertext_buf.len + tac.AUTH_TAG_SIZE);
    const output_buf: []u8 = try alloc.alloc(u8, output_size);
    defer alloc.free(output_buf);

    // logic changes depending on if trying to encrypt or decrypt
    if (args_obj.opt_enc_file_loc != null) { // if encrypting

        // reconfirm entered password
        var pass_v2_buf: [tac.MAX_PASSWORD_SIZE_BYTES]u8 = std.mem.zeroes([tac.MAX_PASSWORD_SIZE_BYTES]u8);
        _ = try stdout.write("Please Re-Enter Password: "); // print to console
        const pass_v2_len: usize = try stdin_reader.read(&pass_v2_buf); // read from user in console
        const password_v2: []const u8 = pass_v2_buf[0..pass_v2_len];

        // compare password_v1 and password_v2 --> throw error if these don't match
        if (std.mem.eql(u8, password_v1, password_v2) != true) return error.PASSWORDS_DO_NOT_MATCH;

        // generating nonce to "jumble encryption"
        var nonce: [tac.NONCE_SIZE]u8 = undefined;
        std.crypto.random.bytes(&nonce); // reading random bytes into the nonce buffer

        // generate crypto key from password and salt
        var final_key: [tac.SHA256_BYTE_SIZE]u8 = undefined; // 256-bit
        try cipher.deriveKeyFromPass(password_v1, &final_key); // moving crypto key into `final_key`

        // encrypt raw contents into ciphertext buffer
        var auth_tag: [tac.AUTH_TAG_SIZE]u8 = undefined;
        try cipher.encrypt(&nonce, &final_key, raw_buf, ciphertext_buf, &auth_tag);

        // write magic num, then nonce, then ciphertext, then auth tag to ciphertext buffer
        var offset: usize = 0;
        std.mem.writeInt(u64, output_buf[offset..offset + @sizeOf(tac.ZENC_MAGIC_NUM)], tac.ZENC_MAGIC_NUM, tac.ZENC_ENDIAN_TYPE); // writing magic num
        offset += @sizeOf(tac.ZENC_MAGIC_NUM);
        @memcpy(output_buf[offset..offset+tac.NONCE_SIZE], &nonce); // write nonce
        offset += tac.NONCE_SIZE;
        @memcpy(output_buf[offset..offset+ciphertext_buf.len], ciphertext_buf); // write ciphertext
        offset += ciphertext_buf.len;
        @memcpy(output_buf[offset..offset+tac.AUTH_TAG_SIZE], &auth_tag); // write auth tag
        offset += tac.AUTH_TAG_SIZE;

    } else if (args_obj.opt_dec_file_loc != null) { // if decrypting

        // verify entered file starts with ZENC_MAGIC_NUMBER
    
        //  extract nonce and salt from file
    
        // use derived key, nonce and salt to decrypt file contents into second buffer

        // verify auth tag to confirm data is valid (at start of file)



    }


    // TODO: file decrypted straight after encryption --> check auth tag and nonce work
    

    // generate output file name (extension changing)
    
    // save data to the new file

    _ = opt_encdec_file_dir;

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
