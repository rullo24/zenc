const std = @import("std");

// IMPORT LOCAL PACKAGES //
const cipher: type = @import("cipher.zig");
const cli: type = @import("cli.zig");
const tac: type = @import("types_and_constants.zig");

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

    // FIXME: ciphertext_buf size will be as large as file_size in decrypt (not same size as when enc happens due to added baggage)

    // building buf for cipher text (encrypted)
    const ciphertext_buf: []u8 = try alloc.alloc(u8, file_size); // to be parsed to encrypt method for capturing contents
    defer alloc.free(ciphertext_buf);

    // building buf for output file text (NONCE + ciphertext + AUTH_TAG)
    const output_size: usize = (@sizeOf(@TypeOf(tac.ZENC_MAGIC_NUM)) + tac.ZENC_SALT_SIZE + tac.NONCE_SIZE + ciphertext_buf.len + tac.AUTH_TAG_SIZE);
    const output_buf: []u8 = try alloc.alloc(u8, output_size);
    defer alloc.free(output_buf);

    // --- ENCRYPTION/DECRYPTION BRANCHING --- //

    // logic changes depending on if trying to encrypt or decrypt
    if (args_obj.opt_enc_file_loc != null) { // if encrypting

        // reconfirm entered password
        var pass_v2_buf: [tac.MAX_PASSWORD_SIZE_BYTES]u8 = std.mem.zeroes([tac.MAX_PASSWORD_SIZE_BYTES]u8);
        _ = try stdout.write("Please Re-Enter Password: "); // print to console
        const pass_v2_len: usize = try stdin_reader.read(&pass_v2_buf); // read from user in console
        const password_v2: []const u8 = pass_v2_buf[0..pass_v2_len];

        // compare password_v1 and password_v2 --> throw error if these don't match
        if (std.mem.eql(u8, password_v1, password_v2) != true) return error.PASSWORDS_DO_NOT_MATCH;

        // TODO: smash password_v2 cryptographically after the if statement is passed

        // generating nonce to "jumble encryption"
        var nonce: [tac.NONCE_SIZE]u8 = undefined;
        std.crypto.random.bytes(&nonce); // reading random bytes into the nonce buffer

        // generate crypto key from password and salt
        var final_key: [tac.SHA256_BYTE_SIZE]u8 = undefined; // 256-bit
        var salt: [tac.ZENC_SALT_SIZE]u8 = undefined;
        std.crypto.random.bytes(&salt);
        try cipher.deriveKeyFromPass(password_v1, &salt, &final_key); // moving crypto key into `final_key`

        // encrypt raw contents into ciphertext buffer
        var auth_tag: [tac.AUTH_TAG_SIZE]u8 = undefined;
        try cipher.encrypt(&nonce, &final_key, raw_buf, ciphertext_buf, &auth_tag);

        // write magic num, then salt, then nonce, then ciphertext, then auth tag to ciphertext buffer
        var offset: usize = 0;
        
        // 1. magic num
        const magic_num_slice_to_write: []const u8 = output_buf[offset..offset + @sizeOf(@TypeOf(tac.ZENC_MAGIC_NUM))];
        const p_eight_byte_aligned_magic_num: *[8]u8 = @constCast(@ptrCast(@alignCast(magic_num_slice_to_write)));
        std.mem.writeInt(u64, p_eight_byte_aligned_magic_num, tac.ZENC_MAGIC_NUM, tac.ZENC_ENDIAN_TYPE); // writing magic num
        offset += @sizeOf(@TypeOf(tac.ZENC_MAGIC_NUM));

        // 2. salt
        @memcpy(output_buf[offset..offset+tac.ZENC_SALT_SIZE], &salt); // write salt
        offset += tac.ZENC_SALT_SIZE;

        // 3. nonce
        @memcpy(output_buf[offset..offset+tac.NONCE_SIZE], &nonce); // write nonce
        offset += tac.NONCE_SIZE;

        // 4. ciphertext
        @memcpy(output_buf[offset..offset+ciphertext_buf.len], ciphertext_buf); // write ciphertext
        offset += ciphertext_buf.len;

        // 5. auth tag
        @memcpy(output_buf[offset..offset+tac.AUTH_TAG_SIZE], &auth_tag); // write auth tag
        offset += tac.AUTH_TAG_SIZE;

        // TODO: add stdout text to specify the encryption is completed

    } else if (args_obj.opt_dec_file_loc != null) { // if decrypting

        // 1. verify magic num in raw file data
        if (file_size < (@sizeOf(@TypeOf(tac.ZENC_MAGIC_NUM)) + tac.NONCE_SIZE + tac.AUTH_TAG_SIZE)) return error.FILE_READ_TOO_SMALL;
        const retrieved_magic_num_slice: []const u8 = raw_buf[0..@sizeOf(@TypeOf(tac.ZENC_MAGIC_NUM))];
        if (retrieved_magic_num_slice.len != 8) return error.RETRIEVED_MAGIC_NUM_WEIRD_SIZE;
        const p_retrieved_magic_num_buf: *[8]u8 = @constCast(@ptrCast(retrieved_magic_num_slice));
        const retrieved_magic_num: u64 = std.mem.readInt(u64, p_retrieved_magic_num_buf, tac.ZENC_ENDIAN_TYPE);
        if (retrieved_magic_num != tac.ZENC_MAGIC_NUM) return error.TRIED_TO_DECRYPT_NON_ZENC_FILE;
    
        // 2. extract salt, nonce, encrypted text and auth tag from file
        var offset: usize = @sizeOf(@TypeOf(tac.ZENC_MAGIC_NUM)); // skip magic num
        const retrieved_salt: []const u8 = raw_buf[offset..offset+tac.ZENC_SALT_SIZE];
        offset += tac.ZENC_SALT_SIZE;
        const retrieved_nonce: []const u8 = raw_buf[offset..offset+tac.NONCE_SIZE];
        offset += tac.NONCE_SIZE;
        const retrieved_ciphertext: []const u8 = raw_buf[offset..offset+(raw_buf.len-tac.AUTH_TAG_SIZE+1)];
        offset += (raw_buf.len - tac.AUTH_TAG_SIZE) + 1;
        const retrieved_auth_tag: []const u8 = raw_buf[offset..offset+tac.AUTH_TAG_SIZE];
        offset += tac.AUTH_TAG_SIZE;
    
        // 3. generate crypto key using extracted salt
        var final_key: [tac.SHA256_BYTE_SIZE]u8 = undefined; // 256-bit
        try cipher.deriveKeyFromPass(password_v1, @ptrCast(retrieved_salt), &final_key);

        // 4. define bounds of ciphertext buf for decrypted data placement
        const dec_buf: []const u8 = output_buf[0..retrieved_ciphertext.len];

        // 5. decrypt file contents and verify auth tag
        try cipher.decrypt(
            @constCast(@ptrCast(retrieved_nonce)),
            &final_key,
            @constCast(dec_buf),
            @constCast(retrieved_ciphertext),
            @constCast(@ptrCast(retrieved_auth_tag)),
        );

    }


    // TODO: file decrypted straight after encryption --> check auth tag and nonce work

    // TODO: split main function portions out into sub functions

    // TODO: write tests for each sub function
    
    // generate output file name (extension changing)
    
    // save data to new file

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
