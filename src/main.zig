const std = @import("std");

// IMPORT LOCAL PACKAGES //
const cipher: type = @import("cipher.zig");
const cli: type = @import("cli.zig");
const tac: type = @import("types_and_constants.zig");
const packaging: type = @import("packaging.zig");

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

    // using stdout for writing
    var stdout_writer: std.fs.File.Writer = std.fs.File.stdout().writer(&.{});
    const stdout: *std.Io.Writer = &stdout_writer.interface; 

    // capture args from user --> move args into zenc variables
    var args_obj: tac.ARGUMENT_STRUCT = tac.ARGUMENT_STRUCT{}; // to store arguments in easy-to-read format
    const args: []const [:0]u8 = try std.process.argsAlloc(alloc); // capturing args from console
    defer std.process.argsFree(alloc, args); // free args at end of program
    try cli.parseArgs(&args_obj, args); // capture arguments into ARGUMENT_STRUCT for easier use

    // check if help flag is in captured args
    if (args_obj.has_help == true) {
        try cli.printHelp(stdout);
        return; // end program after printing help
    }
    
    // check for sufficient arguments parsed by user to continue
    try cli.validateArgsObj(&args_obj);
    
    // get file directory from path
    const opt_encdec_file_dir: ?[]const u8 = 
        if (args_obj.opt_enc_file_loc != null) std.fs.path.dirname(args_obj.opt_enc_file_loc.?) 
        else if (args_obj.opt_dec_file_loc != null) std.fs.path.dirname(args_obj.opt_dec_file_loc.?) 
        else return error.ENC_OR_DEC_FILE_DNE;
 
    // capture password from stdin (user input)
    var pass_v1_buf: [tac.MAX_PASSWORD_SIZE_BYTES]u8 = std.mem.zeroes([tac.MAX_PASSWORD_SIZE_BYTES]u8);
    const password_v1: []const u8 = try cli.getPassword(&pass_v1_buf, stdout);

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
    var s_opt_output_data: ?[]const u8 = null; // holds slice from output_buf that contains the final data

    // --- ENCRYPTION/DECRYPTION BRANCHING --- //

    // IF ENCRYPTION
    if (args_obj.opt_enc_file_loc != null) {
        
        _ = try stdout.write("\n=== ENCRYPTION MODE SET ===\n");
        try stdout.flush();

        // 1. reconfirm entered password
        var pass_v2_buf: [tac.MAX_PASSWORD_SIZE_BYTES]u8 = std.mem.zeroes([tac.MAX_PASSWORD_SIZE_BYTES]u8);
        const password_v2: []const u8 = try cli.getPassword(&pass_v2_buf, stdout);
        
        // 2. compare password_v1 and password_v2 --> throw error if these don't match
        if (std.mem.eql(u8, password_v1, password_v2) != true) return error.PASSWORDS_DO_NOT_MATCH;

        // 3. create cipher components obj for holding salt, nonce, etc.
        var enc_cipher_obj: packaging.CIPHER_COMPONENTS = .{}; // holds nonce, salt and auth tag

        // 4. generating nonce to "jumble encryption"
        std.crypto.random.bytes(&enc_cipher_obj.nonce); // reading random bytes into the nonce buffer

        // 5. generate crypto key from password and salt
        var final_key: [tac.SHA256_BYTE_SIZE]u8 = undefined; // 256-bit
        std.crypto.random.bytes(&enc_cipher_obj.salt); // scramble entire salt buffer for maximised-randomness crypto algo
        try cipher.deriveKeyFromPass(password_v1, &enc_cipher_obj.salt, &final_key); // moving crypto key into `final_key`

        // 6. encrypt raw contents into ciphertext buffer
        try cipher.encrypt(&enc_cipher_obj.nonce, &final_key, raw_buf, ciphertext_buf, &enc_cipher_obj.auth_tag);

        // 7. write magic num, then salt, then nonce, then ciphertext, then auth tag to ciphertext buffer
        s_opt_output_data = packaging.packEncryptionDataToOutputBuf(output_buf, ciphertext_buf, &enc_cipher_obj.salt, &enc_cipher_obj.nonce, &enc_cipher_obj.auth_tag);

        // 8. destroying all crypto entries
        cipher.secureDestoryAllArgs( .{&password_v1, &password_v2, &final_key, &enc_cipher_obj} );

        _ = try stdout.write("\n=== ENCRYPTION COMPLETED SUCCESSFULLY ===\n");
        try stdout.flush();

    // IF DECRYPTION
    } else if (args_obj.opt_dec_file_loc != null) { 

        _ = try stdout.write("=== DECRYPTION MODE SET ===\n");
        try stdout.flush();

        // 1. basic file check to see if file can hold all non-ciphertext info
        if (file_size < (@sizeOf(@TypeOf(tac.ZENC_MAGIC_NUM)) + tac.NONCE_SIZE + tac.AUTH_TAG_SIZE)) return error.FILE_READ_TOO_SMALL_FOR_ZENC_FILE; 

        // 2. extract magic num, salt, nonce, encrypted text and auth tag from file
        const retrieved_components: packaging.CIPHER_COMPONENTS = try packaging.packDecryptionDataToOutputBuf(raw_buf);
 
        // 3. generate crypto key using extracted salt
        var final_key: [tac.SHA256_BYTE_SIZE]u8 = undefined; // 256-bit
        try cipher.deriveKeyFromPass(password_v1, &retrieved_components.salt, &final_key);

        // 4. define bounds of ciphertext buf for decrypted data placement
        if (retrieved_components.s_opt_payload == null) return error.NULL_DECRYPTION_PAYLOAD;
        const dec_buf: []const u8 = output_buf[0..retrieved_components.s_opt_payload.?.len];

        // 5. decrypt file contents and verify auth tag
        s_opt_output_data = try cipher.decrypt(
            @constCast(dec_buf),
            @constCast(&retrieved_components),
            &final_key,
        );

        // 6. destory all cryptographic entries
        cipher.secureDestoryAllArgs( .{&password_v1, &final_key, &retrieved_components} );
    }

    // ensuring that data was written to the output location
    if (s_opt_output_data == null) return error.FAILED_TO_SAVE_CRYPTO_OPERATION_TO_OUTPUT_BUF;

    // TODO: file decrypted straight after encryption --> check auth tag and nonce work

    // TODO: split main function portions out into sub functions

    // TODO: testing, testing, testing for EVERYTHING
    
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
