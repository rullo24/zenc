const std: type = @import("std");
const builtin: type = @import("builtin");
const version_info: type = @import("build_version_info"); // provided by build.zig

// IMPORT LOCAL PACKAGES //
const cipher: type = @import("cipher.zig");
const cli: type = @import("cli.zig");
const tac: type = @import("types_and_constants.zig");
const packaging: type = @import("packaging.zig");
const saver: type = @import("saver.zig");

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

    // using io_stdout_writer for writing
    const f_stdout: std.fs.File = std.fs.File.stdout();
    defer f_stdout.close();
    var fs_stdout_writer: std.fs.File.Writer = f_stdout.writer(&.{});
    const io_stdout_writer: *std.Io.Writer = &fs_stdout_writer.interface; 

    // creating stdin reader and prompting user for password
    const f_stdin: std.fs.File = std.fs.File.stdin();
    defer f_stdin.close();

    // capture args from user --> move args into zenc variables
    var args_obj: tac.ARGUMENT_STRUCT = tac.ARGUMENT_STRUCT{}; // to store arguments in easy-to-read format
    const args: []const [:0]u8 = try std.process.argsAlloc(alloc); // capturing args from console
    defer std.process.argsFree(alloc, args); // free args at end of program
    try cli.parseArgs(&args_obj, args); // capture arguments into ARGUMENT_STRUCT for easier use
    if (args_obj.verbose_print) {
        _ = try io_stdout_writer.writeAll("\tSUCCESS: Parsed cli Arguments\n");
        try io_stdout_writer.flush();
    }

    // check if help flag is in captured args
    if (args_obj.has_help == true) {
        try cli.printHelp(io_stdout_writer);
        if (args_obj.verbose_print) {
            _ = try io_stdout_writer.writeAll("\targs_obj.has_help == true. Printed help menu\n");
            try io_stdout_writer.flush();
        } 
        return; // end program after printing help
    }

    // check if version flag is in captured args --> print version info
    if (args_obj.has_version == true) {
        
        var v_info: tac.VERSION_INFO = .{
            .app_version = version_info.APP_VERSION,
            .install_cpu = version_info.INSTALL_CPU,
            .install_optimise_mode = version_info.OPTIMISE_MODE,
            .install_os = version_info.INSTALL_OS,
            .zig_build_version = version_info.ZIG_VERSION,
        };

        try cli.printVersionInfo(io_stdout_writer, &v_info);
        if (args_obj.verbose_print) {
            _ = try io_stdout_writer.writeAll("\targs_obj.has_version == true. Printed version info\n");
            try io_stdout_writer.flush();
        } 
        return; // end program after printing version info

    }

    // check for sufficient arguments parsed by user to continue
    try cli.validateArgsObj(&args_obj);
    if (args_obj.verbose_print) {
        _ = try io_stdout_writer.writeAll("\tSUCCESS: Argument Validation\n");
        try io_stdout_writer.flush();
    } 

    // capture password from stdin (user input)
    var b_pass_v1: [tac.MAX_PASSWORD_SIZE_BYTES]u8 = std.mem.zeroes([tac.MAX_PASSWORD_SIZE_BYTES]u8);
    var pass1_stdin_reader: std.fs.File.Reader = f_stdin.reader(&b_pass_v1);
    const pass1_stdin_interface: *std.Io.Reader = &pass1_stdin_reader.interface;
    const s_password_v1: []const u8 = try cli.getPassword(io_stdout_writer, pass1_stdin_interface);
    if (args_obj.verbose_print) {
        _ = try io_stdout_writer.writeAll("\tSUCCESS: Password 1 Captured from User\n");
        try io_stdout_writer.flush();
    } 

    // capture file object from available item
    const p_in_file: std.fs.File = 
        if (args_obj.opt_enc_file_loc != null) try std.fs.cwd().openFile(args_obj.opt_enc_file_loc.?, .{.mode = .read_only})
        else if (args_obj.opt_dec_file_loc != null) try std.fs.cwd().openFile(args_obj.opt_dec_file_loc.?, .{.mode = .read_only})
        else return error.ENC_OR_DEC_FILE_DNE;
    defer p_in_file.close(); // free file descriptor memory
    if (args_obj.verbose_print) {
        _ = try io_stdout_writer.writeAll("\tSUCCESS: Opened parsed enc/dec file\n");
        try io_stdout_writer.flush();
    } 

    // read file contents into buffer (heaped)
    const file_size: u64 = try p_in_file.getEndPos();
    const s_raw_buf: []u8 = try alloc.alloc(u8, file_size); // heap buffer to store file bytes
    defer alloc.free(s_raw_buf); // free copied file bytes on program exit
    _ = try p_in_file.read(s_raw_buf); // reading unencrypted file data into raw buf
    if (args_obj.verbose_print) {
        _ = try io_stdout_writer.writeAll("\tSUCCESS: Read file stream into RAM buffer\n");
        try io_stdout_writer.flush();
    } 

    // building buf for output file text (NONCE + ciphertext + AUTH_TAG)
    const output_size: usize = (@sizeOf(@TypeOf(tac.ZENC_MAGIC_NUM)) + tac.ZENC_SALT_SIZE + tac.NONCE_SIZE + file_size + tac.AUTH_TAG_SIZE);
    const s_output_buf: []u8 = try alloc.alloc(u8, output_size);
    defer alloc.free(s_output_buf);
    var s_opt_output_data: ?[]const u8 = null; // holds slice from s_output_buf that contains the final data
    if (args_obj.verbose_print) {
        _ = try io_stdout_writer.writeAll("\tSUCCESS: Allocated ciphertext and output buffers\n");
        try io_stdout_writer.flush();
    } 

    // --- ENCRYPTION/DECRYPTION BRANCHING --- //

    // IF ENCRYPTION
    if (args_obj.opt_enc_file_loc != null) {

        // building buf for cipher text (encrypted)
        const s_ciphertext_buf: []u8 = try alloc.alloc(u8, file_size); // to be parsed to encrypt method for capturing contents
        defer alloc.free(s_ciphertext_buf);

        _ = try io_stdout_writer.write("\n=== ENCRYPTION MODE SET ===\n");
        try io_stdout_writer.flush();

        // 1. reconfirm entered password
        var b_pass_v2: [tac.MAX_PASSWORD_SIZE_BYTES]u8 = std.mem.zeroes([tac.MAX_PASSWORD_SIZE_BYTES]u8);
        _ = try io_stdout_writer.write("Again "); // text external from getPassword func for modularity (reuse from enc steps)
        try io_stdout_writer.flush();
        var pass2_stdin_reader: std.fs.File.Reader = f_stdin.reader(&b_pass_v2);
        const pass2_stdin_interface: *std.Io.Reader = &pass2_stdin_reader.interface;
        const s_password_v2: []const u8 = try cli.getPassword(io_stdout_writer, pass2_stdin_interface);
        if (args_obj.verbose_print) {
            _ = try io_stdout_writer.writeAll("\tSUCCESS: Password 2 captured from stdin\n");
            try io_stdout_writer.flush();
        } 
        
        // 2. compare s_password_v1 and s_password_v2 --> throw error if these don't match
        if (std.mem.eql(u8, s_password_v1, s_password_v2) != true) return error.PASSWORDS_DO_NOT_MATCH;

        // 3. create cipher components obj for holding salt, nonce, etc.
        var enc_cipher_obj: packaging.CIPHER_COMPONENTS = .{}; // holds nonce, salt and auth tag

        // 4. generating nonce to "jumble encryption"
        std.crypto.random.bytes(&enc_cipher_obj.b_nonce); // reading random bytes into the nonce buffer

        // 5. generate crypto key from password and salt
        var b_final_key: [tac.SHA256_BYTE_SIZE]u8 = undefined; // 256-bit
        std.crypto.random.bytes(&enc_cipher_obj.b_salt); // scramble entire salt buffer for maximised-randomness crypto algo
        try cipher.deriveKeyFromPass(s_password_v1, &enc_cipher_obj.b_salt, &b_final_key); // moving crypto key into `b_final_key`
        if (args_obj.verbose_print) {
            _ = try io_stdout_writer.writeAll("\tSUCCESS: Key derived from provided password\n");
            try io_stdout_writer.flush();
        } 

        // 6. encrypt raw contents into ciphertext buffer
        try cipher.encrypt(&b_final_key, s_raw_buf, s_ciphertext_buf, &enc_cipher_obj);
        if (args_obj.verbose_print) {
            _ = try io_stdout_writer.writeAll("\tSUCCESS: Cipher text encrypted\n");
            try io_stdout_writer.flush();
        } 

        // 7. write magic num, then salt, then nonce, then ciphertext, then auth tag to ciphertext buffer
        s_opt_output_data = packaging.packEncryptionDataToOutputBuf(s_output_buf, s_ciphertext_buf, &enc_cipher_obj);
        if (args_obj.verbose_print) {
            _ = try io_stdout_writer.writeAll("\tSUCCESS: Encryption data packed into output buffer for external flush\n");
            try io_stdout_writer.flush();
        } 

        // -- START SELF TEST ENCRYPTED DATA -- //

        if (args_obj.should_check_enc_data == true) {
            const s_test_dec_buf: []u8 = try alloc.alloc(u8, file_size);
            defer alloc.free(s_test_dec_buf);

            // create component for immediate decryption test
            if (s_opt_output_data == null) return error.NO_OUTPUT_ENC_DATA;
            var test_dec_components: packaging.CIPHER_COMPONENTS = try packaging.unpackDecryptionDataFromOutputBuf(s_opt_output_data.?);
            
            // decrypt data that was just encrypted
            const s_test_dec_data: []const u8 = try cipher.decrypt(
                s_test_dec_buf, // buffer to write the plaintext into
                &test_dec_components,
                &b_final_key,
            );

            // 8. Compare the decrypted data against the original raw file data.
            if (!std.mem.eql(u8, s_raw_buf, s_test_dec_data)) return error.ENCRYPTION_SELF_TEST_FAILED; // if this check fails, the encryption/decryption round-trip is broken.
            if (args_obj.verbose_print) {
                _ = try io_stdout_writer.writeAll("\tSUCCESS: Self test on encrypted data PASSING\n");
                try io_stdout_writer.flush();
            } 
        }
        // -- END SELF TEST ENCRYPTED DATA -- //

        // 9. destroying all crypto entries
        cipher.secureDestoryAllArgs( .{&b_pass_v1[0..s_password_v1.len], &b_pass_v2[0..s_password_v2.len], &b_final_key, &enc_cipher_obj, &s_ciphertext_buf,} );
        if (args_obj.verbose_print) {
            _ = try io_stdout_writer.writeAll("\tSUCCESS: Securely destoryed all encryption arguments\n");
            try io_stdout_writer.flush();
        } 

        _ = try io_stdout_writer.write("\n=== ENCRYPTION COMPLETED SUCCESSFULLY ===\n");
        try io_stdout_writer.flush();

    // IF DECRYPTION
    } else if (args_obj.opt_dec_file_loc != null) { 

        _ = try io_stdout_writer.write("\n=== DECRYPTION MODE SET ===\n");
        try io_stdout_writer.flush();

        // 1. basic file check to see if file can hold all non-ciphertext info
        if (file_size < (@sizeOf(@TypeOf(tac.ZENC_MAGIC_NUM)) + tac.ZENC_SALT_SIZE + tac.NONCE_SIZE + tac.AUTH_TAG_SIZE)) return error.FILE_READ_TOO_SMALL_FOR_ZENC_FILE; 

        // 2. extract magic num, salt, nonce, encrypted text and auth tag from file
        const retrieved_components: packaging.CIPHER_COMPONENTS = try packaging.unpackDecryptionDataFromOutputBuf(s_raw_buf);
 
        // 3. generate crypto key using extracted salt
        var b_final_key: [tac.SHA256_BYTE_SIZE]u8 = undefined; // 256-bit
        try cipher.deriveKeyFromPass(s_password_v1, &retrieved_components.b_salt, &b_final_key);
        if (args_obj.verbose_print) {
            _ = try io_stdout_writer.writeAll("\tSUCCESS: Key derived from user-provided password\n");
            try io_stdout_writer.flush();
        }

        // 4. define bounds of ciphertext buf for decrypted data placement
        if (retrieved_components.s_opt_payload == null) return error.NULL_DECRYPTION_PAYLOAD;
        const dec_buf: []const u8 = s_output_buf[0..retrieved_components.s_opt_payload.?.len];

        // 5. decrypt file contents and verify auth tag
        s_opt_output_data = try cipher.decrypt(
            @constCast(dec_buf),
            @constCast(&retrieved_components),
            &b_final_key,
        );
        if (args_obj.verbose_print) {
            _ = try io_stdout_writer.writeAll("\tSUCCESS: Decrypted file data saved into output buffer\n");
            try io_stdout_writer.flush();
        } 

        // 6. destory all cryptographic entries
        cipher.secureDestoryAllArgs( .{&b_pass_v1[0..s_password_v1.len], &b_final_key, &retrieved_components} );
        if (args_obj.verbose_print) {
            _ = try io_stdout_writer.writeAll("\tSUCCESS: Securely destoryed all decryption arguments\n");
            try io_stdout_writer.flush();
        } 

        _ = try io_stdout_writer.write("\n=== DECRYPTION COMPLETED SUCCESSFULLY ===\n");
        try io_stdout_writer.flush();
    }

    // ensuring that data was written to the output location
    if (s_opt_output_data == null) return error.FAILED_TO_SAVE_CRYPTO_OPERATION_TO_s_output_buf;

    // save cipher processed data to file
    try saver.saveOutput(alloc, &args_obj, s_opt_output_data, io_stdout_writer);

    // ensure all CONFIDENTIAL buffers are destroyed
    cipher.secureDestoryAllArgs(.{&s_output_buf, &s_raw_buf}); 

}

