const std: type = @import("std");
const tac: type = @import("types_and_constants.zig");
const packaging: type = @import("packaging.zig");
const testing: type = std.testing;

//////////////////////////////////////////
// START - PUBLIC FUNCTION DECLARATIONS //
//////////////////////////////////////////

/// DESCRIPTION
/// Responsible for creating a crypto key from a user-entered password.
/// PARAMETERS
/// `password` - The string to use for key derivation
/// `p_salt` - Ptr to bytes that are attached to the encrypted file for scrambling the encrypted output
/// `p_final_key` - A ptr to a buffer for the final key to be moved into (if all goes well)
pub fn deriveKeyFromPass(password: []const u8, p_salt: *const [tac.ZENC_SALT_SIZE]u8, p_final_key: *[tac.SHA256_BYTE_SIZE]u8) !void {
    const ENCRYPTION_CONTEXT_STR: []const u8 = "ZENC_FILE_ENCRYPTION_KEY";

    // extract pseudo random key from password and salt
    const pass_salt_prk: [tac.SHA256_BYTE_SIZE]u8 = std.crypto.kdf.hkdf.HkdfSha256.extract(p_salt.*[0..], password);
    
    // expand prk into final encryption key
    std.crypto.kdf.hkdf.HkdfSha256.expand(
        p_final_key, 
        ENCRYPTION_CONTEXT_STR,
        pass_salt_prk,
    );
}

/// DESCRIPTION
/// Handles all encryption logic. Generates a nonce and adds an auth tag to ensure data integrity.
/// PARAMETERS
/// `p_key` - Generated from the password(s) + salt, the key is used to encrypt the file
/// `plaintext` - A buffer containing the text that we wish to encrypt
/// `ciphertext_buf` - A buffer that receives the encrypted text if successful
/// `p_cipher_obj` - A ptr to an obj that holds a nonce and auth tag buffer
pub fn encrypt(p_key: *[tac.SHA256_BYTE_SIZE]u8, plaintext: []const u8, ciphertext_buf: []u8, p_cipher_obj: *packaging.CIPHER_COMPONENTS) !void {

    // check that the output buffer is capable of receiving data
    if (ciphertext_buf.len < plaintext.len) return error.CIPHERTEXT_BUF_TOO_SMALL_FOR_ENC;

    // run std lib encryption method --> generates auth tag and ciphertext for writing to file w/ nonce
    std.crypto.aead.aes_gcm.Aes256Gcm.encrypt(
        ciphertext_buf, // c: output buffer for encrypted results
        &p_cipher_obj.b_auth_tag, // tag: auth tag
        plaintext, // m: plaintext buf input from file
        tac.CIPHER_ADDITIONAL_DATA, // ad: additional data
        p_cipher_obj.b_nonce, // npub: input nonce
        p_key.*, // key: input cipher key (from password)
    );
}


/// DESCRIPTION
/// Handles all decryption logic. Validates the file and verifies the auth tag. Returns a slice of the decrypted plaintext buf.
/// PARAMETERS
/// `plaintext_buf` - A buffer which the decrypted text will be placed in
/// `ciphertext` - A slice that holds the encrypted data for decrypting
/// `p_retrieved` - A struct that contains the cipher components for encryption and decryption
/// `p_key` - Generated from the password(s) + salt, the key is used to decrypt the file
pub fn decrypt(plaintext_buf: []u8, p_retrieved: *packaging.CIPHER_COMPONENTS, p_key: *[tac.SHA256_BYTE_SIZE]u8) ![]const u8 {

    if (p_retrieved.s_opt_payload == null) return error.NULL_DECRYPTION_PAYLOAD;
    
    // check that the output buffer is capable of receiving data
    if (plaintext_buf.len > p_retrieved.s_opt_payload.?.len) return error.PLAINTEXT_BUF_TOO_SMALL_FOR_ENC;

    // run std lib decrypt method --> takes in auth tag and ciphertext which was saved in file
    try std.crypto.aead.aes_gcm.Aes256Gcm.decrypt(
        plaintext_buf, // m: output buf for decrypted plaintext
        p_retrieved.s_opt_payload.?, // c: input buf (to decrypt)
        p_retrieved.b_auth_tag, // tag: input auth tag
        tac.CIPHER_ADDITIONAL_DATA, // ad: additional data
        p_retrieved.b_nonce, // npub: input nonce
        p_key.*, // key: input cipher key (from password)
    );

    return plaintext_buf[0..p_retrieved.s_opt_payload.?.len];
}

/// DESCRIPTION
/// Compile time, single line function for calling secureZero on all arguments. All arguments must be parsed as pointers.
/// PARAMETERS
/// `args` - Unknown num of ptr arguments that are treated as tuple (captured at comptime)
pub fn secureDestoryAllArgs(args: anytype) void {

    // inline forces compiler to unravel loop at comptime
    inline for (args) |p_argument| { 

        // get type of parsed argument
        const parsed_arg_type: type = @TypeOf(p_argument);
        const parsed_arg_type_info = @typeInfo(parsed_arg_type);

        // skipping raw slice parses
        if ( parsed_arg_type_info.pointer.size == .slice ) @compileError("ERROR: Raw slice parsed to secureDestoryAllArgs");

        // switch the way to zero based on its type
        switch (parsed_arg_type_info) {
            .pointer => {

                switch (@typeInfo(parsed_arg_type_info.pointer.child)) {

                    .array => {

                        if (p_argument.*.len == 0) continue; // pass zero sized arrays
                        const i_arr_start: usize = @intFromPtr(p_argument);
                        const p_arr_start: [*]volatile u8 = @ptrFromInt(i_arr_start);
                        const byte_size: usize = @sizeOf(@TypeOf(p_argument.*[0]));
                        std.crypto.secureZero(u8, p_arr_start[ 0..(p_argument.*.len*byte_size) ] );
                    },

                    .@"struct" => {
                        
                        // convert to byte slice
                        const ptr_as_int: usize = @intFromPtr(p_argument);
                        const byte_size: usize = @sizeOf(@TypeOf(p_argument.*));
                        const p_byte_start: [*]u8 = @ptrFromInt(ptr_as_int);
                        const byte_slice: []u8 = p_byte_start[0..byte_size];
                        std.crypto.secureZero(u8, @constCast(@ptrCast(byte_slice)));

                    },

                    else => {
                        
                        if (@typeInfo(@TypeOf(p_argument.*)).pointer.size == .slice) { // ptr to slice provided
                            
                            // avoiding compiler static memory ([]const u8's)
                            if (@typeInfo(@TypeOf(p_argument.*)).pointer.is_const == false) {

                                // pass zero sized arrays
                                if (p_argument.*.len != 0) {
                                    std.crypto.secureZero(u8, @ptrCast(@constCast(p_argument.*[0..p_argument.*.len])) );
                                }

                            } else @compileError("ERROR: parsed []const <type>. Cannot change underlying slice values.");

                        } else {
                            @compileError("ERROR: unsupported type provided to secureDestoryAllArgs");
                        }
                    },
                }
            }, 

            else => @compileError("ERROR: type not supported in secureDestroyAllArgs"),

        }
    }
}

//////////////////////////////////////////////
// --- END PUBLIC FUNCTION DECLARATIONS --- //
//////////////////////////////////////////////

///////////////////////////
// --- START TESTING --- //
///////////////////////////

// -- START derive, encrypt and decrypt -- //



// -- END derive, encrypt and decrypt -- //

// -- START secureDestroyAllArgs -- //

test "secureDestroyAllArgs - empty args" {

    secureDestoryAllArgs(.{});

}

test "secureDestroyAllArgs - args all arrays (1x args)" {

    
    var b_str1: [256]u8 = [_]u8{0xFF} ** 256;
    secureDestoryAllArgs(.{&b_str1});
    for (b_str1) |c| try testing.expect(c == 0x0); // check all values are zeroed

}

test "secureDestroyAllArgs - args all arrays (3x args)" {

    var b_str1: [256]u8 = undefined;
    var b_str2: [1024]u8 = [_]u8{0x12} ** 1024;
    var b_str3: [4096]u8 = [_]u8{0x34} ** 4096;
    secureDestoryAllArgs( .{ &b_str1, &b_str2, &b_str3 } );
    for (b_str1) |c| try testing.expect(c == 0x0); // check all values are zeroed
    for (b_str2) |c| try testing.expect(c == 0x0); // check all values are zeroed
    for (b_str3) |c| try testing.expect(c == 0x0); // check all values are zeroed

}

test "secureDestroyAllArgs - args all strings (1x args)" {
    
    const s_str1: []u8 = try testing.allocator.alloc(u8, 1024);
    defer testing.allocator.free(s_str1);
    @memset(s_str1, 'A');
    secureDestoryAllArgs( .{ &s_str1 } );
    for (s_str1) |c| try testing.expect(c == 0x0); // check all values are zeroed
    
}

test "secureDestroyAllArgs - args all strings (3x args)" {

    const s_str1: []u8 = try testing.allocator.alloc(u8, 256);
    defer testing.allocator.free(s_str1);
    @memset(s_str1, 'C');
    @memcpy(s_str1[0..21], "hey_what_is_your_name");
    const s_str2: []u8 = try testing.allocator.alloc(u8, 256);
    defer testing.allocator.free(s_str2);
    @memset(s_str2, 'F');
    const s_str3: []u8 = try testing.allocator.alloc(u8, 256);
    defer testing.allocator.free(s_str3);
    @memset(s_str3, 'D');
    secureDestoryAllArgs( .{ &s_str1, &s_str2, &s_str3 } );
    for (s_str1) |c| try testing.expect(c == 0x0); // check all values are zeroed
    for (s_str2) |c| try testing.expect(c == 0x0); // check all values are zeroed
    for (s_str3) |c| try testing.expect(c == 0x0); // check all values are zeroed

}

test "secureDestroyAllArgs - args all CIPHER_COMPONENTS (1x args)" {

    var cipher1: packaging.CIPHER_COMPONENTS  = .{};
    cipher1.magic_num = tac.ZENC_MAGIC_NUM;
    cipher1.b_salt = [_]u8{0x12} ** tac.ZENC_SALT_SIZE;
    cipher1.b_nonce = [_]u8{0x91} ** tac.NONCE_SIZE;
    cipher1.b_auth_tag = [_]u8{0xff} ** tac.AUTH_TAG_SIZE;
    const cipher1_size: usize = @sizeOf(@TypeOf(cipher1));

    secureDestoryAllArgs( .{ &cipher1 } );

    const p_cipher1: [*]u8 = @ptrCast(&cipher1);
    for (p_cipher1[0..cipher1_size]) |c| try testing.expect (c == 0x0);
}

test "secureDestroyAllArgs - args all CIPHER_COMPONENTS (3x args)" {
    
    var cipher1: packaging.CIPHER_COMPONENTS  = .{};
    cipher1.magic_num = tac.ZENC_MAGIC_NUM;
    cipher1.b_salt = [_]u8{0x12} ** tac.ZENC_SALT_SIZE;
    cipher1.b_nonce = [_]u8{0x91} ** tac.NONCE_SIZE;
    cipher1.b_auth_tag = [_]u8{0xff} ** tac.AUTH_TAG_SIZE;
    const cipher1_size: usize = @sizeOf(@TypeOf(cipher1));

    var cipher2: packaging.CIPHER_COMPONENTS  = .{};
    cipher2.magic_num = tac.ZENC_MAGIC_NUM;
    cipher2.b_salt = [_]u8{0x12} ** tac.ZENC_SALT_SIZE;
    cipher2.b_nonce = [_]u8{0x91} ** tac.NONCE_SIZE;
    cipher2.b_auth_tag = [_]u8{0xff} ** tac.AUTH_TAG_SIZE;
    const cipher2_size: usize = @sizeOf(@TypeOf(cipher2));

    var cipher3: packaging.CIPHER_COMPONENTS  = .{};
    cipher3.magic_num = tac.ZENC_MAGIC_NUM;
    cipher3.b_salt = [_]u8{0x12} ** tac.ZENC_SALT_SIZE;
    cipher3.b_nonce = [_]u8{0x91} ** tac.NONCE_SIZE;
    cipher3.b_auth_tag = [_]u8{0xff} ** tac.AUTH_TAG_SIZE;
    const cipher3_size: usize = @sizeOf(@TypeOf(cipher3));

    secureDestoryAllArgs( .{ &cipher1, &cipher2, &cipher3 } );

    const p_cipher1: [*]u8 = @ptrCast(&cipher1);
    for (p_cipher1[0..cipher1_size]) |c| try testing.expect (c == 0x0);
    const p_cipher2: [*]u8 = @ptrCast(&cipher2);
    for (p_cipher2[0..cipher2_size]) |c| try testing.expect (c == 0x0);
    const p_cipher3: [*]u8 = @ptrCast(&cipher3);
    for (p_cipher3[0..cipher3_size]) |c| try testing.expect (c == 0x0);
 
}

test "secureDestroyAllArgs - mix of strings, arrays and CIPHER_COMPONENTS (5x args)" {

    var b_str1: [256]u8 = [_]u8{0xFF} ** 256;

    const s_str2: []u8 = try testing.allocator.alloc(u8, 1024);
    defer testing.allocator.free(s_str2);
    @memset(s_str2, 'A');

    var b_str3: [256]u8 = [_]u8{0xFF} ** 256;

    const s_str4: []u8 = try testing.allocator.alloc(u8, 1024);
    defer testing.allocator.free(s_str4);
    @memset(s_str4, 'A');

    var cipher5: packaging.CIPHER_COMPONENTS  = .{};
    cipher5.magic_num = tac.ZENC_MAGIC_NUM;
    cipher5.b_salt = [_]u8{0x12} ** tac.ZENC_SALT_SIZE;
    cipher5.b_nonce = [_]u8{0x91} ** tac.NONCE_SIZE;
    cipher5.b_auth_tag = [_]u8{0xff} ** tac.AUTH_TAG_SIZE;
    const cipher5_size: usize = @sizeOf(@TypeOf(cipher5));
    const p_cipher5: [*]u8 = @ptrCast(&cipher5);

    secureDestoryAllArgs( .{ &b_str1, &s_str2, &b_str3, &s_str4, &cipher5 } );

    for (b_str1) |c| try testing.expect(c == 0x0); // check all values are zeroed
    for (s_str2) |c| try testing.expect(c == 0x0); // check all values are zeroed
    for (b_str3) |c| try testing.expect(c == 0x0); // check all values are zeroed
    for (s_str4) |c| try testing.expect(c == 0x0); // check all values are zeroed
    for (p_cipher5[0..cipher5_size]) |c| try testing.expect (c == 0x0);

}

// -- END secureDestroyAllArgs -- //

/////////////////////////
// --- END TESTING --- //
/////////////////////////



