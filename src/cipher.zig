const std: type = @import("std");
const tac: type = @import("types_and_constants.zig");
const packaging: type = @import("packaging.zig");

// PUBLIC FUNCTIONS //

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
/// `p_nonce` - Random bytes to scramble the encryption data.
/// `p_key` - Generated from the password(s) + salt, the key is used to encrypt the file
/// `plaintext` - A buffer containing the text that we wish to encrypt
/// `ciphertext_buf` - A buffer that receives the encrypted text if successful
/// `p_tag` - A ptr to a buffer that will be filled with the output auth tag (for validating decryption)
pub fn encrypt(p_nonce: *[tac.NONCE_SIZE]u8, p_key: *[tac.SHA256_BYTE_SIZE]u8, plaintext: []const u8, ciphertext_buf: []u8, p_tag: *[tac.AUTH_TAG_SIZE]u8) !void {

    // check that the output buffer is capable of receiving data
    if (ciphertext_buf.len <= plaintext.len) return error.CIPHERTEXT_BUF_TOO_SMALL_FOR_ENC;

    // run std lib encryption method --> generates auth tag and ciphertext for writing to file w/ nonce
    std.crypto.aead.aes_gcm.Aes256Gcm.encrypt(
        ciphertext_buf, // c: output buffer for encrypted results
        p_tag, // tag: auth tag
        plaintext, // m: plaintext buf input from file
        tac.CIPHER_ADDITIONAL_DATA, // ad: additional data
        p_nonce.*, // npub: input nonce
        p_key.*, // key: input cipher key (from password)
    );
}


/// DESCRIPTION
/// Handles all decryption logic. Validates the file and verifies the auth tag.
/// PARAMETERS
/// `plaintext_buf` - A buffer which the decrypted text will be placed in
/// `ciphertext` - A slice that holds the encrypted data for decrypting
/// `p_retrieved` - A struct that contains the cipher components for encryption and decryption
/// `p_key` - Generated from the password(s) + salt, the key is used to decrypt the file
pub fn decrypt(plaintext_buf: []u8, p_retrieved: *packaging.CIPHER_COMPONENTS, p_key: *[tac.SHA256_BYTE_SIZE]u8) !void {

    if (p_retrieved.s_opt_payload == null) return error.NULL_DECRYPTION_PAYLOAD;
    
    // check that the output buffer is capable of receiving data
    if (plaintext_buf.len >= p_retrieved.s_opt_payload.?.len) return error.PLAINTEXT_BUF_TOO_SMALL_FOR_ENC;

    // run std lib decrypt method --> takes in auth tag and ciphertext which was saved in file
    try std.crypto.aead.aes_gcm.Aes256Gcm.decrypt(
        plaintext_buf, // m: output buf for decrypted plaintext
        p_retrieved.s_opt_payload.?, // c: input buf (to decrypt)
        p_retrieved.auth_tag, // tag: input auth tag
        tac.CIPHER_ADDITIONAL_DATA, // ad: additional data
        p_retrieved.nonce, // npub: input nonce
        p_key.*, // key: input cipher key (from password)
    );
}

// PRIVATE FUNCTIONS //
