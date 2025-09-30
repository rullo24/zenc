const std: type = @import("std");
const tac: type = @import("types_and_constants.zig");

// PUBLIC FUNCTIONS //

/// DESCRIPTION
/// Responsible for creating a crypto key from a user-entered password.
/// PARAMETERS
/// TBD
// TODO: Add parameters to comment
pub fn deriveKeyFromPass(password: []const u8, salt: *const [tac.ZENC_SALT_SIZE]u8, p_final_key: *[tac.SHA256_BYTE_SIZE]u8) !void {
    const ENCRYPTION_CONTEXT_STR: []const u8 = "ZENC_FILE_ENCRYPTION_KEY";

    // extract pseudo random key from password and salt
    const pass_salt_prk: [tac.SHA256_BYTE_SIZE]u8 = std.crypto.kdf.hkdf.HkdfSha256.extract(salt.*[0..], password);
    
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
/// TBD
// TODO: Add parameters to comment
pub fn encrypt(p_nonce: *[tac.NONCE_SIZE]u8, p_key: *[tac.SHA256_BYTE_SIZE]u8, plaintext: []const u8, ciphertext_buf: []u8, p_tag: *[tac.AUTH_TAG_SIZE]u8) !void {

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
/// TBD
// TODO: Add parameters to comment
pub fn decrypt(p_nonce: *[tac.NONCE_SIZE]u8, p_key: *[tac.SHA256_BYTE_SIZE]u8, plaintext_buf: []u8, ciphertext: []u8, p_tag: *[tac.AUTH_TAG_SIZE]u8) !void {

    // run std lib decrypt method --> takes in auth tag and ciphertext which was saved in file
    try std.crypto.aead.aes_gcm.Aes256Gcm.decrypt(
        plaintext_buf, // m: output buf for decrypted plaintext
        ciphertext, // c: input buf (to decrypt)
        p_tag.*, // tag: input auth tag
        tac.CIPHER_ADDITIONAL_DATA, // ad: additional data
        p_nonce.*, // npub: input nonce
        p_key.*, // key: input cipher key (from password)
    );
}

// PRIVATE FUNCTIONS //