const std = @import("std");
const tac = @import("types_and_constants.zig");

/// STRUCT DECLARATIONS ///

pub const CIPHER_COMPONENTS = struct {
    salt: [tac.ZENC_SALT_SIZE]u8 = undefined,
    nonce: [tac.NONCE_SIZE]u8 = undefined,
    auth_tag: [tac.AUTH_TAG_SIZE]u8 = undefined,
    s_opt_payload: ?[]const u8 = null,
};

/// PUBLIC FUNCTION DECLARATIONS ///

// TODO: write function header
pub fn packEncryptionDataToOutputBuf(s_output_buf: []u8, s_ciphertext_buf: []const u8, p_salt: *const [tac.ZENC_SALT_SIZE]u8, p_nonce: *const [tac.NONCE_SIZE]u8, p_auth_tag: *const [tac.AUTH_TAG_SIZE]u8) []const u8 {
    var offset: usize = 0;
    
    // 1. magic num
    const magic_num_slice_to_write: []const u8 = s_output_buf[offset..offset + @sizeOf(@TypeOf(tac.ZENC_MAGIC_NUM))];
    const p_eight_byte_aligned_magic_num: *[8]u8 = @constCast(@ptrCast(@alignCast(magic_num_slice_to_write)));
    std.mem.writeInt(u64, p_eight_byte_aligned_magic_num, tac.ZENC_MAGIC_NUM, tac.ZENC_ENDIAN_TYPE); // writing magic num
    offset += @sizeOf(@TypeOf(tac.ZENC_MAGIC_NUM));

    // 2. salt
    @memcpy(s_output_buf[offset..offset+tac.ZENC_SALT_SIZE], p_salt); // write salt
    offset += tac.ZENC_SALT_SIZE;

    // 3. nonce
    @memcpy(s_output_buf[offset..offset+tac.NONCE_SIZE], p_nonce); // write nonce
    offset += tac.NONCE_SIZE;

    // 4. ciphertext
    @memcpy(s_output_buf[offset..offset+s_ciphertext_buf.len], s_ciphertext_buf); // write ciphertext
    offset += s_ciphertext_buf.len;

    // 5. auth tag
    @memcpy(s_output_buf[offset..offset+tac.AUTH_TAG_SIZE], p_auth_tag); // write auth tag
    offset += tac.AUTH_TAG_SIZE;

    return s_output_buf[0..offset];
}

// TODO: write function header
pub fn packDecryptionDataToOutputBuf(s_raw_buf: []const u8) !CIPHER_COMPONENTS {
    var retrieved_components: CIPHER_COMPONENTS = .{};
    var offset: usize = @sizeOf(@TypeOf(tac.ZENC_MAGIC_NUM)); // skip magic num

    // store salt from file

    // TODO: convert to [16]u8 type for storage
    
    const retrieved_salt: []const u8  = s_raw_buf[offset..offset+tac.ZENC_SALT_SIZE];
    if (retrieved_salt.len != retrieved_components.salt.len) return error.RETRIEVED_SALT_WONT_FIT_IN_COMP_BUF;
    @memcpy(&retrieved_components.salt, retrieved_salt);
    offset += tac.ZENC_SALT_SIZE;

    // store nonce from file
    const retrieved_nonce: []const u8 = s_raw_buf[offset..offset+tac.NONCE_SIZE];
    if (retrieved_nonce.len != retrieved_components.nonce.len) return error.RETRIEVED_NONCE_WONT_FIT_IN_COMP_BUF;
    @memcpy(&retrieved_components.nonce, retrieved_nonce);
    offset += tac.NONCE_SIZE;

    // store encrypted data from file
    const retrieved_payload: []const u8 = s_raw_buf[offset..offset+(s_raw_buf.len-tac.AUTH_TAG_SIZE+1)];
    retrieved_components.s_opt_payload = retrieved_payload;
    offset += (s_raw_buf.len - tac.AUTH_TAG_SIZE) + 1;

    // store auth_tag from file
    const retrieved_auth_tag: []const u8 = s_raw_buf[offset..offset+tac.AUTH_TAG_SIZE];
    @memcpy(&retrieved_components.auth_tag, retrieved_auth_tag);
    offset += tac.AUTH_TAG_SIZE;

    return retrieved_components;
}





