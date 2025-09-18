const std: type = @import("std");
const builtin: type = @import("builtin");

// STRUCT DEFINITIONS //
pub const ARGUMENT_STRUCT: type = struct {
    has_help: bool = false,
    opt_enc_file_loc: ?[]const u8 = null, // init as empty
    enc_buf: [MAX_PATH_SIZE]u8 = undefined,
    opt_dec_file_loc: ?[]const u8 = null, // init as empty
    dec_buf: [MAX_PATH_SIZE]u8 = undefined,
};

// CONSTANT DEFINITIONS //
const MAX_PATH_SIZE: comptime_int = if (builtin.os.tag == .windows) std.os.windows.MAX_PATH else std.posix.PATH_MAX;
pub const MIN_OTHER_FLAG_AVAILABLE_LEN: comptime_int = 3; // "-e=" or "-d=" before string
pub const ARGUMENT_BEHAVIOUR_LETTER_INDEX: comptime_int = 1; // 'e' - encryption or 'd' - decryption

pub const MAX_PASSWORD_SIZE_BYTES: comptime_int = 256;
pub const ZENC_SALT: []const u8 = "THE_ZENC_SALT";
pub const PASS_CRYPTO_KEY_LENGTH: comptime_int = 32; // 256-bit for
pub const SHA256_BYTE_SIZE: comptime_int = 32; // 32-bytes == 256-bit
pub const NONCE_SIZE: comptime_int = 12; // size used by AES-GCM
pub const AES_GCM_TAG_SIZE: comptime_int = 16;