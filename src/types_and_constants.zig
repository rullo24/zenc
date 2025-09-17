const std = @import("std");
const builtin = @import("builtin");

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