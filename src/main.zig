const std = @import("std");

// IMPORT LOCAL PACKAGES //
const cipher: type = @import("cipher.zig");
const cli: type = @import("cli.zig");
const constants: type = @import("constants.zig");
const err: type = @import("err.zig");

/// DESCRIPTION
/// The entry point of the program
///
/// PARAMETERS
/// N/A
pub fn main() !void {
    // TODO: implement this
    
    // capture args from user
    
    // check args are valid --> -e or -d and not both -e and -d
    
    // check if help flag is in captured args
    
    // move args into zenc variables
 
    // check if file to enc or dec exists

    // get file directory from path
    
    // capture password from stdin (user input)
    
    // derive crypto key from password

    // read unchanged file contents into buffer
        
    // if encrypting 
        // reconfirm entered password

        // generate nonce and salt from password

        // use salt and none to encrypt the file

        // add auth tag to enc output (at start of file)

    // if decrypting
        // verify entered file starts with ZENC_MAGIC_NUMBER
    
        //  extract nonce and salt from file
    
        // use derived key, nonce and salt to decrypt file contents into second buffer

        // verify auth tag to confirm data is valid (at start of file)

    // generate output file name (extension changing)
    
    // save data to the new file

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
