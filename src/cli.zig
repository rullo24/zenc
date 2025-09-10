const std = @import("std");

/// DESCRIPTION
/// Parses and validates cli args to determine the action to be performed on data.
///
/// PARAMETERS
/// TBD
// TODO: Add parameters to comment
pub fn parseArgs() !void {
    // TODO: implement this
}

/// DESCRIPTION
/// Displays the usage instructions and a list of available commands
///
/// PARAMETERS
/// TBD
// TODO: Add parameters to comment
pub fn printHelp(p_file_handle: std.fs.File) !void {
    _ = p_file_handle;
    // TODO: implement this
}

/// DESCRIPTION
/// Checks if a file exists and if the program has the correct permissions to perform its operations
///
/// PARAMETERS
/// TBD
// TODO: Add parameters to comment
pub fn validateFilePath() !void {
    // TODO: implement this
}

/// DESCRIPTION
/// Extract the filename from a file path
///
/// PARAMETERS
/// TBD
// TODO: Add parameters to comment
pub fn getInputFileName() ![]const u8 {
    // TODO: implement this
}

/// DESCRIPTION
/// Generates a new filename (including extension) for the output based on the operation performed
///
/// PARAMETERS
/// TBD
// TODO: Add parameters to comment
pub fn getOutputFileName() ![]const  u8 {
    // TODO: implement this
}

/// DESCRIPTION
/// Reads a password from the cli without echoing characters to the screen (toggle this option).
///
/// PARAMETERS
/// TBD
// TODO: Add parameters to comment
pub fn getPassword() !void {
    // TODO: implement this
}

/// DESCRIPTION
/// Prompts the user to re-enter the password to confirm it is typed correctly.
///
/// PARAMETERS
/// TBD
// TODO: Add parameters to comment
pub fn getPasswordConfirmation() !void {
    // TODO: implement this
}

/// DESCRIPTION
/// Clear the terminal history of the PC
///
/// PARAMETERS
/// TBD
// TODO: Add parameters to comment
pub fn cleanTerminalHistory() !void {
    // TODO: implement this
}
