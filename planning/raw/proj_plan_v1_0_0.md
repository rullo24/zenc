# Project Plan - Available Commands

- `-h` OR `--help` - Prints help menu (overrides all other functionality via argument parsing)
- `-e=<file_to_encrypt>` - Defines the file to encrypt (must work for relative pathing)
- `-d=<file_to_decrypt>` - Defines the file to decrypt (must work for relative pathing)
- `-p=<password>` - Captures the password for encryption/decryption from the user

# Project Plan - File Descriptions

## main.zig

[DESCRIPTION] - This is the entry point of the program.

- Initialises the allocator

### Functions

- `main` - Orchestrates the entire program flow, from parsing arguments and getting password input to performing the encryption/decryption and handling errors.
- `clean_up` - A security function that securely overwrites sensitive data in memory i.e. passwords.

## cipher.zig

[DESCRIPTION] - Contains the core crypto functions for encryption and decryption.

### Functions

- `encrypt` - Handles all encryption logic. Generates a nonce and adds authentication tag to ensure data integrity.
- `decrypt` - Handles all decryption logic. Validates the file and verifies the authentication tag.

## cli.zig

[DESCRIPTION] - Manages all command-line logic. This includes argument parsing, file path validation and writing help messages to stdout.

### Functions

- `parseArgs` - Parses and validates cli arguments to determine the action to be performed on data.
- `printHelp` - Displays the usage instructions and a list of available commands.
- `validateFilePath` - Checks if a file exists and if the program has the correct permissions to perform its operations.
- `getInputFileName` - Extract the filename from a file path.
- `getOutputFileName` - Generates a new filename (including extension) for the output based on the operation performed.
- `getPassword` - Reads a password from the cli without echoing characters to the screen (toggle this option).
- `getPasswordConfirmation` - Prompts the user to re-enter a password to confirm it was typed correctly.
- `cleanTerminalHistory` - Clears the terminal history of the PC (optional).

## constants.zig

[DESCRIPTION] - Stores all application-wide constants and configurations. This way constants can be easily modified without changing core logic.

### Functions

N/A

## err.zig

[DESCRIPTION] - A centralised module for defining all app-specific errors.

### Functions

N/A
