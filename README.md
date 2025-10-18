# Zenc - Zig Secure File Encryption

This project encrypts files to ensure both their privacy and integrity. The process follows a series of best practices to achieve strong security.

## Security and Algorithms
For a security-focused tool, transparency regarding the cryptographic methods is critical for trust and verification.

Zenc follows current cryptographic best practices:

Feature | Details |
| :--- | :--- |
| **Algorithm** | **AES-256** in **Galois/Counter Mode (GCM)**, providing both confidentiality (secrecy) and authenticated encryption. |
| **Integrity** | Ensured by the **GCM Message Authentication Code (GCM-MAC)**, which verifies the integrity and authenticity of the ciphertext to detect any unauthorized modifications or corruption. |
| **Key Derivation** | The symmetric key is derived from a user-supplied passphrase using a robust Key Derivation Function (KDF) to protect against brute-force attacks. The tool will prompt for the passphrase via standard input. |
| **File Naming** | **Encryption** adds the `.ezenc` extension. **Decryption** replaces the `.ezenc` extension (if available) w/ `.dzenc`. |

## Usage
NOTE: Zenc always captures paths relative from the cwd (unless an absolute path is provided).

Encrypting or Decrypting a file creates a file in the same directory as captured from but w/ ezenc (encryption) or dzenc (decryption) concatenated to the end.

### CLI Options

- -h OR --help -> Prints this help menu
- -e=<file_to_encrypt> -> Encrypt file
- -d=<file_to_decrypt> -> Decrypt file
- --dont_check_enc -> Stop immediate encrypted file decryption check (increase speed).
- -v OR --verbose -> Prints extra stdout information

#### Examples

##### 1. Encrypt secret.txt

```bash
.\zenc -e=secret.txt
```

Creates secret.txt.ezenc

##### 2. Decrypt the file

```bash
.\zenc -d=secret.txt.ezenc
```

Creates secret.txt.dzenc

##### 3. Encrypt (Verbose)

```bash
.\zenc -e=secret.txt -v
```

Encrypts and prints details about the process to stdout.

## Building the Project

### Installation

To build the optimised release executable:
```bash
zig build -Doptimize=ReleaseSafe
```

The executable is built to the default location:
```bash
zenc/zig-out/bin/zenc
```

### Zig Version
0.15.1

### Debugging
To launch the executable and run an encryption command within the LLDB debugger:

```bash
lldb .\zig-out\bin\zenc.exe -- -e="./test/file1.txt"
```
