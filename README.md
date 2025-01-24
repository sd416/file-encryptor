# File Encryptor

File Encryptor is a command-line tool written in Go that provides secure file encryption and decryption using either RSA key pairs or password-based encryption. It now supports **all file types**, including text files, media files (e.g., images, videos), and office documents (e.g., XLS, DOCX, PDF).

## Features

- Encrypt files using RSA public keys or passwords
- Decrypt files using RSA private keys or passwords
- Hybrid encryption: RSA for key exchange, AES for file content
- Support for both PEM and OpenSSH format keys
- Automatically preserve and restore the original file extensions
- Detailed logging for transparency and debugging
- Support for **all file types**: text, images (JPG, PNG), videos, spreadsheets, and more
- Parallel processing for faster encryption and decryption of large files

**File Support Note**: 
- The tool supports all file types, including:
  - **Text**: TXT, CSV, JSON
  - **Media**: JPG, PNG, MP4
  - **Documents**: DOCX, PDF, XLS
  - **Others**: Any other binary file format.

Example usage ensures seamless encryption and decryption without data corruption.

## Installation

1. Ensure you have Go installed on your system (version 1.16 or later).
   - Verify with:
     ```bash
     go version
     ```

2. Clone this repository:
   ```bash
   git clone https://github.com/yourusername/file-encryptor.git
   ```

3. Navigate to the project directory:
   ```bash
   cd file-encryptor
   ```

4. Build the project:
   ```bash
   go build -o file-encryptor main.go
   ```

## Usage

### Generate an RSA Key Pair
To generate an RSA key pair (private and public key) in your current folder:
```bash
ssh-keygen -t rsa -b 4096 -f my_ssh_key
```
- This creates `my_ssh_key` (private key) and `my_ssh_key.pub` (public key).

---

### Encryption

#### Encrypt a file using an RSA public key:
```bash
./file-encryptor -e --file <input_file> --key my_ssh_key.pub
```
Example:
```bash
./file-encryptor -e --file picture.jpg --key my_ssh_key.pub
```
- The encrypted file will be saved as `picture.jpg.enc`.

#### Encrypt a file using a password:
```bash
./file-encryptor -e --file <input_file> --password <your_password>
```
Example:
```bash
./file-encryptor -e --file document.pdf --password myStrongPassword123
```

---

### Decryption

#### Decrypt a file using an RSA private key:
```bash
./file-encryptor -d --file <encrypted_file> --key my_ssh_key
```
Example:
```bash
./file-encryptor -d --file picture.jpg.enc --key my_ssh_key
```
- The decrypted file will retain its original extension (e.g., `picture.jpg`).

#### Decrypt a file using a password:
```bash
./file-encryptor -d --file <encrypted_file> --password <your_password>
```
Example:
```bash
./file-encryptor -d --file document.pdf.enc --password myStrongPassword123
```

---

## Security Notes

- Always use strong, unique passwords for password-based encryption.
- Keep your private keys secure and never share them.
- This tool uses:
  - **AES-256** for file encryption (symmetric encryption).
  - **RSA** for secure key exchange (asymmetric encryption).
  - **PBKDF2** for key derivation in password-based encryption.
  - HMAC for integrity verification.
- File extensions are preserved automatically during encryption and restored after decryption.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is provided as-is, without any warranties. Always ensure you have backups of your important files before encryption.

---

