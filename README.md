# File Encryptor

File Encryptor is a command-line tool written in Go that provides secure file encryption and decryption using either RSA key pairs or password-based encryption.

## Features

- Encrypt files using RSA public keys or passwords
- Decrypt files using RSA private keys or passwords
- Hybrid encryption: RSA for key exchange, AES for file content
- Support for both PEM and OpenSSH format keys
- Detailed logging for transparency and debugging

## Installation

1. Ensure you have Go installed on your system (version 1.16 or later).
2. Clone this repository:
   ```
   git clone https://github.com/yourusername/file-encryptor.git
   ```
3. Navigate to the project directory:
   ```
   cd file-encryptor
   ```
4. Build the project:
   ```
   go build -o file-encryptor
   ```

## Usage

### Encryption

To encrypt a file using an RSA public key:
```
./file-encryptor -e --file <input_file> --key <public_key_file>
```

To encrypt a file using a password:
```
./file-encryptor -e --file <input_file> --password <your_password>
```

### Decryption

To decrypt a file using an RSA private key:
```
./file-encryptor -d --file <encrypted_file> --key <private_key_file>
```

To decrypt a file using a password:
```
./file-encryptor -d --file <encrypted_file> --password <your_password>
```

## Security Notes

- Always use strong, unique passwords for password-based encryption.
- Keep your private keys secure and never share them.
- This tool uses AES-256 for file encryption and RSA for key exchange.
- Password-based encryption uses PBKDF2 for key derivation and HMAC for integrity verification.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is provided as-is, without any warranties. Always ensure you have backups of your important files before encryption.