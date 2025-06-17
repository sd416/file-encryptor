# File Encryptor

File Encryptor is a powerful command-line tool written in Go that provides secure file encryption and decryption using either RSA key pairs or password-based encryption. It now features a **modern web UI** and supports **all file types**, including text files, media files (e.g., images, videos), and office documents (e.g., XLS, DOCX, PDF).

## 🌟 Features

### Core Encryption Features
- Encrypt files using RSA public keys or passwords
- Decrypt files using RSA private keys or passwords
- Hybrid encryption: RSA for key exchange, AES for file content
- Support for both PEM and OpenSSH format keys
- Automatically preserve and restore the original file extensions
- Support for **all file types**: text, images (JPG, PNG), videos, spreadsheets, and more
- **Concurrent processing** with worker pool for faster encryption and decryption of multiple files
- **Graceful cancellation** with timeout support and signal handling (Ctrl+C)

### 🌐 Web UI Features
- **Modern Web Interface** - User-friendly drag-and-drop interface
- **Real-time Progress** - Live status updates and progress tracking
- **Responsive Design** - Works on desktop, tablet, and mobile devices
- **Dark/Light Theme** - Toggle between themes with preference persistence
- **File Management** - Drag & drop multiple files for batch operations
- **Key Generation** - Generate RSA key pairs directly in the browser
- **Secure API** - RESTful API with CORS support and security headers
- **No Dependencies** - Single binary with embedded web assets

## 🚀 Installation

### Prerequisites
- Go 1.23 or later
- Git

### Build from Source
1. Clone this repository:
   ```bash
   git clone https://github.com/yourusername/file-encryptor.git
   cd file-encryptor
   ```

2. Build the CLI version:
   ```bash
   make build
   ```

3. Build with Web UI support:
   ```bash
   make build-web
   ```

## 📖 Usage

### 🌐 Web UI Mode

Start the web server:
```bash
# Start web UI on default port 8080
./bin/file-encryptor-web --web

# Start on custom port
./bin/file-encryptor-web --web --web-port 9000

# Start with HTTPS
./bin/file-encryptor-web --web --web-tls --cert-file cert.pem --key-file key.pem
```

Then open your browser to `http://localhost:8080` and enjoy the modern interface!

#### Web UI Features:
- 📁 **Drag & Drop**: Simply drag files onto the interface
- 🔒 **Encrypt/Decrypt**: Choose password or key file authentication
- 🔑 **Generate Keys**: Create RSA key pairs and download them
- 📊 **Progress Tracking**: Real-time status updates
- 🌙 **Theme Toggle**: Switch between dark and light modes
- 📱 **Mobile Friendly**: Responsive design for all devices

### 💻 Command Line Interface

#### Key Generation
```bash
# Generate RSA key pair
./bin/file-encryptor --generate-keys

# Generate keys with custom name
./bin/file-encryptor --generate-keys --key-name mykey

# Generate and encrypt in one step
./bin/file-encryptor --generate-keys -e -f document.pdf
```

#### Encryption

**Using RSA public key:**
```bash
./bin/file-encryptor -e --file picture.jpg --key my_ssh_key.pub
# Output: picture.jpg.enc
```

**Using password:**
```bash
./bin/file-encryptor -e --file document.pdf --password myStrongPassword123
# Output: document.pdf.enc
```

**Multiple files:**
```bash
./bin/file-encryptor -e --password myPassword123 --file file1.txt file2.jpg file3.pdf
```

#### Decryption

**Using RSA private key:**
```bash
./bin/file-encryptor -d --file picture.jpg.enc --key my_ssh_key
# Output: picture.jpg (original extension restored)
```

**Using password:**
```bash
./bin/file-encryptor -d --file document.pdf.enc --password myStrongPassword123
# Output: document.pdf
```

#### Advanced Options

**Set operation timeout:**
```bash
./bin/file-encryptor -e -f large_file.mp4 -p myPassword --timeout 10m
```

**Verbose logging:**
```bash
./bin/file-encryptor -e -f file.txt -p password --verbose
```

**Configuration file:**
```bash
./bin/file-encryptor -e -f file.txt -p password --config custom-config.yaml
```

## 🛠️ Development

### Build Targets
```bash
make build          # Build CLI version
make build-web      # Build with web UI
make test           # Run tests
make lint           # Run linters
make clean          # Clean build artifacts
make dev-setup      # Setup development environment
```

### Project Structure
```
file-encryptor/
├── cmd/file-encryptor/     # Main application
├── pkg/                    # Core packages
│   ├── crypto/            # Encryption logic
│   ├── logging/           # Logging utilities
│   └── webapi/            # Web API components
├── web/                   # Web UI assets
│   ├── templates/         # HTML templates
│   └── static/           # CSS, JS, images
├── Makefile              # Build automation
└── README.md            # This file
```

## 🔒 Security

### Encryption Standards
- **AES-256-GCM** for file encryption (authenticated encryption)
- **RSA-4096** for key exchange (configurable key size)
- **PBKDF2** with SHA-256 for password-based key derivation
- **HMAC-SHA-256** for integrity verification
- **Secure random** number generation for all cryptographic operations

### Web Security
- **CORS Protection** with configurable origins
- **Security Headers** (CSP, HSTS, X-Frame-Options)
- **File Size Limits** to prevent DoS attacks
- **Path Traversal Protection** for static file serving
- **HTTPS Support** with TLS 1.2+ enforcement

### Best Practices
- Always use strong, unique passwords (12+ characters)
- Keep private keys secure and never share them
- Use HTTPS in production environments
- Regularly update to the latest version
- Backup important files before encryption

## 🌍 Supported File Types

The tool supports **all file types**, including:
- **Text**: TXT, CSV, JSON, XML, YAML
- **Images**: JPG, PNG, GIF, BMP, TIFF, SVG
- **Videos**: MP4, AVI, MOV, MKV, WebM
- **Audio**: MP3, WAV, FLAC, AAC
- **Documents**: PDF, DOCX, XLSX, PPTX
- **Archives**: ZIP, TAR, 7Z, RAR
- **Code**: JS, Python, Go, Java, C++
- **Any other binary or text file**

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Guidelines
- Follow Go best practices and conventions
- Add tests for new functionality
- Update documentation as needed
- Ensure all tests pass before submitting

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This tool is provided as-is, without any warranties. Always ensure you have backups of your important files before encryption. Test the tool with non-critical files first to ensure it meets your requirements.

## 🆘 Support

- 📖 **Documentation**: Check this README and inline help (`--help`)
- 🐛 **Issues**: Report bugs via GitHub Issues
- 💡 **Feature Requests**: Submit enhancement ideas via GitHub Issues
- 🔒 **Security**: Report security issues privately via email

---

**Made with ❤️ in Go | Secure • Fast • User-Friendly**
