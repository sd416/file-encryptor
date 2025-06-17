# Docker Usage Guide

This document explains how to use the File Encryptor Docker images published to GitHub Container Registry.

## Quick Start

### Pull the Latest Image

```bash
docker pull ghcr.io/sd416/file-encryptor:latest
```

### Basic Usage

#### Encrypt a File
```bash
# Using password encryption
docker run --rm -v $(pwd):/data ghcr.io/sd416/file-encryptor:latest -e -f myfile.txt -p "mypassword"

# Using RSA key encryption (generate keys first)
docker run --rm -v $(pwd):/data ghcr.io/sd416/file-encryptor:latest --generate-keys --key-name mykey
docker run --rm -v $(pwd):/data ghcr.io/sd416/file-encryptor:latest -e -f myfile.txt -k mykey_public_*.pub
```

#### Decrypt a File
```bash
# Using password decryption
docker run --rm -v $(pwd):/data ghcr.io/sd416/file-encryptor:latest -d -f myfile.txt.enc -p "mypassword"

# Using RSA key decryption
docker run --rm -v $(pwd):/data ghcr.io/sd416/file-encryptor:latest -d -f myfile.txt.enc -k mykey_private_*.key
```

## Available Images

### Tags
- `latest` - Latest stable release from main branch
- `main` - Latest build from main branch
- `v1.0.0` - Specific version releases
- `1.0` - Major.minor version
- `1` - Major version

### Platforms
- `linux/amd64` - Intel/AMD 64-bit
- `linux/arm64` - ARM 64-bit (Apple Silicon, ARM servers)

## Advanced Usage

### Generate RSA Key Pair
```bash
docker run --rm -v $(pwd):/data ghcr.io/sd416/file-encryptor:latest --generate-keys --key-name myproject
```

### Encrypt Multiple Files
```bash
docker run --rm -v $(pwd):/data ghcr.io/sd416/file-encryptor:latest -e -f file1.txt -f file2.pdf -f file3.doc -p "mypassword"
```

### Using Configuration File
```bash
# Create a config file
cat > file-encryptor.yaml << EOF
max_workers: 4
chunk_size: 65536
log_level: info
enable_progress_bar: true
EOF

# Use with Docker
docker run --rm -v $(pwd):/data ghcr.io/sd416/file-encryptor:latest -c file-encryptor.yaml -e -f myfile.txt -p "mypassword"
```

### Verbose Output
```bash
docker run --rm -v $(pwd):/data ghcr.io/sd416/file-encryptor:latest -v -e -f myfile.txt -p "mypassword"
```

## Docker Compose Example

Create a `docker-compose.yml` file:

```yaml
version: '3.8'

services:
  file-encryptor:
    image: ghcr.io/sd416/file-encryptor:latest
    volumes:
      - ./data:/data
      - ./config:/config
    command: ["-c", "/config/file-encryptor.yaml", "-e", "-f", "input.txt", "-p", "mypassword"]
```

Run with:
```bash
docker-compose run --rm file-encryptor
```

## Security Considerations

### Volume Mounting
- Always use specific directory mounts rather than mounting the entire filesystem
- The container runs as a non-root user (UID 1001) for security
- Files are processed in the `/data` directory inside the container

### Key Management
- Store private keys securely and never include them in Docker images
- Use environment variables or mounted secrets for passwords in production
- Consider using Docker secrets for sensitive data

### Example with Environment Variables
```bash
export ENCRYPTION_PASSWORD="your-secure-password"
docker run --rm -v $(pwd):/data -e ENCRYPTION_PASSWORD ghcr.io/sd416/file-encryptor:latest -e -f myfile.txt -p "$ENCRYPTION_PASSWORD"
```

## Troubleshooting

### Permission Issues
If you encounter permission issues:
```bash
# Fix ownership after operations
sudo chown -R $(id -u):$(id -g) .
```

### Check Container Version
```bash
docker run --rm ghcr.io/sd416/file-encryptor:latest --version
```

### Debug Mode
```bash
docker run --rm -v $(pwd):/data ghcr.io/sd416/file-encryptor:latest -v --show-config
```

## Building Custom Images

If you want to build your own image:

```bash
git clone https://github.com/sd416/file-encryptor.git
cd file-encryptor
docker build -t my-file-encryptor .
```

## Support

For issues and questions:
- GitHub Issues: https://github.com/sd416/file-encryptor/issues
- Documentation: https://github.com/sd416/file-encryptor/blob/main/README.md
