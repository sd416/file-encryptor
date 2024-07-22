package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"flag"
	"fmt"
	"golang.org/x/crypto/ssh"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func setupLogging() *os.File {
	logFile, err := os.OpenFile("encryption_log.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		log.Fatal(err)
	}
	log.SetOutput(logFile)
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	return logFile
}

func loadPublicKey(filename string) (*rsa.PublicKey, error) {
	log.Printf("Loading public key from file: %s", filename)
	keyData, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("error reading public key file: %v", err)
	}
	defer secureZeroMemory(keyData)

	// Try parsing as OpenSSH public key
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey(keyData)
	if err == nil {
		log.Println("Parsed OpenSSH public key successfully")
		cryptoPublicKey := pubKey.(ssh.CryptoPublicKey).CryptoPublicKey()
		rsaKey, ok := cryptoPublicKey.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("key is not an RSA public key")
		}
		return rsaKey, nil
	}

	// If OpenSSH parsing failed, try PEM format
	block, _ := pem.Decode(keyData)
	if block != nil {
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		rsaKey, ok := pub.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("key is not an RSA public key")
		}
		return rsaKey, nil
	}

	return nil, fmt.Errorf("failed to parse public key in any supported format")
}

func loadPrivateKey(filename string) (*rsa.PrivateKey, error) {
	log.Printf("Loading private key from file: %s", filename)
	keyData, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("error reading private key file: %v", err)
	}
	defer secureZeroMemory(keyData)

	// Parse the private key
	parsedKey, err := ssh.ParseRawPrivateKey(keyData)
	if err != nil {
		return nil, fmt.Errorf("error parsing private key: %v", err)
	}

	// Assert that it's an RSA key
	rsaKey, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not an RSA key")
	}

	return rsaKey, nil
}

func encryptFile(inputFile, outputFile string, publicKey *rsa.PublicKey) error {
	log.Printf("Starting encryption of file: %s", inputFile)
	startTime := time.Now()

	// Generate a random AES key
	aesKey := make([]byte, 32) // 256-bit key
	if _, err := rand.Read(aesKey); err != nil {
		return fmt.Errorf("error generating AES key: %v", err)
	}
	defer secureZeroMemory(aesKey)

	// Encrypt the AES key with RSA
	encryptedAESKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, aesKey, nil)
	if err != nil {
		return fmt.Errorf("error encrypting AES key: %v", err)
	}

	// Create the output file
	outFile, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("error creating output file: %v", err)
	}
	defer outFile.Close()

	// Write the length of the encrypted AES key, followed by the key itself
	if err := writeLength(outFile, len(encryptedAESKey)); err != nil {
		return fmt.Errorf("error writing AES key length: %v", err)
	}
	if _, err := outFile.Write(encryptedAESKey); err != nil {
		return fmt.Errorf("error writing encrypted AES key: %v", err)
	}

	// Create AES cipher
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return fmt.Errorf("error creating AES cipher: %v", err)
	}

	// Create a random IV
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return fmt.Errorf("error generating IV: %v", err)
	}

	// Write the IV to the output file
	if _, err := outFile.Write(iv); err != nil {
		return fmt.Errorf("error writing IV: %v", err)
	}

	// Create the AES CTR stream
	stream := cipher.NewCTR(block, iv)

	// Open the input file
	inFile, err := os.Open(inputFile)
	if err != nil {
		return fmt.Errorf("error opening input file: %v", err)
	}
	defer inFile.Close()

	// Create a buffer for encryption
	buf := make([]byte, 1024)
	for {
		n, err := inFile.Read(buf)
		if n > 0 {
			outBuf := make([]byte, n)
			stream.XORKeyStream(outBuf, buf[:n])
			if _, err := outFile.Write(outBuf); err != nil {
				return fmt.Errorf("error writing encrypted data: %v", err)
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("error reading input file: %v", err)
		}
	}

	duration := time.Since(startTime)
	log.Printf("Encryption completed. Output file: %s. Duration: %v", outputFile, duration)
	return nil
}

func decryptFile(inputFile, outputFile string, privateKey *rsa.PrivateKey) error {
	log.Printf("Starting decryption of file: %s", inputFile)
	startTime := time.Now()

	// Open the input file
	inFile, err := os.Open(inputFile)
	if err != nil {
		return fmt.Errorf("error opening input file: %v", err)
	}
	defer inFile.Close()

	// Read the length of the encrypted AES key
	encKeyLength, err := readLength(inFile)
	if err != nil {
		return fmt.Errorf("error reading AES key length: %v", err)
	}

	// Read the encrypted AES key
	encryptedAESKey := make([]byte, encKeyLength)
	if _, err := io.ReadFull(inFile, encryptedAESKey); err != nil {
		return fmt.Errorf("error reading encrypted AES key: %v", err)
	}

	// Decrypt the AES key
	aesKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, encryptedAESKey, nil)
	if err != nil {
		return fmt.Errorf("error decrypting AES key: %v", err)
	}
	defer secureZeroMemory(aesKey)

	// Create AES cipher
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return fmt.Errorf("error creating AES cipher: %v", err)
	}

	// Read the IV
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(inFile, iv); err != nil {
		return fmt.Errorf("error reading IV: %v", err)
	}

	// Create the AES CTR stream
	stream := cipher.NewCTR(block, iv)

	// Create the output file
	outFile, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("error creating output file: %v", err)
	}
	defer outFile.Close()

	// Create a buffer for decryption
	buf := make([]byte, 1024)
	for {
		n, err := inFile.Read(buf)
		if n > 0 {
			outBuf := make([]byte, n)
			stream.XORKeyStream(outBuf, buf[:n])
			if _, err := outFile.Write(outBuf); err != nil {
				return fmt.Errorf("error writing decrypted data: %v", err)
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("error reading encrypted data: %v", err)
		}
	}

	duration := time.Since(startTime)
	log.Printf("Decryption completed. Output file: %s. Duration: %v", outputFile, duration)
	return nil
}

func secureZeroMemory(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func writeLength(w io.Writer, length int) error {
	return binary.Write(w, binary.BigEndian, int32(length))
}

func readLength(r io.Reader) (int, error) {
	var length int32
	err := binary.Read(r, binary.BigEndian, &length)
	return int(length), err
}

func parseFlags() (bool, bool, string, string) {
	var encrypt, decrypt bool
	var file, key string

	flag.BoolVar(&encrypt, "e", false, "Encrypt the file")
	flag.BoolVar(&decrypt, "d", false, "Decrypt the file")
	flag.StringVar(&file, "file", "", "File to encrypt or decrypt")
	flag.StringVar(&key, "key", "", "Path to the key file (public key for encryption, private key for decryption)")
	flag.Parse()

	return encrypt, decrypt, file, key
}

func validateFlags(encrypt, decrypt bool, file, key string) error {
	if (encrypt && decrypt) || (!encrypt && !decrypt) {
		return fmt.Errorf("please specify either -e for encryption or -d for decryption")
	}

	if file == "" || key == "" {
		return fmt.Errorf("please provide both --file and --key arguments")
	}

	return nil
}

func handleEncryption(file, key string) error {
	publicKey, err := loadPublicKey(key)
	if err != nil {
		return fmt.Errorf("error loading public key: %v", err)
	}

	outputFile := file + ".enc"
	return encryptFile(file, outputFile, publicKey)
}

func handleDecryption(file, key string) error {
	privateKey, err := loadPrivateKey(key)
	if err != nil {
		return fmt.Errorf("error loading private key: %v", err)
	}
	defer secureZeroMemory(privateKey.D.Bytes())

	outputFile := strings.TrimSuffix(file, filepath.Ext(file))
	return decryptFile(file, outputFile, privateKey)
}

func main() {
	logFile := setupLogging()
	defer logFile.Close()

	log.Println("Starting file encryption/decryption program")

	encrypt, decrypt, file, key := parseFlags()

	if err := validateFlags(encrypt, decrypt, file, key); err != nil {
		log.Println(err)
		fmt.Println(err)
		os.Exit(1)
	}

	var err error
	if encrypt {
		log.Println("Encryption mode selected")
		err = handleEncryption(file, key)
	} else {
		log.Println("Decryption mode selected")
		err = handleDecryption(file, key)
	}

	if err != nil {
		log.Printf("Error: %v", err)
		fmt.Printf("Error: %v\n", err)
		if os.IsNotExist(err) {
			fmt.Println("Please check if the specified file and key exist and are readable.")
		}
		os.Exit(1)
	}

	log.Println("File encryption/decryption program completed")
}
