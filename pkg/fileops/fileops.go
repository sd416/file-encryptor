package fileops

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"file-encryptor/pkg/crypto"
	"file-encryptor/pkg/logging"
	"fmt"
	"io"
	"os"
	"time"
)

func EncryptFile(inputFile, outputFile string, encryptor crypto.Encryptor, logger *logging.Logger) error {
	logger.Log(fmt.Sprintf("Starting encryption of file: %s", inputFile))
	startTime := time.Now()

	// Read the input file
	plaintext, err := os.ReadFile(inputFile)
	if err != nil {
		return fmt.Errorf("error reading input file: %v", err)
	}
	logger.Log(fmt.Sprintf("Read %d bytes from input file", len(plaintext)))

	// Generate a random AES key
	aesKey := make([]byte, 32) // AES-256
	if _, err := rand.Read(aesKey); err != nil {
		return fmt.Errorf("error generating AES key: %v", err)
	}
	logger.Log("Generated AES key")

	// Encrypt the AES key
	encryptedAESKey, err := encryptor.EncryptKey(aesKey)
	if err != nil {
		return fmt.Errorf("error encrypting AES key: %v", err)
	}
	logger.Log(fmt.Sprintf("Encrypted AES key (length: %d bytes)", len(encryptedAESKey)))

	// Create and open the output file
	outFile, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("error creating output file: %v", err)
	}
	defer outFile.Close()

	// Write the length of the encrypted AES key
	if err := binary.Write(outFile, binary.BigEndian, uint32(len(encryptedAESKey))); err != nil {
		return fmt.Errorf("error writing key length: %v", err)
	}

	// Write the encrypted AES key
	if _, err := outFile.Write(encryptedAESKey); err != nil {
		return fmt.Errorf("error writing encrypted key: %v", err)
	}
	logger.Log("Wrote encrypted AES key to file")

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

	// Write the IV
	if _, err := outFile.Write(iv); err != nil {
		return fmt.Errorf("error writing IV: %v", err)
	}
	logger.Log("Wrote IV to file")

	// Create the AES CTR stream
	stream := cipher.NewCTR(block, iv)

	// Encrypt and write the data
	encryptedData := make([]byte, len(plaintext))
	stream.XORKeyStream(encryptedData, plaintext)
	if _, err := outFile.Write(encryptedData); err != nil {
		return fmt.Errorf("error writing encrypted data: %v", err)
	}
	logger.Log(fmt.Sprintf("Wrote %d bytes of encrypted data", len(encryptedData)))

	duration := time.Since(startTime)
	logger.Log(fmt.Sprintf("Encryption completed. Duration: %v", duration))
	return nil
}

func DecryptFile(inputFile, outputFile string, decryptor crypto.Decryptor, logger *logging.Logger) error {
	logger.Log(fmt.Sprintf("Starting decryption of file: %s", inputFile))
	startTime := time.Now()

	// Open the input file
	inFile, err := os.Open(inputFile)
	if err != nil {
		return fmt.Errorf("error opening input file: %v", err)
	}
	defer inFile.Close()

	// Read the length of the encrypted AES key
	var keyLength uint32
	if err := binary.Read(inFile, binary.BigEndian, &keyLength); err != nil {
		return fmt.Errorf("error reading key length: %v", err)
	}
	logger.Log(fmt.Sprintf("Read encrypted AES key length: %d bytes", keyLength))

	// Read the encrypted AES key
	encryptedAESKey := make([]byte, keyLength)
	if _, err := io.ReadFull(inFile, encryptedAESKey); err != nil {
		return fmt.Errorf("error reading encrypted key: %v", err)
	}
	logger.Log(fmt.Sprintf("Read encrypted AES key (%d bytes)", len(encryptedAESKey)))

	// Decrypt the AES key
	aesKey, err := decryptor.DecryptKey(encryptedAESKey)
	if err != nil {
		return fmt.Errorf("error decrypting AES key: %v", err)
	}
	if len(aesKey) != 32 {
		return fmt.Errorf("decrypted AES key has incorrect length: %d (expected 32)", len(aesKey))
	}
	logger.Log("Successfully decrypted AES key")

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
	logger.Log("Read IV from file")

	// Create the AES CTR stream
	stream := cipher.NewCTR(block, iv)

	// Read the encrypted data
	encryptedData, err := io.ReadAll(inFile)
	if err != nil {
		return fmt.Errorf("error reading encrypted data: %v", err)
	}
	logger.Log(fmt.Sprintf("Read %d bytes of encrypted data", len(encryptedData)))

	// Decrypt the data
	decryptedData := make([]byte, len(encryptedData))
	stream.XORKeyStream(decryptedData, encryptedData)

	// Write the decrypted data to the output file
	if err := os.WriteFile(outputFile, decryptedData, 0644); err != nil {
		return fmt.Errorf("error writing decrypted data: %v", err)
	}
	logger.Log(fmt.Sprintf("Wrote %d bytes of decrypted data", len(decryptedData)))

	duration := time.Since(startTime)
	logger.Log(fmt.Sprintf("Decryption completed. Duration: %v", duration))
	return nil
}