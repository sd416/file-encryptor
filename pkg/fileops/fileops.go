package fileops

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"file-encryptor/pkg/crypto"
	"file-encryptor/pkg/logging"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

const chunkSize = 64 * 1024 // 64KB chunks

func EncryptFile(inputFile, outputFile string, encryptor crypto.Encryptor, logger *logging.Logger) error {
	logger.Log(fmt.Sprintf("Starting encryption of file: %s", inputFile))
	startTime := time.Now()

	inFile, err := os.Open(inputFile)
	if err != nil {
		return fmt.Errorf("error opening input file: %v", err)
	}
	defer inFile.Close()

	outFile, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("error creating output file: %v", err)
	}
	defer outFile.Close()

	bufWriter := bufio.NewWriterSize(outFile, chunkSize)
	defer bufWriter.Flush()

	// Write file extension
	extension := filepath.Ext(inputFile)
	if err := writeExtension(bufWriter, extension); err != nil {
		return fmt.Errorf("error writing file extension: %v", err)
	}

	// Generate AES key
	aesKey := make([]byte, 32) // AES-256
	if _, err := io.ReadFull(rand.Reader, aesKey); err != nil {
		return fmt.Errorf("error generating AES key: %v", err)
	}

	// Encrypt AES key
	encryptedAESKey, err := encryptor.EncryptKey(aesKey)
	if err != nil {
		return fmt.Errorf("error encrypting AES key: %v", err)
	}

	// Write encrypted AES key length and key
	if err := writeLengthAndData(bufWriter, encryptedAESKey); err != nil {
		return err
	}

	// Initialize AES encryption
	block, _ := aes.NewCipher(aesKey)
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return fmt.Errorf("error generating IV: %v", err)
	}
	bufWriter.Write(iv)
	stream := cipher.NewCTR(block, iv)

	// Encrypt file content
	if err := processFileContent(bufio.NewReader(inFile), bufWriter, stream); err != nil {
		return err
	}

	logger.Log(fmt.Sprintf("Encryption completed in %v", time.Since(startTime)))
	return nil
}

func DecryptFile(inputFile, outputFile string, decryptor crypto.Decryptor, logger *logging.Logger) error {
	logger.Log(fmt.Sprintf("Starting decryption of file: %s", inputFile))
	startTime := time.Now()

	inFile, err := os.Open(inputFile)
	if err != nil {
		return fmt.Errorf("error opening input file: %v", err)
	}
	defer inFile.Close()

	bufReader := bufio.NewReaderSize(inFile, chunkSize)

	// Read and restore file extension
	extension, err := readExtension(bufReader)
	if err != nil {
		return err
	}
	outputFile += extension

	outFile, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("error creating output file: %v", err)
	}
	defer outFile.Close()

	// Read encrypted AES key
	encryptedAESKey, err := readLengthAndData(bufReader)
	if err != nil {
		return err
	}

	// Decrypt AES key
	aesKey, err := decryptor.DecryptKey(encryptedAESKey)
	if err != nil {
		return fmt.Errorf("error decrypting AES key: %v", err)
	}

	// Initialize AES decryption
	block, _ := aes.NewCipher(aesKey)
	iv := make([]byte, aes.BlockSize)
	bufReader.Read(iv)
	stream := cipher.NewCTR(block, iv)

	// Decrypt file content
	if err := processFileContent(bufReader, bufio.NewWriter(outFile), stream); err != nil {
		return err
	}

	logger.Log(fmt.Sprintf("Decryption completed in %v", time.Since(startTime)))
	return nil
}

func writeExtension(w *bufio.Writer, ext string) error {
	if err := binary.Write(w, binary.BigEndian, int32(len(ext))); err != nil {
		return err
	}
	_, err := w.WriteString(ext)
	return err
}

func readExtension(r *bufio.Reader) (string, error) {
	var length int32
	if err := binary.Read(r, binary.BigEndian, &length); err != nil {
		return "", err
	}
	ext := make([]byte, length)
	_, err := io.ReadFull(r, ext)
	return string(ext), err
}

func writeLengthAndData(w *bufio.Writer, data []byte) error {
	if err := binary.Write(w, binary.BigEndian, int32(len(data))); err != nil {
		return err
	}
	_, err := w.Write(data)
	return err
}

func readLengthAndData(r *bufio.Reader) ([]byte, error) {
	var length int32
	if err := binary.Read(r, binary.BigEndian, &length); err != nil {
		return nil, err
	}
	data := make([]byte, length)
	_, err := io.ReadFull(r, data)
	return data, err
}

func processFileContent(r *bufio.Reader, w *bufio.Writer, stream cipher.Stream) error {
	buf := make([]byte, chunkSize)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			encrypted := make([]byte, n)
			stream.XORKeyStream(encrypted, buf[:n])
			if _, err := w.Write(encrypted); err != nil {
				return err
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	}
	return nil
}
