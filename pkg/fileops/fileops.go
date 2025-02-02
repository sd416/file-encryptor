package fileops

import (
	"bufio"
	"crypto/rand"
	"encoding/binary"
	"file-encryptor/pkg/crypto"
	"file-encryptor/pkg/logging"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
    chunkSize = 64 * 1024 // 64KB chunks
    hashSize  = 64        // SHA-256 hash in hex format is 64 bytes
)

func EncryptFile(inputFile, outputFile string, encryptor crypto.Encryptor, logger *logging.Logger) error {
    logger.LogInfo(fmt.Sprintf("Starting encryption of file: %s", inputFile))
    startTime := time.Now()

    // Calculate original file hash
    originalHash, err := crypto.CalculateFileHash(inputFile)
    if err != nil {
        return fmt.Errorf("error calculating file hash: %v", err)
    }
    logger.LogDebug(fmt.Sprintf("Original file hash: %s", originalHash))

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

    // Write file hash
    if err := writeHash(bufWriter, originalHash); err != nil {
        return fmt.Errorf("error writing file hash: %v", err)
    }

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

    // Encrypt file content
    if err := processFileContent(bufio.NewReader(inFile), bufWriter, aesKey, logger); err != nil {
        return fmt.Errorf("error processing file content: %v", err)
    }

    logger.LogInfof("Encryption completed in %v", time.Since(startTime))
    return nil
}

func DecryptFile(inputFile, outputFile string, decryptor crypto.Decryptor, logger *logging.Logger) error {
    logger.LogInfo(fmt.Sprintf("Starting decryption of file: %s", inputFile))
    startTime := time.Now()

    inFile, err := os.Open(inputFile)
    if err != nil {
        return fmt.Errorf("error opening input file: %v", err)
    }
    defer inFile.Close()

    bufReader := bufio.NewReaderSize(inFile, chunkSize)

    // Read original file hash
    originalHash, err := readHash(bufReader)
    if err != nil {
        return fmt.Errorf("error reading file hash: %v", err)
    }
    logger.LogDebug(fmt.Sprintf("Expected file hash: %s", originalHash))

    // Read and restore file extension
    extension, err := readExtension(bufReader)
    if err != nil {
        return fmt.Errorf("error reading file extension: %v", err)
    }

    // Construct output filename with original extension
    outputFile = strings.TrimSuffix(outputFile, filepath.Ext(outputFile)) // Remove existing extension
    outputFile += extension

    outFile, err := os.Create(outputFile)
    if err != nil {
        return fmt.Errorf("error creating output file: %v", err)
    }
    defer outFile.Close()

    // Read encrypted AES key
    encryptedAESKey, err := readLengthAndData(bufReader)
    if err != nil {
        return fmt.Errorf("error reading encrypted AES key: %v", err)
    }

    // Decrypt AES key
    aesKey, err := decryptor.DecryptKey(encryptedAESKey)
    if err != nil {
        return fmt.Errorf("error decrypting AES key: %v", err)
    }

    // Decrypt file content
    bufWriter := bufio.NewWriter(outFile)
    if err := processFileContentForDecryption(bufReader, bufWriter, aesKey, logger); err != nil {
        return fmt.Errorf("error processing file content: %v", err)
    }
    // Ensure all data is written before validation
    if err := bufWriter.Flush(); err != nil {
        return fmt.Errorf("error flushing output buffer: %v", err)
    }

    // Validate the decrypted file's hash
    valid, err := crypto.ValidateFileHash(outputFile, originalHash)
    if err != nil {
        return fmt.Errorf("error validating file hash: %v", err)
    }
    if !valid {
        // If hash validation fails, delete the output file and return error
        os.Remove(outputFile)
        return fmt.Errorf("file integrity check failed: hash mismatch")
    }

    logger.LogInfo("File integrity verified successfully")
    logger.LogInfof("Decryption completed in %v", time.Since(startTime))
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

func writeHash(w *bufio.Writer, hash string) error {
    return writeLengthAndData(w, []byte(hash))
}

func readHash(r *bufio.Reader) (string, error) {
    hashBytes, err := readLengthAndData(r)
    if err != nil {
        return "", err
    }
    return string(hashBytes), nil
}

func processFileContent(r *bufio.Reader, w *bufio.Writer, key []byte, logger *logging.Logger) error {
    var processedData []byte
    buf := make([]byte, chunkSize)

    // Read all data first
    for {
        n, err := r.Read(buf)
        if n > 0 {
            processedData = append(processedData, buf[:n]...)
        }
        if err == io.EOF {
            break
        }
        if err != nil {
            return fmt.Errorf("read error: %v", err)
        }
    }

    // Encrypt the entire data at once
    encrypted, err := crypto.EncryptAES(processedData, key)
    if err != nil {
        return fmt.Errorf("error encrypting data: %v", err)
    }

    // Write the encrypted data
    if _, err := w.Write(encrypted); err != nil {
        return fmt.Errorf("write error: %v", err)
    }

    return w.Flush()
}

func processFileContentForDecryption(r *bufio.Reader, w *bufio.Writer, key []byte, logger *logging.Logger) error {
    var encryptedData []byte
    buf := make([]byte, chunkSize)

    // Read all encrypted data
    for {
        n, err := r.Read(buf)
        if n > 0 {
            encryptedData = append(encryptedData, buf[:n]...)
        }
        if err == io.EOF {
            break
        }
        if err != nil {
            return fmt.Errorf("read error: %v", err)
        }
    }

    // Decrypt the entire data at once
    decrypted, err := crypto.DecryptAES(encryptedData, key)
    if err != nil {
        return fmt.Errorf("error decrypting data: %v", err)
    }

    // Write the decrypted data
    if _, err := w.Write(decrypted); err != nil {
        return fmt.Errorf("write error: %v", err)
    }

    return w.Flush()
}
