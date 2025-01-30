package crypto

import (
    "crypto/sha256"
    "encoding/hex"
    "io"
    "os"
)

// CalculateFileHash generates SHA-256 hash of a file
func CalculateFileHash(filePath string) (string, error) {
    file, err := os.Open(filePath)
    if err != nil {
        return "", err
    }
    defer file.Close()

    hash := sha256.New()
    if _, err := io.Copy(hash, file); err != nil {
        return "", err
    }

    return hex.EncodeToString(hash.Sum(nil)), nil
}

// ValidateFileHash checks if the file matches the expected hash
func ValidateFileHash(filePath, expectedHash string) (bool, error) {
    actualHash, err := CalculateFileHash(filePath)
    if err != nil {
        return false, err
    }

    return actualHash == expectedHash, nil
}
