package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"file-encryptor/pkg/crypto"
	"file-encryptor/pkg/fileops"
	"file-encryptor/pkg/logging"
)

func main() {
	logger := logging.NewLogger()
	logger.LogDebug("Starting file encryptor")

	// Define custom flag set to allow multiple arguments after flags
	fs := flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	encrypt := fs.Bool("e", false, "Encrypt the files")
	decrypt := fs.Bool("d", false, "Decrypt the files")
	key := fs.String("k", "", "Path to the key file")
	password := fs.String("p", "", "Password for encryption/decryption")
	generateKeys := fs.Bool("generate-keys", false, "Generate a new RSA key pair")
	keyBaseName := fs.String("key-name", "key", "Base name for the generated key files")

	// Parse flags
	if err := fs.Parse(os.Args[1:]); err != nil {
		logger.LogError(fmt.Sprintf("Error parsing flags: %v", err))
		os.Exit(1)
	}

	if *generateKeys {
		if err := handleGenerateKeys(*keyBaseName, logger); err != nil {
			logger.LogError(err.Error())
			os.Exit(1)
		}
		logger.LogInfo("RSA Key pair generated successfully.")
		os.Exit(0)
	}

	// Get remaining arguments (files)
	args := fs.Args()
	if len(args) == 0 {
		logger.LogError("No files specified")
		fs.Usage()
		os.Exit(1)
	}

	// Validate other flags
	if err := validateFlags(*encrypt, *decrypt, *key, *password); err != nil {
		logger.LogError(err.Error())
		fs.Usage()
		os.Exit(1)
	}

	// Process file patterns and collect all matching files
	var filePaths []string
	for _, pattern := range args {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			logger.LogError(fmt.Sprintf("Invalid file pattern '%s': %v", pattern, err))
			continue
		}
		if len(matches) == 0 {
			logger.LogError(fmt.Sprintf("No files match pattern: %s", pattern))
			continue
		}
		filePaths = append(filePaths, matches...)
	}

	// Filter out already encrypted files when encrypting
	if *encrypt {
		var filteredPaths []string
		for _, path := range filePaths {
			if !strings.HasSuffix(path, ".enc") {
				filteredPaths = append(filteredPaths, path)
			}
		}
		filePaths = filteredPaths
	}

	// Verify we have files to process
	if len(filePaths) == 0 {
		logger.LogError("No valid files to process")
		os.Exit(1)
	}

	logger.LogDebug(fmt.Sprintf("Processing files: %v", filePaths))

	var operation string
	var err error
	if *encrypt {
		operation = "Encryption"
		err = handleMultipleFileOperation(filePaths, *key, *password, true, logger)
	} else {
		operation = "Decryption"
		err = handleMultipleFileOperation(filePaths, *key, *password, false, logger)
	}

	if err != nil {
		logger.LogError(fmt.Sprintf("Error during %s: %v", strings.ToLower(operation), err))
		os.Exit(1)
	}

	logger.LogInfo(fmt.Sprintf("%s completed successfully.", operation))
	logger.LogDebug("Operation completed")
}

func validateFlags(encrypt, decrypt bool, key, password string) error {
	if (encrypt && decrypt) || (!encrypt && !decrypt) {
		return fmt.Errorf("please specify either -e for encryption or -d for decryption")
	}

	if key == "" && password == "" {
		return fmt.Errorf("please provide either -k (key file) or -p (password)")
	}

	if key != "" && password != "" {
		return fmt.Errorf("please provide either -k (key file) or -p (password), not both")
	}

	return nil
}

func handleMultipleFileOperation(files []string, key, password string, encrypt bool, logger *logging.Logger) error {
	for _, file := range files {
		if encrypt {
			logger.LogDebug(fmt.Sprintf("Encrypting: %s", file))
			_, err := handleEncryption(file, key, password, logger)
			if err != nil {
				logger.LogError(fmt.Sprintf("Error processing file '%s': %v", file, err))
				return err // Stop on first error
			}
		} else {
			logger.LogDebug(fmt.Sprintf("Decrypting: %s", file))
			_, err := handleDecryption(file, key, password, logger)
			if err != nil {
				logger.LogError(fmt.Sprintf("Error processing file '%s': %v", file, err))
				return err // Stop on first error
			}
		}
	}
	return nil
}

func handleEncryption(file, key, password string, logger *logging.Logger) (string, error) {
	logger.LogInfo("Starting file encryption")
	var encryptor crypto.Encryptor
	var err error

	if key != "" {
		encryptor, err = crypto.NewRSAEncryptor(key)
	} else {
		encryptor, err = crypto.NewPasswordEncryptor(password)
	}
	logger.LogDebugf("Initialized encryptor: %T", encryptor)

	if err != nil {
		return "", fmt.Errorf("error initializing encryptor: %v", err)
	}

	// Calculate and log original file hash before encryption
	if hash, err := crypto.CalculateFileHash(file); err == nil {
		logger.LogDebug(fmt.Sprintf("Original file hash: %s", hash))
	}

	outputFile := file + ".enc"
	err = fileops.EncryptFile(file, outputFile, encryptor, logger)
	if err != nil {
		return "", err
	}

	return outputFile, nil
}

func handleDecryption(file, key, password string, logger *logging.Logger) (string, error) {
	logger.LogInfo("Starting file decryption")
	var decryptor crypto.Decryptor
	var err error

	if key != "" {
		decryptor, err = crypto.NewRSADecryptor(key)
	} else {
		decryptor, err = crypto.NewPasswordDecryptor(password)
	}
	logger.LogDebugf("Initialized decryptor: %T", decryptor)

	if err != nil {
		return "", fmt.Errorf("error initializing decryptor: %v", err)
	}

	outputFile := strings.TrimSuffix(file, ".enc")
	err = fileops.DecryptFile(file, outputFile, decryptor, logger)
	if err != nil {
		// Check for integrity validation error
		if strings.Contains(err.Error(), "file integrity check failed") {
			return "", fmt.Errorf("security error: %v", err)
		}
		return "", err
	}

	// Log the hash of the decrypted file
	if hash, err := crypto.CalculateFileHash(outputFile); err == nil {
		logger.LogDebug(fmt.Sprintf("Decrypted file hash: %s", hash))
	}

	return outputFile, nil
}

func handleGenerateKeys(keyBaseName string, logger *logging.Logger) error {
	logger.LogInfo("Starting RSA key pair generation")

	if err := crypto.GenerateRSAKeyPair(keyBaseName, logger); err != nil {
		return fmt.Errorf("failed to generate RSA key pair: %w", err)
	}

	logger.LogInfo("RSA key pair generated successfully.")
	return nil
}
