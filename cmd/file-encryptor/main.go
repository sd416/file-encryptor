package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"file-encryptor/pkg/crypto"
	"file-encryptor/pkg/fileops"
	"file-encryptor/pkg/logging"
)

func main() {
	logger := logging.NewLogger()
	logger.LogDebug("Starting file encryptor") //Added debug log

	encrypt := flag.Bool("e", false, "Encrypt the file")
	decrypt := flag.Bool("d", false, "Decrypt the file")
	file := flag.String("file", "", "File to encrypt or decrypt")
	key := flag.String("key", "", "Path to the key file (public key for encryption, private key for decryption)")
	password := flag.String("password", "", "Password for encryption/decryption (alternative to key file)")
	flag.Parse()
	logger.LogDebug("Parsed command line flags") // Added debug log

	if err := validateFlags(*encrypt, *decrypt, *file, *key, *password); err != nil {
		logger.LogError(err.Error())
		flag.Usage()
		os.Exit(1)
	}

	var err error
	var operation, outputFile string
	if *encrypt {
		operation = "Encryption"
		outputFile, err = handleEncryption(*file, *key, *password, logger)
	} else {
		operation = "Decryption"
		outputFile, err = handleDecryption(*file, *key, *password, logger)
	}
    logger.LogDebugf("Operation: %s, Output file: %s", operation, outputFile) // Added debug log

	if err != nil {
		logger.LogError(fmt.Sprintf("%v", err))
		if os.IsNotExist(err) {
			logger.LogInfo("Please check if the specified file and key exist and are readable.")
		}
		os.Exit(1)
	}

	logger.LogInfo(fmt.Sprintf("File %s completed. Output file: %s", strings.ToLower(operation), outputFile))
	logger.LogDebug("File encryption/decryption completed") // Added debug log
}

func validateFlags(encrypt, decrypt bool, file, key, password string) error {
	if (encrypt && decrypt) || (!encrypt && !decrypt) {
		return fmt.Errorf("please specify either -e for encryption or -d for decryption")
	}

	if file == "" {
		return fmt.Errorf("please provide the --file argument")
	}

	if key == "" && password == "" {
		return fmt.Errorf("please provide either --key or --password argument")
	}

	if key != "" && password != "" {
		return fmt.Errorf("please provide either --key or --password, not both")
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
    logger.LogDebugf("Initialized encryptor: %T", encryptor) // Added debug log

	if err != nil {
		return "", fmt.Errorf("error initializing encryptor: %v", err)
	}

	outputFile := file + ".enc"
	err = fileops.EncryptFile(file, outputFile, encryptor, logger)
	return outputFile, err
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
    logger.LogDebugf("Initialized decryptor: %T", decryptor) // Added debug log

	if err != nil {
		return "", fmt.Errorf("error initializing decryptor: %v", err)
	}

	outputFile := strings.TrimSuffix(file, ".enc")
	err = fileops.DecryptFile(file, outputFile, decryptor, logger)
	return outputFile, err
}
