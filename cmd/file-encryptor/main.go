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

type stringSliceFlag []string

func (s *stringSliceFlag) String() string {
	return strings.Join(*s, ",")
}

func (s *stringSliceFlag) Set(value string) error {
	*s = append(*s, value)
	return nil
}

func main() {
	logger := logging.NewLogger()
	logger.LogDebug("Starting file encryptor")

	encrypt := flag.Bool("e", false, "Encrypt the file")
	decrypt := flag.Bool("d", false, "Decrypt the file")

	var files stringSliceFlag
	flag.Var(&files, "file", "Files to encrypt or decrypt (can be specified multiple times)")
	flag.Var(&files, "f", "Files to encrypt or decrypt (shorthand)")

	key := flag.String("key", "", "Path to the key file")
	flag.StringVar(key, "k", "", "Path to the key file (shorthand)")

	password := flag.String("password", "", "Password for encryption/decryption")
	flag.StringVar(password, "p", "", "Password for encryption/decryption (shorthand)")

	generateKeys := flag.Bool("generate-keys", false, "Generate a new RSA key pair")
	keyBaseName := flag.String("key-name", "key", "Base name for the generated key files")

	flag.Parse()
	// Add handling for remaining arguments
	remainingArgs := flag.Args()
	if len(remainingArgs) > 0 {
		files = append(files, remainingArgs...)
	}
	logger.LogDebug("Parsed command line flags")

	if *generateKeys && !*encrypt && len(files) == 0 {
		if err := handleGenerateKeys(*keyBaseName, logger); err != nil {
			logger.LogError(err.Error())
			os.Exit(1)
		}
		logger.LogInfo("RSA Key pair generated successfully.")
		os.Exit(0)
	}

	if err := validateFlags(*encrypt, *decrypt, files, *key, *password, *generateKeys); err != nil {
		logger.LogError(err.Error())
		flag.Usage()
		os.Exit(1)
	}

	var err error
	var outputFiles []string
	var operation string

	if *generateKeys && *encrypt && len(files) > 0 {
		operation = "Encryption with key generation"
		outputFiles, err = handleGenerateAndEncrypt(*keyBaseName, files, logger)
	} else if *encrypt {
		operation = "Encryption"
		outputFiles, err = handleEncryption(files, *key, *password, logger)
	} else {
		operation = "Decryption"
		outputFiles, err = handleDecryption(files, *key, *password, logger)
	}

	if err != nil {
		logger.LogError(fmt.Sprintf("Error during %s: %v", strings.ToLower(operation), err))
		if strings.Contains(err.Error(), "security error") {
			fmt.Println("\n⚠️  Security Warning: File integrity check failed!")
			fmt.Println("    The file may have been tampered with or corrupted.")
			fmt.Println("    The decrypted file has been deleted for security reasons.")
		}
		os.Exit(1)
	}

	logger.LogInfo(fmt.Sprintf("%s completed successfully.", operation))
	logger.LogInfo("Output files:")
	for _, file := range outputFiles {
		logger.LogInfo(fmt.Sprintf("- %s", file))
	}
	logger.LogDebug("Operation completed")
}

func validateFlags(encrypt, decrypt bool, files []string, key, password string, generateKeys bool) error {
	if generateKeys && encrypt && len(files) == 0 {
		return fmt.Errorf("the --generate-keys flag requires the -f option to encrypt after generation")
	}

	if generateKeys {
		if decrypt || key != "" || password != "" {
			return fmt.Errorf("the --generate-keys flag cannot be combined with decrypt, key or password options")
		}
	}

	if (encrypt && decrypt) || (!encrypt && !decrypt) {
		return fmt.Errorf("please specify either -e for encryption or -d for decryption")
	}

	if len(files) == 0 && !generateKeys {
		return fmt.Errorf("please provide at least one file using --file or -f argument")
	}

	if key == "" && password == "" && !generateKeys {
		return fmt.Errorf("please provide either --key or -k or --password or -p argument")
	}

	if key != "" && password != "" {
		return fmt.Errorf("please provide either --key or -k or --password or -p, not both")
	}

	return nil
}

func handleGenerateKeys(keyBaseName string, logger *logging.Logger) error {
	logger.LogInfo("Starting RSA key pair generation")

	if err := crypto.GenerateRSAKeyPair(keyBaseName, logger); err != nil {
		return fmt.Errorf("failed to generate RSA key pair: %w", err)
	}

	logger.LogInfo("RSA key pair generated successfully.")
	return nil
}

func handleGenerateAndEncrypt(keyBaseName string, files []string, logger *logging.Logger) ([]string, error) {
	logger.LogInfo("Starting RSA key pair generation and file encryption")

	privateKeyName, publicKeyName, err := crypto.GenerateRSAKeyPairWithNames(keyBaseName, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key pair: %w", err)
	}

	encryptor, err := crypto.NewRSAEncryptor(publicKeyName)
	if err != nil {
		return nil, fmt.Errorf("failed to create encryptor: %w", err)
	}

	outputFiles := make([]string, 0, len(files))
	for _, file := range files {
		if hash, err := crypto.CalculateFileHash(file); err == nil {
			logger.LogDebug(fmt.Sprintf("Original file hash for %s: %s", file, hash))
		}

		outputFile := file + ".enc"
		if err := fileops.EncryptFile(file, outputFile, encryptor, logger); err != nil {
			return outputFiles, fmt.Errorf("failed to encrypt %s: %w", file, err)
		}
		outputFiles = append(outputFiles, outputFile)
	}

	logger.LogInfo(fmt.Sprintf("Private key saved to: %s", privateKeyName))
	logger.LogInfo(fmt.Sprintf("Public key saved to: %s", publicKeyName))
	logger.LogInfo("Keep the private key secure - you will need it to decrypt the files!")

	return outputFiles, nil
}

func handleEncryption(files []string, key, password string, logger *logging.Logger) ([]string, error) {
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
		return nil, fmt.Errorf("error initializing encryptor: %v", err)
	}

	outputFiles := make([]string, 0, len(files))
	for _, file := range files {
		if hash, err := crypto.CalculateFileHash(file); err == nil {
			logger.LogDebug(fmt.Sprintf("Original file hash for %s: %s", file, hash))
		}

		outputFile := file + ".enc"
		if err := fileops.EncryptFile(file, outputFile, encryptor, logger); err != nil {
			return outputFiles, fmt.Errorf("failed to encrypt %s: %w", file, err)
		}
		outputFiles = append(outputFiles, outputFile)
	}

	return outputFiles, nil
}

func handleDecryption(files []string, key, password string, logger *logging.Logger) ([]string, error) {
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
		return nil, fmt.Errorf("error initializing decryptor: %v", err)
	}

	outputFiles := make([]string, 0, len(files))
	for _, file := range files {
		outputFile := strings.TrimSuffix(file, ".enc")
		if err := fileops.DecryptFile(file, outputFile, decryptor, logger); err != nil {
			if strings.Contains(err.Error(), "file integrity check failed") {
				return outputFiles, fmt.Errorf("security error while decrypting %s: %v", file, err)
			}
			return outputFiles, fmt.Errorf("failed to decrypt %s: %w", file, err)
		}
		outputFiles = append(outputFiles, outputFile)
	}

	return outputFiles, nil
}
