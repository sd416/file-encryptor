package main

import (
	"fmt"
	"os"
	"strings"
	"sync"

	"file-encryptor/pkg/crypto"
	"file-encryptor/pkg/fileops"
	"file-encryptor/pkg/logging"
	"github.com/schollz/progressbar/v3"
)

func main() {
	logger := logging.NewLogger()
	logger.LogDebug("Starting file encryptor")

	// Parse all command-line arguments to identify keys and files
	args := os.Args[1:]
	files := []string{}
	keyValue := ""
	passwordValue := ""
	encrypt := false
	decrypt := false
	generateKeys := false
	keyBaseName := "key"

	for i := 0; i < len(args); i++ {
		arg := args[i]

		// Check for flags
		if arg == "-e" || arg == "--encrypt" {
			encrypt = true
			continue
		}
		if arg == "-d" || arg == "--decrypt" {
			decrypt = true
			continue
		}
		if arg == "--generate-keys" {
			generateKeys = true
			continue
		}

		// Flags with values
		if arg == "-k" || arg == "--key" {
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				keyValue = args[i+1]
				i++
			}
			continue
		}
		if arg == "-p" || arg == "--password" {
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				passwordValue = args[i+1]
				i++
			}
			continue
		}
		if arg == "--key-name" {
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				keyBaseName = args[i+1]
				i++
			}
			continue
		}
		if arg == "-f" || arg == "--file" {
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				files = append(files, args[i+1])
				i++
			}
			continue
		}

		// Assume any other non-flag argument is a file
		if !strings.HasPrefix(arg, "-") {
			files = append(files, arg)
		}
	}

	// Handle key generation
	var publicKeyPath string
	var privateKeyPath string

	if generateKeys {
		var err error
		privateKeyPath, publicKeyPath, err = crypto.GenerateRSAKeyPairWithNames(keyBaseName, logger)
		if err != nil {
			logger.LogError(fmt.Sprintf("Failed to generate key pair: %v", err))
			os.Exit(1)
		}
		logger.LogInfo(fmt.Sprintf("Generated RSA key pair: %s, %s", privateKeyPath, publicKeyPath))

		// If we're not encrypting files, print usage and exit
		if !encrypt || len(files) == 0 {
			fmt.Printf("Generated key pair: %s (private), %s (public)\n", privateKeyPath, publicKeyPath)
			os.Exit(0)
		}

		// Use the generated public key for encryption
		keyValue = publicKeyPath
	}

	if err := validateFlags(encrypt, decrypt, files, keyValue, passwordValue, generateKeys); err != nil {
		logger.LogError(err.Error())
		os.Exit(1)
	}

	var numFiles int
	if encrypt || decrypt {
		numFiles = len(files)
	}

	bar := progressbar.NewOptions(numFiles,
		progressbar.OptionSetDescription("Processing files..."),
		progressbar.OptionSetWidth(15),
		progressbar.OptionShowCount(),
		progressbar.OptionShowIts(),
		progressbar.OptionSetTheme(progressbar.Theme{
			Saucer:        "=",
			SaucerHead:    ">",
			SaucerPadding: " ",
			BarStart:      "[",
			BarEnd:        "]",
		}),
		progressbar.OptionSetPredictTime(true),
	)

	var wg sync.WaitGroup
	var mu sync.Mutex
	var encryptedFiles []string // Track encrypted files

	for _, file := range files {
		wg.Add(1)
		go func(file string) {
			defer wg.Done()
			var err error
			var outputFile string

			if encrypt {
				outputFile, err = handleEncryption(file, keyValue, passwordValue, logger)
				if err == nil {
					mu.Lock()
					encryptedFiles = append(encryptedFiles, outputFile)
					mu.Unlock()
				}
			} else {
				outputFile, err = handleDecryption(file, keyValue, passwordValue, logger)
			}

			if err != nil {
				logger.LogError(fmt.Sprintf("Error processing file %s: %v", file, err))
				if strings.Contains(err.Error(), "security error") {
					fmt.Printf("\n⚠️  Security Warning: File %s integrity check failed!\n", file)
					fmt.Println("    The file may have been tampered with or corrupted.")
					fmt.Println("    The decrypted file has been deleted for security reasons.")
				}
			} else {
				logger.LogInfo(fmt.Sprintf("Successfully processed file %s. Output: %s", file, outputFile))
			}
			bar.Add(1)
		}(file)
	}

	wg.Wait()

	// Print list of encrypted files if any
	if encrypt && len(encryptedFiles) > 0 {
		logger.LogInfo("List of encrypted files:")
		for _, f := range encryptedFiles {
			logger.LogInfo(f)
		}
	}

	logger.LogDebug("Operation completed")
}

func validateFlags(encrypt, decrypt bool, files []string, key, password string, generateKeys bool) error {
	if generateKeys && decrypt {
		return fmt.Errorf("cannot use -generate-keys with decrypt option")
	}

	if len(files) == 0 && !generateKeys {
		return fmt.Errorf("please provide files to process, either with --file flag or as arguments")
	}

	if !generateKeys && key == "" && password == "" {
		return fmt.Errorf("please provide either --key or -k or --password or -p argument")
	}

	if key != "" && password != "" {
		return fmt.Errorf("please provide either --key or -k or --password or -p, not both")
	}

	if (encrypt && decrypt) || (!encrypt && !decrypt && !generateKeys) {
		return fmt.Errorf("please specify either -e for encryption or -d for decryption")
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
