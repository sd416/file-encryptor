package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

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

	// Create a context that can be cancelled
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Set up signal handling for graceful shutdown
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)
	
	// Handle cancellation in a separate goroutine
	go func() {
		select {
		case <-signalChan:
			logger.LogInfo("Received termination signal, shutting down gracefully...")
			cancel()
		}
	}()

	encrypt := flag.Bool("e", false, "Encrypt the file")
	decrypt := flag.Bool("d", false, "Decrypt the file")

	var files stringSliceFlag
	flag.Var(&files, "file", "Files to encrypt or decrypt (can be specified multiple times)")
	flag.Var(&files, "f", "Files to encrypt or decrypt (shorthand)")

	var key string
	flag.StringVar(&key, "key", "", "Path to the key file")
	flag.StringVar(&key, "k", "", "Path to the key file (shorthand)")

	var password string
	flag.StringVar(&password, "password", "", "Password for encryption/decryption")
	flag.StringVar(&password, "p", "", "Password for encryption/decryption (shorthand)")

	generateKeys := flag.Bool("generate-keys", false, "Generate a new RSA key pair")
	keyBaseName := flag.String("key-name", "key", "Base name for the generated key files")
	
	timeout := flag.Duration("timeout", 30*time.Minute, "Timeout for the entire operation")

	flag.Parse()
	
	// Set a timeout for the entire operation
	if *timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, *timeout)
		defer cancel()
		logger.LogDebug(fmt.Sprintf("Operation will timeout after %v", *timeout))
	}
	
	// Add remaining arguments as files only if they don't start with "-"
	// This prevents treating flags like "-k" as files
	remainingArgs := flag.Args()
	for _, arg := range remainingArgs {
		if !strings.HasPrefix(arg, "-") {
			files = append(files, arg)
		}
	}
	logger.LogDebug("Parsed command line flags")
	
	// Debug flag values
	logger.LogDebug(fmt.Sprintf("Encrypt: %v, Decrypt: %v", *encrypt, *decrypt))
	logger.LogDebug(fmt.Sprintf("Key: '%s', Password: '%s'", key, password))
	logger.LogDebug(fmt.Sprintf("Files: %v", files))
	logger.LogDebug(fmt.Sprintf("Generate Keys: %v, Key Base Name: %s", *generateKeys, *keyBaseName))

	if *generateKeys && !*encrypt && len(files) == 0 {
		if err := handleGenerateKeys(ctx, *keyBaseName, logger); err != nil {
			logger.LogError(err.Error())
			os.Exit(1)
		}
		logger.LogInfo("RSA Key pair generated successfully.")
		os.Exit(0)
	}

	if err := validateFlags(*encrypt, *decrypt, files, key, password, *generateKeys); err != nil {
		logger.LogError(err.Error())
		flag.Usage()
		os.Exit(1)
	}

	var err error
	var outputFiles []string
	var operation string

	if *generateKeys && *encrypt && len(files) > 0 {
		operation = "Encryption with key generation"
		outputFiles, err = handleGenerateAndEncrypt(ctx, *keyBaseName, files, logger)
	} else if *encrypt {
		operation = "Encryption"
		outputFiles, err = handleEncryption(ctx, files, key, password, logger)
	} else {
		operation = "Decryption"
		outputFiles, err = handleDecryption(ctx, files, key, password, logger)
	}

	// Check if the operation was cancelled
	if ctx.Err() != nil {
		logger.LogError(fmt.Sprintf("Operation cancelled: %v", ctx.Err()))
		os.Exit(1)
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

func handleGenerateKeys(ctx context.Context, keyBaseName string, logger *logging.Logger) error {
	logger.LogInfo("Starting RSA key pair generation")

	// Check for cancellation
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	if err := crypto.GenerateRSAKeyPair(keyBaseName, logger); err != nil {
		return fmt.Errorf("failed to generate RSA key pair: %w", err)
	}

	logger.LogInfo("RSA key pair generated successfully.")
	return nil
}

func handleGenerateAndEncrypt(ctx context.Context, keyBaseName string, files []string, logger *logging.Logger) ([]string, error) {
	logger.LogInfo("Starting RSA key pair generation and file encryption")

	// Check for cancellation
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	privateKeyName, publicKeyName, err := crypto.GenerateRSAKeyPairWithNames(keyBaseName, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key pair: %w", err)
	}

	encryptor, err := crypto.NewRSAEncryptor(publicKeyName)
	if err != nil {
		return nil, fmt.Errorf("failed to create encryptor: %w", err)
	}

	// Use the process files function with the context
	outputFiles, err := processFiles(ctx, files, true, encryptor, logger)
	if err != nil {
		return outputFiles, err
	}

	logger.LogInfo(fmt.Sprintf("Private key saved to: %s", privateKeyName))
	logger.LogInfo(fmt.Sprintf("Public key saved to: %s", publicKeyName))
	logger.LogInfo("Keep the private key secure - you will need it to decrypt the files!")

	return outputFiles, nil
}

// initializeCrypto initializes either an encryptor or decryptor based on the provided parameters
func initializeCrypto(isEncryption bool, key, password string, logger *logging.Logger) (interface{}, error) {
	var result interface{}
	var err error
	operationType := map[bool]string{true: "encryptor", false: "decryptor"}[isEncryption]

	if key != "" {
		if isEncryption {
			result, err = crypto.NewRSAEncryptor(key)
		} else {
			result, err = crypto.NewRSADecryptor(key)
		}
	} else {
		if isEncryption {
			result, err = crypto.NewPasswordEncryptor(password)
		} else {
			result, err = crypto.NewPasswordDecryptor(password)
		}
	}
	
	if err != nil {
		return nil, fmt.Errorf("error initializing %s: %v", operationType, err)
	}
	
	logger.LogDebugf("Initialized %s: %T", operationType, result)
	return result, nil
}

// processFiles handles the common file processing logic for both encryption and decryption
// with support for concurrent processing of multiple files
func processFiles(
	ctx context.Context,
	files []string,
	isEncryption bool,
	cryptoProcessor interface{},
	logger *logging.Logger,
) ([]string, error) {
	operation := map[bool]string{true: "encryption", false: "decryption"}[isEncryption]
	outputFiles := make([]string, 0, len(files))
	
	// Check for cancellation
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	
	logger.LogInfo(fmt.Sprintf("Found %d files to process", len(files)))
	
	// Use a worker pool for concurrent processing
	// For small numbers of files, this might be overkill,
	// but for many files it will provide performance benefits
	numWorkers := 3 // Limit concurrency to avoid system overload
	if len(files) < numWorkers {
		numWorkers = len(files)
	}
	
	// Channel for job results
	type result struct {
		outputFile string
		err        error
	}
	resultChan := make(chan result)
	
	// Process files concurrently using a worker pool
	var wg sync.WaitGroup
	
	// Function to process a single file
	processFile := func(file string) {
		defer wg.Done()
		
		var outputFile string
		var processErr error
		
		logger.LogInfo(fmt.Sprintf("Starting %s of file: %s", strings.ToLower(operation), file))
		
		if isEncryption {
			// For encryption operations
			if hash, err := crypto.CalculateFileHash(file); err == nil {
				logger.LogDebug(fmt.Sprintf("Original file hash for %s: %s", file, hash))
			}
			outputFile = file + ".enc"
			processErr = fileops.EncryptFile(file, outputFile, cryptoProcessor.(crypto.Encryptor), logger)
		} else {
			// For decryption operations
			outputFile = strings.TrimSuffix(file, ".enc")
			processErr = fileops.DecryptFile(file, outputFile, cryptoProcessor.(crypto.Decryptor), logger)
		}
		
		// Send result through channel
		resultChan <- result{outputFile, processErr}
	}
	
	// Limit the number of concurrent goroutines with a semaphore
	semaphore := make(chan struct{}, numWorkers)
	
	// Start all file processing goroutines
	for _, file := range files {
		wg.Add(1)
		
		// Acquire semaphore slot
		semaphore <- struct{}{}
		
		go func(file string) {
			processFile(file)
			// Release semaphore slot when done
			<-semaphore
		}(file)
	}
	
	// Close the results channel when all workers are done
	go func() {
		wg.Wait()
		close(resultChan)
	}()
	
	// Collect results as they come in
	for res := range resultChan {
		if res.err != nil {
			// Let any running goroutines finish, but we'll return the error
			if !isEncryption && strings.Contains(res.err.Error(), "file integrity check failed") {
				return outputFiles, fmt.Errorf("security error while decrypting: %v", res.err)
			}
			return outputFiles, fmt.Errorf("failed to %s: %w", operation, res.err)
		}
		outputFiles = append(outputFiles, res.outputFile)
	}
	
	return outputFiles, nil
}

func handleEncryption(ctx context.Context, files []string, key, password string, logger *logging.Logger) ([]string, error) {
	logger.LogInfo("Starting file encryption")
	
	// Check for cancellation
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	
	encryptor, err := initializeCrypto(true, key, password, logger)
	if err != nil {
		return nil, err
	}
	
	return processFiles(ctx, files, true, encryptor, logger)
}

func handleDecryption(ctx context.Context, files []string, key, password string, logger *logging.Logger) ([]string, error) {
	logger.LogInfo("Starting file decryption")
	
	// Check for cancellation
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	
	decryptor, err := initializeCrypto(false, key, password, logger)
	if err != nil {
		return nil, err
	}
	
	return processFiles(ctx, files, false, decryptor, logger)
}
