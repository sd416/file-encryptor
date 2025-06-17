package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"file-encryptor/pkg/crypto"
	"file-encryptor/pkg/fileops"
	"file-encryptor/pkg/logging"
)

// OperationResult holds the result of a file operation
type OperationResult struct {
	InputFile  string
	OutputFile string
	Error      error
	Duration   time.Duration
	Size       int64
}

// OperationMetrics holds metrics for the entire operation
type OperationMetrics struct {
	TotalFiles     int
	ProcessedFiles int
	FailedFiles    int
	TotalBytes     int64
	ProcessedBytes int64
	StartTime      time.Time
	EndTime        time.Time
	Duration       time.Duration
	Throughput     float64 // MB/s
}

// HandleGenerateKeys handles RSA key pair generation
func HandleGenerateKeys(ctx context.Context, args *CLIArgs, config *Config, logger *logging.Logger) error {
	logger.LogInfo("Starting RSA key pair generation")

	// Check for cancellation
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	keyBaseName := args.KeyBaseName
	if keyBaseName == "" {
		keyBaseName = config.DefaultKeyName
	}

	if err := crypto.GenerateRSAKeyPair(keyBaseName, logger); err != nil {
		return fmt.Errorf("failed to generate RSA key pair: %w", err)
	}

	logger.LogInfo("RSA key pair generated successfully")
	return nil
}

// HandleGenerateAndEncrypt handles key generation followed by encryption
func HandleGenerateAndEncrypt(ctx context.Context, args *CLIArgs, config *Config, logger *logging.Logger) ([]string, error) {
	logger.LogInfo("Starting RSA key pair generation and file encryption")

	// Check for cancellation
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	keyBaseName := args.KeyBaseName
	if keyBaseName == "" {
		keyBaseName = config.DefaultKeyName
	}

	privateKeyName, publicKeyName, err := crypto.GenerateRSAKeyPairWithNames(keyBaseName, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key pair: %w", err)
	}

	encryptor, err := crypto.NewRSAEncryptor(publicKeyName)
	if err != nil {
		return nil, fmt.Errorf("failed to create encryptor: %w", err)
	}

	// Process files with the generated key
	outputFiles, metrics, err := ProcessFiles(ctx, args.Files, true, encryptor, config, logger)
	if err != nil {
		return outputFiles, err
	}

	// Log key information
	logger.LogInfo(fmt.Sprintf("Private key saved to: %s", privateKeyName))
	logger.LogInfo(fmt.Sprintf("Public key saved to: %s", publicKeyName))
	logger.LogInfo("Keep the private key secure - you will need it to decrypt the files!")

	// Log metrics if enabled
	if config.EnableMetrics {
		logMetrics(metrics, logger)
	}

	return outputFiles, nil
}

// HandleEncryption handles file encryption
func HandleEncryption(ctx context.Context, args *CLIArgs, config *Config, logger *logging.Logger) ([]string, error) {
	logger.LogInfo("Starting file encryption")

	// Check for cancellation
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	encryptor, err := initializeCrypto(true, args.Key, args.Password, logger)
	if err != nil {
		return nil, err
	}

	outputFiles, metrics, err := ProcessFiles(ctx, args.Files, true, encryptor, config, logger)

	// Log metrics if enabled
	if config.EnableMetrics {
		logMetrics(metrics, logger)
	}

	return outputFiles, err
}

// HandleDecryption handles file decryption
func HandleDecryption(ctx context.Context, args *CLIArgs, config *Config, logger *logging.Logger) ([]string, error) {
	logger.LogInfo("Starting file decryption")

	// Check for cancellation
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	decryptor, err := initializeCrypto(false, args.Key, args.Password, logger)
	if err != nil {
		return nil, err
	}

	outputFiles, metrics, err := ProcessFiles(ctx, args.Files, false, decryptor, config, logger)

	// Log metrics if enabled
	if config.EnableMetrics {
		logMetrics(metrics, logger)
	}

	return outputFiles, err
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

// ProcessFiles handles the common file processing logic for both encryption and decryption
func ProcessFiles(
	ctx context.Context,
	files []string,
	isEncryption bool,
	cryptoProcessor interface{},
	config *Config,
	logger *logging.Logger,
) ([]string, *OperationMetrics, error) {
	operation := map[bool]string{true: "encryption", false: "decryption"}[isEncryption]

	// Initialize metrics
	metrics := &OperationMetrics{
		TotalFiles: len(files),
		StartTime:  time.Now(),
	}

	// Calculate total size for metrics
	for _, file := range files {
		if info, err := os.Stat(file); err == nil {
			metrics.TotalBytes += info.Size()
		}
	}

	outputFiles := make([]string, 0, len(files))

	// Check for cancellation
	select {
	case <-ctx.Done():
		return nil, metrics, ctx.Err()
	default:
	}

	logger.LogInfo(fmt.Sprintf("Found %d files to process", len(files)))

	// Calculate optimal worker count
	numWorkers := config.GetOptimalWorkerCount(len(files), metrics.TotalBytes)
	logger.LogDebugf("Using %d workers for processing", numWorkers)

	// Use a worker pool for concurrent processing
	if len(files) < numWorkers {
		numWorkers = len(files)
	}

	// Channels for job distribution and result collection
	jobChan := make(chan string, len(files))
	resultChan := make(chan OperationResult, len(files))

	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			processWorker(ctx, workerID, jobChan, resultChan, isEncryption, cryptoProcessor, config, logger)
		}(i)
	}

	// Send jobs to workers
	go func() {
		defer close(jobChan)
		for _, file := range files {
			select {
			case jobChan <- file:
			case <-ctx.Done():
				return
			}
		}
	}()

	// Close result channel when all workers are done
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Collect results
	for result := range resultChan {
		metrics.ProcessedFiles++

		if result.Error != nil {
			metrics.FailedFiles++
			logger.LogError(fmt.Sprintf("Failed to %s file '%s': %v", operation, result.InputFile, result.Error))

			// Handle security errors specially
			if !isEncryption && strings.Contains(result.Error.Error(), "file integrity check failed") {
				return outputFiles, metrics, fmt.Errorf("security error while decrypting '%s': %v", result.InputFile, result.Error)
			}

			// For other errors, continue processing but report the error
			continue
		}

		outputFiles = append(outputFiles, result.OutputFile)
		metrics.ProcessedBytes += result.Size

		logger.LogInfo(fmt.Sprintf("Successfully %sed: %s -> %s (%.2fs)",
			strings.TrimSuffix(operation, "ion"), result.InputFile, result.OutputFile, result.Duration.Seconds()))
	}

	// Finalize metrics
	metrics.EndTime = time.Now()
	metrics.Duration = metrics.EndTime.Sub(metrics.StartTime)
	if metrics.Duration.Seconds() > 0 {
		metrics.Throughput = float64(metrics.ProcessedBytes) / (1024 * 1024) / metrics.Duration.Seconds()
	}

	// Check if we had any failures
	if metrics.FailedFiles > 0 {
		return outputFiles, metrics, fmt.Errorf("failed to process %d out of %d files", metrics.FailedFiles, metrics.TotalFiles)
	}

	return outputFiles, metrics, nil
}

// processWorker is a worker function that processes files from the job channel
func processWorker(
	ctx context.Context,
	workerID int,
	jobChan <-chan string,
	resultChan chan<- OperationResult,
	isEncryption bool,
	cryptoProcessor interface{},
	config *Config,
	logger *logging.Logger,
) {
	for {
		select {
		case file, ok := <-jobChan:
			if !ok {
				return // Channel closed, worker done
			}

			result := processFile(ctx, file, isEncryption, cryptoProcessor, config, logger)
			result.InputFile = file

			select {
			case resultChan <- result:
			case <-ctx.Done():
				return
			}

		case <-ctx.Done():
			return
		}
	}
}

// processFile processes a single file
func processFile(
	ctx context.Context,
	file string,
	isEncryption bool,
	cryptoProcessor interface{},
	config *Config,
	logger *logging.Logger,
) OperationResult {
	startTime := time.Now()

	// Check for cancellation
	select {
	case <-ctx.Done():
		return OperationResult{Error: ctx.Err()}
	default:
	}

	var outputFile string
	var err error

	// Get file size for metrics
	var fileSize int64
	if info, statErr := os.Stat(file); statErr == nil {
		fileSize = info.Size()
	}

	logger.LogDebugf("Worker processing file: %s", file)

	if isEncryption {
		// For encryption operations
		if hash, hashErr := crypto.CalculateFileHash(file); hashErr == nil {
			logger.LogDebug(fmt.Sprintf("Original file hash for %s: %s", file, hash))
		}
		outputFile = file + ".enc"
		err = fileops.EncryptFile(file, outputFile, cryptoProcessor.(crypto.Encryptor), logger)
	} else {
		// For decryption operations
		outputFile = strings.TrimSuffix(file, ".enc")
		err = fileops.DecryptFile(file, outputFile, cryptoProcessor.(crypto.Decryptor), logger)
	}

	duration := time.Since(startTime)

	return OperationResult{
		OutputFile: outputFile,
		Error:      err,
		Duration:   duration,
		Size:       fileSize,
	}
}

// logMetrics logs operation metrics
func logMetrics(metrics *OperationMetrics, logger *logging.Logger) {
	logger.LogInfo("=== Operation Metrics ===")
	logger.LogInfo(fmt.Sprintf("Total files: %d", metrics.TotalFiles))
	logger.LogInfo(fmt.Sprintf("Processed files: %d", metrics.ProcessedFiles))
	logger.LogInfo(fmt.Sprintf("Failed files: %d", metrics.FailedFiles))
	logger.LogInfo(fmt.Sprintf("Total data: %s", formatBytes(metrics.TotalBytes)))
	logger.LogInfo(fmt.Sprintf("Processed data: %s", formatBytes(metrics.ProcessedBytes)))
	logger.LogInfo(fmt.Sprintf("Duration: %v", metrics.Duration))
	logger.LogInfo(fmt.Sprintf("Throughput: %.2f MB/s", metrics.Throughput))
	logger.LogInfo("========================")
}

// ShowConfiguration displays the current configuration
func ShowConfiguration(config *Config, logger *logging.Logger) {
	fmt.Println("=== File Encryptor Configuration ===")
	fmt.Printf("Max Workers: %d\n", config.MaxWorkers)
	fmt.Printf("Chunk Size: %s\n", formatBytes(int64(config.ChunkSize)))
	fmt.Printf("Default Timeout: %v\n", config.DefaultTimeout)
	fmt.Printf("Log Level: %s\n", config.LogLevel)
	fmt.Printf("Log Format: %s\n", config.LogFormat)
	fmt.Printf("Debug Mode: %t\n", config.EnableDebug)
	fmt.Printf("Key Size: %d bits\n", config.KeySize)
	fmt.Printf("Default Key Name: %s\n", config.DefaultKeyName)
	fmt.Printf("Buffer Size: %s\n", formatBytes(int64(config.BufferSize)))
	fmt.Printf("Progress Bar: %t\n", config.EnableProgressBar)
	fmt.Printf("Metrics: %t\n", config.EnableMetrics)
	fmt.Printf("Adaptive Workers: %t\n", config.AdaptiveWorkerCount)
	fmt.Println("===================================")
}
