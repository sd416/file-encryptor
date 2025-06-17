package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"file-encryptor/pkg/logging"
)

// Version information (set by build process)
var (
	Version   = "dev"
	GitCommit = "unknown"
	BuildTime = "unknown"
)

const AppVersion = "1.0.0" // Fallback version

func main() {
	// Parse CLI arguments
	args, err := ParseCLI()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing arguments: %v\n", err)
		os.Exit(1)
	}

	// Load configuration
	configPath := GetConfigPath(args.ConfigFile)
	config, err := LoadConfig(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading configuration: %v\n", err)
		os.Exit(1)
	}

	// Override config with CLI arguments
	if args.Timeout > 0 {
		config.DefaultTimeout = args.Timeout
	}

	// Create logger with configuration
	var logger *logging.Logger
	if args.Verbose {
		logger = logging.NewLoggerWithConfig("debug", config.LogFormat, true)
	} else if args.Quiet {
		logger = logging.NewLoggerWithConfig("error", config.LogFormat, false)
	} else {
		logger = logging.NewLoggerWithConfig(config.LogLevel, config.LogFormat, config.EnableDebug)
	}

	logger.LogDebug("Starting file encryptor")
	logger.LogDebugf("Configuration loaded from: %s", configPath)

	// Handle special commands
	if args.ShowConfig {
		ShowConfiguration(config, logger)
		os.Exit(0)
	}

	if args.SaveConfig != "" {
		if err := config.SaveConfig(args.SaveConfig); err != nil {
			logger.LogError(fmt.Sprintf("Failed to save configuration: %v", err))
			os.Exit(1)
		}
		logger.LogInfo(fmt.Sprintf("Configuration saved to: %s", args.SaveConfig))
		os.Exit(0)
	}

	// Handle web UI mode
	if args.WebUI {
		logger.LogInfo("Starting web UI mode")
		if err := StartWebServer(config, logger, args); err != nil {
			logger.LogError(fmt.Sprintf("Web server failed: %v", err))
			os.Exit(1)
		}
		os.Exit(0)
	}

	// Validate arguments
	if err := ValidateArgs(args, config); err != nil {
		logger.LogError(err.Error())
		os.Exit(1)
	}

	// Create context with cancellation support
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Set up signal handling for graceful shutdown
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)

	// Handle cancellation in a separate goroutine
	go func() {
		select {
		case sig := <-signalChan:
			logger.LogInfo(fmt.Sprintf("Received signal %v, shutting down gracefully...", sig))
			cancel()
		case <-ctx.Done():
			return
		}
	}()

	// Set timeout if specified
	if config.DefaultTimeout > 0 {
		var timeoutCancel context.CancelFunc
		ctx, timeoutCancel = context.WithTimeout(ctx, config.DefaultTimeout)
		defer timeoutCancel()
		logger.LogDebugf("Operation will timeout after %v", config.DefaultTimeout)
	}

	// Execute the main operation
	if err := executeOperation(ctx, args, config, logger); err != nil {
		// Check if the operation was cancelled
		if ctx.Err() != nil {
			logger.LogError(fmt.Sprintf("Operation cancelled: %v", ctx.Err()))
		} else {
			logger.LogError(fmt.Sprintf("Operation failed: %v", err))
		}
		os.Exit(1)
	}

	logger.LogDebug("Operation completed successfully")
}

// executeOperation executes the main file operation based on CLI arguments
func executeOperation(ctx context.Context, args *CLIArgs, config *Config, logger *logging.Logger) error {
	var err error
	var outputFiles []string
	var operation string

	// Create structured logger with operation context
	opLogger := logger.WithFields(map[string]interface{}{
		"version":    Version,
		"files":      len(args.Files),
		"workers":    config.MaxWorkers,
		"chunk_size": config.ChunkSize,
	})

	// Handle different operations
	switch {
	case args.GenerateKeys && args.Encrypt && len(args.Files) > 0:
		operation = "Key generation and encryption"
		opLogger = opLogger.WithField("operation", "generate_and_encrypt")
		outputFiles, err = HandleGenerateAndEncrypt(ctx, args, config, opLogger)

	case args.GenerateKeys && !args.Encrypt:
		operation = "Key generation"
		opLogger = opLogger.WithField("operation", "generate_keys")
		err = HandleGenerateKeys(ctx, args, config, opLogger)

	case args.Encrypt:
		operation = "Encryption"
		opLogger = opLogger.WithField("operation", "encrypt")
		outputFiles, err = HandleEncryption(ctx, args, config, opLogger)

	case args.Decrypt:
		operation = "Decryption"
		opLogger = opLogger.WithField("operation", "decrypt")
		outputFiles, err = HandleDecryption(ctx, args, config, opLogger)

	default:
		return fmt.Errorf("no valid operation specified")
	}

	// Check if the operation was cancelled
	if ctx.Err() != nil {
		return ctx.Err()
	}

	if err != nil {
		// Handle security errors specially
		if args.Decrypt && containsSecurityError(err) {
			fmt.Println("\n⚠️  Security Warning: File integrity check failed!")
			fmt.Println("    The file may have been tampered with or corrupted.")
			fmt.Println("    The decrypted file has been deleted for security reasons.")
		}
		return fmt.Errorf("%s failed: %w", operation, err)
	}

	// Log success
	opLogger.LogInfo(fmt.Sprintf("%s completed successfully", operation))

	// Log output files if any
	if len(outputFiles) > 0 {
		opLogger.LogInfo("Output files:")
		for _, file := range outputFiles {
			opLogger.LogInfo(fmt.Sprintf("- %s", file))
		}
	}

	return nil
}

// containsSecurityError checks if the error contains security-related messages
func containsSecurityError(err error) bool {
	if err == nil {
		return false
	}
	errorMsg := err.Error()
	securityKeywords := []string{
		"security error",
		"integrity check failed",
		"file integrity check failed",
		"hash mismatch",
	}

	for _, keyword := range securityKeywords {
		if contains(errorMsg, keyword) {
			return true
		}
	}
	return false
}

// contains checks if a string contains a substring (case-insensitive)
func contains(s, substr string) bool {
	return len(s) >= len(substr) &&
		(s == substr ||
			len(s) > len(substr) &&
				(s[:len(substr)] == substr ||
					s[len(s)-len(substr):] == substr ||
					containsAt(s, substr)))
}

// containsAt checks if substr exists anywhere in s
func containsAt(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
