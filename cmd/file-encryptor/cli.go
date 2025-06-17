package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// stringSliceFlag implements flag.Value for handling multiple file arguments
type stringSliceFlag []string

func (s *stringSliceFlag) String() string {
	return strings.Join(*s, ",")
}

func (s *stringSliceFlag) Set(value string) error {
	*s = append(*s, value)
	return nil
}

// CLIArgs holds parsed command line arguments
type CLIArgs struct {
	// Operations
	Encrypt      bool
	Decrypt      bool
	GenerateKeys bool

	// Files and keys
	Files       []string
	Key         string
	Password    string
	KeyBaseName string

	// Configuration
	ConfigFile string
	Timeout    time.Duration

	// Output options
	Verbose bool
	Quiet   bool

	// Web UI options
	WebUI    bool
	WebPort  int
	WebHost  string
	WebTLS   bool
	CertFile string
	KeyFile  string

	// Additional options
	ShowConfig  bool
	SaveConfig  string
	ShowVersion bool
	ShowHelp    bool
}

// ParseCLI parses command line arguments and returns CLIArgs
func ParseCLI() (*CLIArgs, error) {
	args := &CLIArgs{}
	var files stringSliceFlag

	// Define flags
	flag.BoolVar(&args.Encrypt, "e", false, "Encrypt the file(s)")
	flag.BoolVar(&args.Encrypt, "encrypt", false, "Encrypt the file(s)")

	flag.BoolVar(&args.Decrypt, "d", false, "Decrypt the file(s)")
	flag.BoolVar(&args.Decrypt, "decrypt", false, "Decrypt the file(s)")

	flag.Var(&files, "file", "Files to encrypt or decrypt (can be specified multiple times)")
	flag.Var(&files, "f", "Files to encrypt or decrypt (shorthand)")

	flag.StringVar(&args.Key, "key", "", "Path to the key file")
	flag.StringVar(&args.Key, "k", "", "Path to the key file (shorthand)")

	flag.StringVar(&args.Password, "password", "", "Password for encryption/decryption")
	flag.StringVar(&args.Password, "p", "", "Password for encryption/decryption (shorthand)")

	flag.BoolVar(&args.GenerateKeys, "generate-keys", false, "Generate a new RSA key pair")
	flag.StringVar(&args.KeyBaseName, "key-name", "key", "Base name for the generated key files")

	flag.StringVar(&args.ConfigFile, "config", "", "Path to configuration file")
	flag.StringVar(&args.ConfigFile, "c", "", "Path to configuration file (shorthand)")

	flag.DurationVar(&args.Timeout, "timeout", 0, "Timeout for the entire operation")
	flag.DurationVar(&args.Timeout, "t", 0, "Timeout for the entire operation (shorthand)")

	flag.BoolVar(&args.Verbose, "verbose", false, "Enable verbose output")
	flag.BoolVar(&args.Verbose, "v", false, "Enable verbose output (shorthand)")

	flag.BoolVar(&args.Quiet, "quiet", false, "Suppress non-error output")
	flag.BoolVar(&args.Quiet, "q", false, "Suppress non-error output (shorthand)")

	flag.BoolVar(&args.ShowConfig, "show-config", false, "Show current configuration and exit")
	flag.StringVar(&args.SaveConfig, "save-config", "", "Save current configuration to file")

	flag.BoolVar(&args.WebUI, "web", false, "Start web UI server")
	flag.IntVar(&args.WebPort, "web-port", 8080, "Port for web UI server")
	flag.StringVar(&args.WebHost, "web-host", "localhost", "Host for web UI server")
	flag.BoolVar(&args.WebTLS, "web-tls", false, "Enable TLS for web UI")
	flag.StringVar(&args.CertFile, "cert-file", "", "TLS certificate file")
	flag.StringVar(&args.KeyFile, "key-file", "", "TLS private key file")

	flag.BoolVar(&args.ShowVersion, "version", false, "Show version information")
	flag.BoolVar(&args.ShowHelp, "help", false, "Show help information")
	flag.BoolVar(&args.ShowHelp, "h", false, "Show help information (shorthand)")

	// Custom usage function
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "File Encryptor - Secure file encryption tool\n\n")
		fmt.Fprintf(os.Stderr, "Usage: %s [options] [files...]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Operations:\n")
		fmt.Fprintf(os.Stderr, "  -e, --encrypt          Encrypt the specified files\n")
		fmt.Fprintf(os.Stderr, "  -d, --decrypt          Decrypt the specified files\n")
		fmt.Fprintf(os.Stderr, "  --generate-keys        Generate a new RSA key pair\n")
		fmt.Fprintf(os.Stderr, "\nFiles and Keys:\n")
		fmt.Fprintf(os.Stderr, "  -f, --file FILE        Files to process (can be used multiple times)\n")
		fmt.Fprintf(os.Stderr, "  -k, --key FILE         Path to key file (public for encrypt, private for decrypt)\n")
		fmt.Fprintf(os.Stderr, "  -p, --password PASS    Password for encryption/decryption\n")
		fmt.Fprintf(os.Stderr, "  --key-name NAME        Base name for generated key files (default: key)\n")
		fmt.Fprintf(os.Stderr, "\nConfiguration:\n")
		fmt.Fprintf(os.Stderr, "  -c, --config FILE      Path to configuration file\n")
		fmt.Fprintf(os.Stderr, "  -t, --timeout DURATION Timeout for operation (e.g., 30m, 1h)\n")
		fmt.Fprintf(os.Stderr, "  --show-config          Show current configuration\n")
		fmt.Fprintf(os.Stderr, "  --save-config FILE     Save current configuration to file\n")
		fmt.Fprintf(os.Stderr, "\nOutput:\n")
		fmt.Fprintf(os.Stderr, "  -v, --verbose          Enable verbose output\n")
		fmt.Fprintf(os.Stderr, "  -q, --quiet            Suppress non-error output\n")
		fmt.Fprintf(os.Stderr, "  --version              Show version information\n")
		fmt.Fprintf(os.Stderr, "  -h, --help             Show this help message\n")
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  # Encrypt files with password\n")
		fmt.Fprintf(os.Stderr, "  %s -e -p mypassword file1.txt file2.pdf\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\n  # Encrypt with RSA public key\n")
		fmt.Fprintf(os.Stderr, "  %s -e -k public.key -f document.docx\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\n  # Decrypt with private key\n")
		fmt.Fprintf(os.Stderr, "  %s -d -k private.key document.docx.enc\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\n  # Generate keys and encrypt\n")
		fmt.Fprintf(os.Stderr, "  %s --generate-keys -e -f secret.txt\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\nEnvironment Variables:\n")
		fmt.Fprintf(os.Stderr, "  FILE_ENCRYPTOR_LOG_LEVEL     Set log level (debug, info, warn, error)\n")
		fmt.Fprintf(os.Stderr, "  FILE_ENCRYPTOR_MAX_WORKERS   Set maximum worker threads\n")
		fmt.Fprintf(os.Stderr, "  FILE_ENCRYPTOR_TIMEOUT       Set default timeout\n")
		fmt.Fprintf(os.Stderr, "  FILE_ENCRYPTOR_DEBUG         Enable debug mode (true/false)\n")
	}

	// Parse flags
	flag.Parse()

	// Add remaining arguments as files (if they don't start with -)
	remainingArgs := flag.Args()
	for _, arg := range remainingArgs {
		if !strings.HasPrefix(arg, "-") {
			files = append(files, arg)
		}
	}

	args.Files = []string(files)

	return args, nil
}

// ValidateArgs validates the parsed CLI arguments
func ValidateArgs(args *CLIArgs, config *Config) error {
	// Handle special cases first
	if args.ShowHelp {
		flag.Usage()
		os.Exit(0)
	}

	if args.ShowVersion {
		if Version != "dev" {
			fmt.Printf("File Encryptor %s\n", Version)
			fmt.Printf("Git Commit: %s\n", GitCommit)
			fmt.Printf("Build Time: %s\n", BuildTime)
		} else {
			fmt.Printf("File Encryptor %s (development build)\n", AppVersion)
		}
		fmt.Printf("Built with Go %s\n", "1.23+")
		os.Exit(0)
	}

	if args.ShowConfig {
		return nil // Will be handled in main
	}

	if args.SaveConfig != "" {
		return nil // Will be handled in main
	}

	// Validate conflicting options
	if args.Verbose && args.Quiet {
		return fmt.Errorf("cannot specify both --verbose and --quiet")
	}

	// Handle key generation special case
	if args.GenerateKeys && !args.Encrypt && len(args.Files) == 0 {
		return nil // Just generating keys
	}

	if args.GenerateKeys {
		if args.Decrypt || args.Key != "" || args.Password != "" {
			return fmt.Errorf("--generate-keys cannot be combined with decrypt, key, or password options")
		}
	}

	// Validate operation selection
	if (args.Encrypt && args.Decrypt) || (!args.Encrypt && !args.Decrypt && !args.GenerateKeys) {
		return fmt.Errorf("please specify either -e/--encrypt or -d/--decrypt")
	}

	// Validate files
	if len(args.Files) == 0 && !args.GenerateKeys {
		return fmt.Errorf("please provide at least one file using --file/-f or as arguments")
	}

	// Validate authentication method
	if args.Key == "" && args.Password == "" && !args.GenerateKeys {
		return fmt.Errorf("please provide either --key/-k or --password/-p")
	}

	if args.Key != "" && args.Password != "" {
		return fmt.Errorf("please provide either --key/-k or --password/-p, not both")
	}

	// Validate file existence and permissions
	if err := validateFiles(args.Files, args.Encrypt); err != nil {
		return err
	}

	// Validate key file if specified
	if args.Key != "" {
		if err := validateKeyFile(args.Key); err != nil {
			return fmt.Errorf("key file validation failed: %w", err)
		}
	}

	return nil
}

// validateFiles checks if the specified files exist and are accessible
func validateFiles(files []string, isEncryption bool) error {
	for _, file := range files {
		if err := validateSingleFile(file, isEncryption); err != nil {
			return fmt.Errorf("file '%s': %w", file, err)
		}
	}
	return nil
}

// validateSingleFile validates a single file
func validateSingleFile(file string, isEncryption bool) error {
	info, err := os.Stat(file)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("file does not exist")
		}
		return fmt.Errorf("cannot access file: %w", err)
	}

	if info.IsDir() {
		return fmt.Errorf("is a directory, not a file")
	}

	// Check file permissions
	if isEncryption {
		// For encryption, we need read access
		if err := checkReadPermission(file); err != nil {
			return fmt.Errorf("cannot read file: %w", err)
		}
	} else {
		// For decryption, check if it looks like an encrypted file
		if !strings.HasSuffix(file, ".enc") {
			return fmt.Errorf("file does not appear to be encrypted (missing .enc extension)")
		}
		if err := checkReadPermission(file); err != nil {
			return fmt.Errorf("cannot read encrypted file: %w", err)
		}
	}

	// Check if file is too large (optional warning)
	if info.Size() > 10<<30 { // 10GB
		fmt.Fprintf(os.Stderr, "Warning: File '%s' is very large (%s). This may take a long time.\n",
			file, formatBytes(info.Size()))
	}

	return nil
}

// validateKeyFile checks if the key file exists and is accessible
func validateKeyFile(keyFile string) error {
	info, err := os.Stat(keyFile)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("key file does not exist")
		}
		return fmt.Errorf("cannot access key file: %w", err)
	}

	if info.IsDir() {
		return fmt.Errorf("key path is a directory, not a file")
	}

	if err := checkReadPermission(keyFile); err != nil {
		return fmt.Errorf("cannot read key file: %w", err)
	}

	return nil
}

// checkReadPermission checks if we can read the file
func checkReadPermission(file string) error {
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	f.Close()
	return nil
}

// formatBytes formats byte count as human readable string
func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// GetConfigPath returns the configuration file path, checking multiple locations
func GetConfigPath(specified string) string {
	if specified != "" {
		return specified
	}

	// Check common configuration locations
	locations := []string{
		"./file-encryptor.yaml",
		"./file-encryptor.yml",
		"~/.config/file-encryptor/config.yaml",
		"~/.file-encryptor.yaml",
	}

	for _, location := range locations {
		// Expand home directory
		if strings.HasPrefix(location, "~/") {
			home, err := os.UserHomeDir()
			if err == nil {
				location = filepath.Join(home, location[2:])
			}
		}

		if _, err := os.Stat(location); err == nil {
			return location
		}
	}

	return "" // No config file found
}
