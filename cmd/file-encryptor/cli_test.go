package main

import (
	"os"
	"strings"
	"testing"
)

func TestStringSliceFlag(t *testing.T) {
	var flag stringSliceFlag

	// Test adding values
	err := flag.Set("file1.txt")
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	err = flag.Set("file2.txt")
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	// Test string representation
	result := flag.String()
	expected := "file1.txt,file2.txt"
	if result != expected {
		t.Errorf("Expected %s, got %s", expected, result)
	}

	// Test slice contents
	if len(flag) != 2 {
		t.Errorf("Expected 2 items, got %d", len(flag))
	}

	if flag[0] != "file1.txt" || flag[1] != "file2.txt" {
		t.Errorf("Unexpected slice contents: %v", flag)
	}
}

func TestValidateArgs(t *testing.T) {
	config := DefaultConfig()

	// Create temporary test files for validation tests
	tmpFile := "testfile.txt"
	file, err := os.Create(tmpFile)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}
	file.WriteString("test content")
	file.Close()
	defer os.Remove(tmpFile)

	tmpEncFile := "testfile.txt.enc"
	encFile, err := os.Create(tmpEncFile)
	if err != nil {
		t.Fatalf("Failed to create test encrypted file: %v", err)
	}
	encFile.WriteString("encrypted content")
	encFile.Close()
	defer os.Remove(tmpEncFile)

	tmpKeyFile := "private.key"
	keyFile, err := os.Create(tmpKeyFile)
	if err != nil {
		t.Fatalf("Failed to create test key file: %v", err)
	}
	keyFile.WriteString("-----BEGIN RSA PRIVATE KEY-----\ntest key\n-----END RSA PRIVATE KEY-----")
	keyFile.Close()
	defer os.Remove(tmpKeyFile)

	tests := []struct {
		name        string
		args        *CLIArgs
		expectError bool
		errorMsg    string
	}{
		{
			name: "Valid encryption with password",
			args: &CLIArgs{
				Encrypt:  true,
				Files:    []string{tmpFile},
				Password: "password123",
			},
			expectError: false,
		},
		{
			name: "Valid decryption with key",
			args: &CLIArgs{
				Decrypt: true,
				Files:   []string{tmpEncFile},
				Key:     tmpKeyFile,
			},
			expectError: false,
		},
		{
			name: "Valid key generation only",
			args: &CLIArgs{
				GenerateKeys: true,
			},
			expectError: false,
		},
		{
			name: "Both encrypt and decrypt",
			args: &CLIArgs{
				Encrypt: true,
				Decrypt: true,
				Files:   []string{"testfile.txt"},
			},
			expectError: true,
			errorMsg:    "either -e",
		},
		{
			name: "Neither encrypt nor decrypt",
			args: &CLIArgs{
				Files: []string{"testfile.txt"},
			},
			expectError: true,
			errorMsg:    "either -e",
		},
		{
			name: "No files provided",
			args: &CLIArgs{
				Encrypt: true,
			},
			expectError: true,
			errorMsg:    "at least one file",
		},
		{
			name: "No authentication method",
			args: &CLIArgs{
				Encrypt: true,
				Files:   []string{"testfile.txt"},
			},
			expectError: true,
			errorMsg:    "either --key",
		},
		{
			name: "Both key and password",
			args: &CLIArgs{
				Encrypt:  true,
				Files:    []string{"testfile.txt"},
				Key:      "key.pub",
				Password: "password123",
			},
			expectError: true,
			errorMsg:    "either --key",
		},
		{
			name: "Verbose and quiet together",
			args: &CLIArgs{
				Encrypt:  true,
				Files:    []string{"testfile.txt"},
				Password: "password123",
				Verbose:  true,
				Quiet:    true,
			},
			expectError: true,
			errorMsg:    "both --verbose and --quiet",
		},
		{
			name: "Generate keys with decrypt",
			args: &CLIArgs{
				GenerateKeys: true,
				Decrypt:      true,
				Files:        []string{"testfile.txt"},
			},
			expectError: true,
			errorMsg:    "cannot be combined",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateArgs(tt.args, config)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				} else if tt.errorMsg != "" && !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error containing '%s', got: %v", tt.errorMsg, err)
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error but got: %v", err)
				}
			}
		})
	}
}

func TestValidateSingleFile(t *testing.T) {
	// Create a temporary test file
	tmpFile := "test_file.txt"
	file, err := os.Create(tmpFile)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}
	file.WriteString("test content")
	file.Close()
	defer os.Remove(tmpFile)

	// Create a temporary encrypted file
	tmpEncFile := "test_file.txt.enc"
	encFile, err := os.Create(tmpEncFile)
	if err != nil {
		t.Fatalf("Failed to create test encrypted file: %v", err)
	}
	encFile.WriteString("encrypted content")
	encFile.Close()
	defer os.Remove(tmpEncFile)

	tests := []struct {
		name         string
		filename     string
		isEncryption bool
		expectError  bool
		errorMsg     string
	}{
		{
			name:         "Valid file for encryption",
			filename:     tmpFile,
			isEncryption: true,
			expectError:  false,
		},
		{
			name:         "Valid encrypted file for decryption",
			filename:     tmpEncFile,
			isEncryption: false,
			expectError:  false,
		},
		{
			name:         "Non-existent file",
			filename:     "nonexistent.txt",
			isEncryption: true,
			expectError:  true,
			errorMsg:     "does not exist",
		},
		{
			name:         "File without .enc extension for decryption",
			filename:     tmpFile,
			isEncryption: false,
			expectError:  true,
			errorMsg:     "does not appear to be encrypted",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSingleFile(tt.filename, tt.isEncryption)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				} else if tt.errorMsg != "" && !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error containing '%s', got: %v", tt.errorMsg, err)
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error but got: %v", err)
				}
			}
		})
	}
}

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		bytes    int64
		expected string
	}{
		{0, "0 B"},
		{512, "512 B"},
		{1024, "1.0 KB"},
		{1536, "1.5 KB"},
		{1024 * 1024, "1.0 MB"},
		{1024 * 1024 * 1024, "1.0 GB"},
		{1024 * 1024 * 1024 * 1024, "1.0 TB"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := formatBytes(tt.bytes)
			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestGetConfigPath(t *testing.T) {
	// Test with specified path
	specified := "/path/to/config.yaml"
	result := GetConfigPath(specified)
	if result != specified {
		t.Errorf("Expected %s, got %s", specified, result)
	}

	// Test with empty path (should check default locations)
	result = GetConfigPath("")
	// Since we don't have config files in default locations during testing,
	// it should return empty string
	if result != "" && result != "./file-encryptor.yaml" {
		// Allow for the case where the default config file exists
		if _, err := os.Stat(result); os.IsNotExist(err) {
			t.Errorf("Expected empty string or existing file, got %s", result)
		}
	}
}

func TestValidateKeyFile(t *testing.T) {
	// Create a temporary key file
	tmpKeyFile := "test_key.pem"
	keyFile, err := os.Create(tmpKeyFile)
	if err != nil {
		t.Fatalf("Failed to create test key file: %v", err)
	}
	keyFile.WriteString("-----BEGIN RSA PRIVATE KEY-----\ntest key content\n-----END RSA PRIVATE KEY-----")
	keyFile.Close()
	defer os.Remove(tmpKeyFile)

	tests := []struct {
		name        string
		keyFile     string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "Valid key file",
			keyFile:     tmpKeyFile,
			expectError: false,
		},
		{
			name:        "Non-existent key file",
			keyFile:     "nonexistent.key",
			expectError: true,
			errorMsg:    "does not exist",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateKeyFile(tt.keyFile)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				} else if tt.errorMsg != "" && !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error containing '%s', got: %v", tt.errorMsg, err)
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error but got: %v", err)
				}
			}
		})
	}
}

func TestCLIArgsDefaults(t *testing.T) {
	args := &CLIArgs{}

	// Test default values
	if args.Encrypt {
		t.Errorf("Expected Encrypt to be false by default")
	}

	if args.Decrypt {
		t.Errorf("Expected Decrypt to be false by default")
	}

	if args.GenerateKeys {
		t.Errorf("Expected GenerateKeys to be false by default")
	}

	if args.Verbose {
		t.Errorf("Expected Verbose to be false by default")
	}

	if args.Quiet {
		t.Errorf("Expected Quiet to be false by default")
	}

	if args.Timeout != 0 {
		t.Errorf("Expected Timeout to be 0 by default, got %v", args.Timeout)
	}
}

func TestValidateFiles(t *testing.T) {
	// Create test files
	tmpFile1 := "test1.txt"
	tmpFile2 := "test2.txt"
	tmpEncFile := "test.txt.enc"

	// Create regular files
	for _, filename := range []string{tmpFile1, tmpFile2} {
		file, err := os.Create(filename)
		if err != nil {
			t.Fatalf("Failed to create test file %s: %v", filename, err)
		}
		file.WriteString("test content")
		file.Close()
		defer os.Remove(filename)
	}

	// Create encrypted file
	encFile, err := os.Create(tmpEncFile)
	if err != nil {
		t.Fatalf("Failed to create test encrypted file: %v", err)
	}
	encFile.WriteString("encrypted content")
	encFile.Close()
	defer os.Remove(tmpEncFile)

	tests := []struct {
		name         string
		files        []string
		isEncryption bool
		expectError  bool
	}{
		{
			name:         "Valid files for encryption",
			files:        []string{tmpFile1, tmpFile2},
			isEncryption: true,
			expectError:  false,
		},
		{
			name:         "Valid encrypted file for decryption",
			files:        []string{tmpEncFile},
			isEncryption: false,
			expectError:  false,
		},
		{
			name:         "Mixed valid and invalid files",
			files:        []string{tmpFile1, "nonexistent.txt"},
			isEncryption: true,
			expectError:  true,
		},
		{
			name:         "Regular file for decryption (should fail)",
			files:        []string{tmpFile1},
			isEncryption: false,
			expectError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateFiles(tt.files, tt.isEncryption)

			if tt.expectError && err == nil {
				t.Errorf("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}
		})
	}
}
