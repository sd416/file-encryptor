package main

import (
	"os"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	// Test default values
	if config.MaxWorkers != 3 {
		t.Errorf("Expected MaxWorkers to be 3, got %d", config.MaxWorkers)
	}

	if config.ChunkSize != 64*1024 {
		t.Errorf("Expected ChunkSize to be 65536, got %d", config.ChunkSize)
	}

	if config.DefaultTimeout != 30*time.Minute {
		t.Errorf("Expected DefaultTimeout to be 30m, got %v", config.DefaultTimeout)
	}

	if config.LogLevel != "info" {
		t.Errorf("Expected LogLevel to be 'info', got %s", config.LogLevel)
	}

	if config.LogFormat != "text" {
		t.Errorf("Expected LogFormat to be 'text', got %s", config.LogFormat)
	}

	if config.KeySize != 4096 {
		t.Errorf("Expected KeySize to be 4096, got %d", config.KeySize)
	}
}

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name        string
		config      *Config
		expectError bool
	}{
		{
			name:        "Valid config",
			config:      DefaultConfig(),
			expectError: false,
		},
		{
			name: "Invalid MaxWorkers",
			config: &Config{
				MaxWorkers:     0,
				ChunkSize:      64 * 1024,
				DefaultTimeout: 30 * time.Minute,
				LogLevel:       "info",
				LogFormat:      "text",
				KeySize:        4096,
				BufferSize:     64 * 1024,
			},
			expectError: true,
		},
		{
			name: "Invalid ChunkSize",
			config: &Config{
				MaxWorkers:     3,
				ChunkSize:      512, // Too small
				DefaultTimeout: 30 * time.Minute,
				LogLevel:       "info",
				LogFormat:      "text",
				KeySize:        4096,
				BufferSize:     64 * 1024,
			},
			expectError: true,
		},
		{
			name: "Invalid LogLevel",
			config: &Config{
				MaxWorkers:     3,
				ChunkSize:      64 * 1024,
				DefaultTimeout: 30 * time.Minute,
				LogLevel:       "invalid",
				LogFormat:      "text",
				KeySize:        4096,
				BufferSize:     64 * 1024,
			},
			expectError: true,
		},
		{
			name: "Invalid LogFormat",
			config: &Config{
				MaxWorkers:     3,
				ChunkSize:      64 * 1024,
				DefaultTimeout: 30 * time.Minute,
				LogLevel:       "info",
				LogFormat:      "invalid",
				KeySize:        4096,
				BufferSize:     64 * 1024,
			},
			expectError: true,
		},
		{
			name: "Invalid KeySize",
			config: &Config{
				MaxWorkers:     3,
				ChunkSize:      64 * 1024,
				DefaultTimeout: 30 * time.Minute,
				LogLevel:       "info",
				LogFormat:      "text",
				KeySize:        1024, // Too small
				BufferSize:     64 * 1024,
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.expectError && err == nil {
				t.Errorf("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}
		})
	}
}

func TestLoadConfigFromEnv(t *testing.T) {
	// Save original env vars
	originalVars := map[string]string{
		"FILE_ENCRYPTOR_MAX_WORKERS": os.Getenv("FILE_ENCRYPTOR_MAX_WORKERS"),
		"FILE_ENCRYPTOR_LOG_LEVEL":   os.Getenv("FILE_ENCRYPTOR_LOG_LEVEL"),
		"FILE_ENCRYPTOR_DEBUG":       os.Getenv("FILE_ENCRYPTOR_DEBUG"),
	}

	// Clean up after test
	defer func() {
		for key, value := range originalVars {
			if value == "" {
				os.Unsetenv(key)
			} else {
				os.Setenv(key, value)
			}
		}
	}()

	// Set test environment variables
	os.Setenv("FILE_ENCRYPTOR_MAX_WORKERS", "8")
	os.Setenv("FILE_ENCRYPTOR_LOG_LEVEL", "debug")
	os.Setenv("FILE_ENCRYPTOR_DEBUG", "true")

	config, err := LoadConfig("")
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	if config.MaxWorkers != 8 {
		t.Errorf("Expected MaxWorkers to be 8, got %d", config.MaxWorkers)
	}

	if config.LogLevel != "debug" {
		t.Errorf("Expected LogLevel to be 'debug', got %s", config.LogLevel)
	}

	if !config.EnableDebug {
		t.Errorf("Expected EnableDebug to be true, got %v", config.EnableDebug)
	}
}

func TestGetOptimalWorkerCount(t *testing.T) {
	config := DefaultConfig()

	tests := []struct {
		name      string
		fileCount int
		totalSize int64
		expected  int
	}{
		{
			name:      "Few files",
			fileCount: 2,
			totalSize: 1024,
			expected:  2, // Should use fileCount when less than MaxWorkers
		},
		{
			name:      "Many small files",
			fileCount: 10,
			totalSize: 1024,
			expected:  3, // Should use MaxWorkers
		},
		{
			name:      "Large files",
			fileCount: 5,
			totalSize: 2 * 1024 * 1024 * 1024, // 2GB
			expected:  1,                      // Should reduce workers for large files
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := config.GetOptimalWorkerCount(tt.fileCount, tt.totalSize)
			if result != tt.expected {
				t.Errorf("Expected %d workers, got %d", tt.expected, result)
			}
		})
	}
}

func TestConfigSaveAndLoad(t *testing.T) {
	// Create a temporary config file
	tmpFile := "test_config.yaml"
	defer os.Remove(tmpFile)

	// Create a config with custom values
	originalConfig := &Config{
		MaxWorkers:          8,
		ChunkSize:           128 * 1024,
		DefaultTimeout:      60 * time.Minute,
		LogLevel:            "debug",
		LogFormat:           "json",
		EnableDebug:         true,
		KeySize:             2048,
		DefaultKeyName:      "test_key",
		BufferSize:          128 * 1024,
		EnableProgressBar:   false,
		EnableMetrics:       true,
		AdaptiveWorkerCount: false,
	}

	// Save config
	err := originalConfig.SaveConfig(tmpFile)
	if err != nil {
		t.Fatalf("Failed to save config: %v", err)
	}

	// Load config
	loadedConfig, err := LoadConfig(tmpFile)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Compare values
	if loadedConfig.MaxWorkers != originalConfig.MaxWorkers {
		t.Errorf("MaxWorkers mismatch: expected %d, got %d", originalConfig.MaxWorkers, loadedConfig.MaxWorkers)
	}

	if loadedConfig.LogLevel != originalConfig.LogLevel {
		t.Errorf("LogLevel mismatch: expected %s, got %s", originalConfig.LogLevel, loadedConfig.LogLevel)
	}

	if loadedConfig.EnableDebug != originalConfig.EnableDebug {
		t.Errorf("EnableDebug mismatch: expected %v, got %v", originalConfig.EnableDebug, loadedConfig.EnableDebug)
	}
}
