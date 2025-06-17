package main

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"gopkg.in/yaml.v3"
)

// Config holds all configuration options for the file encryptor
type Config struct {
	// Core settings
	MaxWorkers     int           `yaml:"max_workers" env:"FILE_ENCRYPTOR_MAX_WORKERS"`
	ChunkSize      int           `yaml:"chunk_size" env:"FILE_ENCRYPTOR_CHUNK_SIZE"`
	DefaultTimeout time.Duration `yaml:"default_timeout" env:"FILE_ENCRYPTOR_TIMEOUT"`

	// Logging settings
	LogLevel    string `yaml:"log_level" env:"FILE_ENCRYPTOR_LOG_LEVEL"`
	LogFormat   string `yaml:"log_format" env:"FILE_ENCRYPTOR_LOG_FORMAT"` // "text" or "json"
	EnableDebug bool   `yaml:"enable_debug" env:"FILE_ENCRYPTOR_DEBUG"`

	// Security settings
	KeySize        int    `yaml:"key_size" env:"FILE_ENCRYPTOR_KEY_SIZE"`
	DefaultKeyName string `yaml:"default_key_name" env:"FILE_ENCRYPTOR_KEY_NAME"`

	// Performance settings
	BufferSize          int  `yaml:"buffer_size" env:"FILE_ENCRYPTOR_BUFFER_SIZE"`
	EnableProgressBar   bool `yaml:"enable_progress_bar" env:"FILE_ENCRYPTOR_PROGRESS"`
	EnableMetrics       bool `yaml:"enable_metrics" env:"FILE_ENCRYPTOR_METRICS"`
	AdaptiveWorkerCount bool `yaml:"adaptive_worker_count" env:"FILE_ENCRYPTOR_ADAPTIVE_WORKERS"`
}

// DefaultConfig returns a configuration with sensible defaults
func DefaultConfig() *Config {
	return &Config{
		MaxWorkers:          3,
		ChunkSize:           64 * 1024, // 64KB
		DefaultTimeout:      30 * time.Minute,
		LogLevel:            "info",
		LogFormat:           "text",
		EnableDebug:         false,
		KeySize:             4096,
		DefaultKeyName:      "key",
		BufferSize:          64 * 1024, // 64KB
		EnableProgressBar:   true,
		EnableMetrics:       false,
		AdaptiveWorkerCount: true,
	}
}

// LoadConfig loads configuration from file and environment variables
func LoadConfig(configPath string) (*Config, error) {
	config := DefaultConfig()

	// Load from config file if it exists
	if configPath != "" {
		if err := loadFromFile(config, configPath); err != nil {
			return nil, fmt.Errorf("failed to load config file: %w", err)
		}
	}

	// Override with environment variables
	if err := loadFromEnv(config); err != nil {
		return nil, fmt.Errorf("failed to load environment variables: %w", err)
	}

	// Validate configuration
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return config, nil
}

// loadFromFile loads configuration from a YAML file
func loadFromFile(config *Config, path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil // File doesn't exist, use defaults
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	return yaml.Unmarshal(data, config)
}

// loadFromEnv loads configuration from environment variables
func loadFromEnv(config *Config) error {
	// MaxWorkers
	if val := os.Getenv("FILE_ENCRYPTOR_MAX_WORKERS"); val != "" {
		if parsed, err := strconv.Atoi(val); err == nil {
			config.MaxWorkers = parsed
		}
	}

	// ChunkSize
	if val := os.Getenv("FILE_ENCRYPTOR_CHUNK_SIZE"); val != "" {
		if parsed, err := strconv.Atoi(val); err == nil {
			config.ChunkSize = parsed
		}
	}

	// DefaultTimeout
	if val := os.Getenv("FILE_ENCRYPTOR_TIMEOUT"); val != "" {
		if parsed, err := time.ParseDuration(val); err == nil {
			config.DefaultTimeout = parsed
		}
	}

	// LogLevel
	if val := os.Getenv("FILE_ENCRYPTOR_LOG_LEVEL"); val != "" {
		config.LogLevel = val
	}

	// LogFormat
	if val := os.Getenv("FILE_ENCRYPTOR_LOG_FORMAT"); val != "" {
		config.LogFormat = val
	}

	// EnableDebug
	if val := os.Getenv("FILE_ENCRYPTOR_DEBUG"); val != "" {
		config.EnableDebug = val == "true" || val == "1"
	}

	// KeySize
	if val := os.Getenv("FILE_ENCRYPTOR_KEY_SIZE"); val != "" {
		if parsed, err := strconv.Atoi(val); err == nil {
			config.KeySize = parsed
		}
	}

	// DefaultKeyName
	if val := os.Getenv("FILE_ENCRYPTOR_KEY_NAME"); val != "" {
		config.DefaultKeyName = val
	}

	// BufferSize
	if val := os.Getenv("FILE_ENCRYPTOR_BUFFER_SIZE"); val != "" {
		if parsed, err := strconv.Atoi(val); err == nil {
			config.BufferSize = parsed
		}
	}

	// EnableProgressBar
	if val := os.Getenv("FILE_ENCRYPTOR_PROGRESS"); val != "" {
		config.EnableProgressBar = val == "true" || val == "1"
	}

	// EnableMetrics
	if val := os.Getenv("FILE_ENCRYPTOR_METRICS"); val != "" {
		config.EnableMetrics = val == "true" || val == "1"
	}

	// AdaptiveWorkerCount
	if val := os.Getenv("FILE_ENCRYPTOR_ADAPTIVE_WORKERS"); val != "" {
		config.AdaptiveWorkerCount = val == "true" || val == "1"
	}

	return nil
}

// Validate checks if the configuration values are valid
func (c *Config) Validate() error {
	if c.MaxWorkers < 1 {
		return fmt.Errorf("max_workers must be at least 1")
	}

	if c.ChunkSize < 1024 {
		return fmt.Errorf("chunk_size must be at least 1024 bytes")
	}

	if c.DefaultTimeout < time.Second {
		return fmt.Errorf("default_timeout must be at least 1 second")
	}

	validLogLevels := map[string]bool{
		"debug": true,
		"info":  true,
		"warn":  true,
		"error": true,
	}
	if !validLogLevels[c.LogLevel] {
		return fmt.Errorf("log_level must be one of: debug, info, warn, error")
	}

	validLogFormats := map[string]bool{
		"text": true,
		"json": true,
	}
	if !validLogFormats[c.LogFormat] {
		return fmt.Errorf("log_format must be either 'text' or 'json'")
	}

	if c.KeySize < 2048 {
		return fmt.Errorf("key_size must be at least 2048 bits")
	}

	if c.BufferSize < 1024 {
		return fmt.Errorf("buffer_size must be at least 1024 bytes")
	}

	return nil
}

// SaveConfig saves the current configuration to a file
func (c *Config) SaveConfig(path string) error {
	data, err := yaml.Marshal(c)
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0644)
}

// GetOptimalWorkerCount calculates the optimal number of workers based on configuration and system resources
func (c *Config) GetOptimalWorkerCount(fileCount int, totalSize int64) int {
	if !c.AdaptiveWorkerCount {
		return c.MaxWorkers
	}

	// Start with configured max workers
	workers := c.MaxWorkers

	// Adjust based on file count
	if fileCount < workers {
		workers = fileCount
	}

	// Adjust based on total size (reduce workers for very large files to save memory)
	if totalSize > 1<<30 { // > 1GB total
		workers = workers / 2
		if workers < 1 {
			workers = 1
		}
	}

	return workers
}
