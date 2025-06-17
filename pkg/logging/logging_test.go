package logging

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestNewLogger(t *testing.T) {
	// Save original env vars
	originalLevel := os.Getenv("LOG_LEVEL")
	originalFormat := os.Getenv("LOG_FORMAT")
	
	// Clean up after test
	defer func() {
		if originalLevel == "" {
			os.Unsetenv("LOG_LEVEL")
		} else {
			os.Setenv("LOG_LEVEL", originalLevel)
		}
		if originalFormat == "" {
			os.Unsetenv("LOG_FORMAT")
		} else {
			os.Setenv("LOG_FORMAT", originalFormat)
		}
	}()
	
	// Test default logger
	os.Unsetenv("LOG_LEVEL")
	os.Unsetenv("LOG_FORMAT")
	
	logger := NewLogger()
	if logger.logLevel != INFO {
		t.Errorf("Expected default log level to be INFO, got %v", logger.logLevel)
	}
	
	if logger.logFormat != TEXT {
		t.Errorf("Expected default log format to be TEXT, got %v", logger.logFormat)
	}
	
	// Test with environment variables
	os.Setenv("LOG_LEVEL", "DEBUG")
	os.Setenv("LOG_FORMAT", "json")
	
	logger = NewLogger()
	if logger.logLevel != DEBUG {
		t.Errorf("Expected log level to be DEBUG, got %v", logger.logLevel)
	}
	
	if logger.logFormat != JSON {
		t.Errorf("Expected log format to be JSON, got %v", logger.logFormat)
	}
}

func TestNewLoggerWithConfig(t *testing.T) {
	logger := NewLoggerWithConfig("warn", "json", true)
	
	if logger.logLevel != WARN {
		t.Errorf("Expected log level to be WARN, got %v", logger.logLevel)
	}
	
	if logger.logFormat != JSON {
		t.Errorf("Expected log format to be JSON, got %v", logger.logFormat)
	}
	
	if !logger.showCaller {
		t.Errorf("Expected showCaller to be true")
	}
}

func TestSetLogLevel(t *testing.T) {
	logger := NewLogger()
	
	logger.SetLogLevel(ERROR)
	if logger.logLevel != ERROR {
		t.Errorf("Expected log level to be ERROR, got %v", logger.logLevel)
	}
	
	// Debug mode should be disabled for non-DEBUG levels
	if logger.showCaller {
		t.Errorf("Expected showCaller to be false for ERROR level")
	}
	
	logger.SetLogLevel(DEBUG)
	if !logger.showCaller {
		t.Errorf("Expected showCaller to be true for DEBUG level")
	}
}

func TestSetLogLevelFromString(t *testing.T) {
	logger := NewLogger()
	
	tests := []struct {
		input    string
		expected LogLevel
	}{
		{"debug", DEBUG},
		{"DEBUG", DEBUG},
		{"info", INFO},
		{"INFO", INFO},
		{"warn", WARN},
		{"WARN", WARN},
		{"error", ERROR},
		{"ERROR", ERROR},
		{"invalid", INFO}, // Should default to INFO
		{"", INFO},        // Should default to INFO
	}
	
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			logger.SetLogLevelFromString(tt.input)
			if logger.logLevel != tt.expected {
				t.Errorf("Expected log level %v, got %v", tt.expected, logger.logLevel)
			}
		})
	}
}

func TestSetLogFormatFromString(t *testing.T) {
	logger := NewLogger()
	
	tests := []struct {
		input    string
		expected LogFormat
	}{
		{"text", TEXT},
		{"TEXT", TEXT},
		{"json", JSON},
		{"JSON", JSON},
		{"invalid", TEXT}, // Should default to TEXT
		{"", TEXT},        // Should default to TEXT
	}
	
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			logger.SetLogFormatFromString(tt.input)
			if logger.logFormat != tt.expected {
				t.Errorf("Expected log format %v, got %v", tt.expected, logger.logFormat)
			}
		})
	}
}

func TestWithFields(t *testing.T) {
	logger := NewLogger()
	
	// Add initial fields
	logger = logger.WithFields(map[string]interface{}{
		"component": "test",
		"version":   "1.0",
	})
	
	if len(logger.fields) != 2 {
		t.Errorf("Expected 2 fields, got %d", len(logger.fields))
	}
	
	if logger.fields["component"] != "test" {
		t.Errorf("Expected component field to be 'test', got %v", logger.fields["component"])
	}
	
	// Add more fields
	logger2 := logger.WithFields(map[string]interface{}{
		"operation": "encrypt",
		"files":     5,
	})
	
	if len(logger2.fields) != 4 {
		t.Errorf("Expected 4 fields, got %d", len(logger2.fields))
	}
	
	// Original logger should be unchanged
	if len(logger.fields) != 2 {
		t.Errorf("Original logger should still have 2 fields, got %d", len(logger.fields))
	}
}

func TestWithField(t *testing.T) {
	logger := NewLogger()
	
	logger = logger.WithField("user", "testuser")
	
	if len(logger.fields) != 1 {
		t.Errorf("Expected 1 field, got %d", len(logger.fields))
	}
	
	if logger.fields["user"] != "testuser" {
		t.Errorf("Expected user field to be 'testuser', got %v", logger.fields["user"])
	}
}

func TestLogLevels(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger()
	logger.output = &buf
	logger.SetLogLevel(DEBUG)
	
	// Test all log levels
	logger.LogDebug("debug message")
	logger.LogInfo("info message")
	logger.LogWarn("warn message")
	logger.LogError("error message")
	
	output := buf.String()
	lines := strings.Split(strings.TrimSpace(output), "\n")
	
	if len(lines) != 4 {
		t.Errorf("Expected 4 log lines, got %d", len(lines))
	}
	
	// Check that each level appears in output
	expectedLevels := []string{"DEBUG", "INFO", "WARN", "ERROR"}
	for i, expectedLevel := range expectedLevels {
		if !strings.Contains(lines[i], expectedLevel) {
			t.Errorf("Expected line %d to contain %s, got: %s", i, expectedLevel, lines[i])
		}
	}
}

func TestLogFiltering(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger()
	logger.output = &buf
	logger.SetLogLevel(WARN) // Only WARN and ERROR should be logged
	
	logger.LogDebug("debug message")
	logger.LogInfo("info message")
	logger.LogWarn("warn message")
	logger.LogError("error message")
	
	output := buf.String()
	lines := strings.Split(strings.TrimSpace(output), "\n")
	
	// Should only have 2 lines (WARN and ERROR)
	if len(lines) != 2 {
		t.Errorf("Expected 2 log lines, got %d", len(lines))
	}
	
	if !strings.Contains(lines[0], "WARN") {
		t.Errorf("Expected first line to contain WARN, got: %s", lines[0])
	}
	
	if !strings.Contains(lines[1], "ERROR") {
		t.Errorf("Expected second line to contain ERROR, got: %s", lines[1])
	}
}

func TestJSONFormat(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger()
	logger.output = &buf
	logger.SetLogFormat(JSON)
	logger.SetLogLevel(INFO)
	
	// Add some fields
	logger = logger.WithFields(map[string]interface{}{
		"component": "test",
		"count":     42,
	})
	
	logger.LogInfo("test message")
	
	output := strings.TrimSpace(buf.String())
	
	// Parse as JSON to verify it's valid
	var entry LogEntry
	err := json.Unmarshal([]byte(output), &entry)
	if err != nil {
		t.Fatalf("Failed to parse JSON output: %v", err)
	}
	
	// Verify fields
	if entry.Level != "INFO" {
		t.Errorf("Expected level to be INFO, got %s", entry.Level)
	}
	
	if entry.Message != "test message" {
		t.Errorf("Expected message to be 'test message', got %s", entry.Message)
	}
	
	if entry.Fields["component"] != "test" {
		t.Errorf("Expected component field to be 'test', got %v", entry.Fields["component"])
	}
	
	// count should be parsed as float64 in JSON
	if entry.Fields["count"] != float64(42) {
		t.Errorf("Expected count field to be 42, got %v", entry.Fields["count"])
	}
}

func TestTextFormat(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger()
	logger.output = &buf
	logger.SetLogFormat(TEXT)
	logger.SetLogLevel(INFO)
	
	// Add some fields
	logger = logger.WithFields(map[string]interface{}{
		"component": "test",
		"count":     42,
	})
	
	logger.LogInfo("test message")
	
	output := strings.TrimSpace(buf.String())
	
	// Verify text format contains expected elements
	if !strings.Contains(output, "[INFO]") {
		t.Errorf("Expected output to contain [INFO], got: %s", output)
	}
	
	if !strings.Contains(output, "test message") {
		t.Errorf("Expected output to contain 'test message', got: %s", output)
	}
	
	if !strings.Contains(output, "component=test") {
		t.Errorf("Expected output to contain 'component=test', got: %s", output)
	}
	
	if !strings.Contains(output, "count=42") {
		t.Errorf("Expected output to contain 'count=42', got: %s", output)
	}
}

func TestLogf(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger()
	logger.output = &buf
	logger.SetLogLevel(DEBUG)
	
	logger.LogInfof("Processing %d files with %s encryption", 5, "AES")
	
	output := strings.TrimSpace(buf.String())
	
	if !strings.Contains(output, "Processing 5 files with AES encryption") {
		t.Errorf("Expected formatted message, got: %s", output)
	}
}

func TestLogWithFields(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger()
	logger.output = &buf
	logger.SetLogFormat(JSON)
	logger.SetLogLevel(DEBUG)
	
	logger.LogWithFields(INFO, "operation completed", map[string]interface{}{
		"duration": "5.2s",
		"files":    3,
	})
	
	output := strings.TrimSpace(buf.String())
	
	var entry LogEntry
	err := json.Unmarshal([]byte(output), &entry)
	if err != nil {
		t.Fatalf("Failed to parse JSON output: %v", err)
	}
	
	if entry.Fields["duration"] != "5.2s" {
		t.Errorf("Expected duration field to be '5.2s', got %v", entry.Fields["duration"])
	}
	
	if entry.Fields["files"] != float64(3) {
		t.Errorf("Expected files field to be 3, got %v", entry.Fields["files"])
	}
}

func TestLevelToString(t *testing.T) {
	logger := NewLogger()
	
	tests := []struct {
		level    LogLevel
		expected string
	}{
		{DEBUG, "DEBUG"},
		{INFO, "INFO"},
		{WARN, "WARN"},
		{ERROR, "ERROR"},
		{LogLevel(999), "UNKNOWN"}, // Invalid level
	}
	
	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := logger.levelToString(tt.level)
			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestCallerInformation(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger()
	logger.output = &buf
	logger.SetLogFormat(JSON)
	logger.SetLogLevel(DEBUG)
	logger.showCaller = true
	
	logger.LogInfo("test message")
	
	output := strings.TrimSpace(buf.String())
	
	var entry LogEntry
	err := json.Unmarshal([]byte(output), &entry)
	if err != nil {
		t.Fatalf("Failed to parse JSON output: %v", err)
	}
	
	// Caller should be present and contain file name and line number
	if entry.Caller == "" {
		t.Errorf("Expected caller information to be present")
	}
	
	if !strings.Contains(entry.Caller, "logging_test.go") {
		t.Errorf("Expected caller to contain file name, got: %s", entry.Caller)
	}
	
	if !strings.Contains(entry.Caller, ":") {
		t.Errorf("Expected caller to contain line number, got: %s", entry.Caller)
	}
}
