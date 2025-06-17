package logging

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"runtime"
	"strings"
	"time"
)

// LogLevel type to define log levels
type LogLevel int

const (
	DEBUG LogLevel = iota
	INFO
	WARN
	ERROR
)

// LogFormat type to define log output formats
type LogFormat int

const (
	TEXT LogFormat = iota
	JSON
)

// LogEntry represents a structured log entry
type LogEntry struct {
	Timestamp string                 `json:"timestamp"`
	Level     string                 `json:"level"`
	Message   string                 `json:"message"`
	Fields    map[string]interface{} `json:"fields,omitempty"`
	Caller    string                 `json:"caller,omitempty"`
}

type Logger struct {
	logger     *log.Logger
	logLevel   LogLevel
	logFormat  LogFormat
	output     io.Writer
	fields     map[string]interface{}
	showCaller bool
}

// NewLogger creates a new logger instance with default settings
func NewLogger() *Logger {
	// Default log level should be INFO unless specified otherwise
	logLevelEnv := strings.ToUpper(os.Getenv("LOG_LEVEL"))
	var logLevel LogLevel
	switch logLevelEnv {
	case "DEBUG":
		logLevel = DEBUG
	case "WARN":
		logLevel = WARN
	case "ERROR":
		logLevel = ERROR
	default:
		logLevel = INFO
	}

	// Default log format
	logFormatEnv := strings.ToLower(os.Getenv("LOG_FORMAT"))
	var logFormat LogFormat
	switch logFormatEnv {
	case "json":
		logFormat = JSON
	default:
		logFormat = TEXT
	}

	return &Logger{
		logger:     log.New(os.Stdout, "", 0), // We'll handle our own formatting
		logLevel:   logLevel,
		logFormat:  logFormat,
		output:     os.Stdout,
		fields:     make(map[string]interface{}),
		showCaller: logLevel == DEBUG,
	}
}

// NewLoggerWithConfig creates a new logger with specific configuration
func NewLoggerWithConfig(level string, format string, debug bool) *Logger {
	logger := NewLogger()
	logger.SetLogLevelFromString(level)
	logger.SetLogFormatFromString(format)
	logger.showCaller = debug
	return logger
}

// SetLogLevel sets the log level
func (l *Logger) SetLogLevel(level LogLevel) {
	l.logLevel = level
	l.showCaller = level == DEBUG
}

// SetLogLevelFromString sets the log level from a string
func (l *Logger) SetLogLevelFromString(level string) {
	switch strings.ToUpper(level) {
	case "DEBUG":
		l.SetLogLevel(DEBUG)
	case "WARN":
		l.SetLogLevel(WARN)
	case "ERROR":
		l.SetLogLevel(ERROR)
	default:
		l.SetLogLevel(INFO)
	}
}

// SetLogFormat sets the log format
func (l *Logger) SetLogFormat(format LogFormat) {
	l.logFormat = format
}

// SetLogFormatFromString sets the log format from a string
func (l *Logger) SetLogFormatFromString(format string) {
	switch strings.ToLower(format) {
	case "json":
		l.SetLogFormat(JSON)
	default:
		l.SetLogFormat(TEXT)
	}
}

// WithFields returns a new logger with additional fields
func (l *Logger) WithFields(fields map[string]interface{}) *Logger {
	newLogger := *l
	newLogger.fields = make(map[string]interface{})

	// Copy existing fields
	for k, v := range l.fields {
		newLogger.fields[k] = v
	}

	// Add new fields
	for k, v := range fields {
		newLogger.fields[k] = v
	}

	return &newLogger
}

// WithField returns a new logger with an additional field
func (l *Logger) WithField(key string, value interface{}) *Logger {
	return l.WithFields(map[string]interface{}{key: value})
}

// Log logs a message with a specific log level
func (l *Logger) Log(level LogLevel, message string) {
	if level >= l.logLevel {
		l.writeLog(level, message, nil)
	}
}

// Logf logs a formatted message with a specific log level
func (l *Logger) Logf(level LogLevel, format string, v ...interface{}) {
	if level >= l.logLevel {
		message := fmt.Sprintf(format, v...)
		l.writeLog(level, message, nil)
	}
}

// LogWithFields logs a message with additional fields
func (l *Logger) LogWithFields(level LogLevel, message string, fields map[string]interface{}) {
	if level >= l.logLevel {
		l.writeLog(level, message, fields)
	}
}

// LogDebug logs a debug message
func (l *Logger) LogDebug(message string) {
	l.Log(DEBUG, message)
}

// LogDebugf logs a formatted debug message
func (l *Logger) LogDebugf(format string, v ...interface{}) {
	l.Logf(DEBUG, format, v...)
}

// LogInfo logs an info message
func (l *Logger) LogInfo(message string) {
	l.Log(INFO, message)
}

// LogInfof logs a formatted info message
func (l *Logger) LogInfof(format string, v ...interface{}) {
	l.Logf(INFO, format, v...)
}

// LogWarn logs a warning message
func (l *Logger) LogWarn(message string) {
	l.Log(WARN, message)
}

// LogWarnf logs a formatted warning message
func (l *Logger) LogWarnf(format string, v ...interface{}) {
	l.Logf(WARN, format, v...)
}

// LogError logs an error message
func (l *Logger) LogError(message string) {
	l.Log(ERROR, message)
}

// LogErrorf logs a formatted error message
func (l *Logger) LogErrorf(format string, v ...interface{}) {
	l.Logf(ERROR, format, v...)
}

// writeLog handles the actual log writing with proper formatting
func (l *Logger) writeLog(level LogLevel, message string, extraFields map[string]interface{}) {
	entry := LogEntry{
		Timestamp: time.Now().Format(time.RFC3339),
		Level:     l.levelToString(level),
		Message:   message,
		Fields:    make(map[string]interface{}),
	}

	// Add logger fields
	for k, v := range l.fields {
		entry.Fields[k] = v
	}

	// Add extra fields
	for k, v := range extraFields {
		entry.Fields[k] = v
	}

	// Add caller information if enabled
	if l.showCaller {
		if _, file, line, ok := runtime.Caller(3); ok {
			entry.Caller = fmt.Sprintf("%s:%d", file, line)
		}
	}

	// Remove empty fields map
	if len(entry.Fields) == 0 {
		entry.Fields = nil
	}

	var output string
	switch l.logFormat {
	case JSON:
		if jsonBytes, err := json.Marshal(entry); err == nil {
			output = string(jsonBytes)
		} else {
			output = l.formatTextLog(level, message) // Fallback to text
		}
	default:
		output = l.formatTextLog(level, message)
	}

	fmt.Fprintln(l.output, output)
}

// formatTextLog formats a log entry as text
func (l *Logger) formatTextLog(level LogLevel, message string) string {
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	levelStr := l.levelToString(level)

	var fieldsStr string
	if len(l.fields) > 0 {
		var fieldPairs []string
		for k, v := range l.fields {
			fieldPairs = append(fieldPairs, fmt.Sprintf("%s=%v", k, v))
		}
		fieldsStr = fmt.Sprintf(" [%s]", strings.Join(fieldPairs, " "))
	}

	var callerStr string
	if l.showCaller {
		if _, file, line, ok := runtime.Caller(3); ok {
			callerStr = fmt.Sprintf(" (%s:%d)", file, line)
		}
	}

	return fmt.Sprintf("%s [%s]%s%s %s", timestamp, levelStr, fieldsStr, callerStr, message)
}

// levelToString converts LogLevel to string
func (l *Logger) levelToString(level LogLevel) string {
	switch level {
	case DEBUG:
		return "DEBUG"
	case INFO:
		return "INFO"
	case WARN:
		return "WARN"
	case ERROR:
		return "ERROR"
	default:
		return "UNKNOWN"
	}
}

// formatLog function to format the log message (kept for backward compatibility)
func (l *Logger) formatLog(level LogLevel, message string) string {
	return fmt.Sprintf("[%s] %s", l.levelToString(level), message)
}
