package logging

import (
	"fmt"
	"log"
	"os"
	"strings"
)

// LogLevel type to define log levels
type LogLevel int

const (
	DEBUG LogLevel = iota
	INFO
	ERROR
)

type Logger struct {
	logger    *log.Logger
	logLevel  LogLevel
}

// NewLogger function to create a new logger instance
func NewLogger() *Logger {
    // default log level should be INFO unless specified otherwise
	logLevelEnv := strings.ToUpper(os.Getenv("LOG_LEVEL"))
    var logLevel LogLevel
    switch logLevelEnv {
    case "DEBUG":
        logLevel = DEBUG
    case "ERROR":
        logLevel = ERROR
    default:
        logLevel = INFO
    }

	return &Logger{
		logger:    log.New(os.Stdout, "", log.Ldate|log.Ltime),
		logLevel:  logLevel,
	}
}

// SetLogLevel function to set the log level
func (l *Logger) SetLogLevel(level LogLevel) {
	l.logLevel = level
}

// Log function to log a message with a specific log level
func (l *Logger) Log(level LogLevel, message string) {
	if level >= l.logLevel {
		l.logger.Println(l.formatLog(level, message))
	}
}

// Logf function to log a formatted message with a specific log level
func (l *Logger) Logf(level LogLevel, format string, v ...interface{}) {
	if level >= l.logLevel {
		l.logger.Printf(l.formatLog(level, format), v...)
	}
}

// LogInfo function to log an info message
func (l *Logger) LogInfo(message string) {
	l.Log(INFO, message)
}

// LogInfof function to log a formatted info message
func (l *Logger) LogInfof(format string, v ...interface{}) {
	l.Logf(INFO, format, v...)
}


// LogDebug function to log a debug message
func (l *Logger) LogDebug(message string) {
	l.Log(DEBUG, message)
}

// LogDebugf function to log a formatted debug message
func (l *Logger) LogDebugf(format string, v ...interface{}) {
    l.Logf(DEBUG, format, v...)
}


// LogError function to log an error message
func (l *Logger) LogError(message string) {
	l.Log(ERROR, message)
}

// LogErrorf function to log a formatted error message
func (l *Logger) LogErrorf(format string, v ...interface{}) {
	l.Logf(ERROR, format, v...)
}

// formatLog function to format the log message
func (l *Logger) formatLog(level LogLevel, message string) string {
	levelStr := ""
	switch level {
	case DEBUG:
		levelStr = "DEBUG"
	case INFO:
		levelStr = "INFO"
	case ERROR:
		levelStr = "ERROR"
	}
	return fmt.Sprintf("[%s] %s", levelStr, message)
}
