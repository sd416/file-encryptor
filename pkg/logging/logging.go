package logging

import (
	"log"
	"os"
)

type Logger struct {
	logger *log.Logger
}

func NewLogger() *Logger {
	return &Logger{
		logger: log.New(os.Stdout, "", log.Ldate|log.Ltime),
	}
}

func (l *Logger) Log(message string) {
	l.logger.Println(message)
}

func (l *Logger) LogError(message string) {
	l.logger.Printf("Error: %s", message)
}