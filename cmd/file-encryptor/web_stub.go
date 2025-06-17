//go:build !web
// +build !web

package main

import (
	"fmt"

	"file-encryptor/pkg/logging"
)

// StartWebServer is a stub function when web build tag is not used
func StartWebServer(config *Config, logger *logging.Logger, args *CLIArgs) error {
	return fmt.Errorf("web UI support not compiled in - rebuild with 'make build-web' or use build tag 'web'")
}
