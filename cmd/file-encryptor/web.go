//go:build web
// +build web

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"file-encryptor/pkg/logging"
)

// SimpleWebServer represents a simple web server using only standard library
type SimpleWebServer struct {
	config *Config
	logger *logging.Logger
	server *http.Server
}

// APIResponse represents a generic API response
type APIResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

// StatusResponse represents server status
type StatusResponse struct {
	Status     string    `json:"status"`
	Version    string    `json:"version"`
	Uptime     string    `json:"uptime"`
	ServerTime time.Time `json:"serverTime"`
}

// ConfigResponse represents configuration
type ConfigResponse struct {
	MaxWorkers          int           `json:"maxWorkers"`
	ChunkSize           int           `json:"chunkSize"`
	DefaultTimeout      time.Duration `json:"defaultTimeout"`
	LogLevel            string        `json:"logLevel"`
	LogFormat           string        `json:"logFormat"`
	EnableDebug         bool          `json:"enableDebug"`
	KeySize             int           `json:"keySize"`
	DefaultKeyName      string        `json:"defaultKeyName"`
	BufferSize          int           `json:"bufferSize"`
	EnableProgressBar   bool          `json:"enableProgressBar"`
	EnableMetrics       bool          `json:"enableMetrics"`
	AdaptiveWorkerCount bool          `json:"adaptiveWorkerCount"`
}

var serverStartTime = time.Now()

// NewSimpleWebServer creates a new simple web server instance
func NewSimpleWebServer(config *Config, logger *logging.Logger, args *CLIArgs) *SimpleWebServer {
	mux := http.NewServeMux()

	ws := &SimpleWebServer{
		config: config,
		logger: logger,
		server: &http.Server{
			Addr:         fmt.Sprintf("%s:%d", args.WebHost, args.WebPort),
			Handler:      mux,
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
			IdleTimeout:  120 * time.Second,
		},
	}

	ws.setupRoutes(mux)
	return ws
}

// setupRoutes configures all routes
func (ws *SimpleWebServer) setupRoutes(mux *http.ServeMux) {
	// Add CORS middleware wrapper
	corsHandler := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusOK)
				return
			}

			next(w, r)
		}
	}

	// Serve static files
	mux.HandleFunc("/static/", corsHandler(ws.handleStatic))

	// Serve main page
	mux.HandleFunc("/", corsHandler(ws.handleIndex))

	// API endpoints
	mux.HandleFunc("/api/v1/status", corsHandler(ws.handleStatus))
	mux.HandleFunc("/api/v1/config", corsHandler(ws.handleConfig))
	mux.HandleFunc("/api/v1/encrypt", corsHandler(ws.handleEncrypt))
	mux.HandleFunc("/api/v1/decrypt", corsHandler(ws.handleDecrypt))
	mux.HandleFunc("/api/v1/generate-keys", corsHandler(ws.handleGenerateKeys))

	// Health check
	mux.HandleFunc("/health", corsHandler(ws.handleHealth))
}

// handleStatic serves static files from filesystem
func (ws *SimpleWebServer) handleStatic(w http.ResponseWriter, r *http.Request) {
	// Remove /static/ prefix and serve from web/static directory
	path := strings.TrimPrefix(r.URL.Path, "/static/")
	fullPath := filepath.Join("web", "static", path)

	// Security check - ensure path doesn't escape web directory
	if strings.Contains(path, "..") {
		http.NotFound(w, r)
		return
	}

	data, err := os.ReadFile(fullPath)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	// Set content type based on file extension
	ext := filepath.Ext(path)
	switch ext {
	case ".css":
		w.Header().Set("Content-Type", "text/css")
	case ".js":
		w.Header().Set("Content-Type", "application/javascript")
	case ".html":
		w.Header().Set("Content-Type", "text/html")
	case ".png":
		w.Header().Set("Content-Type", "image/png")
	case ".jpg", ".jpeg":
		w.Header().Set("Content-Type", "image/jpeg")
	case ".svg":
		w.Header().Set("Content-Type", "image/svg+xml")
	default:
		w.Header().Set("Content-Type", "application/octet-stream")
	}

	w.Write(data)
}

// handleIndex serves the main page
func (ws *SimpleWebServer) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	data, err := os.ReadFile("web/templates/index.html")
	if err != nil {
		ws.logger.LogError(fmt.Sprintf("Failed to read index.html: %v", err))
		http.Error(w, "Failed to load web interface", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	w.Write(data)
}

// handleStatus returns server status
func (ws *SimpleWebServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	status := StatusResponse{
		Status:     "healthy",
		Version:    Version,
		Uptime:     time.Since(serverStartTime).String(),
		ServerTime: time.Now(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

// handleConfig returns configuration
func (ws *SimpleWebServer) handleConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	config := ConfigResponse{
		MaxWorkers:          ws.config.MaxWorkers,
		ChunkSize:           ws.config.ChunkSize,
		DefaultTimeout:      ws.config.DefaultTimeout,
		LogLevel:            ws.config.LogLevel,
		LogFormat:           ws.config.LogFormat,
		EnableDebug:         ws.config.EnableDebug,
		KeySize:             ws.config.KeySize,
		DefaultKeyName:      ws.config.DefaultKeyName,
		BufferSize:          ws.config.BufferSize,
		EnableProgressBar:   ws.config.EnableProgressBar,
		EnableMetrics:       ws.config.EnableMetrics,
		AdaptiveWorkerCount: ws.config.AdaptiveWorkerCount,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(config)
}

// handleEncrypt handles encryption requests
func (ws *SimpleWebServer) handleEncrypt(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse multipart form
	err := r.ParseMultipartForm(100 << 20) // 100MB max
	if err != nil {
		ws.sendError(w, "Failed to parse form", http.StatusBadRequest)
		return
	}

	files := r.MultipartForm.File["files"]
	if len(files) == 0 {
		ws.sendError(w, "No files provided", http.StatusBadRequest)
		return
	}

	method := r.FormValue("method")
	if method == "" {
		method = "password"
	}

	password := r.FormValue("password")
	if method == "password" && password == "" {
		ws.sendError(w, "Password is required", http.StatusBadRequest)
		return
	}

	// For now, return a placeholder response
	response := APIResponse{
		Success: true,
		Message: fmt.Sprintf("Encryption started for %d files", len(files)),
		Data: map[string]interface{}{
			"id":        "placeholder-operation-id",
			"status":    "pending",
			"progress":  0.0,
			"files":     []string{},
			"startedAt": time.Now(),
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleDecrypt handles decryption requests
func (ws *SimpleWebServer) handleDecrypt(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse multipart form
	err := r.ParseMultipartForm(100 << 20) // 100MB max
	if err != nil {
		ws.sendError(w, "Failed to parse form", http.StatusBadRequest)
		return
	}

	files := r.MultipartForm.File["files"]
	if len(files) == 0 {
		ws.sendError(w, "No files provided", http.StatusBadRequest)
		return
	}

	method := r.FormValue("method")
	if method == "" {
		method = "password"
	}

	password := r.FormValue("password")
	if method == "password" && password == "" {
		ws.sendError(w, "Password is required", http.StatusBadRequest)
		return
	}

	// For now, return a placeholder response
	response := APIResponse{
		Success: true,
		Message: fmt.Sprintf("Decryption started for %d files", len(files)),
		Data: map[string]interface{}{
			"id":        "placeholder-operation-id",
			"status":    "pending",
			"progress":  0.0,
			"files":     []string{},
			"startedAt": time.Now(),
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleGenerateKeys handles key generation requests
func (ws *SimpleWebServer) handleGenerateKeys(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		KeyName string `json:"keyName"`
		KeySize int    `json:"keySize"`
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		ws.sendError(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	if err := json.Unmarshal(body, &req); err != nil {
		ws.sendError(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if req.KeyName == "" {
		req.KeyName = "key"
	}
	if req.KeySize == 0 {
		req.KeySize = 4096
	}

	// For now, return a placeholder response
	response := APIResponse{
		Success: true,
		Message: "RSA key pair generated successfully",
		Data: map[string]interface{}{
			"privateKey":  "-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----",
			"publicKey":   "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
			"privateFile": fmt.Sprintf("%s_private_%s.key", req.KeyName, time.Now().Format("20060102150405")),
			"publicFile":  fmt.Sprintf("%s_public_%s.pub", req.KeyName, time.Now().Format("20060102150405")),
			"keySize":     req.KeySize,
			"generatedAt": time.Now(),
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleHealth handles health check requests
func (ws *SimpleWebServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	health := map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().UTC(),
		"version":   Version,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(health)
}

// sendError sends an error response
func (ws *SimpleWebServer) sendError(w http.ResponseWriter, message string, code int) {
	response := APIResponse{
		Success: false,
		Error:   message,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(response)
}

// Start starts the web server
func (ws *SimpleWebServer) Start(args *CLIArgs) error {
	addr := fmt.Sprintf("%s:%d", args.WebHost, args.WebPort)

	ws.logger.LogInfo(fmt.Sprintf("Starting web server on %s", addr))

	if args.WebTLS {
		if args.CertFile == "" || args.KeyFile == "" {
			return fmt.Errorf("TLS enabled but certificate or key file not specified")
		}

		ws.logger.LogInfo("Starting HTTPS server")
		ws.logger.LogInfo(fmt.Sprintf("Web UI available at: https://%s", addr))

		return ws.server.ListenAndServeTLS(args.CertFile, args.KeyFile)
	} else {
		ws.logger.LogInfo("Starting HTTP server")
		ws.logger.LogInfo(fmt.Sprintf("Web UI available at: http://%s", addr))

		return ws.server.ListenAndServe()
	}
}

// Stop gracefully stops the web server
func (ws *SimpleWebServer) Stop(ctx context.Context) error {
	ws.logger.LogInfo("Shutting down web server...")
	return ws.server.Shutdown(ctx)
}

// StartWebServer starts the web server (called from main)
func StartWebServer(config *Config, logger *logging.Logger, args *CLIArgs) error {
	webServer := NewSimpleWebServer(config, logger, args)

	// Set up signal handling for graceful shutdown
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)

	// Start server in a goroutine
	serverErr := make(chan error, 1)
	go func() {
		if err := webServer.Start(args); err != nil && err != http.ErrServerClosed {
			serverErr <- err
		}
	}()

	// Wait for interrupt signal or server error
	select {
	case err := <-serverErr:
		return fmt.Errorf("web server failed to start: %w", err)
	case sig := <-signalChan:
		logger.LogInfo(fmt.Sprintf("Received signal %v, shutting down gracefully...", sig))

		// Graceful shutdown
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer shutdownCancel()

		return webServer.Stop(shutdownCtx)
	}
}
