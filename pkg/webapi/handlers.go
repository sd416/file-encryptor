package webapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"

	"file-encryptor/pkg/logging"
)

// APIHandlers contains all the API handlers
type APIHandlers struct {
	config     interface{} // Will be *Config from main package
	logger     *logging.Logger
	operations map[string]*Operation
	opMutex    sync.RWMutex
	upgrader   websocket.Upgrader
	clients    map[string]*websocket.Conn
	clientMutex sync.RWMutex
	startTime  time.Time
	totalOps   int
}

// Operation represents an ongoing operation
type Operation struct {
	ID          string
	Status      string
	Progress    float64
	Files       []FileResult
	Error       string
	StartedAt   time.Time
	CompletedAt *time.Time
	Context     context.Context
	Cancel      context.CancelFunc
}

// NewAPIHandlers creates a new API handlers instance
func NewAPIHandlers(config interface{}, logger *logging.Logger) *APIHandlers {
	return &APIHandlers{
		config:     config,
		logger:     logger,
		operations: make(map[string]*Operation),
		clients:    make(map[string]*websocket.Conn),
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true // In production, implement proper origin checking
			},
		},
		startTime: time.Now(),
	}
}

// generateOperationID generates a unique operation ID
func (h *APIHandlers) generateOperationID() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// HandleEncrypt handles file encryption requests
func (h *APIHandlers) HandleEncrypt(c *gin.Context) {
	h.logger.LogInfo("Received encryption request")

	// Parse multipart form
	form, err := c.MultipartForm()
	if err != nil {
		h.logger.LogError(fmt.Sprintf("Failed to parse multipart form: %v", err))
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "Invalid Form Data",
			Code:    http.StatusBadRequest,
			Message: "Failed to parse multipart form",
			Details: err.Error(),
		})
		return
	}

	// Extract files
	files := form.File["files"]
	if len(files) == 0 {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "No Files",
			Code:    http.StatusBadRequest,
			Message: "No files provided for encryption",
		})
		return
	}

	// Extract parameters
	method := c.PostForm("method")
	password := c.PostForm("password")
	
	if method == "" {
		method = "password" // Default to password
	}

	if method == "password" && password == "" {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "Missing Password",
			Code:    http.StatusBadRequest,
			Message: "Password is required for password-based encryption",
		})
		return
	}

	// Create operation
	opID := h.generateOperationID()
	ctx, cancel := context.WithCancel(context.Background())
	
	operation := &Operation{
		ID:        opID,
		Status:    "pending",
		Progress:  0.0,
		Files:     make([]FileResult, 0, len(files)),
		StartedAt: time.Now(),
		Context:   ctx,
		Cancel:    cancel,
	}

	h.opMutex.Lock()
	h.operations[opID] = operation
	h.totalOps++
	h.opMutex.Unlock()

	// Start encryption in background
	go h.processEncryption(operation, files, method, password)

	// Return operation response
	c.JSON(http.StatusAccepted, OperationResponse{
		ID:        opID,
		Status:    "pending",
		Progress:  0.0,
		Files:     []FileResult{},
		StartedAt: operation.StartedAt,
	})
}

// HandleDecrypt handles file decryption requests
func (h *APIHandlers) HandleDecrypt(c *gin.Context) {
	h.logger.LogInfo("Received decryption request")

	// Parse multipart form
	form, err := c.MultipartForm()
	if err != nil {
		h.logger.LogError(fmt.Sprintf("Failed to parse multipart form: %v", err))
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "Invalid Form Data",
			Code:    http.StatusBadRequest,
			Message: "Failed to parse multipart form",
			Details: err.Error(),
		})
		return
	}

	// Extract files
	files := form.File["files"]
	if len(files) == 0 {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "No Files",
			Code:    http.StatusBadRequest,
			Message: "No files provided for decryption",
		})
		return
	}

	// Extract parameters
	method := c.PostForm("method")
	password := c.PostForm("password")
	
	if method == "" {
		method = "password" // Default to password
	}

	if method == "password" && password == "" {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "Missing Password",
			Code:    http.StatusBadRequest,
			Message: "Password is required for password-based decryption",
		})
		return
	}

	// Create operation
	opID := h.generateOperationID()
	ctx, cancel := context.WithCancel(context.Background())
	
	operation := &Operation{
		ID:        opID,
		Status:    "pending",
		Progress:  0.0,
		Files:     make([]FileResult, 0, len(files)),
		StartedAt: time.Now(),
		Context:   ctx,
		Cancel:    cancel,
	}

	h.opMutex.Lock()
	h.operations[opID] = operation
	h.totalOps++
	h.opMutex.Unlock()

	// Start decryption in background
	go h.processDecryption(operation, files, method, password)

	// Return operation response
	c.JSON(http.StatusAccepted, OperationResponse{
		ID:        opID,
		Status:    "pending",
		Progress:  0.0,
		Files:     []FileResult{},
		StartedAt: operation.StartedAt,
	})
}

// HandleGenerateKeys handles RSA key generation requests
func (h *APIHandlers) HandleGenerateKeys(c *gin.Context) {
	h.logger.LogInfo("Received key generation request")

	var req GenerateKeysRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "Invalid Request",
			Code:    http.StatusBadRequest,
			Message: "Invalid JSON request body",
			Details: err.Error(),
		})
		return
	}

	// Set defaults
	if req.KeyName == "" {
		req.KeyName = "key"
	}
	if req.KeySize == 0 {
		req.KeySize = 4096
	}

	// Validate key size
	if req.KeySize < 2048 || req.KeySize > 8192 {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "Invalid Key Size",
			Code:    http.StatusBadRequest,
			Message: "Key size must be between 2048 and 8192 bits",
		})
		return
	}

	// TODO: Implement actual key generation
	// This would call the existing key generation logic
	
	c.JSON(http.StatusOK, KeyPairResponse{
		PrivateKey:  "-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----",
		PublicKey:   "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
		PrivateFile: fmt.Sprintf("%s_private_%s.key", req.KeyName, time.Now().Format("20060102150405")),
		PublicFile:  fmt.Sprintf("%s_public_%s.pub", req.KeyName, time.Now().Format("20060102150405")),
		KeySize:     req.KeySize,
		GeneratedAt: time.Now(),
	})
}

// HandleGetConfig returns the current configuration
func (h *APIHandlers) HandleGetConfig(c *gin.Context) {
	// TODO: Convert config to ConfigResponse
	// This would access the actual config from the main package
	
	c.JSON(http.StatusOK, ConfigResponse{
		MaxWorkers:          4,
		ChunkSize:           65536,
		DefaultTimeout:      30 * time.Minute,
		LogLevel:            "info",
		LogFormat:           "text",
		EnableDebug:         false,
		KeySize:             4096,
		DefaultKeyName:      "key",
		BufferSize:          65536,
		EnableProgressBar:   true,
		EnableMetrics:       false,
		AdaptiveWorkerCount: true,
	})
}

// HandleGetStatus returns server status
func (h *APIHandlers) HandleGetStatus(c *gin.Context) {
	h.opMutex.RLock()
	activeOps := 0
	for _, op := range h.operations {
		if op.Status == "processing" {
			activeOps++
		}
	}
	totalOps := h.totalOps
	h.opMutex.RUnlock()

	c.JSON(http.StatusOK, StatusResponse{
		Status:     "healthy",
		Version:    "1.0.0", // TODO: Get from build info
		Uptime:     time.Since(h.startTime).String(),
		ActiveOps:  activeOps,
		TotalOps:   totalOps,
		ServerTime: time.Now(),
	})
}

// HandleGetOperation returns the status of a specific operation
func (h *APIHandlers) HandleGetOperation(c *gin.Context) {
	opID := c.Param("id")
	
	h.opMutex.RLock()
	operation, exists := h.operations[opID]
	h.opMutex.RUnlock()
	
	if !exists {
		c.JSON(http.StatusNotFound, ErrorResponse{
			Error:   "Operation Not Found",
			Code:    http.StatusNotFound,
			Message: "The specified operation ID was not found",
		})
		return
	}

	c.JSON(http.StatusOK, OperationResponse{
		ID:          operation.ID,
		Status:      operation.Status,
		Progress:    operation.Progress,
		Files:       operation.Files,
		Error:       operation.Error,
		StartedAt:   operation.StartedAt,
		CompletedAt: operation.CompletedAt,
	})
}

// HandleWebSocket handles WebSocket connections for real-time updates
func (h *APIHandlers) HandleWebSocket(c *gin.Context) {
	conn, err := h.upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		h.logger.LogError(fmt.Sprintf("Failed to upgrade WebSocket: %v", err))
		return
	}
	defer conn.Close()

	clientID := h.generateOperationID()
	h.clientMutex.Lock()
	h.clients[clientID] = conn
	h.clientMutex.Unlock()

	defer func() {
		h.clientMutex.Lock()
		delete(h.clients, clientID)
		h.clientMutex.Unlock()
	}()

	h.logger.LogInfo(fmt.Sprintf("WebSocket client connected: %s", clientID))

	// Keep connection alive and handle messages
	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			h.logger.LogDebug(fmt.Sprintf("WebSocket client disconnected: %s", clientID))
			break
		}
	}
}

// broadcastProgress sends progress updates to all connected WebSocket clients
func (h *APIHandlers) broadcastProgress(update ProgressUpdate) {
	h.clientMutex.RLock()
	defer h.clientMutex.RUnlock()

	for clientID, conn := range h.clients {
		err := conn.WriteJSON(update)
		if err != nil {
			h.logger.LogError(fmt.Sprintf("Failed to send progress to client %s: %v", clientID, err))
			conn.Close()
			delete(h.clients, clientID)
		}
	}
}

// processEncryption handles the actual encryption process
func (h *APIHandlers) processEncryption(operation *Operation, files []*multipart.FileHeader, method, password string) {
	h.logger.LogInfo(fmt.Sprintf("Starting encryption operation: %s", operation.ID))
	
	operation.Status = "processing"
	
	for i, fileHeader := range files {
		select {
		case <-operation.Context.Done():
			operation.Status = "cancelled"
			operation.Error = "Operation was cancelled"
			now := time.Now()
			operation.CompletedAt = &now
			return
		default:
		}

		// Update progress
		operation.Progress = float64(i) / float64(len(files))
		
		// Broadcast progress
		h.broadcastProgress(ProgressUpdate{
			OperationID:   operation.ID,
			Progress:      operation.Progress,
			CurrentFile:   fileHeader.Filename,
			FilesComplete: i,
			TotalFiles:    len(files),
			Status:        "processing",
			Message:       fmt.Sprintf("Encrypting %s", fileHeader.Filename),
		})

		// Process file (placeholder - would call actual encryption logic)
		result := h.processFileEncryption(fileHeader, method, password)
		operation.Files = append(operation.Files, result)
		
		// Small delay to simulate processing
		time.Sleep(100 * time.Millisecond)
	}

	// Complete operation
	operation.Status = "completed"
	operation.Progress = 1.0
	now := time.Now()
	operation.CompletedAt = &now

	// Final progress broadcast
	h.broadcastProgress(ProgressUpdate{
		OperationID:   operation.ID,
		Progress:      1.0,
		CurrentFile:   "",
		FilesComplete: len(files),
		TotalFiles:    len(files),
		Status:        "completed",
		Message:       "Encryption completed successfully",
	})

	h.logger.LogInfo(fmt.Sprintf("Encryption operation completed: %s", operation.ID))
}

// processDecryption handles the actual decryption process
func (h *APIHandlers) processDecryption(operation *Operation, files []*multipart.FileHeader, method, password string) {
	h.logger.LogInfo(fmt.Sprintf("Starting decryption operation: %s", operation.ID))
	
	operation.Status = "processing"
	
	for i, fileHeader := range files {
		select {
		case <-operation.Context.Done():
			operation.Status = "cancelled"
			operation.Error = "Operation was cancelled"
			now := time.Now()
			operation.CompletedAt = &now
			return
		default:
		}

		// Update progress
		operation.Progress = float64(i) / float64(len(files))
		
		// Broadcast progress
		h.broadcastProgress(ProgressUpdate{
			OperationID:   operation.ID,
			Progress:      operation.Progress,
			CurrentFile:   fileHeader.Filename,
			FilesComplete: i,
			TotalFiles:    len(files),
			Status:        "processing",
			Message:       fmt.Sprintf("Decrypting %s", fileHeader.Filename),
		})

		// Process file (placeholder - would call actual decryption logic)
		result := h.processFileDecryption(fileHeader, method, password)
		operation.Files = append(operation.Files, result)
		
		// Small delay to simulate processing
		time.Sleep(100 * time.Millisecond)
	}

	// Complete operation
	operation.Status = "completed"
	operation.Progress = 1.0
	now := time.Now()
	operation.CompletedAt = &now

	// Final progress broadcast
	h.broadcastProgress(ProgressUpdate{
		OperationID:   operation.ID,
		Progress:      1.0,
		CurrentFile:   "",
		FilesComplete: len(files),
		TotalFiles:    len(files),
		Status:        "completed",
		Message:       "Decryption completed successfully",
	})

	h.logger.LogInfo(fmt.Sprintf("Decryption operation completed: %s", operation.ID))
}

// processFileEncryption processes a single file for encryption
func (h *APIHandlers) processFileEncryption(fileHeader *multipart.FileHeader, method, password string) FileResult {
	// Open the file
	file, err := fileHeader.Open()
	if err != nil {
		return FileResult{
			OriginalName: fileHeader.Filename,
			Status:       "error",
			Error:        fmt.Sprintf("Failed to open file: %v", err),
			ProcessedAt:  time.Now(),
		}
	}
	defer file.Close()

	// Read file content
	content, err := io.ReadAll(file)
	if err != nil {
		return FileResult{
			OriginalName: fileHeader.Filename,
			Status:       "error",
			Error:        fmt.Sprintf("Failed to read file: %v", err),
			ProcessedAt:  time.Now(),
		}
	}

	// TODO: Call actual encryption logic here
	// For now, just simulate success
	outputName := fileHeader.Filename + ".enc"
	
	return FileResult{
		OriginalName: fileHeader.Filename,
		OutputName:   outputName,
		Size:         int64(len(content)),
		Status:       "success",
		DownloadURL:  fmt.Sprintf("/api/v1/download/%s", outputName),
		ProcessedAt:  time.Now(),
	}
}

// processFileDecryption processes a single file for decryption
func (h *APIHandlers) processFileDecryption(fileHeader *multipart.FileHeader, method, password string) FileResult {
	// Open the file
	file, err := fileHeader.Open()
	if err != nil {
		return FileResult{
			OriginalName: fileHeader.Filename,
			Status:       "error",
			Error:        fmt.Sprintf("Failed to open file: %v", err),
			ProcessedAt:  time.Now(),
		}
	}
	defer file.Close()

	// Read file content
	content, err := io.ReadAll(file)
	if err != nil {
		return FileResult{
			OriginalName: fileHeader.Filename,
			Status:       "error",
			Error:        fmt.Sprintf("Failed to read file: %v", err),
			ProcessedAt:  time.Now(),
		}
	}

	// TODO: Call actual decryption logic here
	// For now, just simulate success
	outputName := fileHeader.Filename
	if filepath.Ext(outputName) == ".enc" {
		outputName = outputName[:len(outputName)-4] // Remove .enc extension
	}
	
	return FileResult{
		OriginalName: fileHeader.Filename,
		OutputName:   outputName,
		Size:         int64(len(content)),
		Status:       "success",
		DownloadURL:  fmt.Sprintf("/api/v1/download/%s", outputName),
		ProcessedAt:  time.Now(),
	}
}
