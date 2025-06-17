package webapi

import "time"

// FileData represents an uploaded file
type FileData struct {
	Name     string `json:"name"`
	Size     int64  `json:"size"`
	Content  []byte `json:"content"`
	MimeType string `json:"mimeType"`
}

// EncryptRequest represents a request to encrypt files
type EncryptRequest struct {
	Files    []FileData     `json:"files"`
	Method   string         `json:"method"` // "password" or "key"
	Password string         `json:"password,omitempty"`
	KeyData  string         `json:"keyData,omitempty"`
	Options  EncryptOptions `json:"options"`
}

// DecryptRequest represents a request to decrypt files
type DecryptRequest struct {
	Files    []FileData     `json:"files"`
	Method   string         `json:"method"` // "password" or "key"
	Password string         `json:"password,omitempty"`
	KeyData  string         `json:"keyData,omitempty"`
	Options  DecryptOptions `json:"options"`
}

// GenerateKeysRequest represents a request to generate RSA keys
type GenerateKeysRequest struct {
	KeyName string `json:"keyName"`
	KeySize int    `json:"keySize"`
}

// EncryptOptions contains encryption-specific options
type EncryptOptions struct {
	ChunkSize int `json:"chunkSize,omitempty"`
}

// DecryptOptions contains decryption-specific options
type DecryptOptions struct {
	ChunkSize int `json:"chunkSize,omitempty"`
}

// FileResult represents the result of processing a single file
type FileResult struct {
	OriginalName string    `json:"originalName"`
	OutputName   string    `json:"outputName"`
	Size         int64     `json:"size"`
	Status       string    `json:"status"` // "success", "error", "processing"
	Error        string    `json:"error,omitempty"`
	DownloadURL  string    `json:"downloadUrl,omitempty"`
	ProcessedAt  time.Time `json:"processedAt"`
}

// OperationResponse represents the response from an operation
type OperationResponse struct {
	ID          string       `json:"id"`
	Status      string       `json:"status"`   // "pending", "processing", "completed", "error"
	Progress    float64      `json:"progress"` // 0.0 to 1.0
	Files       []FileResult `json:"files"`
	Error       string       `json:"error,omitempty"`
	StartedAt   time.Time    `json:"startedAt"`
	CompletedAt *time.Time   `json:"completedAt,omitempty"`
}

// ProgressUpdate represents a real-time progress update
type ProgressUpdate struct {
	OperationID   string  `json:"operationId"`
	Progress      float64 `json:"progress"`
	CurrentFile   string  `json:"currentFile"`
	FilesComplete int     `json:"filesComplete"`
	TotalFiles    int     `json:"totalFiles"`
	Status        string  `json:"status"`
	Message       string  `json:"message,omitempty"`
}

// ConfigResponse represents the current configuration
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

// StatusResponse represents server status
type StatusResponse struct {
	Status     string    `json:"status"`
	Version    string    `json:"version"`
	Uptime     string    `json:"uptime"`
	ActiveOps  int       `json:"activeOperations"`
	TotalOps   int       `json:"totalOperations"`
	ServerTime time.Time `json:"serverTime"`
}

// ErrorResponse represents an API error
type ErrorResponse struct {
	Error   string `json:"error"`
	Code    int    `json:"code"`
	Message string `json:"message"`
	Details string `json:"details,omitempty"`
}

// KeyPairResponse represents generated RSA keys
type KeyPairResponse struct {
	PrivateKey  string    `json:"privateKey"`
	PublicKey   string    `json:"publicKey"`
	PrivateFile string    `json:"privateFile"`
	PublicFile  string    `json:"publicFile"`
	KeySize     int       `json:"keySize"`
	GeneratedAt time.Time `json:"generatedAt"`
}
