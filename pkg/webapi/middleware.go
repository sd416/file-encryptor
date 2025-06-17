package webapi

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

// SetupCORS configures CORS middleware
func SetupCORS() gin.HandlerFunc {
	config := cors.Config{
		AllowOrigins:     []string{"*"}, // In production, specify exact origins
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization", "X-Requested-With"},
		ExposeHeaders:    []string{"Content-Length", "Content-Disposition"},
		AllowCredentials: false,
		MaxAge:           12 * time.Hour,
	}
	return cors.New(config)
}

// SecurityHeaders adds security headers to responses
func SecurityHeaders() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'")
		
		// Only add HSTS in production with HTTPS
		if c.Request.TLS != nil {
			c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		
		c.Next()
	})
}

// RequestLogger creates a custom request logger
func RequestLogger() gin.HandlerFunc {
	return gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {
		return fmt.Sprintf("%s - [%s] \"%s %s %s %d %s \"%s\" %s\"\n",
			param.ClientIP,
			param.TimeStamp.Format(time.RFC1123),
			param.Method,
			param.Path,
			param.Request.Proto,
			param.StatusCode,
			param.Latency,
			param.Request.UserAgent(),
			param.ErrorMessage,
		)
	})
}

// ErrorHandler handles panics and errors
func ErrorHandler() gin.HandlerFunc {
	return gin.CustomRecovery(func(c *gin.Context, recovered interface{}) {
		if err, ok := recovered.(string); ok {
			c.JSON(http.StatusInternalServerError, ErrorResponse{
				Error:   "Internal Server Error",
				Code:    http.StatusInternalServerError,
				Message: "An unexpected error occurred",
				Details: err,
			})
		}
		c.AbortWithStatus(http.StatusInternalServerError)
	})
}

// RateLimiter implements basic rate limiting
func RateLimiter() gin.HandlerFunc {
	// Simple in-memory rate limiter
	// In production, use Redis or similar
	clients := make(map[string][]time.Time)
	
	return gin.HandlerFunc(func(c *gin.Context) {
		clientIP := c.ClientIP()
		now := time.Now()
		
		// Clean old entries (older than 1 minute)
		if requests, exists := clients[clientIP]; exists {
			var validRequests []time.Time
			for _, reqTime := range requests {
				if now.Sub(reqTime) < time.Minute {
					validRequests = append(validRequests, reqTime)
				}
			}
			clients[clientIP] = validRequests
		}
		
		// Check rate limit (60 requests per minute)
		if len(clients[clientIP]) >= 60 {
			c.JSON(http.StatusTooManyRequests, ErrorResponse{
				Error:   "Rate Limit Exceeded",
				Code:    http.StatusTooManyRequests,
				Message: "Too many requests. Please try again later.",
			})
			c.Abort()
			return
		}
		
		// Add current request
		clients[clientIP] = append(clients[clientIP], now)
		c.Next()
	})
}

// FileSizeLimit limits the size of uploaded files
func FileSizeLimit(maxSize int64) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		if c.Request.ContentLength > maxSize {
			c.JSON(http.StatusRequestEntityTooLarge, ErrorResponse{
				Error:   "File Too Large",
				Code:    http.StatusRequestEntityTooLarge,
				Message: fmt.Sprintf("File size exceeds maximum allowed size of %d bytes", maxSize),
			})
			c.Abort()
			return
		}
		
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxSize)
		c.Next()
	})
}

// ValidateContentType ensures the request has the expected content type
func ValidateContentType(expectedTypes ...string) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		contentType := c.GetHeader("Content-Type")
		
		for _, expectedType := range expectedTypes {
			if strings.Contains(contentType, expectedType) {
				c.Next()
				return
			}
		}
		
		c.JSON(http.StatusUnsupportedMediaType, ErrorResponse{
			Error:   "Unsupported Media Type",
			Code:    http.StatusUnsupportedMediaType,
			Message: fmt.Sprintf("Expected content type: %s", strings.Join(expectedTypes, " or ")),
		})
		c.Abort()
	})
}
