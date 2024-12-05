package utils

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// Mock for JWT blacklist
var jwtBlacklist = make(map[string]bool)

// Response structure
type Response struct {
	Message string `json:"message"`
	Error   string `json:"error,omitempty"`
}

// Function to validate the token (for demo purposes)
func ValidateToken(token string) (bool, string) {
	if token == "" {
		return false, "Token is missing"
	}
	// Check if token is blacklisted
	if jwtBlacklist[token] {
		return false, "Token is invalidated"
	}
	// Add real JWT validation logic here (e.g., parsing and verifying signature)
	return true, ""
}

// Handler for logout
func LogoutHandler(c *gin.Context) {
	// Extract Authorization header
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header missing"})
		return
	}

	// Extract token from "Bearer <token>"
	token := strings.TrimPrefix(authHeader, "Bearer ")
	if token == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid Authorization header format"})
		return
	}
	
	// Validate the token
	isValid, errMsg := ValidateToken(token)
	if !isValid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": errMsg})
		return
	}

	// Invalidate the token by adding it to the blacklist
	jwtBlacklist[token] = true

	// Respond with success
	c.JSON(http.StatusOK, gin.H{"message": "Logged out successfully"})
}