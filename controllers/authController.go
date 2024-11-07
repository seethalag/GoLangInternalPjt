package controllers

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"go-login-app/models"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

// MongoDB setup
var client, err = mongo.NewClient(options.Client().ApplyURI("mongodb+srv://pumex123:pumex123@cluster0.kf99m.mongodb.net/"))
var userCollection = client.Database("armada").Collection("users")
var validate = validator.New()

var jwtSecret = []byte("jhdtrytuy767863hgyt6")  // In production, use env variables

// JWT claims structure
type Claims struct {
    Username string `json:"username"`
    jwt.StandardClaims
}

// Initialize MongoDB connection
func init() {
    ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
    err := client.Connect(ctx)
    if err != nil {
        panic(err)
    }
}

// HashPassword hashes the user password
func HashPassword(password string) (string, error) {
    bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
    return string(bytes), err
}

// CheckPasswordHash compares plain password with hashed password
func CheckPasswordHash(password, hash string) bool {
    err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
    return err == nil
}

// GenerateJWT generates a JWT token for the user
func GenerateJWT(username string) (string, error) {
    expirationTime := time.Now().Add(24 * time.Hour)
    claims := &Claims{
        Username: username,
        StandardClaims: jwt.StandardClaims{
            ExpiresAt: expirationTime.Unix(),
        },
    }

    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    tokenString, err := token.SignedString(jwtSecret)
    if err != nil {
        return "", err
    }
    return tokenString, nil
}

// ValidateJWT validates the JWT token from the request
func ValidateJWT(tokenString string) (*Claims, bool) {
    claims := &Claims{}
    token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
        return jwtSecret, nil
    })

    if err != nil || !token.Valid {
        return nil, false
    }
    return claims, true
}

func Register(c *gin.Context) {
    var user models.User

    // Parse and validate user input
    if err := c.ShouldBindJSON(&user); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
        return
    }

    // Validate using validator package
    err := validate.Struct(user)
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }

    // Hash the password
    hashedPassword, _ := HashPassword(user.Password)
    user.Password = hashedPassword

    // Save user to the database
    ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
    _, err = userCollection.InsertOne(ctx, user)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to register"})
        return
    }

    c.JSON(http.StatusOK, gin.H{"message": "Registration successful"})
}

func Login(c *gin.Context) {
    var user models.User
    var foundUser models.User

    // Parse and validate user input
    if err := c.ShouldBindJSON(&user); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
        return
    }

    // Validate the input
    err := validate.Struct(user)
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }

    // Check if the user exists in the database
    ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
    err = userCollection.FindOne(ctx, bson.M{"username": user.Username}).Decode(&foundUser)
    if err != nil {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid username or password"})
        return
    }

    // Check if the password matches
    if !CheckPasswordHash(user.Password, foundUser.Password) {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid username or password"})
        return
    }

    // Generate a JWT token
    token, err := GenerateJWT(foundUser.Username)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not generate token"})
        return
    }

    // Return token to client
    c.JSON(http.StatusOK, gin.H{"token": token})
}

func JWTAuthMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        tokenString := c.GetHeader("Authorization")

        if tokenString == "" {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "No token provided"})
            c.Abort()
            return
        }

        // Validate the JWT token
        claims, valid := ValidateJWT(tokenString)
        if !valid {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
            c.Abort()
            return
        }

        // Store claims in context for later use
        c.Set("username", claims.Username)
        c.Next()
    }
}

func Profile(c *gin.Context) {
    username := c.MustGet("username").(string)
    c.JSON(http.StatusOK, gin.H{"message": "Welcome to your profile", "username": username})
}

// generateResetToken generates a random token for password reset
func generateResetToken() (string, error) {
    bytes := make([]byte, 16)
    if _, err := rand.Read(bytes); err != nil {
        return "", err
    }
    return hex.EncodeToString(bytes), nil
}

// ForgotPassword handles the request to initiate a password reset
func ForgotPassword(c *gin.Context) {
    var userInput struct {
        Username string `json:"username" binding:"required"`
    }

    if err := c.ShouldBindJSON(&userInput); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
        return
    }

    var foundUser models.User
    ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)

    // Find the user by username
    err := userCollection.FindOne(ctx, bson.M{"username": userInput.Username}).Decode(&foundUser)
    if err != nil {
        c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
        return
    }

    // Generate a reset token and set its expiration time
    resetToken, err := generateResetToken()
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not generate reset token"})
        return
    }

    tokenExpiresAt := time.Now().Add(1 * time.Hour)  // Token valid for 1 hour

    // Update user document with the reset token and expiration time
    _, err = userCollection.UpdateOne(ctx, bson.M{"_id": foundUser.ID}, bson.M{
        "$set": bson.M{
            "reset_token":     resetToken,
            "token_expires_at": tokenExpiresAt,
        },
    })
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not save reset token"})
        return
    }

    // Simulate sending email (or you can integrate with an actual email service)
    fmt.Println("Reset password link: http://localhost:8080/auth/reset-password?token=" + resetToken)

    c.JSON(http.StatusOK, gin.H{"message": "Password reset link sent to your email"})
}

// ResetPassword handles the request to reset the password
func ResetPassword(c *gin.Context) {
    var passwordResetInput struct {
        Token       string `json:"token" binding:"required"`
        NewPassword string `json:"new_password" binding:"required,min=6"`
    }

    if err := c.ShouldBindJSON(&passwordResetInput); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
        return
    }

    var foundUser models.User
    ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)

    // Find the user by the reset token
    err := userCollection.FindOne(ctx, bson.M{"reset_token": passwordResetInput.Token}).Decode(&foundUser)
    if err != nil {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired reset token"})
        return
    }

    // Check if the token has expired
    if time.Now().After(foundUser.TokenExpiresAt) {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Reset token has expired"})
        return
    }

    // Hash the new password
    hashedPassword, err := HashPassword(passwordResetInput.NewPassword)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not hash password"})
        return
    }

    // Update user's password and clear the reset token
    _, err = userCollection.UpdateOne(ctx, bson.M{"_id": foundUser.ID}, bson.M{
        "$set": bson.M{
            "password": hashedPassword,
        },
        "$unset": bson.M{
            "reset_token":     "",
            "token_expires_at": "",
        },
    })

    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not reset password"})
        return
    }

    c.JSON(http.StatusOK, gin.H{"message": "Password has been reset successfully"})
}
