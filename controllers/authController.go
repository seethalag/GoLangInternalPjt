package controllers

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"go-login-app/models"
	"go-login-app/utils"
	"log"
	"net/http"
	"net/smtp"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// MongoDB setup
var client, err = mongo.NewClient(options.Client().ApplyURI("mongodb+srv://pumex123:pumex123@cluster0.kf99m.mongodb.net/"))
var userCollection = client.Database("armada").Collection("users")
var validate = validator.New()


// Initialize MongoDB connection
func init() {
    ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
    err := client.Connect(ctx)
    if err != nil {
        panic(err)
    }
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
    hashedPassword, _ := utils.HashPassword(user.Password)
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
    if !utils.CheckPasswordHash(user.Password, foundUser.Password) {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid username or password"})
        return
    }

    // Generate a JWT token
    token, err := utils.GenerateJWT(foundUser.Username)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not generate token"})
        return
    }

    // Return token to client
    c.JSON(http.StatusOK, gin.H{"token": token,"username":foundUser.Username})
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

    // Find user by username
    err := userCollection.FindOne(ctx, bson.M{"username": userInput.Username}).Decode(&foundUser)
    if err != nil {
        c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
        return
    }

    // Generate reset token and expiration time
    resetToken, err := generateResetToken()
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not generate reset token"})
        return
    }

    tokenExpiresAt := time.Now().Add(1 * time.Hour)

    // Update user with reset token and expiration time
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

    // Send the reset email
    if err := SendResetEmail(foundUser.Username, resetToken); err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not send reset email"})
        return
    }

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
    hashedPassword, err := utils.HashPassword(passwordResetInput.NewPassword)
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

// SendResetEmail sends an email with the password reset link
func SendResetEmail(toEmail string, resetToken string) error {
    smtpHost := os.Getenv("SMTP_HOST")
    smtpPort := os.Getenv("SMTP_PORT")
    sender := os.Getenv("EMAIL_SENDER")
    password := os.Getenv("EMAIL_PASSWORD")

    fmt.Println("Sender-",sender)
    fmt.Println("password-",password)

    resetLink := fmt.Sprintf("http://localhost:8080/auth/reset-password?token=%s", resetToken)
    subject := "Subject: Password Reset Request\n"
    body := fmt.Sprintf("Click the following link to reset your password: %s", resetLink)
    message := []byte(subject + "\n" + body)

    auth := smtp.PlainAuth("", sender, password, smtpHost)

    err := smtp.SendMail(smtpHost+":"+smtpPort, auth, sender, []string{toEmail}, message)
    if err != nil {
        log.Printf("SMTP error: %s", err)
        return err
    }

    log.Println("Password reset email sent successfully to", toEmail)
    return nil
}

type ChangePasswordRequest struct {
    Username      string `json:"username"`
    OldPassword string `json:"oldPassword"`
    NewPassword string `json:"newPassword"`
}

// ResetPassword handles the request to reset the password
func ChangePassword(c *gin.Context) {
    var req ChangePasswordRequest
    // Decode the request body
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
        return
    }

    // Validate input
    if req.Username == "" || req.OldPassword == "" || req.NewPassword == "" {
        c.JSON(http.StatusBadRequest, gin.H{"error": "All fields are required"})
        return
    }   

    var foundUser models.User
     // Check if the user exists in the database
     ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
     err = userCollection.FindOne(ctx, bson.M{"username": req.Username}).Decode(&foundUser)
     if err != nil {
         c.JSON(http.StatusUnauthorized, gin.H{"error": "user not found"})
         return
     }

       // Check if the password matches
    if !utils.CheckPasswordHash(req.OldPassword, foundUser.Password) {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Old password is incorrect"})
        return
    }
    // Hash the new password
    hashedPassword, err := utils.HashPassword(req.NewPassword)
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
      c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not change password"})
      return
  }
  c.JSON(http.StatusOK, gin.H{"message": "Password changed successfully"})
}










