package utils

import (
	"golang.org/x/crypto/bcrypt"
)

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
