package main

import (
	"go-login-app/routes"
	"log"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func init() {
    err := godotenv.Load()
    if err != nil {
        log.Fatal("Error loading .env file")
    }
}

func main() {
    router := gin.Default()

    // Load routes
    routes.AuthRoutes(router)

    // Start server
    router.Run(":8080")
}