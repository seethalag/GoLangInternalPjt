package main

import (
	"go-login-app/routes"

	"github.com/gin-gonic/gin"
)

func main() {
    router := gin.Default()

    // Load routes
    routes.AuthRoutes(router)

    // Start server
    router.Run(":8080")
}