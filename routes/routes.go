package routes

import (
	"go-login-app/controllers"
	"go-login-app/utils"

	"github.com/gin-gonic/gin"
)

func AuthRoutes(router *gin.Engine) {
    authGroup := router.Group("/auth")
    {
        authGroup.POST("/login", controllers.Login)
        authGroup.POST("/register", controllers.Register)
        authGroup.POST("/forgot-password", controllers.ForgotPassword)  // Forgot password
        authGroup.POST("/reset-password", controllers.ResetPassword)    // Reset password       
    } 

    // Protect routes with JWT middleware
    protectedGroup := router.Group("/profile")
    protectedGroup.Use(utils.JWTAuthMiddleware())
    {
        protectedGroup.GET("", controllers.Profile)
        protectedGroup.GET("/weather/:city", utils.WeatherHandler)
    }
}
