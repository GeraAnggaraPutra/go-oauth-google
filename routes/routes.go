package routes

import (
	"github.com/labstack/echo/v4"

	"gooauthgoogle/handlers"
)

func Init() *echo.Echo {
	e := echo.New()

	// Root
	e.Static("/", "templates/")

	// OauthGoogle
	e.GET("/auth/google/login", handlers.OAuthGoogleLogin)
	e.GET("/auth/google/callback", handlers.OAuthGoogleCallback)

	return e
}
