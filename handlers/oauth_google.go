package handlers

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/joho/godotenv"
	"github.com/labstack/echo/v4"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"gooauthgoogle/models"
)

var (
	err               = godotenv.Load(".env")
	googleOauthConfig = &oauth2.Config{
		RedirectURL:  "http://localhost:8000/auth/google/callback",
		ClientID:     os.Getenv("GOOGLE_OAUTH_CLIENT_ID"),
		ClientSecret: os.Getenv("GOOGLE_OAUTH_CLIENT_SECRET"),
		Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email"},
		Endpoint:     google.Endpoint,
	}
)

const oauthGoogleUrlAPI = "https://www.googleapis.com/oauth2/v2/userinfo?access_token="

func OAuthGoogleLogin(c echo.Context) error {
	if err != nil {
		log.Fatalf("error load env file : %s", err.Error())
	}

	// Create oauthState cookie
	oauthState := generateStateOauthCookie(c.Response())

	/*
	   AuthCodeURL receive state that is a token to protect the user from CSRF attacks. You must always provide a non-empty string and
	   validate that it matches the the state query parameter on your redirect callback.
	*/
	u := googleOauthConfig.AuthCodeURL(oauthState)
	return c.Redirect(http.StatusTemporaryRedirect, u)
}

func OAuthGoogleCallback(c echo.Context) error {
	// Read oauthState from Cookie
	oauthState, err := c.Cookie("oauthstate")
	if err != nil {
		log.Println("Invalid oauth google state")
		return c.Redirect(http.StatusTemporaryRedirect, "/")
	}

	if c.QueryParam("state") != oauthState.Value {
		log.Println("Invalid oauth google state")
		return c.Redirect(http.StatusTemporaryRedirect, "/")
	}

	data, err := getUserDataFromGoogle(c.QueryParam("code"))
	if err != nil {
		log.Println(err.Error())
		return c.Redirect(http.StatusTemporaryRedirect, "/")
	}

	// GetOrCreate User in your db.
	// Redirect or response with a token.
	// More code .....
	return c.JSON(http.StatusOK, map[string]interface{}{
		"status":  200,
		"message": "Successfully login with Google",
		"data":    data,
	})
}

func generateStateOauthCookie(w http.ResponseWriter) string {
	var expiration = time.Now().Add(20 * time.Minute)

	b := make([]byte, 16)
	rand.Read(b)
	state := base64.URLEncoding.EncodeToString(b)
	cookie := new(http.Cookie)
	cookie.Name = "oauthstate"
	cookie.Value = state
	cookie.Expires = expiration
	http.SetCookie(w, cookie)

	return state
}

func getUserDataFromGoogle(code string) (*models.GoogleUserResponse, error) {
	// Use code to get token and get user info from Google.

	token, err := googleOauthConfig.Exchange(context.Background(), code)
	if err != nil {
		return nil, fmt.Errorf("code exchange wrong: %s", err.Error())
	}

	response, err := http.Get(oauthGoogleUrlAPI + token.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("failed getting user info: %s", err.Error())
	}
	defer response.Body.Close()

	contents, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("failed read response: %s", err.Error())
	}

	var user models.GoogleUserResponse
	if err := json.Unmarshal(contents, &user); err != nil {
		return nil, fmt.Errorf("failed to unmarshal user data: %s", err.Error())
	}

	return &user, nil
}
