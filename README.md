# Golang Oauth2 Google With Echo Framework
Authentication is the most common part in any application. You can implement your own authentication system or use one of the many alternatives that exist, but in this case we are going to use OAuth2.

OAuth is a specification that allows users to delegate access to their data without sharing
their username and password with that service, if you want to read more about Oauth2 go [here](https://oauth.net/2/).
 
 
## Config Google Project
First things first, we need to create our Google Project and create OAuth2 credentials.

* Go to Google Cloud Platform
* Create a new project or select one if you already have it.
* Go to Credentials and then create a new one choosing  “OAuth client ID”
* Add "authorized redirect URL", for this example `localhost:8000/auth/google/callback`
* Copy the client_id and client secret


## How OAuth2 works with Google
The authorization sequence begins when your application redirects the browser to a Google URL; the URL includes query parameters that indicate the type of access being requested. Google handles the user authentication, session selection, and user consent. The result is an authorization code, which the application can exchange for an access token and a refresh token.

The application should store the refresh token for future use and use the access token to access a Google API. Once the access token expires, the application uses the refresh token to obtain a new one.

![Oauth2Google](https://developers.google.com/accounts/images/webflow.png)

## Let's go to the code
We will use the package "golang.org/x/oauth2" that provides support for making OAuth2 authorized and authenticated HTTP requests.

Create a new project(folder) in your workdir in my case I will call it 'oauth2-example', and we need to include the package of oauth2.

`go get golang.org/x/oauth2`


So into the project we create a main.go.

```go
package main

import (
	"gooauthgoogle/routes"
)

func main() {
	e := routes.Init()
	e.Logger.Fatal(e.Start("localhost:8000"))
}
```
We create a simple server using framework echo.

Next, we create folder 'routes' that contains routes of our application, in this folder create 'routes.go'.

```go
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
```

We use variable **e** to handle our endpoints, next we create the Root endpoint "/" for serving a simple template with a minimmum HTML&CSS in this example we use 'e.Static', that template is 'index.html' and is in the folder 'templates'.

Also we create two endpoints for Oauth with Google "/auth/google/login" and "/auth/google/callback". Remember when we configured our application in the Google console? The callback url must be the same.

Next, we create another file into handlers, we'll call it 'oauth_google.go', this file contains all logic to handle OAuth with Google in our application.

We Declare the var googleOauthConfig with auth.Config to communicate with Google.
Scopes: OAuth 2.0 scopes provide a way to limit the amount of access that is granted to an
access token.

```go
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
```


### Handler OAuthGoogleLogin

This handler creates a login link and redirects the user to it:


AuthCodeURL receive state that is a token to protect the user from CSRF attacks. You must
always provide a non-empty string and validate that it matches with the state query parameter on your redirect callback, It's advisable that this is randomly generated for each request, that's why we use a simple cookie.
	
```go
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
```

### Handler OAuthGoogleCallback

This handler check if the state is equals to oauthStateCookie, and pass the code to the function **getUserDataFromGoogle**.

```go
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
```

### Full code oauth_google.go

```go
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
```
## let's run and test
```bash
go run main.go
```