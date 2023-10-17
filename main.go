package main

import (
	"gooauthgoogle/routes"
)

func main() {
	e := routes.Init()
	e.Logger.Fatal(e.Start("localhost:8000"))
}
