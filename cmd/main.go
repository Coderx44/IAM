package main

import (
	"github.com/Coderx44/oauth_and_saml/config"
	"github.com/Coderx44/oauth_and_saml/server"
)

func main() {
	config.Load()
	server.StartServer()
}
