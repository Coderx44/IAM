package config

import (
	"log"
	"os"

	"github.com/joho/godotenv"
	"golang.org/x/oauth2"
)

var (
	ClientID, ClientSecret, AuthURL, TokenURL string
	OktaConfig                                *oauth2.Config
)

func Load() {
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	OktaConfig = &oauth2.Config{
		ClientID:     os.Getenv("CLIENT_ID"),
		ClientSecret: os.Getenv("CLIENT_SECRET"),
		Endpoint: oauth2.Endpoint{
			AuthURL:  os.Getenv("AUTH_URL"),
			TokenURL: os.Getenv("TOKEN_URL"),
		},
		RedirectURL: os.Getenv("REDIRECT_URL"),
		Scopes:      []string{"openid", "email", "profile"},
	}
}
