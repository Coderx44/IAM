package config

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"log"
	"net/http"
	"net/url"
	"os"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	"github.com/joho/godotenv"
	"golang.org/x/oauth2"
)

// ConfigVars
var (
	ClientID, ClientSecret, AuthURL, TokenURL string
	OktaConfig                                *oauth2.Config
	SamlSP                                    *samlsp.Middleware
)

func configSamlSP() {
	keyPair, err := tls.LoadX509KeyPair("./myservice.cert", "./myservice.key")
	if err != nil {
		panic(err)
	}
	keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		panic(err)
	}

	idpMetadataURL, err := url.Parse(os.Getenv("IDP_METADATA_URL"))
	if err != nil {
		panic(err)
	}
	idpMetadata, err := samlsp.FetchMetadata(context.Background(), http.DefaultClient,
		*idpMetadataURL)
	if err != nil {
		panic(err)
	}

	rootURL, err := url.Parse(os.Getenv("ROOT_URL"))
	if err != nil {
		panic(err)
	}

	SamlSP, err = samlsp.New(samlsp.Options{
		EntityID:    os.Getenv("ROOT_URL"),
		URL:         *rootURL,
		Key:         keyPair.PrivateKey.(*rsa.PrivateKey),
		Certificate: keyPair.Leaf,
		IDPMetadata: idpMetadata,
		SignRequest: true,
	})
	SamlSP.Binding = saml.HTTPPostBinding
	if err != nil {
		panic(err)
	}
}

func configOkta() {
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

// Load ...
func Load() {
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	configOkta()

	configSamlSP()
}
