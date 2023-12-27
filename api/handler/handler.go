package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"time"

	"github.com/Coderx44/oauth_and_saml/middlewares"
	"github.com/crewjam/saml/samlsp"
	"github.com/gorilla/sessions"
	jwtverifier "github.com/okta/okta-jwt-verifier-golang"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

func genRandonState() string {
	var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	rand.NewSource(time.Now().UnixNano())
	b := make([]rune, 10)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}

	state := string(b)
	return state
}

func Login(okta *oauth2.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, err := middlewares.Store.Get(r, middlewares.SessionName)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		state := genRandonState()
		session.Values["state"] = state

		err = session.Save(r, w)
		if err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		url := okta.AuthCodeURL(state)
		http.Redirect(w, r, url, http.StatusTemporaryRedirect)
	}
}

func HandleCallback(okta *oauth2.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, err := middlewares.Store.Get(r, middlewares.SessionName)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
		state := session.Values["state"].(string)
		stateParam := r.FormValue("state")
		if stateParam != state {
			http.Error(w, "Invalid state parameter", http.StatusBadRequest)
			return
		}

		code := r.FormValue("code")
		token, err := okta.Exchange(context.Background(), code)
		if err != nil {
			zap.S().Errorf("error in auth code %s", err)
			http.Error(w, fmt.Sprintf("Failed to exchange code: %s", err), http.StatusInternalServerError)
			return
		}
		idToken, ok := token.Extra("id_token").(string)
		if !ok {
			http.Error(w, "ID token not found in response", http.StatusInternalServerError)
			return
		}

		session.Values["id_token"] = idToken
		session.Values["access_token"] = token.AccessToken
		session.Save(r, w)

		http.Redirect(w, r, "http://localhost:8080/", http.StatusTemporaryRedirect)
	}
}

func HandleHome(w http.ResponseWriter, r *http.Request) {
	session := r.Context().Value("my-session").(*sessions.Session)
	idToken := session.Values["id_token"].(string)
	toValidate := map[string]string{}
	toValidate["aud"] = "0oaa12x6jexq58nL8697"

	jwtVerifierSetup := jwtverifier.JwtVerifier{
		Issuer:           "https://trial-8230984.okta.com/oauth2/default",
		ClaimsToValidate: toValidate,
	}

	verifier := jwtVerifierSetup.New()

	token, err := verifier.VerifyIdToken(idToken)
	if err != nil {
		fmt.Println("err:", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	UserInfo := UserInfo{
		Name:  token.Claims["name"].(string),
		Email: token.Claims["email"].(string),
	}

	err = json.NewEncoder(w).Encode(UserInfo)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

func Logout(w http.ResponseWriter, r *http.Request) {
	session, ok := r.Context().Value("my-session").(*sessions.Session)
	if !ok {
		http.Error(w, "Failed to get session", http.StatusInternalServerError)
		return
	}
	idToken := session.Values["id_token"].(string)
	session.Values = make(map[interface{}]interface{})
	session.Options.MaxAge = -1

	session.Save(r, w)

	oktaLogoutURL := os.Getenv("LOGOUT_URL") + fmt.Sprintf("?id_token_hint=%s&post_logout_redirect_uri=%s", idToken, "http://localhost:8080/logout/callback")
	http.Redirect(w, r, oktaLogoutURL, http.StatusTemporaryRedirect)

}

func HandleLogoutCallback(w http.ResponseWriter, r *http.Request) {

	http.Redirect(w, r, "/login", http.StatusFound)
}

func Hello(w http.ResponseWriter, r *http.Request) {
	s := samlsp.SessionFromContext(r.Context())
	if s == nil {
		return
	}
	sa, ok := s.(samlsp.SessionWithAttributes)
	if !ok {
		return
	}

	fmt.Fprintf(w, "Token contents, %+v!", sa.GetAttributes())
}
