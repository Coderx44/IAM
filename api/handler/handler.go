package handler

import (
	"context"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"text/template"
	"time"

	"github.com/Coderx44/oauth_and_saml/config"
	"github.com/Coderx44/oauth_and_saml/middlewares"
	"github.com/crewjam/saml/samlsp"
	"github.com/gorilla/sessions"
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

// Login ...
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

// HandleCallback ...
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
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
	}
}

// HandleHome ...
func HandleHome(w http.ResponseWriter, r *http.Request) {

	userInfo, err := decodeToken(r)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}

	tmpl, err := template.ParseFiles("html/home.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	err = tmpl.Execute(w, userInfo)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// Logout ...
func Logout(w http.ResponseWriter, r *http.Request) {

	session, ok := r.Context().Value("okta-session").(*sessions.Session)
	if !ok {
		http.Error(w, "Failed to get session", http.StatusInternalServerError)
		return
	}
	idToken := session.Values["id_token"].(string)

	session.Save(r, w)

	oktaLogoutURL := os.Getenv("LOGOUT_URL") + fmt.Sprintf("?id_token_hint=%s&post_logout_redirect_uri=%s", idToken, "https://iam-pxqo.onrender.com/logout/callback")

	http.Redirect(w, r, oktaLogoutURL, http.StatusFound)

}

// HandleLogoutCallback ...
func HandleLogoutCallback(w http.ResponseWriter, r *http.Request) {

	session, err := getSession(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	accessToken := session.Values["access_token"].(string)
	session.Values = make(map[interface{}]interface{})
	session.Options.MaxAge = -1
	session.Save(r, w)

	err = revokeToken(accessToken, "access_token")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/login", http.StatusFound)
}

// SamlHome ...
func SamlHome(w http.ResponseWriter, r *http.Request) {

	s := samlsp.SessionFromContext(r.Context())
	if s == nil {
		return
	}
	sa, ok := s.(samlsp.SessionWithAttributes)
	if !ok {
		return
	}

	tmpl, err := template.ParseFiles("html/home.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	userInfo := UserInfo{
		Name:  sa.GetAttributes().Get("name"),
		Email: sa.GetAttributes().Get("email"),
		Type:  "saml",
	}

	err = tmpl.Execute(w, userInfo)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// HandleLogin ...
func HandleLogin(w http.ResponseWriter, r *http.Request) {

	tmpl, err := template.ParseFiles("html/login.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	tmpl.Execute(w, nil)
}

func SamlLogout(w http.ResponseWriter, r *http.Request) {
	s := samlsp.SessionFromContext(r.Context())
	if s == nil {
		fmt.Println("no session")
		return
	}
	sa, ok := s.(samlsp.SessionWithAttributes)
	if !ok {
		return
	}
	attr := sa.GetAttributes()

	// Generate a SAML LogoutRequest
	logoutURL, err := config.SamlSP.ServiceProvider.MakeRedirectLogoutRequest(attr.Get("email"), "")
	if err != nil {
		http.Error(w, fmt.Sprintf("Error creating LogoutRequest: %s", err), http.StatusInternalServerError)
		return
	}
	err = config.SamlSP.Session.DeleteSession(w, r)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error deleting cookies: %s", err), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, logoutURL.String(), http.StatusFound)
}

func SloLogout(w http.ResponseWriter, r *http.Request) {

	s := samlsp.SessionFromContext(r.Context())
	if s == nil {
		fmt.Println("no session")
	}
	err := config.SamlSP.Session.DeleteSession(w, r)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error deleting cookies: %s", err), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/login", http.StatusFound)
}
