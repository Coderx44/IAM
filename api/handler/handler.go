package handler

import (
	"context"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"time"

	gojwt "github.com/golang-jwt/jwt"
	"github.com/gorilla/sessions"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

func genRandonState() string {
	var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	rand.Seed(time.Now().UnixNano())
	b := make([]rune, 10)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}

	state := string(b)
	return state
}

func Login(okta *oauth2.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session := r.Context().Value("my-session").(*sessions.Session)
		state := genRandonState()
		session.Values["state"] = state

		session.Save(r, w)
		url := okta.AuthCodeURL(state)
		http.Redirect(w, r, url, http.StatusFound)
	}
}

type Token string

var Tokens Token = "token"

func HandleCallback(okta *oauth2.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("$354V35V35V3553W5")
		session := r.Context().Value("my-session").(*sessions.Session)
		state := session.Values["state"].(string)
		stateParam := r.FormValue("state")
		if stateParam != state {
			http.Error(w, "Invalid state parameter", http.StatusBadRequest)
			return
		}

		code := r.FormValue("code")
		token, err := okta.Exchange(context.Background(), code)
		if err != nil {
			zap.S().Errorf("erorr in auth code %s", err)
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

		http.Redirect(w, r, "http://localhost:8080/", http.StatusFound)
	}
}

func HandleHome(w http.ResponseWriter, r *http.Request) {
	session := r.Context().Value("my-session").(*sessions.Session)
	idToken := session.Values["id_token"].(string)
	token, err := gojwt.Parse(idToken, func(token *gojwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*gojwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return nil, nil
	})
	if err != nil {
		zap.S().Errorf("error parsing token: %v", err)
	}

	claims, ok := token.Claims.(gojwt.MapClaims)
	if !ok || !token.Valid {
		zap.S().Errorf("invalid token: %v", err)
	}

	w.Write([]byte(claims["name"].(string)))
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
