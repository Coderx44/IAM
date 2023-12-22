package server

import (
	"context"
	"net/http"

	"github.com/Coderx44/oauth_and_saml/api/handler"
	"github.com/Coderx44/oauth_and_saml/config"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
)

func sessionsMiddleware(store *sessions.CookieStore) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			session, _ := store.Get(r, SessionName)
			r = r.WithContext(context.WithValue(r.Context(), SessionName, session))
			next.ServeHTTP(w, r)
		})
	}
}

var SessionName = "my-session"

func InitRouter() (router *mux.Router) {

	router = mux.NewRouter()
	store := sessions.NewCookieStore([]byte("q1w2e3r4t5"))

	router.Use(sessionsMiddleware(store))
	router.HandleFunc("/login", handler.Login(config.OktaConfig)).Methods(http.MethodGet)
	router.HandleFunc("/", handler.HandleHome).Methods(http.MethodGet)
	router.HandleFunc("/authorization-code/callback", handler.HandleCallback(config.OktaConfig)).Methods(http.MethodGet)
	router.HandleFunc("/logout", handler.Logout).Methods(http.MethodGet)
	router.HandleFunc("/logout/callback", handler.HandleLogoutCallback).Methods(http.MethodGet)

	return
}
