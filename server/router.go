package server

import (
	"net/http"

	"github.com/Coderx44/oauth_and_saml/api/handler"
	"github.com/Coderx44/oauth_and_saml/config"
	"github.com/Coderx44/oauth_and_saml/middlewares"
	"github.com/gorilla/mux"
)

func InitRouter() (router *mux.Router) {

	router = mux.NewRouter()
	samlRoute := router.PathPrefix("").Subrouter()
	loginRoute := router.PathPrefix("").Subrouter()
	loginRoute.HandleFunc("/oauth/login", handler.Login(config.OktaConfig)).Methods(http.MethodGet)
	loginRoute.HandleFunc("/authorization-code/callback", handler.HandleCallback(config.OktaConfig)).Methods(http.MethodGet)
	loginRoute.HandleFunc("/logout/callback", handler.HandleLogoutCallback).Methods(http.MethodGet)

	appRoutes := router.PathPrefix("").Subrouter()
	appRoutes.Use(middlewares.SessionsMiddleware())

	appRoutes.HandleFunc("/", handler.HandleHome).Methods(http.MethodGet)
	appRoutes.HandleFunc("/logout", handler.Logout).Methods(http.MethodGet)

	samlRoute.Handle("/saml/login", config.SamlSP.RequireAccount(http.HandlerFunc(handler.Hello))).Methods(http.MethodGet)
	samlRoute.Handle("/saml/acs", config.SamlSP).Methods(http.MethodPost)
	return
}
