package server

import (
	"fmt"
	"net/http"
	"os"

	"github.com/rs/cors"
	"github.com/urfave/negroni"
	"go.uber.org/zap"
)

// StartServer ...
func StartServer() {

	port := os.Getenv("PORT")
	server := negroni.Classic()

	router := InitRouter()
	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowCredentials: true,
		AllowedMethods:   []string{http.MethodGet, http.MethodPost, http.MethodDelete, http.MethodOptions, http.MethodPut},
		AllowedHeaders:   []string{"*"},
	})
	server.UseHandler(c.Handler(router))

	zap.S().Infof("server started on port %s", port)
	fmt.Println(port)
	server.Run(fmt.Sprintf(":%s", port))

}
