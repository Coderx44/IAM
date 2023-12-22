package server

import (
	"fmt"
	"os"

	"github.com/urfave/negroni"
	"go.uber.org/zap"
)

func StartServer() {

	port := os.Getenv("PORT")
	server := negroni.Classic()

	router := InitRouter()

	server.UseHandler(router)

	zap.S().Infof("server started on port %s", port)
	fmt.Println(port)
	server.Run(fmt.Sprintf(":%s", port))

}
