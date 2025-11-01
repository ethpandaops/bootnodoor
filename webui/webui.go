package webui

import (
	"embed"
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	bootnode "github.com/pk910/bootoor/beacon-bootnode"
	"github.com/pk910/bootoor/webui/handlers"
	"github.com/pk910/bootoor/webui/server"
	"github.com/pk910/bootoor/webui/types"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
	"github.com/urfave/negroni"

	_ "net/http/pprof"
)

var (
	//go:embed static/*
	staticEmbedFS embed.FS

	//go:embed templates/*
	templateEmbedFS embed.FS
)

func StartHttpServer(config *types.FrontendConfig, logger logrus.FieldLogger, bootnodeService *bootnode.Service) {
	// init router
	router := mux.NewRouter()

	frontend, err := server.NewFrontend(config, logger, staticEmbedFS, templateEmbedFS)
	if err != nil {
		logrus.Fatalf("error initializing frontend: %v", err)
	}

	// register frontend routes
	frontendHandler := handlers.NewFrontendHandler(bootnodeService)
	router.HandleFunc("/", frontendHandler.Overview).Methods("GET")
	router.HandleFunc("/nodes", frontendHandler.Nodes).Methods("GET")
	router.HandleFunc("/enr", frontendHandler.ENR).Methods("GET")

	// metrics endpoint
	router.Handle("/metrics", promhttp.Handler()).Methods("GET")

	// add pprof handler
	router.PathPrefix("/debug/pprof/").Handler(http.DefaultServeMux)

	router.PathPrefix("/").Handler(frontend)

	n := negroni.New()
	n.Use(negroni.NewRecovery())
	//n.Use(gzip.Gzip(gzip.DefaultCompression))
	n.UseHandler(router)

	if config.Host == "" {
		config.Host = "0.0.0.0"
	}
	if config.Port == 0 {
		config.Port = 8080
	}
	srv := &http.Server{
		Addr:         fmt.Sprintf("%s:%d", config.Host, config.Port),
		WriteTimeout: 0,
		ReadTimeout:  0,
		IdleTimeout:  120 * time.Second,
		Handler:      n,
	}

	logrus.Printf("http server listening on %v", srv.Addr)
	go func() {
		if err := srv.ListenAndServe(); err != nil {
			logrus.WithError(err).Fatal("Error serving frontend")
		}
	}()
}
