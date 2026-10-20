// Package server exposes the Scanropod REST API: it wires together the
// HTTP routes, API-key authentication, TLS configuration, and the scan
// and report components.
package server

import (
	"crypto/tls"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/kozlm/scanropod/internal/scanner"
	"github.com/kozlm/scanropod/internal/store"
)

type Config struct {
	APIKeyEnabled bool
	APIKey        string
	HTTPS         bool
	CertFile      string
	KeyFile       string
}

// apiServer carries the runtime configuration of one API instance.
type apiServer struct {
	config  Config
	baseDir string
}

func (s *apiServer) apiKeyMiddleware() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		if !s.config.APIKeyEnabled {
			ctx.Next()
			return
		}

		key := ctx.GetHeader("X-API-Key")
		if key == "" || key != s.config.APIKey {
			ctx.AbortWithStatusJSON(
				http.StatusUnauthorized,
				gin.H{"error": "invalid or missing API key"},
			)
			return
		}

		ctx.Next()
	}
}

func Run(config Config) error {
	store.Init()
	log.Println("[server] store initialized")

	if config.APIKeyEnabled {
		log.Println("[security] API key authentication enabled")
	} else {
		log.Println("[security] API key authentication disabled")
	}

	dir, err := os.Getwd()
	if err != nil {
		log.Fatal("[server] could not get working directory")
	}
	log.Printf("[server] base dir: %s", dir)

	s := &apiServer{
		config:  config,
		baseDir: dir,
	}

	scanner.Init(s.baseDir)

	r := gin.Default()
	r.Use(s.apiKeyMiddleware())

	r.POST("/scan/start", s.startHandler)
	r.GET("/scan/status/:id", s.statusHandler)
	r.GET("/scan/result/:id", s.resultHandler)
	r.POST("/scan/stop/:id", s.stopHandler)

	server := &http.Server{
		Addr:           ":8443",
		Handler:        r,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   0,
		MaxHeaderBytes: 1 << 20, // 1 MB
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}

	if config.HTTPS {
		log.Println("[server] HTTPS enabled")
		log.Printf("[server] listening on https://localhost%s", server.Addr)
		return server.ListenAndServeTLS(config.CertFile, config.KeyFile)
	}

	log.Println("[server] HTTPS disabled")
	log.Printf("[server] listening on http://localhost%s", server.Addr)
	return server.ListenAndServe()
}
