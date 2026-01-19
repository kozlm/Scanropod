package main

import (
	"flag"
	"log"

	"github.com/kozlm/scanropod/internal/server"
)

func main() {
	apiKey := flag.String("api-key", "", "API key for securing HTTP endpoints")
	noAPIKey := flag.Bool("no-api-key", false, "Disable API key authentication")

	https := flag.Bool("https", false, "Enable HTTPS")
	certFile := flag.String("tls-cert", "", "Path to TLS certificate")
	keyFile := flag.String("tls-key", "", "Path to TLS private key")

	flag.Parse()

	if *apiKey == "" && !*noAPIKey {
		log.Fatal("you must specify --api-key or --no-api-key")
	}

	if *apiKey != "" && *noAPIKey {
		log.Fatal("cannot use --api-key and --no-api-key at the same time")
	}

	if *https && (*certFile == "" || *keyFile == "") {
		log.Fatal("HTTPS enabled but --tls-cert or --tls-key not provided")
	}

	cfg := server.Config{
		APIKeyEnabled: !*noAPIKey,
		APIKey:        *apiKey,

		HTTPS:    *https,
		CertFile: *certFile,
		KeyFile:  *keyFile,
	}

	if err := server.Run(cfg); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}
