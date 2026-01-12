package main

import (
	"flag"
	"log"

	"github.com/kozlm/scanropods/internal/server"
)

func main() {
	apiKey := flag.String("api-key", "", "API key for securing HTTP endpoints")
	noAPIKey := flag.Bool("no-api-key", false, "Disable API key authentication")

	flag.Parse()

	if *apiKey == "" && !*noAPIKey {
		log.Fatal("you must specify --api-key or --no-api-key")
	}

	if *apiKey != "" && *noAPIKey {
		log.Fatal("cannot use --api-key and --no-api-key at the same time")
	}

	cfg := server.SecurityConfig{
		APIKeyEnabled: !*noAPIKey,
		APIKey:        *apiKey,
	}

	if err := server.Run(cfg); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}
