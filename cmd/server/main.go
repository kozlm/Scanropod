package main

import (
	"log"

	"github.com/kozlm/scanropods/internal/server"
)

func main() {
	if err := server.Run(); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}
