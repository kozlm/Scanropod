package scanner

import (
	"log"
	"os"
	"strings"
)

var (
	mkdirAll  = os.MkdirAll
	ensureDir = func(dir string) {
		if err := mkdirAll(dir, 0o755); err != nil {
			log.Printf("[scanner] failed to create dir %s: %v", dir, err)
		}
	}
)

// sanitizeFilename makes URL safe for use as filename
func sanitizeFilename(filename string) string {
	filename = strings.TrimSpace(filename)
	if filename == "" {
		return "unknown"
	}
	replacer := strings.NewReplacer(
		"://", "_",
		":", "_",
		"/", "_",
		"?", "_",
		"&", "_",
		"=", "_",
		" ", "_",
	)
	return replacer.Replace(filename)
}
