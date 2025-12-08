package helper

import (
	"log"
	"os"
	"strings"
)

// EnsureDir makes sure given directory exists
func EnsureDir(dir string) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		log.Printf("[scanner] failed to create dir %s: %v", dir, err)
	}
}

// SanitizeFilename makes URL safe for use as filename
func SanitizeFilename(filename string) string {
	filename = strings.TrimSpace(filename)
	if filename == "" {
		return "unknown"
	}
	r := strings.NewReplacer(
		"://", "_",
		":", "_",
		"/", "_",
		"?", "_",
		"&", "_",
		"=", "_",
		" ", "_",
	)
	return r.Replace(filename)
}

func SchemeFromReportFileName(filename string) string {
	// after "nikto-" up to first "_"
	hyphenIdx := strings.Index(filename, "-")
	s := filename[hyphenIdx+1:]
	underscoreIdx := strings.IndexRune(s, '_')
	if underscoreIdx == -1 {
		return "http"
	}
	scheme := s[:underscoreIdx]
	if scheme == "https" {
		return "https"
	}
	return "http"
}
