package helper

import (
	"log"
	"os"
	"strings"
)

var mkdirAll = os.MkdirAll

// EnsureDir makes sure given directory exists
func EnsureDir(dir string) {
	if err := mkdirAll(dir, 0o755); err != nil {
		log.Printf("[scanner] failed to create dir %s: %v", dir, err)
	}
}

// SanitizeFilename makes URL safe for use as filename
func SanitizeFilename(filename string) string {
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

func SchemeFromReportFileName(filename string) string {
	// after "nikto-" up to first "_"
	hyphenIdx := strings.Index(filename, "-")
	afterHyphen := filename[hyphenIdx+1:]
	underscoreIdx := strings.IndexRune(afterHyphen, '_')
	if underscoreIdx == -1 {
		return "http"
	}
	scheme := afterHyphen[:underscoreIdx]
	if scheme == "https" {
		return "https"
	}
	return "http"
}
