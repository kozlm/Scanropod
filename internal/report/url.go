package report

import (
	"net/url"
	"path"
	"strings"
)

var (
	cleanURL = func(rawUrl string) (string, error) {
		decoded, _ := url.QueryUnescape(rawUrl)

		parsedUrl, err := url.Parse(decoded)
		if err != nil {
			return "", err
		}

		parsedUrl.Path = path.Clean(parsedUrl.Path)

		if parsedUrl.Path == "." {
			parsedUrl.Path = ""
		}

		parsedUrl.RawQuery = ""
		parsedUrl.Fragment = ""

		parsedUrl.Path = strings.ReplaceAll(parsedUrl.Path, "//", "/")

		return parsedUrl.String(), nil
	}

	buildURL = func(host string, path string, port string, scheme string) string {
		defaultPort := map[string]string{
			"http":  "80",
			"https": "443",
		}
		withPort := host
		includePort := port != defaultPort[scheme]
		if includePort {
			withPort = host + ":" + port
		}

		finalUrl := &url.URL{
			Scheme: scheme,
			Host:   withPort,
			Path:   path,
		}

		return finalUrl.String()
	}
)

func schemeFromReportFileName(filename string) string {
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
