package helper

import (
	"net/url"
	"path"
	"strings"
)

func CleanUrl(rawUrl string) (string, error) {
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

func BuildUrl(host string, path string, port string, scheme string) string {
	defaultPort := map[string]string{
		"http":  "80",
		"https": "443",
	}
	withPort := host
	includePort := port != defaultPort[scheme]
	if includePort {
		withPort = host + ":" + port
	}

	u := &url.URL{
		Scheme: scheme,
		Host:   withPort,
		Path:   path,
	}

	return u.String()
}
