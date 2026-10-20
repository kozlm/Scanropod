package scanner

import (
	"context"
	"os/exec"
	"strings"
)

// wapitiModules is the fixed module list passed to every Wapiti run.
var wapitiModules = []string{
	"backup", "cms", "cookieflags", "crlf", "csp",
	"csrf", "exec", "file", "htaccess", "https_redirect",
	"ldap", "log4shell", "methods", "permanentxss", "http_headers",
	"redirect", "shellshock", "spring4shell", "sql", "ssl", "ssrf",
	"upload", "wp_enum", "xss", "xxe",
}

func wapitiCommand(ctx context.Context, target, _, reportFile string) *exec.Cmd {
	return execCommandContext(
		ctx,
		"wapiti",
		"--flush-session",
		"-m", strings.Join(wapitiModules, ","),
		"-u", target,
		"--scope", "page",
		"-f", "json",
		"-o", reportFile,
	)
}
