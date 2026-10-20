package scanner

import (
	"context"
	"os/exec"
	"strings"
)

// niktoPlugins is the fixed plugin list passed to every Nikto run.
var niktoPlugins = []string{
	"tests", "cookies", "headers", "ssl", "httpoptions", "robots",
	"paths", "dictionary", "cgi", "content_search", "fileops",
	"msgs", "sitefiles", "clientaccesspolicy", "multiple_index",
	"shellshock", "strutschock", "apache_expect_xss", "put_del_test", "report_json",
}

func niktoCommand(ctx context.Context, target, _, reportFile string) *exec.Cmd {
	return execCommandContext(
		ctx,
		"nikto",
		"-h", target,
		"-Tuning", "x6abd",
		"-Plugins", strings.Join(niktoPlugins, ";"),
		"-ask", "no",
		"-nointeractive",
		"-o", reportFile,
		"-Format", "json",
	)
}
