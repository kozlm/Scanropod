package scanner

import (
	"context"
	"os/exec"
)

func nucleiCommand(ctx context.Context, target, _, reportFile string) *exec.Cmd {
	return execCommandContext(
		ctx,
		"nuclei",
		"-u", target,
		"-duc",
		"-ni",
		"-config", nucleiConfigPath,
		"-json-export", reportFile,
	)
}
