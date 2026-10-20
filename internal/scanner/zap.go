package scanner

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
)

// zapCommand runs ZAP in autorun mode; target URL and report paths are
// passed to the ZAP script through SCANROPOD_* environment variables.
func zapCommand(ctx context.Context, target, reportDir, reportFile string) *exec.Cmd {
	cmd := execCommandContext(
		ctx,
		"zap",
		"-cmd",
		"-autorun", zapConfigPath,
	)
	env := os.Environ()
	env = append(env, "SCANROPOD_TARGET_URL="+target)
	env = append(env, "SCANROPOD_REPORT_DIR="+reportDir)
	env = append(env, "SCANROPOD_REPORT_FILE="+filepath.Base(reportFile))
	cmd.Env = env
	return cmd
}
