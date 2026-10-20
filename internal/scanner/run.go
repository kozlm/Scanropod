package scanner

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

var (
	execCommandContext = exec.CommandContext
	writeFile          = os.WriteFile
	statFile           = os.Stat
	runScanner         = runSingleScanner
)

// commandBuilder builds the subprocess invocation for a single target.
type commandBuilder func(ctx context.Context, target, reportDir, reportFile string) *exec.Cmd

// scannerSpec describes how to run one external scanner. name is the
// executable name and the report/log file prefix; build constructs the
// command for a single target.
type scannerSpec struct {
	name   string
	logTag string
	build  commandBuilder
}

var scannerSpecs = map[string]scannerSpec{
	"nikto":  {name: "nikto", logTag: "[runNikto]", build: niktoCommand},
	"nuclei": {name: "nuclei", logTag: "[runNuclei]", build: nucleiCommand},
	"wapiti": {name: "wapiti", logTag: "[runWapiti]", build: wapitiCommand},
	"zap":    {name: "zap", logTag: "[runZap]", build: zapCommand},
}

func runSingleScanner(ctx context.Context, name string, targets []string) error {
	log.Printf("[runSingleScanner] starting scanner '%s' on targets: %v", name, targets)

	spec, ok := scannerSpecs[strings.ToLower(name)]
	if !ok {
		log.Printf("[runSingleScanner] unknown scanner: %s (skipping)", name)
		return nil
	}

	return runTargets(ctx, spec, targets)
}

// runTargets runs the scanner for every target sequentially, saving
// combined output as a log file and verifying the report file exists.
func runTargets(ctx context.Context, spec scannerSpec, targets []string) error {
	reportDir := reportsDirFromCtx(ctx)
	outputDir := outputsDirFromCtx(ctx)

	log.Printf("%s starting for targets: %v", spec.logTag, targets)

	for _, target := range targets {
		select {
		case <-ctx.Done():
			log.Printf("%s context cancelled, stopping. Last target: %s", spec.logTag, target)
			return nil
		default:
		}

		safeTarget := sanitizeFilename(target)
		timestamp := time.Now().Unix()

		reportFile := filepath.Join(
			reportDir,
			fmt.Sprintf("%s-%s-%d.json", spec.name, safeTarget, timestamp),
		)
		outputFile := filepath.Join(
			outputDir,
			fmt.Sprintf("%s-%s-%d.log", spec.name, safeTarget, timestamp),
		)

		log.Printf("%s scanning target: %s -> report: %s, output: %s",
			spec.logTag, target, reportFile, outputFile)

		cmd := spec.build(ctx, target, reportDir, reportFile)
		output, err := cmd.CombinedOutput()
		if err != nil {
			log.Printf("%s error running %s for %s: %v (output: %s)",
				spec.logTag, spec.name, target, err, string(output))
		}

		if writeErr := writeFile(outputFile, output, 0o644); writeErr != nil {
			log.Printf("%s failed to write %s output for %s to %s: %v",
				spec.logTag, spec.name, target, outputFile, writeErr)
		} else {
			log.Printf("%s %s output written for %s: %s",
				spec.logTag, spec.name, target, outputFile)
		}

		if _, err := statFile(reportFile); err == nil {
			log.Printf("%s %s report saved to %s", spec.logTag, spec.name, reportFile)
		} else {
			log.Printf("%s %s did not produce report for %s (expected: %s): %v",
				spec.logTag, spec.name, target, reportFile, err)
			return fmt.Errorf("%s did not produce report for %s", spec.name, target)
		}
	}

	log.Printf("%s completed for all targets", spec.logTag)
	return nil
}
