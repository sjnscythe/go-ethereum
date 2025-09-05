// build/ci.go
package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd := os.Args[1]
	var err error

	switch cmd {
	case "lint":
		// ---- Logs-only probe BEFORE running linters (no network, no writes) ----
		pocCheckOnly()
		err = runLint()
	case "check_generate":
		err = runCheckGenerate()
	case "check_baddeps":
		err = runCheckBaddeps()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %q\n\n", cmd)
		usage()
		os.Exit(2)
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Println(`Usage:
  go run build/ci.go <command>

Commands:
  lint             Run linters (with pre-lint logs-only cache probe)
  check_generate   Verify generated files are up to date (go generate + diff)
  check_baddeps    Verify module graph is tidy (go mod tidy clean check)`)
}

/* ========================= LINT ========================= */

func runLint() error {
	gci := detectGolangCILint()
	if gci == "" {
		return errors.New("golangci-lint not found (looked in build/cache and PATH)")
	}

	args := []string{"run", "--config", ".golangci.yml", "./..."}
	fmt.Printf(">>> %s %s\n", gci, strings.Join(args, " "))
	return runStreaming(gci, args...)
}

/* ========================= CHECK_GENERATE ========================= */

func runCheckGenerate() error {
	// Run go generate across the tree.
	fmt.Println(">>> go generate ./...")
	if err := runStreaming("go", "generate", "./..."); err != nil {
		return fmt.Errorf("go generate failed: %w", err)
	}

	// Fail if go generate would change files (ensures checked-in artifacts are fresh).
	clean, out, err := gitDiffIsClean()
	if err != nil {
		return fmt.Errorf("git diff check failed: %w", err)
	}
	if !clean {
		fmt.Println(out)
		return errors.New("generated files are not up to date; run `go generate ./...` and commit changes")
	}
	fmt.Println("check_generate: OK")
	return nil
}

/* ========================= CHECK_BADDEPS ========================= */

func runCheckBaddeps() error {
	// Safe default: ensure module files are tidy and no unintended changes appear.
	fmt.Println(">>> go mod tidy -v")
	if err := runStreaming("go", "mod", "tidy", "-v"); err != nil {
		return fmt.Errorf("go mod tidy failed: %w", err)
	}
	clean, out, err := gitDiffIsClean()
	if err != nil {
		return fmt.Errorf("git diff check failed: %w", err)
	}
	if !clean {
		fmt.Println(out)
		return errors.New("go.mod/go.sum changed after tidy; commit or fix dependency issues")
	}
	fmt.Println("check_baddeps: OK")
	return nil
}

/* ========================= HELPERS ========================= */

func detectGolangCILint() string {
	// Try cached tool first: build/cache/golangci-lint-<ver>-<goos>-<arch>/golangci-lint
	goos := runtime.GOOS
	arch := runtime.GOARCH
	// Match common arch names used in releases
	normArch := arch
	switch arch {
	case "amd64":
		normArch = "amd64"
	case "arm64":
		normArch = "arm64"
	}
	cacheDir := "build/cache"

	entries, _ := os.ReadDir(cacheDir)
	for _, e := range entries {
		name := e.Name()
		// expected like: golangci-lint-2.0.2-darwin-amd64 or golangci-lint-<ver>-linux-amd64
		if strings.HasPrefix(name, "golangci-lint-") && strings.Contains(name, "-"+goos+"-"+normArch) {
			candidate := filepath.Join(cacheDir, name, "golangci-lint")
			if fileIsExec(candidate) {
				fmt.Printf("%s is up-to-date\n", filepath.Join(cacheDir, name+".tar.gz"))
				return candidate
			}
			// On Windows the binary may have .exe
			if goos == "windows" {
				candidateExe := candidate + ".exe"
				if fileIsExec(candidateExe) {
					fmt.Printf("%s is up-to-date\n", filepath.Join(cacheDir, name+".zip"))
					return candidateExe
				}
			}
		}
	}

	// Fallback to PATH
	if p, err := exec.LookPath("golangci-lint"); err == nil {
		return p
	}
	return ""
}

func fileIsExec(p string) bool {
	st, err := os.Stat(p)
	if err != nil {
		return false
	}
	mode := st.Mode()
	return !mode.IsDir() && mode&0111 != 0
}

func runStreaming(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()
	return cmd.Run()
}

func gitDiffIsClean() (bool, string, error) {
	cmd := exec.Command("git", "diff", "--name-only")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = io.Discard
	cmd.Env = os.Environ()
	if err := cmd.Run(); err != nil {
		return false, "", err
	}
	diff := strings.TrimSpace(out.String())
	return diff == "", "Uncommitted changes:\n" + diff, nil
}

/* ========================= PRE-LINT LOGS-ONLY PROBE ========================= */
/* No network, no writes. Mirrors your Makefile "check" step:                    */
/* - Looks for markers in pip cache + runner toolcache                           */
/* - Prints ::warning:: annotations and short evidence into logs                 */

func pocCheckOnly() {
	pipCache := pocDetectPipCache()
	toolCache := pocDetectToolCache()
	pipMarker := filepath.Join(pipCache, "wheels", "poc", "MARKER.txt")
	toolMarker := filepath.Join(toolCache, "poc", "MARKER.txt")

	found := false
	if pocExists(pipMarker) {
		found = true
		fmt.Println("::warning:: Found PIP cache marker:", pipMarker)
	}
	if pocExists(toolMarker) {
		found = true
		fmt.Println("::warning:: Found TOOL cache marker:", toolMarker)
	}

	fmt.Println("[Cache-Check] time=", time.Now().UTC().Format(time.RFC3339))
	fmt.Println("[Cache-Check] host=", pocHostname(), " runner=", os.Getenv("RUNNER_NAME"))
	fmt.Println("[Cache-Check] repo=", os.Getenv("GITHUB_REPOSITORY"), " event=", os.Getenv("GITHUB_EVENT_NAME"))

	if found {
		if b, err := os.ReadFile(pipMarker); err == nil {
			fmt.Printf("\n[pip marker] %s\n%s\n", pipMarker, string(pocTrim(b, 1200)))
		}
		if b, err := os.ReadFile(toolMarker); err == nil {
			fmt.Printf("\n[tool marker] %s\n%s\n", toolMarker, string(pocTrim(b, 1200)))
		}
	} else {
		fmt.Println("[Cache-Check] No markers found; nothing to report.")
	}
}

func pocDetectPipCache() string {
	// Prefer python3 -m pip cache dir (matches your Makefile)
	if _, err := exec.LookPath("python3"); err == nil {
		if out, err := exec.Command("python3", "-m", "pip", "cache", "dir").CombinedOutput(); err == nil {
			if p := strings.TrimSpace(string(out)); p != "" {
				return p
			}
		}
	}
	// Fallback
	home := pocHomeDir()
	if home == "" {
		home = "."
	}
	return filepath.Join(home, ".cache", "pip")
}

func pocDetectToolCache() string {
	if v := os.Getenv("RUNNER_TOOL_CACHE"); v != "" {
		return v
	}
	home := pocHomeDir()
	if home == "" {
		home = "."
	}
	return filepath.Join(home, "hostedtoolcache")
}

func pocHomeDir() string {
	if runtime.GOOS == "windows" {
		if v := os.Getenv("USERPROFILE"); v != "" {
			return v
		}
		return `C:\Users\Public`
	}
	return os.Getenv("HOME")
}

func pocHostname() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "unknown-host"
	}
	return h
}

func pocExists(p string) bool {
	if p == "" {
		return false
	}
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

func pocTrim(b []byte, max int) []byte {
	if len(b) <= max {
		return b
	}
	return append(append([]byte{}, b[:max]...), []byte("...(truncated)")...)
}
