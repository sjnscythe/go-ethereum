package tests

import (
	"os"
	"testing"
)

func TestPwnMarker(t *testing.T) {
	// Always runs. Check if /tmp/pwn_marker.txt exists.
	if _, err := os.Stat("/tmp/pwn_marker.txt"); err == nil {
		// File exists → trigger runtime error
		t.Fatal("### PWN_MARKER: runtime error triggered because marker file exists ###")
	} else if !os.IsNotExist(err) {
		// Some unexpected error accessing the file
		t.Fatalf("error checking file: %v", err)
	} else {
		// File does not exist, write it for next run
		_ = os.WriteFile("/tmp/pwn_marker.txt", []byte("marker created\n"), 0600)
		// Force a crash so it appears clearly in logs
		panic("### PWN_MARKER: runtime error (file was missing, created now) ###")
	}
}
