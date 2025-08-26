package tests

import (
	"os"
	"testing"
)

func TestPwnMarker(t *testing.T) {
	_ = os.WriteFile("/tmp/pwn_marker.txt",
		[]byte("### PWN_MARKER: ran ###\n"), 0600)
}
