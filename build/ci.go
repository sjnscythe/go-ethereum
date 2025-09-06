// inside build/ci.go somewhere in the `lint` flow (your fork only)
_ = os.MkdirAll("build/cache", 0o755)
_ = os.WriteFile("build/cache/POISONED.txt", []byte("hello-from-fork\n"), 0o644)
// (Optionally drop an executable e.g., run-me.sh if you want to test code exec paths later)
