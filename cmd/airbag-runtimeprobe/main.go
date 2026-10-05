//go:build linux

// airbag-runtimeprobe is a deterministic, offline execution experiment. It is
// not an agent sandbox or a security attestation service.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type config struct {
	CanaryPath string `json:"canary_path"`
	CanaryAddr string `json:"canary_addr"`
}

type result struct {
	Status    string             `json:"status"`
	Error     string             `json:"error,omitempty"`
	Phases    map[string]float64 `json:"phases_seconds"`
	Checks    map[string]bool    `json:"checks"`
	GoVersion string             `json:"go_version,omitempty"`
	SHA256    string             `json:"output_sha256,omitempty"`
}

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--child" {
		fmt.Println("child-ok")
		return
	}
	vm := len(os.Args) == 1 && os.Getpid() == 1
	r := result{Status: "failed", Phases: make(map[string]float64), Checks: make(map[string]bool)}
	code := 0
	if err := run(&r, vm); err != nil {
		r.Error, code = err.Error(), 1
	} else {
		r.Status = "passed"
	}
	b, err := json.Marshal(r)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("AIRBAG_RESULT " + string(b))
	if vm {
		poweroff()
	}
	os.Exit(code)
}

func run(r *result, vm bool) error {
	if vm {
		if err := prepareVM(); err != nil {
			return err
		}
	}
	fs := flag.NewFlagSet("runtimeprobe", flag.ContinueOnError)
	work := fs.String("work", "/work", "private workspace")
	goDir := fs.String("go", "/opt/go", "fixed Go toolchain")
	configPath := fs.String("config", "/lab.json", "host canary addresses (no real secrets)")
	checksOnly := fs.Bool("checks-only", false, "negative-control boundary probes only")
	if err := fs.Parse(os.Args[1:]); err != nil {
		return err
	}
	b, err := os.ReadFile(*configPath)
	if err != nil {
		return err
	}
	var c config
	if err := json.Unmarshal(b, &c); err != nil {
		return err
	}
	if c.CanaryPath == "" || c.CanaryAddr == "" {
		return fmt.Errorf("both host canaries are required")
	}
	fmt.Println("AIRBAG_READY")
	_, err = os.ReadFile(c.CanaryPath)
	r.Checks["host_canary_hidden"] = os.IsNotExist(err) || os.IsPermission(err)
	dialer := net.Dialer{Timeout: time.Second}
	conn, err := dialer.DialContext(context.Background(), "tcp", c.CanaryAddr)
	r.Checks["direct_egress_denied"] = err != nil
	if conn != nil {
		_ = conn.Close()
	}
	for name, passed := range r.Checks {
		if !passed {
			return fmt.Errorf("boundary check %s failed", name)
		}
	}
	if *checksOnly {
		return nil
	}
	cache := filepath.Join(*work, ".lab-cache")
	if err := os.MkdirAll(cache, 0o700); err != nil {
		return err
	}
	goBin := filepath.Join(*goDir, "bin", "go")
	env := []string{
		"PATH=" + filepath.Join(*goDir, "bin"), "GOROOT=" + *goDir,
		"HOME=" + cache, "TMPDIR=" + cache, "GOCACHE=" + filepath.Join(cache, "build"),
		"GOMODCACHE=" + filepath.Join(cache, "modules"), "CGO_ENABLED=0", "GOMAXPROCS=1",
		"GOTOOLCHAIN=local", "GOPROXY=off", "GOSUMDB=off", "GOENV=off", "GOFLAGS=",
	}
	command := func(name string, args ...string) ([]byte, error) {
		cmd := exec.CommandContext(context.Background(), name, args...) //nolint:gosec // trusted developer-supplied toolchain and probe; never agent argv
		cmd.Dir, cmd.Env = *work, env
		out, err := cmd.CombinedOutput()
		if err != nil {
			return out, fmt.Errorf("%s %v: %w: %s", name, args, err, out)
		}
		return out, nil
	}
	out, err := command(goBin, "version")
	if err != nil {
		return err
	}
	r.GoVersion = strings.TrimSpace(string(out))
	phase := func(name string, fn func() error) error {
		start := time.Now()
		err := fn()
		r.Phases[name] = time.Since(start).Seconds()
		return err
	}
	build := func() error {
		_, err := command(goBin, "build", "-p=1", "-mod=vendor", "-trimpath", "-buildvcs=false", "-ldflags=-buildid=", "-o", "airbag", "./cmd/airbag")
		return err
	}
	if err := phase("cold_build", build); err != nil {
		return err
	}
	for i := 0; i < 3; i++ {
		if err := phase(fmt.Sprintf("unchanged_build_%d", i+1), build); err != nil {
			return err
		}
	}
	mainPath := filepath.Join(*work, "cmd", "airbag", "main.go")
	mainSource, err := os.ReadFile(mainPath)
	if err != nil {
		return err
	}
	if err := os.WriteFile(mainPath, append(mainSource, []byte("\nvar airbagRuntimeProbeIncremental = 1\n")...), 0o600); err != nil { //nolint:gosec // explicitly supplied private benchmark workspace, not a policy boundary
		return err
	}
	if err := phase("incremental_build", build); err != nil {
		return err
	}
	if err := phase("compatibility_tests", func() error {
		_, err := command(goBin, "test", "-p=1", "-mod=vendor", "./internal/term", "./internal/models")
		return err
	}); err != nil {
		return err
	}
	if err := phase("small_files_2048", func() error { return smallFiles(*work) }); err != nil {
		return err
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	if err := phase("exec_children_32", func() error {
		for i := 0; i < 32; i++ {
			out, err := command(self, "--child")
			if err != nil {
				return err
			}
			if string(out) != "child-ok\n" {
				return fmt.Errorf("unexpected child output %q", out)
			}
		}
		return nil
	}); err != nil {
		return err
	}
	out, err = command(filepath.Join(*work, "airbag"), "version")
	if err != nil {
		return err
	}
	r.Checks["built_program_runs"] = string(out) == "airbag dev\n"
	if !r.Checks["built_program_runs"] {
		return fmt.Errorf("unexpected built program output %q", out)
	}
	b, err = os.ReadFile(filepath.Join(*work, "airbag"))
	if err != nil {
		return err
	}
	digest := sha256.Sum256(b)
	r.SHA256 = hex.EncodeToString(digest[:])
	return nil
}

func smallFiles(work string) error {
	dir := filepath.Join(work, ".lab-files")
	if err := os.Mkdir(dir, 0o700); err != nil {
		return err
	}
	for i := 0; i < 2048; i++ {
		p := filepath.Join(dir, fmt.Sprint(i))
		if err := os.WriteFile(p, []byte("small-file\n"), 0o600); err != nil {
			return err
		}
		if _, err := os.Stat(p); err != nil {
			return err
		}
		if err := os.Rename(p, p+".renamed"); err != nil {
			return err
		}
		b, err := os.ReadFile(p + ".renamed")
		if err != nil {
			return fmt.Errorf("read file %d: %w", i, err)
		}
		if string(b) != "small-file\n" {
			return fmt.Errorf("read-back mismatch at file %d", i)
		}
		if err := os.Remove(p + ".renamed"); err != nil {
			return err
		}
	}
	return nil
}
