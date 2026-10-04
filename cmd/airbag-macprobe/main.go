package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"time"
)

// Usage: airbag-macprobe [-json] [-v] [-keep] [-files N] [-no-net]
//
// The probe needs no root and writes only inside a temporary directory,
// which it removes at the end (unless -keep, or when the export under it
// would not unmount: then it says so and exits 1). It mounts an NFS export
// from a server inside this process under that directory and unmounts
// it. With -no-net it skips the one check that reaches the internet
// (Go TLS through a local proxy to proxy.golang.org).
type options struct {
	json, verbose, keep, noNet bool
	files                      int
}

func main() {
	// The TLS check re-runs this binary inside the sandbox as a client.
	if len(os.Args) == 3 && os.Args[1] == tlsClientArg {
		os.Exit(tlsClient(os.Args[2]))
	}
	var o options
	flag.BoolVar(&o.json, "json", false, "print the report as JSON")
	flag.BoolVar(&o.verbose, "v", false, "print command output under passing checks too")
	flag.BoolVar(&o.keep, "keep", false, "keep the temporary directory")
	flag.BoolVar(&o.noNet, "no-net", false, "skip the check that reaches the internet")
	flag.IntVar(&o.files, "files", 5000, "files in the tree the speed checks create")
	flag.Parse()

	if runtime.GOOS != "darwin" {
		fmt.Fprintln(os.Stderr, "airbag-macprobe: runs on macOS only")
		os.Exit(2)
	}
	rep := &Report{
		Probe:  "airbag-macprobe",
		Time:   time.Now().UTC().Format(time.RFC3339),
		System: systemVersion(),
		Go:     runtime.Version() + " " + runtime.GOARCH,
		User:   fmt.Sprintf("uid=%d", os.Getuid()),
		Args:   os.Args[1:],
	}
	if os.Getuid() == 0 {
		fmt.Fprintln(os.Stderr, "airbag-macprobe: run it as your normal user, not root: the point is what works without root")
		os.Exit(2)
	}

	home, err := homeDir()
	if err != nil {
		fmt.Fprintln(os.Stderr, "airbag-macprobe:", err)
		os.Exit(2)
	}
	dir, err := os.MkdirTemp("", "airbag-macprobe-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "airbag-macprobe:", err)
		os.Exit(1)
	}
	rp := strings.NewReplacer(dir, "$TMP", resolve(dir), "$TMP", home, "~")

	p := &probe{opts: o, dir: resolve(dir), home: home}
	interrupted := make(chan os.Signal, 2)
	signal.Notify(interrupted, os.Interrupt)
	if !o.json {
		fmt.Println(rep.Header())
	}
	// Only the worker touches rep and the probe's mounts while it runs;
	// on Ctrl-C it is told to stop and waited for, so cleanup never races
	// a check that is still using the tree, the server or the mount.
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		for _, c := range checks {
			select {
			case <-stop:
				return
			default:
			}
			r := redact(c(p), rp)
			rep.Add(r)
			if !o.json {
				writeResult(os.Stdout, r, o.verbose)
			}
		}
	}()
	select {
	case <-done:
	case <-interrupted:
		close(stop)
		fmt.Fprintln(os.Stderr, "airbag-macprobe: interrupted; finishing the running check, then cleaning up (Ctrl-C again to quit now)")
		select {
		case <-done:
		case <-interrupted:
			fmt.Fprintln(os.Stderr, "airbag-macprobe: quit without cleanup; remove", dir, "and any mount under it by hand")
			os.Exit(130)
		}
		rep.Interrupted = true
	}
	// A mount that would not go stays where it is, and so does the
	// directory: removing it would go through the mount.
	cerr := p.cleanup()
	switch {
	case cerr != nil:
		fmt.Fprintln(os.Stderr, "airbag-macprobe:", cerr)
		fmt.Fprintln(os.Stderr, "airbag-macprobe: left", dir, "in place; unmount the export under it, then remove it")
	case o.keep:
		fmt.Fprintln(os.Stderr, "kept", dir)
	default:
		if err := os.RemoveAll(dir); err != nil {
			fmt.Fprintln(os.Stderr, "airbag-macprobe: remove", dir+":", err)
		}
	}
	if o.json {
		_ = writeJSON(os.Stdout, rep)
	} else {
		fmt.Println(rep.SummaryLine())
	}
	// An interrupted run is incomplete even when every check it ran passed.
	switch {
	case rep.Interrupted:
		os.Exit(130)
	case rep.Summary.Fail > 0, cerr != nil:
		os.Exit(1)
	}
}
