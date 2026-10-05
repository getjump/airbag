//go:build linux

// probe is the agent in test/tty's relay test. It reports, one line
// each, what crosses airbag's terminal relay in both directions:
//
//	probe size 120x36           its terminal size, at start
//	probe da1 "\x1b[?62;...c"   the replies to the queries it sends
//	probe cpr "\x1b[3;1R"
//	probe osc11 "\x1b]11;rgb:..."
//	probe ready
//	probe in "\x1b[I"           each burst of input, quoted
//	probe winch 100x30          each SIGWINCH, with the new size
//	probe sigint                then it exits with status 3
//
// It reads its terminal in raw mode but keeps ISIG, so a Ctrl-C byte
// becomes SIGINT in this terminal's line discipline, as it would for
// a shell.
package main

import (
	"fmt"
	"os"
	"os/signal"
	"regexp"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// The status after SIGINT: neither airbag's own failures (1, 2) nor a
// death by the signal (130), so the test can tell whose it is.
const sigintStatus = 3

// The queries go out in one write, DA1 last: terminals answer in order,
// so its reply means the others had their chance.
const queries = "\x1b]11;?\x1b\\" + "\x1b[6n" + "\x1b[c"

var replies = []struct {
	name string
	re   *regexp.Regexp
}{
	{"da1", regexp.MustCompile(`\x1b\[\?[0-9;]*c`)},
	{"cpr", regexp.MustCompile(`\x1b\[[0-9]+;[0-9]+R`)},
	{"osc11", regexp.MustCompile(`\x1b\]11;[^\x07\x1b]*(\x07|\x1b\\)`)},
}

// Bracketed paste, focus events and SGR mouse reports, so that a real
// terminal sends what the test sends by hand.
const (
	modesOn  = "\x1b[?2004h\x1b[?1004h\x1b[?1000h\x1b[?1006h"
	modesOff = "\x1b[?1006l\x1b[?1000l\x1b[?1004l\x1b[?2004l"
)

func main() {
	fd := int(os.Stdin.Fd())
	saved, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		fmt.Fprintln(os.Stderr, "probe: stdin is not a terminal:", err)
		os.Exit(2)
	}
	raw := *saved
	raw.Iflag &^= unix.ICRNL | unix.INLCR | unix.IGNCR | unix.IXON | unix.ISTRIP
	raw.Lflag &^= unix.ICANON | unix.ECHO | unix.ECHONL | unix.IEXTEN
	raw.Lflag |= unix.ISIG
	raw.Cc[unix.VMIN], raw.Cc[unix.VTIME] = 1, 0
	if err := unix.IoctlSetTermios(fd, unix.TCSETS, &raw); err != nil {
		fmt.Fprintln(os.Stderr, "probe: raw mode:", err)
		os.Exit(2)
	}
	exit := func(code int) {
		fmt.Print(modesOff)
		_ = unix.IoctlSetTermios(fd, unix.TCSETS, saved)
		os.Exit(code)
	}

	sigs := make(chan os.Signal, 8)
	signal.Notify(sigs, syscall.SIGWINCH, syscall.SIGINT)
	in := make(chan []byte, 64)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := os.Stdin.Read(buf)
			if n > 0 {
				in <- append([]byte(nil), buf[:n]...)
			}
			if err != nil {
				close(in)
				return
			}
		}
	}()

	fmt.Printf("probe size %s\n", size(fd))
	fmt.Print(queries)
	got := collect(in, replies[0].re, 10*time.Second)
	for _, r := range replies {
		if m := r.re.Find(got); m != nil {
			fmt.Printf("probe %s %q\n", r.name, m)
			got = r.re.ReplaceAll(got, nil)
		} else {
			fmt.Printf("probe %s missing\n", r.name)
		}
	}
	if len(got) > 0 {
		fmt.Printf("probe extra %q\n", got)
	}
	fmt.Print(modesOn)
	fmt.Println("probe ready")

	// A burst of input is printed once it has been quiet for a moment:
	// a relay may split one write of the test into several reads.
	var pending []byte
	quiet := time.NewTimer(time.Hour)
	quiet.Stop()
	for {
		select {
		case b, ok := <-in:
			if !ok {
				fmt.Println("probe eof")
				exit(1)
			}
			pending = append(pending, b...)
			quiet.Reset(150 * time.Millisecond)
		case <-quiet.C:
			fmt.Printf("probe in %q\n", pending)
			pending = nil
		case s := <-sigs:
			if s == syscall.SIGWINCH {
				fmt.Printf("probe winch %s\n", size(fd))
				continue
			}
			fmt.Println("probe sigint")
			exit(sigintStatus)
		}
	}
}

// collect reads input until it matches last or the time is up.
func collect(in <-chan []byte, last *regexp.Regexp, timeout time.Duration) []byte {
	var got []byte
	deadline := time.After(timeout)
	for !last.Match(got) {
		select {
		case b, ok := <-in:
			if !ok {
				return got
			}
			got = append(got, b...)
		case <-deadline:
			return got
		}
	}
	return got
}

func size(fd int) string {
	ws, err := unix.IoctlGetWinsize(fd, unix.TIOCGWINSZ)
	if err != nil {
		return "unknown"
	}
	return fmt.Sprintf("%dx%d", ws.Col, ws.Row)
}
