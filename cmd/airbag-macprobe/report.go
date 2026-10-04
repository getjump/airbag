// airbag-macprobe checks, on a real Mac, the assumptions behind the native
// macOS design in docs/macos.md: a deny-first Seatbelt profile, an NFS
// mount from a localhost server without root, its speed, git and the
// agents at the mount path, the sandbox violation log, and Go TLS through
// a proxy without trustd. It prints one line per check; -json prints the
// same as JSON.
//
// The checks run only on macOS (the _darwin.go files). The report, the
// profile text, the tree layout and the proxy are plain Go and are tested
// on Linux too.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
)

// Status of one check.
type Status string

const (
	Pass Status = "PASS"
	Fail Status = "FAIL"
	Info Status = "INFO"
)

// Number is a measurement attached to a result: create_nfs=4.21s.
type Number struct {
	Name  string  `json:"name"`
	Value float64 `json:"value"`
	Unit  string  `json:"unit,omitempty"`
}

func (n Number) String() string { return n.Name + "=" + formatValue(n.Value) + n.Unit }

// formatValue keeps three significant digits and no exponent for the
// values the probe measures.
func formatValue(v float64) string {
	if v == math.Trunc(v) || math.Abs(v) >= 100 {
		return strconv.FormatFloat(v, 'f', 0, 64)
	}
	return strconv.FormatFloat(v, 'g', 3, 64)
}

// Result is one line of the report. Detail holds command output and
// errors; the text report shows it under failures and notes.
type Result struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Status  Status   `json:"status"`
	Reason  string   `json:"reason"`
	Numbers []Number `json:"numbers,omitempty"`
	Detail  string   `json:"detail,omitempty"`
}

// Line formats the result as one line: status, id, name, reason, numbers.
func (r Result) Line() string {
	s := fmt.Sprintf("%-4s %-4s %s: %s", r.Status, r.ID, r.Name, r.Reason)
	if len(r.Numbers) > 0 {
		parts := make([]string, len(r.Numbers))
		for i, n := range r.Numbers {
			parts[i] = n.String()
		}
		s += " [" + strings.Join(parts, " ") + "]"
	}
	return s
}

// Summary counts results by status.
type Summary struct {
	Pass int `json:"pass"`
	Fail int `json:"fail"`
	Info int `json:"info"`
}

// Report is everything the probe found, in the order the checks ran.
type Report struct {
	Probe       string   `json:"probe"`
	Time        string   `json:"time"`
	System      string   `json:"system"`
	Go          string   `json:"go"`
	User        string   `json:"user"`
	Args        []string `json:"args"`
	Results     []Result `json:"results"`
	Summary     Summary  `json:"summary"`
	Interrupted bool     `json:"interrupted,omitempty"`
}

// Add appends a result and counts it.
func (rep *Report) Add(r Result) {
	rep.Results = append(rep.Results, r)
	switch r.Status {
	case Pass:
		rep.Summary.Pass++
	case Fail:
		rep.Summary.Fail++
	default:
		rep.Summary.Info++
	}
}

// Header is the first line of the text report.
func (rep *Report) Header() string {
	return fmt.Sprintf("%s  %s  %s  %s  %s", rep.Probe, rep.System, rep.Go, rep.User, rep.Time)
}

// SummaryLine is the last line of the text report.
func (rep *Report) SummaryLine() string {
	s := fmt.Sprintf("summary: %d PASS, %d FAIL, %d INFO", rep.Summary.Pass, rep.Summary.Fail, rep.Summary.Info)
	if rep.Interrupted {
		s += " (interrupted)"
	}
	return s
}

// maxDetail keeps a pasted report readable.
const maxDetail = 40

// writeResult prints the result's line, and its detail indented under it
// unless it passed (verbose prints that too).
func writeResult(w io.Writer, r Result, verbose bool) {
	fmt.Fprintln(w, r.Line())
	if r.Detail == "" || (r.Status == Pass && !verbose) {
		return
	}
	lines := strings.Split(strings.TrimRight(r.Detail, "\n"), "\n")
	if len(lines) > maxDetail {
		lines = append(lines[:maxDetail], fmt.Sprintf("... %d more lines (see -json)", len(lines)-maxDetail))
	}
	for _, l := range lines {
		fmt.Fprintln(w, "          | "+l)
	}
}

// writeText prints the whole report as text, as the probe does live.
func writeText(w io.Writer, rep *Report, verbose bool) {
	fmt.Fprintln(w, rep.Header())
	for _, r := range rep.Results {
		writeResult(w, r, verbose)
	}
	fmt.Fprintln(w, rep.SummaryLine())
}

func writeJSON(w io.Writer, rep *Report) error {
	b, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return err
	}
	_, err = w.Write(append(b, '\n'))
	return err
}

// redact replaces local paths in a result before it is printed: the temp
// directory, which names the user's folder under /var/folders, and $HOME.
func redact(r Result, rp *strings.Replacer) Result {
	r.Reason = rp.Replace(r.Reason)
	r.Detail = rp.Replace(r.Detail)
	return r
}

// clip shortens command output for a reason or a detail.
func clip(s string, max int) string {
	s = strings.TrimSpace(s)
	if len(s) <= max {
		return s
	}
	return s[:max] + " ..."
}

// firstLine is the first non-empty line of s.
func firstLine(s string) string {
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			return l
		}
	}
	return ""
}
