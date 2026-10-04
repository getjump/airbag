package review

import (
	"encoding/json"
	"io"
	"net"
	"time"

	"github.com/getjump/airbag/internal/effects"
	"github.com/getjump/airbag/internal/outbox"
	"github.com/getjump/airbag/internal/session"
	"github.com/getjump/airbag/internal/steps"
)

type SessionReport struct {
	ID        string   `json:"id"`
	Argv      []string `json:"argv"`
	Status    string   `json:"status"`
	ExitCode  int      `json:"exit_code"`
	Workspace string   `json:"workspace"`
	Duration  string   `json:"duration"`
}

type SecretRead struct {
	File    string `json:"file"`
	Program string `json:"program"`
}

type LabelSource struct {
	Label  string `json:"label"`
	Source string `json:"source"`
}

type HostCounts struct {
	Count int            `json:"count"`
	Hosts map[string]int `json:"hosts"`
}

type NetworkReport struct {
	Allowed HostCounts `json:"allowed"`
	Denied  HostCounts `json:"denied"`
	Cut     HostCounts `json:"cut"`
}

type BlockedEffect struct {
	Kind    string `json:"kind"`
	Target  string `json:"target"`
	Verdict string `json:"verdict"`
	Rule    string `json:"rule"`
}

type IntentReport struct {
	ID     string   `json:"id"`
	Argv   []string `json:"argv"`
	Status string   `json:"status"`
}

// Report is the shared collection used by both the human and JSON review.
type Report struct {
	Session        SessionReport   `json:"session"`
	Changes        []Change        `json:"changes"`
	SecretsRead    []SecretRead    `json:"secrets_read"`
	Labels         []LabelSource   `json:"labels"`
	Network        NetworkReport   `json:"network"`
	Packages       []string        `json:"packages"`
	Steps          []steps.Step    `json:"steps"`
	BlockedEffects []BlockedEffect `json:"blocked_effects"`
	Outbox         []IntentReport  `json:"outbox"`
}

// Collect derives the review fields once so text and machine output agree.
func Collect(s *session.Session, changes []Change, events []effects.Effect, intents []outbox.Intent, toolSteps []steps.Step) Report {
	duration := "running"
	if !s.Ended.IsZero() {
		duration = s.Ended.Sub(s.Created).Round(time.Second).String()
	}
	report := Report{
		Session:     SessionReport{ID: s.ID, Argv: s.Argv, Status: s.Status, ExitCode: s.ExitCode, Workspace: s.Workspace, Duration: duration},
		Changes:     append([]Change{}, changes...),
		SecretsRead: []SecretRead{}, Labels: []LabelSource{},
		Network:  NetworkReport{Allowed: newHostCounts(), Denied: newHostCounts(), Cut: newHostCounts()},
		Packages: []string{}, Steps: append([]steps.Step{}, toolSteps...),
		BlockedEffects: []BlockedEffect{}, Outbox: []IntentReport{},
	}
	seenLabels, seenPackages := map[LabelSource]bool{}, map[string]bool{}
	for _, event := range events {
		switch {
		case event.Kind == "secret.read":
			report.SecretsRead = append(report.SecretsRead, SecretRead{File: event.Target, Program: event.Reason})
		case event.Kind == "label":
			label := LabelSource{Label: event.Verdict, Source: event.Target}
			if !seenLabels[label] {
				seenLabels[label] = true
				report.Labels = append(report.Labels, label)
			}
		case event.Kind == "net.egress":
			host := event.Target
			if h, _, err := net.SplitHostPort(host); err == nil {
				host = h
			}
			category := &report.Network.Allowed
			switch event.Verdict {
			case "deny":
				category = &report.Network.Denied
			case "cut":
				category = &report.Network.Cut
			}
			category.Count++
			category.Hosts[host]++
		case event.Kind == "pkg.fetch" && !seenPackages[event.Target]:
			seenPackages[event.Target] = true
			report.Packages = append(report.Packages, event.Target)
		}
		if (event.Verdict == "deny" || event.Verdict == "ask") && event.Kind != "net.egress" {
			report.BlockedEffects = append(report.BlockedEffects, BlockedEffect{
				Kind: event.Kind, Target: event.Target, Verdict: event.Verdict, Rule: event.Reason,
			})
		}
	}
	for _, intent := range intents {
		report.Outbox = append(report.Outbox, IntentReport{ID: intent.ID, Argv: intent.Argv, Status: intent.Status})
	}
	return report
}

func newHostCounts() HostCounts {
	return HostCounts{Hosts: map[string]int{}}
}

func WriteJSON(w io.Writer, report Report) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}
