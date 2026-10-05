package runtimepolicy

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

const maxProfileMetrics = 128
const maxMetricName = 96

// Metric aggregates observations without keeping paths, argv, or individual
// samples. DurationNS is wall time, including waits; overlapping observations
// must not be added together to infer elapsed session time.
type Metric struct {
	Count      uint64 `json:"count"`
	Requests   uint64 `json:"requests"`
	DurationNS uint64 `json:"duration_ns"`
	MaxNS      uint64 `json:"max_ns"`
}

type ProfileSnapshot struct {
	Metrics map[string]Metric `json:"metrics"`
}

// Profile is optional, bounded, and safe to record from concurrent callbacks.
// Its zero value is ready for use. A nil Profile records nothing.
type Profile struct {
	mu      sync.Mutex
	metrics map[string]Metric
}

func (p *Profile) Record(name string, elapsed time.Duration, requests uint64) {
	if p == nil {
		return
	}
	if elapsed < 0 {
		elapsed = 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.metrics == nil {
		p.metrics = make(map[string]Metric)
	}
	if !validMetricName(name) || (len(p.metrics) >= maxProfileMetrics-1 && p.metrics[name].Count == 0) {
		name = "profile.overflow"
	}
	m := p.metrics[name]
	m.Count++
	m.Requests += requests
	m.DurationNS += uint64(elapsed)
	if uint64(elapsed) > m.MaxNS {
		m.MaxNS = uint64(elapsed)
	}
	p.metrics[name] = m
}

func (p *Profile) Snapshot() ProfileSnapshot {
	s := ProfileSnapshot{Metrics: make(map[string]Metric)}
	if p == nil {
		return s
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for name, metric := range p.metrics {
		s.Metrics[name] = metric
	}
	return s
}

func validMetricName(name string) bool {
	if name == "" || len(name) > maxMetricName {
		return false
	}
	for _, c := range name {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("._-", c)) {
			return false
		}
	}
	return true
}

func (s ProfileSnapshot) validate() error {
	if len(s.Metrics) > maxProfileMetrics {
		return fmt.Errorf("too many runtime profile metrics")
	}
	for name, m := range s.Metrics {
		if !validMetricName(name) || len(name)+len("child.") > maxMetricName || m.MaxNS > m.DurationNS {
			return fmt.Errorf("invalid runtime profile metric")
		}
	}
	return nil
}

func (p *Profile) mergeChild(s ProfileSnapshot) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.metrics == nil {
		p.metrics = make(map[string]Metric)
	}
	for name, m := range s.Metrics {
		name = "child." + name
		if len(p.metrics) >= maxProfileMetrics-1 && p.metrics[name].Count == 0 {
			name = "profile.overflow"
		}
		old := p.metrics[name]
		old.Count += m.Count
		old.Requests += m.Requests
		old.DurationNS += m.DurationNS
		if m.MaxNS > old.MaxNS {
			old.MaxNS = m.MaxNS
		}
		p.metrics[name] = old
	}
}
