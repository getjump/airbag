package sandbox

import (
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/getjump/airbag/internal/creds"
	"github.com/getjump/airbag/internal/proxy"
	"github.com/getjump/airbag/internal/session"
)

// setupCredentials reads each bound credential's value on the host,
// keeps or makes its placeholder, and makes the session CA, whose
// certificate and a bundle of this machine's roots with it go to the
// session's run directory. A credential whose value cannot be read is
// left out with a warning: the agent then runs without it.
func setupCredentials(s *session.Session, bindings []creds.Binding) (creds.Set, *proxy.CA, error) {
	var set creds.Set
	var metas []session.Credential
	var hosts []string
	for _, b := range bindings {
		v, err := creds.Resolve(b.Source, s.Home)
		if err != nil {
			fmt.Fprintf(os.Stderr, "airbag: credential %s not available (%v); the agent runs without it\n", b.Name, err)
			continue
		}
		ph := ""
		for _, c := range s.Credentials {
			if c.Name == b.Name {
				ph = c.Placeholder
			}
		}
		if ph == "" || ph == v {
			ph = creds.Placeholder(v)
		}
		set = append(set, &creds.Live{Name: b.Name, Hosts: b.Hosts, Value: v, Placeholder: ph})
		metas = append(metas, session.Credential{Name: b.Name, Hosts: b.Hosts, Env: b.Env, Placeholder: ph})
		hosts = append(hosts, b.Hosts...)
	}
	s.Credentials = metas
	if err := s.Save(); err != nil {
		return nil, nil, err
	}
	_ = os.Remove(s.CACert())
	_ = os.Remove(s.CABundle())
	if len(set) == 0 {
		return nil, nil, nil
	}
	ca, err := proxy.NewCA(hosts)
	if err != nil {
		return nil, nil, err
	}
	if err := os.MkdirAll(s.RunDir(), 0o700); err != nil {
		return nil, nil, err
	}
	if err := os.WriteFile(s.CACert(), ca.PEM, 0o644); err != nil {
		return nil, nil, err
	}
	if roots := machineRoots(); roots != nil {
		if err := os.WriteFile(s.CABundle(), append(roots, ca.PEM...), 0o644); err != nil {
			return nil, nil, err
		}
	} else {
		fmt.Fprintln(os.Stderr, "airbag: warning: no CA bundle found on this machine; only Node tools will trust airbag's certificates")
	}
	return set, ca, nil
}

// caVars point tools at a bundle of their own.
var caVars = []string{"SSL_CERT_FILE", "CURL_CA_BUNDLE", "REQUESTS_CA_BUNDLE", "GIT_SSL_CAINFO", "AWS_CA_BUNDLE",
	"PIP_CERT", "CARGO_HTTP_CAINFO", "DENO_CERT"}

var systemBundles = []string{
	"/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt", "/etc/ssl/ca-bundle.pem",
	"/etc/pki/tls/cacert.pem", "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", "/etc/ssl/cert.pem",
}

// machineRoots: the bundles this machine's tools use, those the
// environment names first, so a corporate root stays trusted.
func machineRoots() []byte {
	var paths []string
	for _, k := range append(slices.Clone(caVars), "NODE_EXTRA_CA_CERTS") {
		if p := os.Getenv(k); p != "" && !slices.Contains(paths, p) {
			paths = append(paths, p)
		}
	}
	for _, p := range systemBundles {
		if _, err := os.Stat(p); err == nil {
			paths = append(paths, p)
			break
		}
	}
	var out []byte
	sys := false
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil || len(b) == 0 {
			continue
		}
		out = append(append(out, b...), '\n')
		sys = sys || slices.Contains(systemBundles, p) || p == os.Getenv("SSL_CERT_FILE")
	}
	if !sys {
		return nil
	}
	return out
}

// credEnv: the placeholders under the names the bindings give, and the
// CA for tools to trust. cert and bundle are the paths the agent sees.
func credEnv(s *session.Session, cert, bundle string) map[string]string {
	env := map[string]string{}
	if len(s.Credentials) == 0 {
		return env
	}
	var names []string
	for _, c := range s.Credentials {
		for _, name := range c.Env {
			env[name] = c.Placeholder
			names = append(names, name)
		}
	}
	env["AIRBAG_PLACEHOLDERS"] = strings.Join(names, ",")
	env["NODE_EXTRA_CA_CERTS"] = cert
	if bundle != "" {
		for _, k := range caVars {
			env[k] = bundle
		}
	}
	return env
}
