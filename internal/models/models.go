// Package models predicts the effects of shell commands before they
// run. A model is a signature: argv in, effects out. Commands airbag
// does not know, and anything that runs arbitrary code (python, make,
// npm test), are "opaque": only the sandbox's observation covers them.
package models

import (
	"net/url"
	"path"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// Effect kinds.
const (
	FSWrite   = "fs.write"
	FSDelete  = "fs.delete"
	FSExecBit = "fs.exec_bit"
	NetFetch  = "net.fetch"  // read-only download
	NetEgress = "net.egress" // anything that sends data out
	GitPush   = "intent.git_push"
	Persist   = "persist"
	Opaque    = "opaque"
)

type Effect struct {
	Kind   string `json:"kind"`
	Target string `json:"target,omitempty"`
	Detail string `json:"detail,omitempty"`
}

func (e Effect) String() string {
	s := e.Kind
	if e.Target != "" {
		s += " " + e.Target
	}
	if e.Detail != "" {
		s += " (" + e.Detail + ")"
	}
	return s
}

// Background reports whether a script leaves processes running after
// it returns (cmd &, nohup, setsid, disown).
func Background(script string) bool {
	f, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(script), "")
	if err != nil {
		return true
	}
	bg := false
	syntax.Walk(f, func(n syntax.Node) bool {
		switch n := n.(type) {
		case *syntax.Stmt:
			bg = bg || n.Background || n.Coprocess
		case *syntax.CallExpr:
			if len(n.Args) > 0 {
				if s, _ := word(n.Args[0]); s == "nohup" || s == "setsid" || s == "disown" {
					bg = true
				}
			}
		}
		return !bg
	})
	return bg
}

type Command struct {
	Argv    []string `json:"argv"`
	Dynamic bool     `json:"dynamic,omitempty"` // some words depend on runtime values
	Effects []Effect `json:"effects,omitempty"`
}

// Analyze parses a shell script and predicts each simple command.
func Analyze(script string) ([]Command, error) {
	f, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(script), "")
	if err != nil {
		return nil, err
	}
	var out []Command
	redirs := map[*syntax.CallExpr][]Effect{}
	syntax.Walk(f, func(n syntax.Node) bool {
		switch n := n.(type) {
		case *syntax.Stmt:
			var ws []Effect
			for _, r := range n.Redirs {
				switch r.Op {
				case syntax.RdrOut, syntax.AppOut, syntax.RdrAll, syntax.AppAll:
					if t, _ := word(r.Word); t != "/dev/null" && !strings.HasPrefix(t, "/dev/std") {
						ws = append(ws, Effect{Kind: FSWrite, Target: t, Detail: "redirect"})
					}
				}
			}
			if len(ws) == 0 {
				break
			}
			if call, ok := n.Cmd.(*syntax.CallExpr); ok {
				redirs[call] = ws
			} else {
				out = append(out, Command{Argv: []string{"(redirect)"}, Effects: ws})
			}
		case *syntax.CallExpr:
			if len(n.Args) == 0 {
				break
			}
			c := Command{}
			for _, w := range n.Args {
				s, static := word(w)
				c.Argv = append(c.Argv, s)
				c.Dynamic = c.Dynamic || !static
			}
			// eval 'cmd' and bash -c 'cmd' hide the real command in a string.
			if inner := innerScript(c.Argv); inner != "" {
				if sub, err := Analyze(inner); err == nil {
					out = append(out, sub...)
					break
				}
			}
			c.Effects = append(Predict(c.Argv), redirs[n]...)
			out = append(out, c)
		}
		return true
	})
	return out, nil
}

// word returns the static text of a shell word, with "$…" standing in
// for parts known only at run time.
func word(w *syntax.Word) (string, bool) {
	var b strings.Builder
	static := true
	var part func(p syntax.WordPart)
	part = func(p syntax.WordPart) {
		switch p := p.(type) {
		case *syntax.Lit:
			b.WriteString(p.Value)
		case *syntax.SglQuoted:
			b.WriteString(p.Value)
		case *syntax.DblQuoted:
			for _, q := range p.Parts {
				part(q)
			}
		default:
			b.WriteString("$…")
			static = false
		}
	}
	for _, p := range w.Parts {
		part(p)
	}
	return b.String(), static
}

func innerScript(argv []string) string {
	switch base(argv[0]) {
	case "eval":
		return strings.Join(argv[1:], " ")
	case "bash", "sh", "dash", "zsh":
		for i, a := range argv[1:] {
			if strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--") && strings.Contains(a, "c") && i+2 < len(argv) {
				return argv[i+2]
			}
		}
	}
	return ""
}

func base(p string) string { return path.Base(p) }

// prefixes run their argument as the real command.
var prefixes = map[string]bool{"env": true, "nohup": true, "time": true, "command": true, "exec": true, "nice": true, "timeout": true, "stdbuf": true}

var readOnly = map[string]bool{
	"ls": true, "cat": true, "head": true, "tail": true, "grep": true, "rg": true, "wc": true,
	"echo": true, "printf": true, "pwd": true, "which": true, "test": true, "[": true, "true": true,
	"false": true, "sort": true, "uniq": true, "diff": true, "jq": true, "date": true, "ps": true,
	"stat": true, "file": true, "du": true, "df": true, "tree": true, "less": true, "more": true,
	"cd": true, "source": true, ".": true, "export": true, "set": true, "unset": true, "type": true,
	"read": true, "sleep": true, "id": true, "whoami": true, "uname": true, "basename": true,
	"dirname": true, "realpath": true, "readlink": true, "cut": true, "tr": true, "awk": true,
	"sed": true, "xxd": true, "od": true, "md5sum": true, "sha256sum": true, "local": true,
	"return": true, "shift": true, "trap": true, "wait": true, "kill": true, "shopt": true,
	"getent": true, "hostname": true, "tput": true, "stty": true, "clear": true,
	"alias": true, "unalias": true, "builtin": true, "exit": true, "declare": true,
	"typeset": true, "complete": true, "compgen": true, "hash": true, "let": true,
	"getopts": true, "pushd": true, "popd": true, "dirs": true, "umask": true, "ulimit": true,
}

var codeRunners = map[string]bool{
	"python": true, "python3": true, "node": true, "deno": true, "bun": true, "ruby": true,
	"perl": true, "php": true, "make": true, "cmake": true, "ninja": true, "npx": true,
	"bash": true, "sh": true, "zsh": true, "java": true, "dotnet": true, "./configure": true,
}

// Predict returns the effects of one command.
func Predict(argv []string) []Effect {
	for len(argv) > 0 && (prefixes[base(argv[0])] || strings.Contains(argv[0], "=") && !strings.HasPrefix(argv[0], "-")) {
		argv = argv[1:]
		for len(argv) > 0 && strings.HasPrefix(argv[0], "-") {
			argv = argv[1:] // flags of env/timeout/nice
		}
	}
	if len(argv) == 0 {
		return nil
	}
	name, args := strings.TrimPrefix(base(argv[0]), "\\"), argv[1:] // \cmd skips aliases
	files := nonFlags(args)
	switch {
	case readOnly[name]:
		if name == "sed" || name == "perl" {
			if hasFlagPrefix(args, "-i") && len(files) > 1 {
				return each(FSWrite, files[1:], "in place")
			}
		}
		return nil
	case name == "rm" || name == "rmdir" || name == "unlink":
		detail := ""
		if hasShortFlag(args, 'r') || hasShortFlag(args, 'R') || has(args, "--recursive") {
			detail = "recursive"
		}
		return each(FSDelete, files, detail)
	case name == "mv":
		if len(files) < 2 {
			return nil
		}
		return append(each(FSDelete, files[:len(files)-1], "moved"), Effect{Kind: FSWrite, Target: files[len(files)-1]})
	case name == "cp" || name == "install" || name == "ln" || name == "rsync" && !remote(files):
		if len(files) == 0 {
			return nil
		}
		return []Effect{{Kind: FSWrite, Target: files[len(files)-1]}}
	case name == "mkdir" || name == "touch" || name == "tee" || name == "truncate":
		return each(FSWrite, files, "")
	case name == "chmod":
		if len(files) > 1 && (strings.Contains(files[0], "+x") || execBits(files[0])) {
			return each(FSExecBit, files[1:], "")
		}
		return each(FSWrite, files[min(1, len(files)):], "mode")
	case name == "git":
		return predictGit(args)
	case name == "curl" || name == "wget" || name == "http" || name == "xh":
		return predictHTTP(name, args)
	case name == "ssh" || name == "scp" || name == "sftp" || name == "rsync" || name == "nc" || name == "ncat" || name == "socat" || name == "telnet":
		return []Effect{{Kind: NetEgress, Target: firstRemote(files), Detail: name}}
	case name == "npm" || name == "pnpm" || name == "yarn":
		return predictNPM(name, args)
	case name == "pip" || name == "pip3" || name == "uv" || name == "poetry":
		if len(files) > 0 && (files[0] == "install" || files[0] == "add" || files[0] == "sync") {
			return []Effect{{Kind: NetFetch, Target: "pypi.org"}, {Kind: FSWrite, Target: "site-packages"}}
		}
		return []Effect{{Kind: Opaque, Detail: name}}
	case name == "go":
		return predictGo(files)
	case name == "crontab" || name == "at":
		return []Effect{{Kind: Persist, Target: name}}
	case name == "systemctl" && has(args, "--user"):
		return []Effect{{Kind: Persist, Target: "systemd --user"}}
	case name == "find":
		if has(args, "-delete") {
			return []Effect{{Kind: FSDelete, Target: first(files), Detail: "find -delete"}}
		}
		if has(args, "-exec") || has(args, "-execdir") {
			return []Effect{{Kind: Opaque, Detail: "find -exec"}}
		}
		return nil
	case codeRunners[name] || strings.HasPrefix(argv[0], "./"):
		return []Effect{{Kind: Opaque, Detail: "runs code: " + name}}
	}
	return []Effect{{Kind: Opaque, Detail: "no model for " + name}}
}

func predictGit(args []string) []Effect {
	sub, rest := gitSub(args)
	files := nonFlags(rest)
	switch sub {
	case "push":
		return []Effect{{Kind: GitPush, Target: strings.Join(files, " ")}}
	case "clone":
		e := []Effect{{Kind: NetFetch, Target: host(first(files))}}
		if len(files) > 1 {
			e = append(e, Effect{Kind: FSWrite, Target: files[1]})
		}
		return e
	case "fetch", "pull", "ls-remote", "submodule":
		return []Effect{{Kind: NetFetch, Target: first(files)}, {Kind: FSWrite, Target: ".git"}}
	case "config":
		if has(rest, "--global") || has(rest, "--system") {
			return []Effect{{Kind: Persist, Target: "~/.gitconfig"}}
		}
		for _, f := range files {
			if strings.HasPrefix(f, "core.hooksPath") || strings.HasPrefix(f, "core.sshCommand") || strings.HasPrefix(f, "alias.") || strings.Contains(f, ".pushurl") || strings.Contains(f, "insteadOf") {
				return []Effect{{Kind: Persist, Target: ".git/config", Detail: f}}
			}
		}
		if len(files) >= 2 {
			return []Effect{{Kind: FSWrite, Target: ".git/config"}}
		}
		return nil
	case "clean":
		return []Effect{{Kind: FSDelete, Target: "untracked files", Detail: "git clean"}}
	case "status", "log", "diff", "show", "blame", "grep", "rev-parse", "ls-files", "describe", "shortlog", "reflog", "remote", "help", "version", "":
		return nil
	}
	return []Effect{{Kind: FSWrite, Target: ".git", Detail: "git " + sub}}
}

func gitSub(args []string) (string, []string) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-C" || a == "-c" || a == "--git-dir" || a == "--work-tree":
			i++
		case strings.HasPrefix(a, "-"):
		default:
			return a, args[i+1:]
		}
	}
	return "", nil
}

func predictHTTP(name string, args []string) []Effect {
	method := "GET"
	var out []Effect
	for i, a := range args {
		switch {
		case a == "-X" || a == "--request":
			if i+1 < len(args) {
				method = strings.ToUpper(args[i+1])
			}
		case strings.HasPrefix(a, "-d") || strings.HasPrefix(a, "--data") || a == "-F" || a == "--form" ||
			a == "-T" || a == "--upload-file" || a == "--json" || strings.HasPrefix(a, "--post-"):
			if method == "GET" {
				method = "POST"
			}
		case (a == "-o" || a == "--output" || a == "-O" && name == "wget") && i+1 < len(args):
			out = append(out, Effect{Kind: FSWrite, Target: args[i+1]})
		}
	}
	for _, a := range args {
		if h := host(a); h != "" {
			kind := NetFetch
			if method != "GET" && method != "HEAD" {
				kind = NetEgress
			}
			out = append(out, Effect{Kind: kind, Target: h, Detail: method})
		}
	}
	return out
}

func predictNPM(name string, args []string) []Effect {
	files := nonFlags(args)
	switch first(files) {
	case "install", "i", "ci", "add", "update", "upgrade":
		return []Effect{{Kind: NetFetch, Target: "registry.npmjs.org"}, {Kind: FSWrite, Target: "node_modules"},
			{Kind: Opaque, Detail: "install scripts"}}
	case "publish":
		return []Effect{{Kind: NetEgress, Target: "registry.npmjs.org", Detail: "publish"}}
	case "ls", "list", "view", "info", "outdated", "why", "-v", "--version":
		return nil
	}
	return []Effect{{Kind: Opaque, Detail: "runs package scripts: " + name + " " + first(files)}}
}

func predictGo(files []string) []Effect {
	switch first(files) {
	case "get", "install":
		return []Effect{{Kind: NetFetch, Target: "proxy.golang.org"}, {Kind: FSWrite, Target: "go.mod"}}
	case "mod":
		return []Effect{{Kind: NetFetch, Target: "proxy.golang.org"}, {Kind: FSWrite, Target: "go.mod"}}
	case "build":
		return []Effect{{Kind: FSWrite, Target: "build output"}}
	case "fmt", "vet", "list", "version", "env", "doc":
		return nil
	}
	return []Effect{{Kind: Opaque, Detail: "runs code: go " + first(files)}}
}

func host(s string) string {
	if !strings.Contains(s, "://") {
		return ""
	}
	u, err := url.Parse(s)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

func remote(files []string) bool { return firstRemote(files) != "" }

func firstRemote(files []string) string {
	for _, f := range files {
		if strings.Contains(f, "@") || (strings.Contains(f, ":") && !strings.HasPrefix(f, "/")) {
			return f
		}
	}
	return ""
}

func nonFlags(args []string) []string {
	var out []string
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			out = append(out, a)
		}
	}
	return out
}

func each(kind string, targets []string, detail string) []Effect {
	var out []Effect
	for _, t := range targets {
		out = append(out, Effect{Kind: kind, Target: t, Detail: detail})
	}
	return out
}

func has(args []string, flag string) bool {
	for _, a := range args {
		if a == flag {
			return true
		}
	}
	return false
}

func hasFlagPrefix(args []string, p string) bool {
	for _, a := range args {
		if strings.HasPrefix(a, p) {
			return true
		}
	}
	return false
}

// hasShortFlag finds c in clustered short flags like -rf.
func hasShortFlag(args []string, c rune) bool {
	for _, a := range args {
		if strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--") && strings.ContainsRune(a[1:], c) {
			return true
		}
	}
	return false
}

func execBits(mode string) bool {
	if len(mode) < 3 || strings.Trim(mode, "01234567") != "" {
		return false
	}
	for _, d := range mode[len(mode)-3:] {
		if (d-'0')&1 == 1 {
			return true
		}
	}
	return false
}

func first(s []string) string {
	if len(s) == 0 {
		return ""
	}
	return s[0]
}
