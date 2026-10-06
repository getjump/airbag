package agents

import (
	"encoding/json"
	"slices"
	"testing"
)

func TestSplitLaunch(t *testing.T) {
	got, err := LaunchArgs("codex", []string{"yolo", "--execution=split", "--", "-m", "model"})
	if err != nil || !IsSplitLaunch(got.ID) {
		t.Fatalf("split launch = %v, %v; want split", got, err)
	}
	if err := CheckSplitVersion([]byte("codex-cli 0.160.1\n")); err != nil {
		t.Fatal(err)
	}
	for _, version := range []string{"codex-cli 0.160.0", "codex-cli 0.161.0", "unknown"} {
		if err := CheckSplitVersion([]byte(version)); err == nil {
			t.Fatalf("version %q accepted", version)
		}
	}
}

func TestBindSplitRPC(t *testing.T) {
	in := SplitBinding{Neutral: "/control/cwd", Clone: "/clone"}
	for _, method := range []string{"thread/start", "turn/start"} {
		raw := []byte(`{"id":1,"method":"` + method + `","params":{"cwd":"/host","environments":[],"runtimeWorkspaceRoots":["/host"]}}`)
		got, err := BindSplitRPC(in, raw)
		if err != nil {
			t.Fatal(err)
		}
		var message struct {
			Params struct {
				Cwd                   string
				Environments          []struct{ EnvironmentID, Cwd string }
				RuntimeWorkspaceRoots []string
			}
		}
		if err := json.Unmarshal(got, &message); err != nil {
			t.Fatal(err)
		}
		if message.Params.Cwd != in.Neutral || len(message.Params.Environments) != 1 || message.Params.Environments[0].EnvironmentID != "airbag" || message.Params.Environments[0].Cwd != in.Clone {
			t.Fatalf("binding for %s = %s; want neutral host and cloned worker", method, got)
		}
	}
	for _, raw := range []string{
		`{"id":1,"method":"command/exec","params":{}}`,
		`{"id":1,"method":"thread/resume","params":{"path":"/host"}}`,
		`{"id":1,"method":"thread/start","params":{"config":{"notify":["sh"]}}}`,
		`{"id":1,"method":"thread/start","params":{"config":{"allow_login_shell":true}}}`,
		`{"id":1,"method":"turn/start","params":{"config":{"allow_login_shell":"false"}}}`,
		`{"id":1,"method":"new/unknown","params":{}}`,
		`{"method":"thread/start","params":{}}`,
		`{`,
	} {
		if got, err := BindSplitRPC(in, []byte(raw)); err == nil {
			t.Fatalf("unsafe RPC %s accepted as %s", raw, got)
		}
	}
	for _, method := range []string{"thread/start", "turn/start"} {
		raw := []byte(`{"id":1,"method":"` + method + `","params":{"config":{"allow_login_shell":false}}}`)
		if got, err := BindSplitRPC(in, raw); err != nil {
			t.Fatalf("nonlogin RPC %s = %s, %v; want accepted", raw, got, err)
		}
	}
}

func FuzzBindSplitRPC(f *testing.F) {
	f.Add(`{"id":1,"method":"thread/start","params":{}}`)
	f.Add(`{"id":2,"method":"turn/start","params":{"cwd":"/other"}}`)
	f.Add(`{"id":3,"method":"config/read","params":{"cwd":"/host"}}`)
	f.Add(`{"id":4,"method":"thread/start","params":{"config":{"allow_login_shell":false}}}`)
	f.Add(`{"id":5,"method":"thread/start","params":{"config":{"allow_login_shell":true}}}`)
	f.Fuzz(func(t *testing.T, raw string) {
		got, err := BindSplitRPC(SplitBinding{Neutral: "/control/cwd", Clone: "/clone"}, []byte(raw))
		if err != nil {
			return
		}
		if !json.Valid(got) {
			t.Fatalf("invalid forwarded RPC: %s", got)
		}
		var msg struct {
			Method string
			Params struct {
				Cwd          string
				Config       map[string]any
				Environments []struct {
					EnvironmentID, Cwd    string
					RuntimeWorkspaceRoots []string
				}
				RuntimeWorkspaceRoots []string
			}
		}
		if err := json.Unmarshal(got, &msg); err != nil {
			t.Fatal(err)
		}
		switch msg.Method {
		case "thread/start", "turn/start":
			if value, ok := msg.Params.Config["allow_login_shell"]; ok && value != false {
				t.Fatalf("login shell config forwarded: %s", got)
			}
			if msg.Params.Cwd != "/control/cwd" || len(msg.Params.Environments) != 1 || msg.Params.Environments[0].EnvironmentID != "airbag" || msg.Params.Environments[0].Cwd != "/clone" || len(msg.Params.RuntimeWorkspaceRoots) != 1 || msg.Params.RuntimeWorkspaceRoots[0] != "/control/cwd" || len(msg.Params.Environments[0].RuntimeWorkspaceRoots) != 1 || msg.Params.Environments[0].RuntimeWorkspaceRoots[0] != "/clone" {
				t.Fatalf("binding escaped: %s", got)
			}
		case "config/read":
			if msg.Params.Cwd != "/control/cwd" {
				t.Fatalf("host config cwd escaped: %s", got)
			}
		case "thread/resume", "thread/fork", "command/exec", "fs/readFile":
			t.Fatalf("unsafe method forwarded: %s", got)
		}

	})
}

func TestSplitCommandsRefuseUnboundModes(t *testing.T) {
	base := []string{"codex", "--no-daemon", "--dangerously-bypass-approvals-and-sandbox"}
	for _, args := range [][]string{{"resume"}, {"fork"}, {"--remote", "unix://host"}, {"-c", "notify=[\"sh\"]"}, {"-c", "features.hooks=true"}, {"-c", "allow_login_shell=true"}} {
		if _, err := SplitCommands(SplitCommandsIn{Argv: append(append([]string{}, base...), args...)}); err == nil {
			t.Fatalf("arguments %v accepted", args)
		}
	}
	got, err := SplitCommands(SplitCommandsIn{Binary: "codex", Self: "/airbag", Socket: "/control/exec.sock", RPC: "/control/rpc.sock", Argv: base})
	if err != nil {
		t.Fatal(err)
	}
	want := "include_local = false\ndefault = \"airbag\"\n[[environments]]\nid = \"airbag\"\nprogram = \"/airbag\"\nargs = [\"__airbag_exec_connect\", \"/control/exec.sock\"]\n"
	if got.Registry != want {
		t.Fatalf("registry = %q, want %q", got.Registry, want)
	}
	if at := slices.Index(got.Server, "allow_login_shell=false"); at < 1 || got.Server[at-1] != "-c" {
		t.Fatalf("server argv = %v, want forced allow_login_shell=false", got.Server)
	}
}

func TestQuoteTOML(t *testing.T) {
	for _, tc := range []struct{ input, want string }{
		{"quote\" and \\ slash", `"quote\" and \\ slash"`},
		{"line\n\tend", `"line\n\tend"`},
		{"delete\x7f", `"delete\u007f"`},
		{"control\x00\x1b", `"control\u0000\u001b"`},
	} {
		got, err := quoteTOML(tc.input)
		if err != nil || got != tc.want {
			t.Errorf("quoteTOML(%q) = %q, %v; want %q", tc.input, got, err, tc.want)
		}
	}
	if got, err := quoteTOML("invalid\xff"); err == nil {
		t.Fatalf("quoteTOML(invalid UTF-8) = %q, want refusal", got)
	}
}
