package agents

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

func IsSplitLaunch(id string) bool { return id == "codex-yolo-split" }

func CheckSplitVersion(output []byte) error {
	if strings.TrimSpace(string(output)) != "codex-cli 0.160.1" {
		return errors.New("split execution requires Codex 0.160.1; other versions are refused (no fallback)")
	}
	return nil
}

type SplitBinding struct{ Neutral, Clone string }

var splitMethods = map[string]bool{
	"account/read": true, "account/rateLimits/read": true,
	"model/list": true, "experimentalFeature/list": true,
	"configRequirements/read": true, "skills/list": true,
	"mcpServerStatus/list": true, "hooks/list": true, "plugin/list": true, "collaborationMode/list": true,
	"app/list": true, "thread/list": true, "thread/read": true,
	"thread/loaded/list": true, "thread/turns/list": true, "thread/items/list": true,
	"thread/unsubscribe": true, "thread/name/set": true,
	"turn/interrupt": true, "thread/archive": true,
}

func BindSplitRPC(in SplitBinding, raw []byte) ([]byte, error) {
	var msg map[string]json.RawMessage
	if err := json.Unmarshal(raw, &msg); err != nil || msg == nil {
		return nil, errors.New("invalid split RPC")
	}
	var method string
	if err := json.Unmarshal(msg["method"], &method); err != nil {
		return nil, errors.New("split RPC requires a method")
	}
	if method == "initialized" {
		return raw, nil
	}
	if id, ok := msg["id"]; !ok || bytes.Equal(id, []byte("null")) {
		return nil, errors.New("split RPC requires an id")
	}
	var params map[string]any
	if data := msg["params"]; len(data) > 0 && !bytes.Equal(data, []byte("null")) {
		if err := json.Unmarshal(data, &params); err != nil {
			return nil, errors.New("invalid split RPC parameters")
		}
	}
	if params == nil {
		params = map[string]any{}
	}
	switch method {
	case "initialize":
		caps, _ := params["capabilities"].(map[string]any)
		if caps == nil {
			caps = map[string]any{}
		}
		caps["experimentalApi"] = true
		params["capabilities"] = caps
	case "thread/start", "turn/start":
		for _, key := range []string{"dynamicTools", "selectedCapabilityRoots", "path", "history"} {
			value := params[key]
			if value != nil {
				return nil, fmt.Errorf("split execution refuses %s", key)
			}
			delete(params, key)
		}
		if value := params["permissions"]; value != nil {
			if value != "full-access" {
				return nil, errors.New("split execution refuses permission profile")
			}
			delete(params, "permissions")
		}
		if config, ok := params["config"].(map[string]any); ok {
			for key := range config {
				if !splitConfigKey(key) {
					return nil, fmt.Errorf("split execution refuses config key %q", key)
				}
			}
		} else if params["config"] != nil {
			return nil, errors.New("invalid split config")
		}
		params["cwd"] = in.Neutral
		params["runtimeWorkspaceRoots"] = []string{in.Neutral}
		params["environments"] = []map[string]any{{"environmentId": "airbag", "cwd": in.Clone, "runtimeWorkspaceRoots": []string{in.Clone}}}
		params["approvalPolicy"] = "never"
		if method == "thread/start" {
			params["sandbox"] = "danger-full-access"
		} else {
			params["sandboxPolicy"] = map[string]string{"type": "dangerFullAccess"}
		}
	case "config/read":
		params["cwd"] = in.Neutral
	default:
		if !splitMethods[method] {
			return nil, fmt.Errorf("split execution refuses RPC %q", method)
		}
		if _, ok := params["cwd"]; ok {
			params["cwd"] = in.Neutral
		}
	}
	encoded, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	msg["params"] = encoded
	return json.Marshal(msg)
}

type SplitCommandsIn struct {
	Binary, Self, Socket, RPC string
	Argv                      []string
}
type SplitCommandsOut struct {
	Worker, Server, TUI []string
	Registry            string
}

func SplitCommands(in SplitCommandsIn) (SplitCommandsOut, error) {
	if err := ValidateLaunch("codex-yolo-split", in.Argv); err != nil {
		return SplitCommandsOut{}, err
	}
	var config []string
	rest := in.Argv[3:]
	for i := 0; i < len(rest); i++ {
		switch rest[i] {
		case "-c", "--config", "-m", "--model":
			if i+1 == len(rest) {
				return SplitCommandsOut{}, errors.New("missing split launcher option value")
			}
			option := rest[i]
			i++
			if option == "-m" || option == "--model" {
				quoted, err := quoteTOML(rest[i])
				if err != nil {
					return SplitCommandsOut{}, err
				}
				config = append(config, "-c", "model="+quoted)
			} else {
				key, _, ok := strings.Cut(rest[i], "=")
				if !ok || !splitConfigKey(strings.TrimSpace(key)) {
					return SplitCommandsOut{}, fmt.Errorf("unsupported split config key %q", key)
				}
				config = append(config, "-c", rest[i])
			}
		case "--no-alt-screen":
		default:
			if strings.HasPrefix(rest[i], "-") || i != len(rest)-1 {
				return SplitCommandsOut{}, fmt.Errorf("unsupported split launcher argument %q", rest[i])
			}
			if rest[i] == "resume" || rest[i] == "fork" || rest[i] == "exec" {
				return SplitCommandsOut{}, errors.New("split execution currently supports new TUI conversations only")
			}
		}
	}
	self, err := quoteTOML(in.Self)
	if err != nil {
		return SplitCommandsOut{}, err
	}
	socket, err := quoteTOML(in.Socket)
	if err != nil {
		return SplitCommandsOut{}, err
	}
	server := append([]string{in.Binary, "app-server", "--listen", "stdio://"}, config...)
	for _, value := range []string{"features.hooks=false", "features.plugins=false", "features.apps=false", "notify=[]", "mcp_servers={}", "approval_policy=\"never\"", "sandbox_mode=\"danger-full-access\""} {
		server = append(server, "-c", value)
	}
	return SplitCommandsOut{
		Worker:   []string{in.Binary, "exec-server", "--listen", "stdio"},
		Server:   server,
		TUI:      append([]string{in.Binary, "--remote", "unix://" + in.RPC, "--dangerously-bypass-approvals-and-sandbox"}, rest...),
		Registry: "include_local = false\ndefault = \"airbag\"\n[[environments]]\nid = \"airbag\"\nprogram = " + self + "\nargs = [\"__airbag_exec_connect\", " + socket + "]\n",
	}, nil
}

func quoteTOML(value string) (string, error) {
	if !utf8.ValidString(value) {
		return "", errors.New("split config requires valid UTF-8")
	}
	var encoded strings.Builder
	encoded.WriteByte('"')
	for _, r := range value {
		switch r {
		case '"', '\\':
			encoded.WriteByte('\\')
			encoded.WriteRune(r)
		case '\b':
			encoded.WriteString(`\b`)
		case '\t':
			encoded.WriteString(`\t`)
		case '\n':
			encoded.WriteString(`\n`)
		case '\f':
			encoded.WriteString(`\f`)
		case '\r':
			encoded.WriteString(`\r`)
		default:
			if r < 0x20 || r == 0x7f {
				fmt.Fprintf(&encoded, `\u%04x`, r)
			} else {
				encoded.WriteRune(r)
			}
		}
	}
	encoded.WriteByte('"')
	return encoded.String(), nil
}

func splitConfigKey(key string) bool {
	switch key {
	case "model", "model_provider", "model_reasoning_effort", "model_reasoning_summary", "model_verbosity", "web_search", "personality", "tui.animations", "check_for_update_on_startup":
		return true
	}
	if strings.HasPrefix(key, "model_providers.") {
		parts := strings.Split(key, ".")
		if len(parts) == 3 {
			switch parts[2] {
			case "name", "base_url", "wire_api", "env_key":
				return true
			}
		}
	}
	return false
}
