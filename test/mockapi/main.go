// mockapi is a scripted stand-in for the Anthropic Messages API. It lets
// the real Claude Code binary run tool calls inside airbag in tests,
// without a model or credentials:
//
//	mockapi -addr 127.0.0.1:8099 -script calls.json &
//	ANTHROPIC_BASE_URL=http://127.0.0.1:8099 ANTHROPIC_API_KEY=x claude -p go
//
// The script is a JSON list of tool calls, e.g.
// [{"name":"Bash","input":{"command":"echo hi > a.txt"}}]. Each request
// gets the next call (counted by tool results so far), then "done".
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
)

type call struct {
	Name  string          `json:"name"`
	Input json.RawMessage `json:"input"`
}

type request struct {
	Stream   bool `json:"stream"`
	Tools    []any
	Messages []struct {
		Role    string          `json:"role"`
		Content json.RawMessage `json:"content"`
	} `json:"messages"`
}

func main() {
	addr := flag.String("addr", "127.0.0.1:8099", "listen address")
	script := flag.String("script", "", "JSON file with tool calls")
	logPath := flag.String("log", "", "append every request body here (what the model would see)")
	verbose := flag.Bool("v", false, "print each tool call to stderr")
	flag.Parse()
	var calls []call
	if b, err := os.ReadFile(*script); err == nil {
		if err := json.Unmarshal(b, &calls); err != nil {
			log.Fatal(err)
		}
	}
	http.HandleFunc("/v1/messages", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if *logPath != "" {
			if f, err := os.OpenFile(*logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600); err == nil {
				_, _ = f.Write(append(body, '\n'))
				f.Close()
			}
		}
		var req request
		_ = json.Unmarshal(body, &req)
		done := strings.Count(string(body), `"type":"tool_result"`)
		if *verbose {
			showResult(lastResult(body))
		}
		if len(req.Tools) > 0 && done < len(calls) {
			c := calls[done]
			if *verbose {
				fmt.Fprintf(os.Stderr, "  \033[2magent ▶ %s: %s\033[0m\n", c.Name, c.summary())
			}
			respond(w, req.Stream, map[string]any{"type": "tool_use", "id": fmt.Sprintf("toolu_mock_%02d", done+1), "name": c.Name, "input": json.RawMessage(c.Input)}, "tool_use")
			return
		}
		respond(w, req.Stream, map[string]any{"type": "text", "text": "done"}, "end_turn")
	})
	// OpenAI Responses API, as used by Codex CLI.
	http.HandleFunc("/v1/responses", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if *logPath != "" {
			if f, err := os.OpenFile(*logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600); err == nil {
				_, _ = f.Write(append(body, '\n'))
				f.Close()
			}
		}
		done := strings.Count(string(body), `"type":"function_call_output"`) + strings.Count(string(body), `"type":"custom_tool_call_output"`)
		if *verbose {
			showResult(lastResult(body))
		}
		var item map[string]any
		if done < len(calls) {
			c := calls[done]
			if *verbose {
				fmt.Fprintf(os.Stderr, "  \033[2magent ▶ %s: %s\033[0m\n", c.Name, c.summary())
			}
			item = map[string]any{"type": "function_call", "name": c.Name, "arguments": string(c.Input),
				"call_id": fmt.Sprintf("call_mock_%02d", done+1), "id": fmt.Sprintf("fc_mock_%02d", done+1)}
		} else {
			item = map[string]any{"type": "message", "role": "assistant", "id": "msg_mock",
				"content": []any{map[string]any{"type": "output_text", "text": "done"}}}
		}
		w.Header().Set("Content-Type", "text/event-stream")
		f, _ := w.(http.Flusher)
		send := func(data map[string]any) {
			b, _ := json.Marshal(data)
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", data["type"], b)
			if f != nil {
				f.Flush()
			}
		}
		resp := map[string]any{"id": fmt.Sprintf("resp_mock_%02d", done+1), "object": "response", "status": "in_progress", "output": []any{}}
		send(map[string]any{"type": "response.created", "response": resp})
		send(map[string]any{"type": "response.output_item.added", "output_index": 0, "item": item})
		send(map[string]any{"type": "response.output_item.done", "output_index": 0, "item": item})
		resp["status"] = "completed"
		resp["output"] = []any{item}
		resp["usage"] = map[string]any{"input_tokens": 10, "output_tokens": 10, "total_tokens": 20,
			"input_tokens_details": map[string]int{"cached_tokens": 0}, "output_tokens_details": map[string]int{"reasoning_tokens": 0}}
		send(map[string]any{"type": "response.completed", "response": resp})
	})
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{}"))
	})
	log.Fatal(http.ListenAndServe(*addr, nil))
}

func respond(w http.ResponseWriter, stream bool, block map[string]any, stop string) {
	msg := map[string]any{
		"id": "msg_mock", "type": "message", "role": "assistant", "model": "mock",
		"stop_sequence": nil, "usage": map[string]int{"input_tokens": 10, "output_tokens": 10},
	}
	if !stream {
		msg["content"] = []any{block}
		msg["stop_reason"] = stop
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(msg)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	f, _ := w.(http.Flusher)
	send := func(event string, data any) {
		b, _ := json.Marshal(data)
		fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, b)
		if f != nil {
			f.Flush()
		}
	}
	msg["content"], msg["stop_reason"] = []any{}, nil
	send("message_start", map[string]any{"type": "message_start", "message": msg})
	start := map[string]any{}
	for k, v := range block {
		start[k] = v
	}
	var delta map[string]any
	if block["type"] == "tool_use" {
		start["input"] = map[string]any{}
		delta = map[string]any{"type": "input_json_delta", "partial_json": string(block["input"].(json.RawMessage))}
	} else {
		start["text"] = ""
		delta = map[string]any{"type": "text_delta", "text": block["text"]}
	}
	send("content_block_start", map[string]any{"type": "content_block_start", "index": 0, "content_block": start})
	send("content_block_delta", map[string]any{"type": "content_block_delta", "index": 0, "delta": delta})
	send("content_block_stop", map[string]any{"type": "content_block_stop", "index": 0})
	send("message_delta", map[string]any{"type": "message_delta", "delta": map[string]any{"stop_reason": stop, "stop_sequence": nil}, "usage": map[string]int{"output_tokens": 10}})
	send("message_stop", map[string]any{"type": "message_stop"})
}

// summary is how -v shows a call.
func (c call) summary() string {
	var in map[string]any
	_ = json.Unmarshal(c.Input, &in)
	for _, k := range []string{"command", "cmd", "file_path"} {
		if s, ok := in[k].(string); ok {
			return s
		}
	}
	return string(c.Input)
}

// lastResult is what the agent sent back for its previous call, in
// either API: the last tool_result block or function_call_output item.
func lastResult(body []byte) string {
	var r struct {
		Messages []struct {
			Content json.RawMessage `json:"content"`
		} `json:"messages"`
		Input json.RawMessage `json:"input"`
	}
	_ = json.Unmarshal(body, &r)
	var items []map[string]json.RawMessage
	for _, m := range r.Messages {
		var c []map[string]json.RawMessage
		_ = json.Unmarshal(m.Content, &c)
		items = append(items, c...)
	}
	if len(r.Messages) == 0 {
		_ = json.Unmarshal(r.Input, &items)
	}
	for i := len(items) - 1; i >= 0; i-- {
		var typ string
		_ = json.Unmarshal(items[i]["type"], &typ)
		switch typ {
		case "tool_result":
			return text(items[i]["content"])
		case "function_call_output", "custom_tool_call_output":
			return text(items[i]["output"])
		}
	}
	return ""
}

// text flattens a string or a list of text blocks.
func text(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var blocks []struct {
		Text string `json:"text"`
	}
	_ = json.Unmarshal(raw, &blocks)
	var parts []string
	for _, b := range blocks {
		parts = append(parts, b.Text)
	}
	return strings.Join(parts, "\n")
}

// showResult prints the first lines of a result, dimmed and wrapped.
func showResult(s string) {
	// Codex frames exec_command output with chunk and timing headers.
	if i := strings.Index(s, "Output:\n"); i >= 0 && strings.HasPrefix(s, "Chunk ID:") {
		s = s[i+len("Output:\n"):]
	}
	// Claude wraps a hook's refusal.
	s = strings.NewReplacer("<tool_use_error>", "", "</tool_use_error>", "").Replace(s)
	if _, after, ok := strings.Cut(s, " hook error: "); ok {
		s = after
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return
	}
	const width, rows = 100, 5
	var out []string
	for _, l := range strings.Split(s, "\n") {
		r := []rune(l)
		for first := true; first || len(r) > 0; first = false {
			n := min(len(r), width)
			if n < len(r) {
				if sp := strings.LastIndex(string(r[:n]), " "); sp > 0 {
					n = len([]rune(string(r[:n])[:sp])) + 1
				}
			}
			prefix := "  agent ◀ "
			if !first {
				prefix = "          "
			}
			out = append(out, prefix+strings.TrimRight(string(r[:n]), " "))
			r = r[n:]
		}
	}
	if len(out) > rows {
		out = append(out[:rows-1], fmt.Sprintf("  agent ◀ … %d more lines", len(out)-rows+1))
	}
	for _, l := range out {
		fmt.Fprintf(os.Stderr, "\033[2m%s\033[0m\n", l)
	}
}
