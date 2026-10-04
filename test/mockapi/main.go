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
		if len(req.Tools) > 0 && done < len(calls) {
			c := calls[done]
			if *verbose {
				var in map[string]any
				_ = json.Unmarshal(c.Input, &in)
				what, _ := in["command"].(string)
				if what == "" {
					what, _ = in["file_path"].(string)
				}
				fmt.Fprintf(os.Stderr, "  \033[2magent ▶ %s: %s\033[0m\n", c.Name, what)
			}
			respond(w, req.Stream, map[string]any{"type": "tool_use", "id": fmt.Sprintf("toolu_mock_%02d", done+1), "name": c.Name, "input": json.RawMessage(c.Input)}, "tool_use")
			return
		}
		respond(w, req.Stream, map[string]any{"type": "text", "text": "done"}, "end_turn")
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
