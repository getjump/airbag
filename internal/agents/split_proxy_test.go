package agents

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/coder/websocket"
	"go.uber.org/goleak"
)

func TestSplitProxyRejectsLocalExecutionAndJoinsOnDisconnect(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	input, inputWriter := io.Pipe()
	output, outputWriter := io.Pipe()
	defer func() { _ = input.Close(); _ = outputWriter.Close() }()
	done := make(chan error, 1)
	go func() {
		done <- RunSplitProxy(ctx, SplitProxyIn{Binding: SplitBinding{Neutral: "/control/cwd", Clone: "/clone"}, Listener: listener, Input: inputWriter, Output: output})
	}()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("proxy did not join after cancellation")
		}
	}()
	client, response, err := websocket.Dial(ctx, "ws://"+listener.Addr().String()+"/rpc", nil)
	if response != nil && response.Body != nil {
		defer func() { _ = response.Body.Close() }()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.CloseNow() }()
	if err := client.Write(ctx, websocket.MessageText, []byte(`{"id":1,"method":"command/exec","params":{"command":"touch /host"}}`)); err != nil {
		t.Fatal(err)
	}
	_, raw, err := client.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var refusal struct {
		ID    int
		Error struct{ Code int }
	}
	if err := json.Unmarshal(raw, &refusal); err != nil {
		t.Fatal(err)
	}
	if refusal.ID != 1 || refusal.Error.Code != -32602 {
		t.Fatalf("local command response = %s, want refusal for id 1", raw)
	}
	received := make(chan []byte, 1)
	go func() {
		scan := bufio.NewScanner(input)
		if scan.Scan() {
			received <- append([]byte{}, scan.Bytes()...)
		} else {
			received <- nil
		}
	}()
	if err := client.Write(ctx, websocket.MessageText, []byte(`{"id":2,"method":"turn/start","params":{"cwd":"/host","environments":[]}}`)); err != nil {
		t.Fatal(err)
	}
	select {
	case raw := <-received:
		var forwarded struct {
			ID     int
			Params struct {
				Cwd          string
				Environments []struct{ EnvironmentID, Cwd string }
			}
		}
		if err := json.Unmarshal(raw, &forwarded); err != nil {
			t.Fatal(err)
		}
		if forwarded.ID != 2 || forwarded.Params.Cwd != "/control/cwd" || len(forwarded.Params.Environments) != 1 || forwarded.Params.Environments[0].EnvironmentID != "airbag" || forwarded.Params.Environments[0].Cwd != "/clone" {
			t.Fatalf("upstream request = %s, want only bound turn 2", raw)
		}
	case <-ctx.Done():
		t.Fatal("bound turn did not reach upstream")
	}
	if _, err := outputWriter.Write([]byte("{\"id\":2,\"result\":{}}\n")); err != nil {
		t.Fatal(err)
	}
	if _, raw, err := client.Read(ctx); err != nil || string(raw) != `{"id":2,"result":{}}` {
		t.Fatalf("upstream response = %s, %v; want result for id 2", raw, err)
	}
	if err := client.Close(websocket.StatusNormalClosure, ""); err != nil {
		t.Fatal(err)
	}
}

func TestSplitProxyCancellationBeforeConnection(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	ctx, cancel := context.WithCancel(context.Background())
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	input, inputWriter := io.Pipe()
	output, outputWriter := io.Pipe()
	defer func() { _ = input.Close(); _ = outputWriter.Close() }()
	cancel()
	if err := RunSplitProxy(ctx, SplitProxyIn{Listener: listener, Input: inputWriter, Output: output}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled proxy = %v, want context.Canceled", err)
	}
}
