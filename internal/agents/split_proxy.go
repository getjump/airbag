package agents

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
)

type SplitProxyIn struct {
	Binding  SplitBinding
	Listener net.Listener
	Input    io.WriteCloser
	Output   io.ReadCloser
}

func RunSplitProxy(ctx context.Context, in SplitProxyIn) error {
	parent := ctx
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var accepted atomic.Bool
	done := make(chan error, 1)
	handlerDone := make(chan struct{})
	server := &http.Server{ReadHeaderTimeout: 5 * time.Second}
	server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/rpc" || !accepted.CompareAndSwap(false, true) {
			http.Error(w, "one private session connection only", http.StatusForbidden)
			return
		}
		defer close(handlerDone)
		ws, err := websocket.Accept(w, r, nil)
		if err != nil {
			done <- err
			return
		}
		defer func() { _ = ws.CloseNow() }()
		ws.SetReadLimit(8 << 20)
		pump := make(chan error, 2)
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			scan := bufio.NewScanner(in.Output)
			scan.Buffer(make([]byte, 4096), 8<<20)
			for scan.Scan() {
				if !json.Valid(scan.Bytes()) {
					pump <- errors.New("invalid app-server response")
					return
				}
				if err := ws.Write(ctx, websocket.MessageText, scan.Bytes()); err != nil {
					pump <- err
					return
				}
			}
			if err := scan.Err(); err != nil {
				pump <- err
			} else {
				pump <- io.EOF
			}
		}()
		go func() {
			defer wg.Done()
			for {
				kind, raw, err := ws.Read(ctx)
				if err != nil {
					pump <- err
					return
				}
				if kind != websocket.MessageText {
					pump <- errors.New("split RPC must be text")
					return
				}
				bound, err := BindSplitRPC(in.Binding, raw)
				if err != nil {
					var request struct{ ID json.RawMessage }
					if json.Unmarshal(raw, &request) != nil || len(request.ID) == 0 {
						pump <- err
						return
					}
					reply, encodeErr := json.Marshal(map[string]any{"id": request.ID, "error": map[string]any{"code": -32602, "message": err.Error()}})
					if encodeErr != nil {
						pump <- encodeErr
						return
					}
					if err := ws.Write(ctx, websocket.MessageText, reply); err != nil {
						pump <- err
						return
					}
					continue
				}
				if _, err := in.Input.Write(append(bound, '\n')); err != nil {
					pump <- err
					return
				}
			}
		}()
		err = <-pump
		cancel()
		_ = in.Input.Close()
		_ = in.Output.Close()
		_ = ws.CloseNow()
		wg.Wait()
		done <- err
	})
	serving := make(chan error, 1)
	go func() { serving <- server.Serve(in.Listener) }()
	var err error
	select {
	case err = <-done:
	case err = <-serving:
		serving = nil
	case <-parent.Done():
		err = parent.Err()
	}
	cancel()
	_ = in.Input.Close()
	_ = in.Output.Close()
	_ = server.Close()
	if serving != nil {
		<-serving
	}
	if accepted.Load() {
		<-handlerDone
	}
	return err
}

func ExecConnect(ctx context.Context, path string) error {
	connection, err := (&net.Dialer{}).DialContext(ctx, "unix", path)
	if err != nil {
		return fmt.Errorf("connect private executor (no fallback): %w", err)
	}
	defer func() { _ = connection.Close() }()
	stop := context.AfterFunc(ctx, func() { _ = connection.Close() })
	defer stop()
	copied := make(chan error, 1)
	go func() {
		_, err := io.Copy(connection, os.Stdin)
		if socket, ok := connection.(*net.UnixConn); ok {
			_ = socket.CloseWrite()
		}
		copied <- err
	}()
	_, err = io.Copy(os.Stdout, connection)
	_ = connection.Close()
	_ = os.Stdin.Close()
	copyErr := <-copied
	return errors.Join(err, copyErr)
}

func SplitClientClosed(err error) bool {
	switch websocket.CloseStatus(err) {
	case websocket.StatusNormalClosure, websocket.StatusGoingAway, websocket.StatusNoStatusRcvd:
		return true
	}
	return false
}
