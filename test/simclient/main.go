// Command simclient is the Go net/http client of test/simulate-e2e.sh:
// it GETs (or POSTs, with -data) a URL with Go's default transport, so
// the proxy and the roots come from the environment as for any Go
// program (HTTPS_PROXY, SSL_CERT_FILE), and prints the status and body.
// -proxy names the proxy instead: Go never sends a request for a
// loopback address through the environment's proxy.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

func main() {
	proxy := flag.String("proxy", "", "proxy URL to use instead of the environment's")
	data := flag.String("data", "", "POST this body")
	flag.Parse()
	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: simclient [-proxy URL] [-data BODY] URL")
		os.Exit(2)
	}
	out, err := get(flag.Arg(0), *proxy, *data)
	if err != nil {
		fmt.Println("ERR", err)
		os.Exit(1)
	}
	fmt.Println(out)
}

func get(target, proxy, data string) (string, error) {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if proxy != "" {
		pu, err := url.Parse(proxy)
		if err != nil {
			return "", err
		}
		tr.Proxy = http.ProxyURL(pu)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	method, body := http.MethodGet, io.Reader(nil)
	if data != "" {
		method, body = http.MethodPost, strings.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		return "", err
	}
	resp, err := (&http.Client{Transport: tr}).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return fmt.Sprint(resp.StatusCode, " ", strings.TrimSpace(string(b))), nil
}
