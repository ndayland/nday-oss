// Command replayhttp runs an nday CLI command with every HTTP GET answered
// from a recorded response (curl -D headers file + raw body file, e.g. the
// gzip bytes exactly as the server sent them), keeping the recorded status
// line headers (ETag, Content-Encoding, Content-Length). It is the offline
// replay harness for the feed collectors (tools/replay always answers 200
// without headers, so it cannot exercise gzip / ETag / 304).
//
//	go run ./internal/collector/feed/testdata/replayhttp -headers x.headers -body x.body [-conditional] collect nuclei
//
// Without -conditional every request gets the recorded 200 (full parse even
// when the request carries the matching If-None-Match). With -conditional a
// request whose If-None-Match equals the recorded ETag gets a 304 carrying
// that ETag, like raw.githubusercontent.com / GitLab. Request headers are
// logged to stderr.
package main

import (
	"bufio"
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/textproto"
	"os"
	"sort"
	"strings"

	"nday.land/nday/internal/cli"
	"nday.land/nday/internal/httpc"
)

func main() {
	hdrFile := flag.String("headers", "", "curl -D output of the recorded response")
	bodyFile := flag.String("body", "", "raw body bytes of the recorded response")
	conditional := flag.Bool("conditional", false, "answer a matching If-None-Match with 304")
	flag.Parse()
	body, err := os.ReadFile(*bodyFile)
	check(err)
	raw, err := os.ReadFile(*hdrFile)
	check(err)
	tp := textproto.NewReader(bufio.NewReader(bytes.NewReader(raw)))
	status, err := tp.ReadLine()
	check(err)
	mh, err := tp.ReadMIMEHeader()
	if err != nil && err != io.EOF {
		check(err)
	}
	hdr := http.Header(mh)
	if !strings.Contains(status, " 200") {
		check(fmt.Errorf("recorded status %q is not 200", status))
	}
	etag := hdr.Get("Etag")
	rt := httpc.RoundTripFunc(func(r *http.Request) (*http.Response, error) {
		var keys []string
		for k := range r.Header {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var parts []string
		for _, k := range keys {
			parts = append(parts, fmt.Sprintf("%s: %s", k, strings.Join(r.Header[k], ", ")))
		}
		if *conditional && etag != "" && r.Header.Get("If-None-Match") == etag {
			fmt.Fprintf(os.Stderr, "replayhttp: GET %s [%s] -> 304\n", r.URL, strings.Join(parts, "; "))
			return &http.Response{StatusCode: 304, Status: "304 Not Modified", Header: http.Header{"Etag": {etag}},
				Body: io.NopCloser(bytes.NewReader(nil)), ContentLength: 0, Request: r,
				Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1}, nil
		}
		fmt.Fprintf(os.Stderr, "replayhttp: GET %s [%s] -> 200 (%d body bytes, Content-Encoding %q)\n",
			r.URL, strings.Join(parts, "; "), len(body), hdr.Get("Content-Encoding"))
		return &http.Response{StatusCode: 200, Status: "200 OK", Header: hdr.Clone(),
			Body: io.NopCloser(bytes.NewReader(body)), ContentLength: int64(len(body)), Request: r,
			Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1}, nil
	})
	os.Exit(cli.Main(context.Background(), flag.Args(), cli.Env{Transport: rt}))
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "replayhttp:", err)
		os.Exit(1)
	}
}
