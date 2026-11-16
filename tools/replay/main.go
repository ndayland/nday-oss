// Command replay runs any nday CLI command with every HTTP GET answered from
// a local file instead of the network (status 200, the file as body). It is
// the Go half of a "same upstream bytes through both implementations" parity
// check; tools/replay_py.py is the Python half.
//
//	curl -sSL -A nday-collector/0.1.0 -o /tmp/kev.json <feed URL>
//	NDAY_DATABASE_URL=... go run ./tools/replay -file /tmp/kev.json collect kev
//
// Requested URLs are logged to stderr. Only single-file feeds can be replayed
// this way; everything else behaves exactly like the nday binary.
package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"

	"nday.land/nday/internal/cli"
	"nday.land/nday/internal/httpc"
)

func main() {
	file := flag.String("file", "", "file served as the body of every GET")
	flag.Parse()
	body, err := os.ReadFile(*file)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	rt := httpc.RoundTripFunc(func(r *http.Request) (*http.Response, error) {
		fmt.Fprintf(os.Stderr, "replay: GET %s (User-Agent %q) <- %s\n", r.URL, r.Header.Get("User-Agent"), *file)
		return &http.Response{StatusCode: 200, Status: "200 OK", Header: http.Header{},
			Body: io.NopCloser(bytes.NewReader(body)), ContentLength: int64(len(body)), Request: r,
			Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1}, nil
	})
	os.Exit(cli.Main(context.Background(), flag.Args(), cli.Env{Transport: rt}))
}
