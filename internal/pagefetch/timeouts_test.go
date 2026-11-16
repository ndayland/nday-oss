package pagefetch

import (
	"net/http"
	"testing"
	"time"
)

// TestTimeouts: a page whose first byte takes ~15 s (seen live) fits the
// budget: the whole Get (redirects included) 25 s, response headers 20 s;
// and New wires exactly these into the client and transport.
func TestTimeouts(t *testing.T) {
	const slowFirstByte = 15 * time.Second
	if Timeout != 25*time.Second || HeaderTimeout != 20*time.Second || DialTimeout != 5*time.Second ||
		HeaderTimeout <= slowFirstByte || Timeout <= slowFirstByte {
		t.Errorf("timeouts %v %v %v", Timeout, HeaderTimeout, DialTimeout)
	}
	c := New(Options{UserAgent: "t"})
	tr, ok := c.hc.Transport.(*http.Transport)
	if c.hc.Timeout != Timeout || !ok || tr.ResponseHeaderTimeout != HeaderTimeout || tr.TLSHandshakeTimeout != DialTimeout || tr.Proxy != nil {
		t.Errorf("client %v, transport %+v", c.hc.Timeout, tr)
	}
}
