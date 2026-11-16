package audit

import (
	"context"
	"strings"
	"testing"
)

// Client address and ray id come from request headers and are shown on the
// audit page: only plain identifier characters are kept.
func TestWithClientKeepsIdentifierCharactersOnly(t *testing.T) {
	ctx := WithClient(context.Background(), "2001:db8::/64‮<x>", "‮abc-SIN\r\n\"'<")
	c, _ := ctx.Value(clientKey{}).(client)
	if c.addr != "2001:db8::/64x" {
		t.Errorf("addr = %q", c.addr)
	}
	if c.ray != "abc-SIN" {
		t.Errorf("ray = %q", c.ray)
	}
	long := WithClient(context.Background(), strings.Repeat("1", 500), strings.Repeat("a", 500))
	if c, _ := long.Value(clientKey{}).(client); len(c.addr) != maxClient || len(c.ray) != maxClient {
		t.Errorf("not cut: %d %d", len(c.addr), len(c.ray))
	}
}
