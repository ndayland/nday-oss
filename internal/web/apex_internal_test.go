package web

import "testing"

// TestApexRedirectTargetRefuses: raw inputs a client library would escape.
func TestApexRedirectTargetRefuses(t *testing.T) {
	s := New(Config{PublicURL: "https://www.nday.land"})
	if got := s.apexHost(); got != "nday.land" {
		t.Fatalf("apexHost %q", got)
	}
	for _, c := range []struct{ path, query string }{
		{"//evil.example/x", ""}, {"/\\evil.example", ""}, {"/a\\b", ""}, {"", ""}, {"evil", ""},
		{"/a\r\nSet-Cookie: x", ""}, {"/a", "q=\n"}, {"/a\x7f", ""}, {"/a", "x#frag"},
	} {
		if got, ok := s.apexRedirectTarget(c.path, c.query); ok {
			t.Errorf("apexRedirectTarget(%q, %q) = %q, want refusal", c.path, c.query, got)
		}
	}
	if got, ok := s.apexRedirectTarget("/vuln/CVE-2026-1", "a=1&b=%2F"); !ok || got != "https://www.nday.land/vuln/CVE-2026-1?a=1&b=%2F" {
		t.Errorf("good target: %q %v", got, ok)
	}
	for _, public := range []string{"https://nday.land", "https://www.", "https://www.:443", ""} {
		if got := New(Config{PublicURL: public}).apexHost(); got != "" {
			t.Errorf("apexHost(%q) = %q", public, got)
		}
	}
}
