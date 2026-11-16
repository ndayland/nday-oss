package posts

import "testing"

func TestLinks(t *testing.T) {
	str := func(p *string) string {
		if p == nil {
			return "<nil>"
		}
		return *p
	}
	for _, c := range [][3]string{
		{"https://x.com/alice_sec/status/123", "123", "https://x.com/alice_sec/status/123"},
		{"https://x.com/i/web/status/123", "123", "https://x.com/i/web/status/123"},
		{"javascript:alert(1)", "123", "https://x.com/i/web/status/123"},
		{"https://x.com/alice_sec/status/123?x=1", "123", "https://x.com/i/web/status/123"},
		{"https://evil.example/alice/status/1", "1", "https://x.com/i/web/status/1"},
		{"https://x.com/a/status/1#frag", "abc", "<nil>"},
		{"", "", "<nil>"},
		{"https://x.com/toolonghandle_1234/status/1", "1\n", "<nil>"},
	} {
		if got := str(PostURL(c[0], c[1])); got != c[2] {
			t.Errorf("PostURL(%q, %q) = %s, want %s", c[0], c[1], got, c[2])
		}
	}
	for h, want := range map[string]string{"alice_sec": "https://x.com/alice_sec", `"><svg>`: "<nil>", "": "<nil>",
		"a b": "<nil>", "toolonghandle_1234": "<nil>"} {
		if got := str(ProfileURL(h)); got != want {
			t.Errorf("ProfileURL(%q) = %s, want %s", h, got, want)
		}
	}
}
