package xavatar

import (
	"net/url"
	"strings"
	"testing"
)

func TestAvatarURL(t *testing.T) {
	ok := "https://pbs.twimg.com/profile_images/1790000000000000001/aBc-_x_normal.jpg"
	for _, tc := range []struct {
		in   string
		want bool
	}{
		{ok, true},
		{"https://pbs.twimg.com/profile_images/1/a_400x400.png", true},
		{"http://pbs.twimg.com/profile_images/1/a.jpg", false},
		{"https://pbs.twimg.com.evil.tld/profile_images/1/a.jpg", false},
		{"https://evil.tld/profile_images/1/a.jpg", false},
		{"https://abs.twimg.com/profile_images/1/a.jpg", false},
		{"https://twimg.com/profile_images/1/a.jpg", false},
		{"https://PBS.twimg.com/profile_images/1/a.jpg", false},
		{"https://pbs.twimg.com./profile_images/1/a.jpg", false},
		{"https://user@pbs.twimg.com/profile_images/1/a.jpg", false},
		{"https://user:pw@pbs.twimg.com/profile_images/1/a.jpg", false},
		{"https://pbs.twimg.com:443/profile_images/1/a.jpg", false},
		{"https://pbs.twimg.com:8443/profile_images/1/a.jpg", false},
		{"https://pbs.twimg.com/media/abc.jpg", false},
		{"https://pbs.twimg.com/profile_images/", false},
		{"https://pbs.twimg.com/profile_images/../media/a.jpg", false},
		{"https://pbs.twimg.com/profile_images/1/../../media/a.jpg", false},
		{"https://pbs.twimg.com/profile_images/%2e%2e/media/a.jpg", false},
		{"https://pbs.twimg.com/profile_images/1%2Fa.jpg", false},
		{"https://pbs.twimg.com/profile_images/1/./a.jpg", false},
		{"https://pbs.twimg.com/profile_images/1/a.jpg?x=1", false},
		{"https://pbs.twimg.com/profile_images/1/a.jpg#f", false},
		{"https://pbs.twimg.com\\@evil.tld/profile_images/1/a.jpg", false},
		{"https://pbs.twimg.com/profile_images/1/a b.jpg", false},
		{"//pbs.twimg.com/profile_images/1/a.jpg", false},
		{"javascript:alert(1)", false},
		{"data:image/png;base64,AAAA", false},
		{"", false},
		{"https://pbs.twimg.com/profile_images/" + strings.Repeat("a", 2100), false},
	} {
		got, accepted := AvatarURL(tc.in)
		if accepted != tc.want {
			t.Errorf("AvatarURL(%q) = %q, %v; want %v", tc.in, got, accepted, tc.want)
		}
		if accepted && got != tc.in {
			t.Errorf("AvatarURL(%q) rewrote it to %q", tc.in, got)
		}
	}
	// the redirect rule is the same check
	for in, want := range map[string]bool{ok: true, "https://evil.tld/profile_images/1/a.jpg": false,
		"https://pbs.twimg.com/media/a.jpg": false} {
		u, _ := url.Parse(in)
		if SameHost(u) != want {
			t.Errorf("SameHost(%s) != %v", in, want)
		}
	}
}

func TestCleanName(t *testing.T) {
	for _, tc := range []struct {
		in, want string
		ok       bool
	}{
		{"Alice", "Alice", true},
		{"  Bob \t the\n\nbuilder  ", "Bob the builder", true},
		{"evil\u202egnp.exe", "evilgnp.exe", true},
		{"\u2066iso\u2069late \u200e\u200fmarks\u061c", "isolate marks", true},
		{"zero\u200bwidth\ufeff", "zerowidth", true},
		{"ctl\x00\x07\x1b[31mred", "ctl[31mred", true},
		{"line\u2028sep\u2029para", "line sep para", true},
		{"family 👨\u200d👩\u200d👧", "family 👨\u200d👩\u200d👧", true},
		{"bad \xff utf8", "bad utf8", true},
		{"中文 名字", "中文 名字", true},
		{"", "", false},
		{"   \t\n", "", false},
		{"\u202e\u200f\u2066", "", false},
		{strings.Repeat("あ", 70), strings.Repeat("あ", 64), true},
		{strings.Repeat("a", 63) + " b", strings.Repeat("a", 63), true},
		// nothing visible left: no name
		{"‍‌‍", "", false},
		{"ㅤ", "", false},
		{"ᅟᅠ ﾠ", "", false},
		{"⠀⠀", "", false},
		{"́̂̃", "", false},
		{" ͏︀᠋ ", "", false},
		{"‍́ ㅤ", "", false},
		// fillers around a real name are dropped
		{"ㅤBobㅤ", "Bob", true},
		// combining marks: at most two a base, none without one
		{"Zé̂̃̄̅lgo", "Zé̂lgo", true},
		{"́abc", "abc", true},
		{"á ̂b", "á b", true},
		{"❤️ ok", "❤️ ok", true},
	} {
		got, ok := CleanName(tc.in)
		if got != tc.want || ok != tc.ok {
			t.Errorf("CleanName(%q) = %q, %v; want %q, %v", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}
