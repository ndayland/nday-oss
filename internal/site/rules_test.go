package site

import (
	"errors"
	"reflect"
	"sort"
	"testing"
	"time"

	"nday.land/nday/internal/registry"
)

func tp(t time.Time) *time.Time { return &t }

var t0 = time.Date(2026, 11, 9, 0, 0, 0, 0, time.UTC)

func states(s []Slot) string {
	out := ""
	for _, x := range s {
		c := map[string]string{SlotNone: "-", SlotKnown: "K", SlotUnknown: "U", SlotImplied: "I"}[x.State]
		if x.Latest {
			c += "*"
		}
		out += c
	}
	return out
}

func TestComputeSlots(t *testing.T) {
	cases := []struct {
		name string
		in   SlotInput
		want string
	}{
		{"nothing", SlotInput{}, "------"},
		{"known and unknown", SlotInput{Exists: [6]bool{true, true}, FirstAt: [6]*time.Time{tp(t0)}, Latest: "disclosed"}, "K*U----"},
		{"kev only implies itw", SlotInput{Exists: [6]bool{5: true}, FirstAt: [6]*time.Time{5: tp(t0)}, Latest: "kev_added"}, "----IK*"},
		{"kev unknown time still implies", SlotInput{Exists: [6]bool{5: true}}, "----IU"},
		{"real itw known wins", SlotInput{Exists: [6]bool{4: true, 5: true}, FirstAt: [6]*time.Time{4: tp(t0), 5: tp(t0)}, Latest: "kev_added"}, "----KK*"},
		{"real itw unknown is unknown, not implied", SlotInput{Exists: [6]bool{4: true, 5: true}, FirstAt: [6]*time.Time{5: tp(t0)}}, "----UK"},
		{"itw without kev", SlotInput{Exists: [6]bool{4: true}, FirstAt: [6]*time.Time{4: tp(t0)}, Latest: "exploited_in_wild"}, "----K*-"},
	}
	for _, c := range cases {
		got := ComputeSlots(c.in)
		if s := states(got); s != c.want {
			t.Errorf("%s: %s want %s", c.name, s, c.want)
		}
		if len(got) != 6 || got[0].Code != "DIS" || got[5].Code != "KEV" || got[4].Type != "exploited_in_wild" {
			t.Errorf("%s: order %+v", c.name, got)
		}
	}
	s := ComputeSlots(SlotInput{Exists: [6]bool{5: true}, FirstAt: [6]*time.Time{5: tp(t0)}})
	if s[4].NotAfter == nil || !s[4].NotAfter.Equal(t0) || s[4].At != nil || *s[4].ImpliedBy != "kev_added" {
		t.Errorf("implied slot %+v", s[4])
	}
	if s[5].At == nil || !s[5].At.Equal(t0) || s[5].NotAfter != nil || s[5].ImpliedBy != nil {
		t.Errorf("kev slot %+v", s[5])
	}
	u := ComputeSlots(SlotInput{Exists: [6]bool{5: true}})
	if u[4].State != SlotImplied || u[4].NotAfter != nil {
		t.Errorf("implied with unknown kev time must have no bound: %+v", u[4])
	}
}

func TestEventPrecision(t *testing.T) {
	day := "day"
	other := "minute"
	for _, c := range []struct {
		occ      *time.Time
		backfill bool
		prec     *string
		want     string
	}{
		{tp(t0), true, &day, PrecisionDay},
		{tp(t0), false, &day, PrecisionDay},
		{nil, true, &day, PrecisionDay}, // rule order: detail.precision first
		{tp(t0), true, nil, PrecisionExact},
		{tp(t0), false, &other, PrecisionExact},
		{nil, false, nil, PrecisionObserved},
		{nil, true, nil, PrecisionUnknown},
		{nil, true, &other, PrecisionUnknown},
	} {
		if got := EventPrecision(c.occ, c.backfill, c.prec); got != c.want {
			t.Errorf("%v %v %v: %s want %s", c.occ, c.backfill, c.prec, got, c.want)
		}
	}
}

func TestCalendarDays(t *testing.T) {
	dis := time.Date(2026, 11, 4, 21, 16, 59, 0, time.UTC)
	if d := CalendarDays(&dis, tp(t0)); d == nil || *d != 5 {
		t.Errorf("GPUStack T+5d: %v", d)
	}
	late := time.Date(2026, 11, 4, 23, 59, 0, 0, time.FixedZone("x", -5*3600)) // = 11-05T04:59Z
	if d := CalendarDays(&late, tp(t0)); *d != 4 {
		t.Errorf("UTC dates: %d", *d)
	}
	if d := CalendarDays(tp(t0), &dis); *d != -5 {
		t.Errorf("negative: %d", *d)
	}
	if CalendarDays(nil, tp(t0)) != nil || CalendarDays(tp(t0), nil) != nil {
		t.Error("nil")
	}
}

func TestParseSinceAndStage(t *testing.T) {
	for in, want := range map[string]time.Duration{"24h": 24 * time.Hour, "7d": 7 * 24 * time.Hour, " 30D ": 30 * 24 * time.Hour, "1h": time.Hour, "366d": MaxSince} {
		if got, err := ParseSince(in); err != nil || got != want {
			t.Errorf("%q: %v %v", in, got, err)
		}
	}
	for _, in := range []string{"", "0h", "5m", "1.5d", "-1d", "367d", "99999d", "7", "d"} {
		var ie *InputError
		if _, err := ParseSince(in); !errors.As(err, &ie) || ie.Param != "since" {
			t.Errorf("%q accepted or wrong error: %v", in, err)
		}
	}
	if FormatSince(30*24*time.Hour) != "30d" || FormatSince(36*time.Hour) != "36h" {
		t.Error("FormatSince")
	}
	for in, want := range map[string]string{"patch": "patch_released", "PATCH_RELEASED": "patch_released", "poc": "poc_published",
		"exploited": "exploited_in_wild", "kev": "kev_added", "disclosed": "disclosed", "analysis": "analysis_published", "ITW": "exploited_in_wild"} {
		if got, err := ParseStage(in); err != nil || got != want {
			t.Errorf("%q: %v %v", in, got, err)
		}
	}
	if _, err := ParseStage("zzz"); err == nil {
		t.Error("zzz")
	}
}

func TestParseCVEIDAndPrefix(t *testing.T) {
	if id, ok := ParseCVEID(" cve-2026-102895 "); !ok || id != "CVE-2026-102895" {
		t.Error(id)
	}
	for _, bad := range []string{"CVE-2026-12", "2026-102895", "CVE-2026-1x", "CVE-２０２６-1234", "GHSA-x"} {
		if _, ok := ParseCVEID(bad); ok {
			t.Errorf("%q accepted", bad)
		}
	}
	for in, want := range map[string]string{"CVE-2026-102895": "CVE-2026-102895", "cve-2026-1028": "CVE-2026-1028",
		"2026-1028": "CVE-2026-1028", "cve2026": "CVE-2026", "CVE-2026-": "CVE-2026-", "cve-20": "CVE-20", "2026-": "CVE-2026-"} {
		if got, ok := cvePrefix(in); !ok || got != want {
			t.Errorf("%q: %q %v", in, got, ok)
		}
	}
	for _, in := range []string{"cve", "2026", "cve-20-1", "barracuda", "CVE-2026-1028 x", "1028"} {
		if got, ok := cvePrefix(in); ok {
			t.Errorf("%q -> %q", in, got)
		}
	}
}

func TestEscapeLikeAndNormalizeQuery(t *testing.T) {
	if got := EscapeLike(`100%_a\b`); got != `100\%\_a\\b` {
		t.Error(got)
	}
	if q, err := NormalizeQuery("  a \t\n b  "); err != nil || q != "a b" {
		t.Errorf("%q %v", q, err)
	}
	long := make([]rune, MaxQueryRunes+1)
	for i := range long {
		long[i] = '漏'
	}
	if _, err := NormalizeQuery(string(long)); err == nil {
		t.Error("too long accepted")
	}
	if _, err := NormalizeQuery(string(long[:MaxQueryRunes])); err != nil {
		t.Error(err)
	}
	if _, err := NormalizeQuery("a\x00b"); err == nil {
		t.Error("NUL accepted")
	}
	if _, err := NormalizeQuery("\xff\xfe"); err == nil {
		t.Error("invalid UTF-8 accepted")
	}
}

func TestCursorRoundTrip(t *testing.T) {
	c := cursor{at: time.Date(2026, 11, 9, 0, 0, 0, 123000, time.UTC), rank: 6, cve: "CVE-2026-1" + "0001"}
	got, err := decodeCursor(encodeCursor(c))
	if err != nil || !reflect.DeepEqual(got, c) {
		t.Errorf("%+v %v", got, err)
	}
	for _, bad := range []string{"x", "!!!", encodeCursor(cursor{at: t0, rank: 9, cve: "CVE-2026-1000"}), "MXwyfENWRS0="} {
		if _, err := decodeCursor(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestRawPathAndKey(t *testing.T) {
	if p := RawPath("metasploit", "exploit/linux/http/a b"); p != "/raw/metasploit/exploit/linux/http/a%20b.json" {
		t.Error(p)
	}
	for _, ok := range [][2]string{{"kev", "CVE-2026-1"}, {"metasploit", "exploit/linux/http/x_y"}, {"ghsa", "GHSA-gj9m-f8ph-pmhr"}, {"exploitdb", "52001"}} {
		if err := ValidateRawKey(ok[0], ok[1]); err != nil {
			t.Errorf("%v: %v", ok, err)
		}
	}
	for _, bad := range [][2]string{{"nosuch", "x"}, {"kev", "../etc"}, {"kev", "a/../b"}, {"kev", "/abs"}, {"kev", "a//b"}, {"kev", "a/"}, {"kev", "x;drop"}, {"kev", ""}} {
		if err := ValidateRawKey(bad[0], bad[1]); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
}

// Every registered collector must be classified explicitly: public
// (SourceNames) or non-public (NonPublicSources, public.go), never both.
func TestSourceNamesMatchRegistry(t *testing.T) {
	for _, n := range NonPublicSources {
		if contains(SourceNames, n) {
			t.Errorf("%s is both public and non-public", n)
		}
	}
	a := append(append([]string(nil), SourceNames...), NonPublicSources...)
	sort.Strings(a)
	if !reflect.DeepEqual(a, registry.Names()) {
		t.Errorf("public+non-public %v != registry %v", a, registry.Names())
	}
}
