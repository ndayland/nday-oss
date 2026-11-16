package stats

import (
	"math"
	"sort"
	"strings"
	"time"
)

// TopN is the number of entries stored per (day, kind) in stats_top.
const TopN = 100

// maxTopKeys bounds the distinct keys counted per top list and day (memory
// bound against e.g. a scanner requesting millions of distinct 404 paths);
// keys first seen after the bound are counted in rollup/top_overflow.
const maxTopKeys = 200_000

// minSearchVisitors: a search term is stored only when at least this many
// distinct visitors used it that day (privacy rule, docs/stats.md).
const minSearchVisitors = 2

// Top-list kinds (stats_top.kind).
const (
	TopVulnPage      = "vuln_page"
	TopVulnPageHuman = "vuln_page_human"
	TopAPIVuln       = "api_vuln"
	TopReferrer      = "referrer_host"
	TopReferrerHuman = "referrer_host_human"
	TopCountry       = "country"
	TopCountryHuman  = "country_human"
	TopSearch        = "search"
	TopNotFound      = "not_found_human"
	TopBotUA         = "bot_ua"
)

type metricKey struct{ metric, dim string }

// termStat counts one search term; multi records a second distinct
// visitor (minSearchVisitors = 2 needs no full visitor set).
type termStat struct {
	n     int64
	first [8]byte
	seen  bool
	multi bool
}

// dayAgg accumulates one day.
type dayAgg struct {
	day  string
	salt []byte
	own  func(string) bool

	daily      map[metricKey]int64
	tops       map[string]map[string]int64
	overflow   int64
	visitors   map[[8]byte]bool // page visitors -> human
	apiClients map[[8]byte]bool
	search     map[string]*termStat
	rt         map[string]map[int64]int64 // "page|all" -> ms -> count
}

func newDayAgg(day string, salt []byte, own func(string) bool) *dayAgg {
	return &dayAgg{day: day, salt: salt, own: own, daily: map[metricKey]int64{},
		tops: map[string]map[string]int64{}, visitors: map[[8]byte]bool{},
		apiClients: map[[8]byte]bool{}, search: map[string]*termStat{}, rt: map[string]map[int64]int64{}}
}

func (a *dayAgg) inc(metric, dim string, n int64) { a.daily[metricKey{metric, dim}] += n }

// both counts n under audience "all" and, for human traffic, "human";
// value "" gives the scalar dims "all" / "human", else "all:<value>".
func (a *dayAgg) both(metric, value string, human bool, n int64) {
	if value == "" {
		a.inc(metric, "all", n)
		if human {
			a.inc(metric, "human", n)
		}
		return
	}
	a.inc(metric, "all:"+value, n)
	if human {
		a.inc(metric, "human:"+value, n)
	}
}

func (a *dayAgg) top(kind, key string) {
	if key == "" {
		return
	}
	m := a.tops[kind]
	if m == nil {
		m = map[string]int64{}
		a.tops[kind] = m
	}
	if _, ok := m[key]; !ok && len(m) >= maxTopKeys {
		a.overflow++
		return
	}
	m[key]++
}

func (a *dayAgg) rtAdd(group string, human bool, seconds float64) {
	ms := int64(math.Round(seconds * 1000))
	if ms < 0 || math.IsNaN(seconds) {
		ms = 0
	}
	for _, aud := range []string{"all", "human"} {
		if aud == "human" && !human {
			break
		}
		k := group + "|" + aud
		h := a.rt[k]
		if h == nil {
			h = map[int64]int64{}
			a.rt[k] = h
		}
		h[ms]++
	}
}

// add accumulates one well-formed line of this day.
func (a *dayAgg) add(l *Line) {
	human := !IsBot(l.UserAgent)
	c := Classify(l.Domain, l.Method, l.URI, l.Status)
	domain := l.Domain
	if domain == "" {
		domain = "(none)"
	} else if len(domain) > 255 {
		domain = domain[:255]
	}
	a.both("req", "", human, 1)
	if !human {
		a.inc("req", "bot", 1)
	}
	a.both("req_domain", domain, human, 1)
	a.both("req_status", StatusClass(l.Status), human, 1)
	a.both("req_kind", c.Kind, human, 1)
	if c.Error {
		a.both("req_error_kind", c.BaseKind, human, 1)
	}
	bytes := l.BytesSent
	if bytes < 0 {
		bytes = 0
	}
	a.both("bytes", "", human, bytes)
	a.both("bytes_kind", c.Kind, human, bytes)

	var vk [8]byte
	haveKey := false
	key := func() [8]byte {
		if !haveKey {
			vk, haveKey = VisitorKey(a.salt, a.day, l.ClientIP, l.UserAgent), true
		}
		return vk
	}
	if c.PageView {
		a.both("pv", "", human, 1)
		a.both("pv_page", c.PageKind, human, 1)
		a.both("pv_locale", c.Locale, human, 1)
		a.visitors[key()] = human
		a.rtAdd("page", human, l.RequestTime)
		if c.CVE != "" {
			a.top(TopVulnPage, c.CVE)
			if human {
				a.top(TopVulnPageHuman, c.CVE)
			}
		}
		if h := RefererHost(l.Referer, func(h string) bool { return a.own(h) || h == l.Domain }); h != "" {
			a.top(TopReferrer, h)
			if human {
				a.top(TopReferrerHuman, h)
			}
		}
		if cc := countryCode(l.Country); cc != "" {
			a.top(TopCountry, cc)
			if human {
				a.top(TopCountryHuman, cc)
			}
		}
	}
	if c.Kind == KindAPI {
		a.both("api", "", human, 1)
		a.both("api_endpoint", c.APIEndpoint, human, 1)
		a.apiClients[key()] = human
		a.rtAdd("api", human, l.RequestTime)
		if c.CVE != "" {
			a.top(TopAPIVuln, c.CVE)
		}
	}
	if c.Search != "" {
		ts := a.search[c.Search]
		if ts == nil && len(a.search) < maxTopKeys {
			ts = &termStat{}
			a.search[c.Search] = ts
		}
		if ts == nil {
			a.overflow++
		} else {
			ts.n++
			switch k := key(); {
			case !ts.seen:
				ts.first, ts.seen = k, true
			case ts.first != k:
				ts.multi = true
			}
		}
	}
	if l.Status == 404 && human {
		a.top(TopNotFound, NotFoundPath(l.URI))
	}
	if !human {
		a.top(TopBotUA, BotFamily(l.UserAgent))
	}
}

// countryCode keeps a CF-IPCountry value if it looks like one ("US", "T1",
// "XX"); anything else is dropped.
func countryCode(s string) string {
	if len(s) != 2 {
		return ""
	}
	s = strings.ToUpper(s)
	for i := 0; i < 2; i++ {
		if !(s[i] >= 'A' && s[i] <= 'Z' || s[i] >= '0' && s[i] <= '9') {
			return ""
		}
	}
	return s
}

// DailyRow is one stats_daily row.
type DailyRow struct {
	Metric, Dim string
	Value       int64
}

// TopRow is one stats_top row.
type TopRow struct {
	Kind, Key string
	Value     int64
}

// percentile is the nearest-rank percentile of a histogram.
func percentile(h map[int64]int64, p float64) int64 {
	var n int64
	keys := make([]int64, 0, len(h))
	for k, c := range h {
		keys = append(keys, k)
		n += c
	}
	if n == 0 {
		return 0
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	rank := int64(math.Ceil(p / 100 * float64(n)))
	if rank < 1 {
		rank = 1
	}
	var seen int64
	for _, k := range keys {
		seen += h[k]
		if seen >= rank {
			return k
		}
	}
	return keys[len(keys)-1]
}

// rows finalises the day: counters (non-zero only), unique counts,
// percentiles, and the top lists (search terms filtered by the visitor
// threshold), each sorted for deterministic output.
func (a *dayAgg) rows(scan scanResult, misfiledIn int64) ([]DailyRow, []TopRow) {
	var uvAll, uvHuman, apiAll, apiHuman int64
	for _, h := range a.visitors {
		uvAll++
		if h {
			uvHuman++
		}
	}
	for _, h := range a.apiClients {
		apiAll++
		if h {
			apiHuman++
		}
	}
	a.inc("uv", "all", uvAll)
	a.inc("uv", "human", uvHuman)
	a.inc("api_clients", "all", apiAll)
	a.inc("api_clients", "human", apiHuman)
	for k, h := range a.rt {
		group, aud, _ := strings.Cut(k, "|")
		for _, p := range []struct {
			name string
			v    float64
		}{{"p50", 50}, {"p95", 95}, {"p99", 99}} {
			a.daily[metricKey{"rt_" + group + "_ms", aud + ":" + p.name}] = percentile(h, p.v)
		}
	}
	for term, ts := range a.search {
		if ts.multi { // >= minSearchVisitors distinct visitors
			if a.tops[TopSearch] == nil {
				a.tops[TopSearch] = map[string]int64{}
			}
			a.tops[TopSearch][term] = ts.n
		}
	}
	a.inc("rollup", "lines", scan.Lines)
	a.inc("rollup", "bad", scan.Bad)
	a.inc("rollup", "partial", scan.Partial)
	a.inc("rollup", "misfiled_in", misfiledIn)
	a.inc("rollup", "top_overflow", a.overflow)

	daily := make([]DailyRow, 0, len(a.daily))
	for k, v := range a.daily {
		// percentiles are kept even when 0 ms; other zero counters are not stored
		if v != 0 || strings.HasPrefix(k.metric, "rt_") {
			daily = append(daily, DailyRow{k.metric, k.dim, v})
		}
	}
	sort.Slice(daily, func(i, j int) bool {
		if daily[i].Metric != daily[j].Metric {
			return daily[i].Metric < daily[j].Metric
		}
		return daily[i].Dim < daily[j].Dim
	})
	var tops []TopRow
	kinds := make([]string, 0, len(a.tops))
	for k := range a.tops {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	for _, kind := range kinds {
		m := a.tops[kind]
		list := make([]TopRow, 0, len(m))
		for k, v := range m {
			list = append(list, TopRow{kind, k, v})
		}
		sort.Slice(list, func(i, j int) bool {
			if list[i].Value != list[j].Value {
				return list[i].Value > list[j].Value
			}
			return list[i].Key < list[j].Key
		})
		if len(list) > TopN {
			list = list[:TopN]
		}
		tops = append(tops, list...)
	}
	return daily, tops
}

// visitorRows lists the page visitors of the day.
func (a *dayAgg) visitorRows(day time.Time) [][]any {
	out := make([][]any, 0, len(a.visitors))
	for k, h := range a.visitors {
		kk := k
		out = append(out, []any{day, kk[:], h})
	}
	return out
}
