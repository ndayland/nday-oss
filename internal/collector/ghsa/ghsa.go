// Package ghsa is the GitHub Advisory Database collector (port of
// src/nday/collectors/ghsa.py; read that module's docstring for the upstream
// facts and the strategy).
//
// Fetch: GET https://api.github.com/advisories?type=reviewed&sort=updated&
// direction=asc&per_page=100&updated=>=<since>, following Link rel="next"
// verbatim, at most MaxRequests list requests per run. The cursor
// ({"since", "pending", "gaps", "last_run", "bootstrap"}) has exactly the
// Python keys, values and types, so a cursor written by Python is continued
// as is. Rate limits (403/429 with x-ratelimit-remaining: 0, Retry-After,
// "rate limit" in the body) stop pagination: the first run fails (nothing
// stored), an incremental run keeps what it fetched and stores the
// remaining next URL in cursor.pending.
//
// Normalize: no cve_id -> nothing; withdrawn -> alias only; otherwise alias,
// stub vuln and, iff a package has a first_patched_version, one
// patch_released event (dedupe_key = GHSA id, occurred_at nil).
//
// HTTP: this package has its own small GET loop instead of internal/httpc
// because GHSA needs Python's exact policy, which httpc cannot express: no
// redirects (httpx follow_redirects=False; a 3xx is an error), 403
// classification by headers AND body, per-attempt rate-limit bookkeeping, and
// "stop" (keep progress) instead of "error" when retries run out. The
// User-Agent is httpc.UserAgent.
package ghsa

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"math/big"
	"net"
	"net/http"
	"time"

	"nday.land/nday/internal/collector"
	"nday.land/nday/internal/pyjson"
	"nday.land/nday/internal/pystr"
)

// Name is the source name (raw_record.source, event.source, collector_state.source).
const Name = "ghsa"

// Constants, identical to ghsa.py.
const (
	APIBase        = "https://api.github.com"
	AdvisoriesURL  = APIBase + "/advisories"
	APIVersion     = "2022-11-28"
	PerPage        = 100
	AcceptHeader   = "application/vnd.github+json"
	TokenEnv       = "NDAY_GITHUB_TOKEN"
	BootstrapEnv   = "NDAY_GHSA_BOOTSTRAP_DAYS"
	MaxRequestsEnv = "NDAY_GHSA_MAX_REQUESTS"
	OverlapEnv     = "NDAY_GHSA_OVERLAP_MINUTES"

	DefaultBootstrapDays  = 7
	MaxBootstrapDays      = 90
	DefaultMaxRequests    = 10
	DefaultOverlapMinutes = 60
	MaxAttempts           = 4 // 1 try + 3 retries
	BackoffBase           = 1.0
	MaxRetryAfter         = 60.0
	MaxGapsKept           = 50
	LagWarn               = 24 * time.Hour

	// Python: httpx.Timeout(60.0, connect=15.0).
	ConnectTimeout = 15 * time.Second
	ReadTimeout    = 60 * time.Second
	// MaxBodyBytes is a Go-only safety cap (Python reads any size); a body
	// over it fails the run. A full page of 100 advisories is ~750 KB.
	MaxBodyBytes = 64 << 20

	// maxTimedeltaMinutes: timedelta(minutes=m) raises OverflowError above
	// 999999999 days 23:59:59.999999.
	maxTimedeltaMinutes = 999999999*1440 + 1439
)

// Options configures New. Nil pointer fields are read from the environment
// exactly like Python's constructor arguments left at None.
type Options struct {
	Transport      http.RoundTripper // tests: fake transport; nil = real network
	Env            collector.Env     // nil = no environment
	BootstrapDays  *int64
	MaxRequests    *int64
	OverlapMinutes *int64
	Token          *string // nil = NDAY_GITHUB_TOKEN
	Clock          func() time.Time
	Sleep          func(ctx context.Context, d time.Duration) error
	Logger         *slog.Logger
}

// Collector implements collector.Collector for GHSA. Like the Python object,
// RequestsMade and the rate-limit snapshot accumulate over the lifetime of
// the collector (the CLI builds a new one per run).
type Collector struct {
	BootstrapDays  int
	MaxRequests    int // saturated at MaxInt for absurd values (never reached)
	OverlapMinutes int64

	token  string // never logged, never in errors or the cursor
	clock  func() time.Time
	sleep  func(ctx context.Context, d time.Duration) error
	logger *slog.Logger
	client *http.Client

	RequestsMade int
	rate         *pyjson.Object // Python self.rate (insertion-ordered)
}

// envInt is ghsa.py's env_int.
func envInt(env collector.Env, name string, def int64) (*big.Int, error) {
	raw, ok := "", false
	if env != nil {
		raw, ok = env(name)
	}
	if !ok || pystr.Strip(raw) == "" {
		return big.NewInt(def), nil
	}
	n, err := pyInt(raw)
	if err != nil {
		return nil, fmt.Errorf("%s must be an integer, got %s", name, pyStrRepr(raw))
	}
	return n, nil
}

func pick(explicit *int64, env collector.Env, name string, def int64) (*big.Int, error) {
	if explicit != nil {
		return big.NewInt(*explicit), nil
	}
	return envInt(env, name, def)
}

// New builds the collector; configuration errors match Python's ValueErrors.
func New(o Options) (*Collector, error) {
	days, err := pick(o.BootstrapDays, o.Env, BootstrapEnv, DefaultBootstrapDays)
	if err != nil {
		return nil, err
	}
	if days.Sign() < 0 || days.Cmp(big.NewInt(MaxBootstrapDays)) > 0 {
		return nil, fmt.Errorf("bootstrap_days must be 0..%d, got %s", MaxBootstrapDays, days)
	}
	capN, err := pick(o.MaxRequests, o.Env, MaxRequestsEnv, DefaultMaxRequests)
	if err != nil {
		return nil, err
	}
	if capN.Cmp(big.NewInt(1)) < 0 {
		return nil, fmt.Errorf("max_requests must be >= 1, got %s", capN)
	}
	overlap, err := pick(o.OverlapMinutes, o.Env, OverlapEnv, DefaultOverlapMinutes)
	if err != nil {
		return nil, err
	}
	if overlap.Sign() < 0 {
		return nil, fmt.Errorf("overlap_minutes must be >= 0, got %s", overlap)
	}
	if overlap.Cmp(big.NewInt(maxTimedeltaMinutes)) > 0 {
		// Python: timedelta(minutes=...) raises OverflowError.
		return nil, fmt.Errorf("OverflowError: days=%s; must have magnitude <= 999999999",
			new(big.Int).Quo(overlap, big.NewInt(1440)))
	}
	maxReq := math.MaxInt
	if capN.IsInt64() && capN.Int64() < math.MaxInt {
		maxReq = int(capN.Int64())
	}
	var tok string
	if o.Token != nil {
		tok = *o.Token
	} else if o.Env != nil {
		tok, _ = o.Env(TokenEnv)
	}
	c := &Collector{
		BootstrapDays:  int(days.Int64()),
		MaxRequests:    maxReq,
		OverlapMinutes: overlap.Int64(),
		token:          pystr.Strip(tok),
		clock:          o.Clock,
		sleep:          o.Sleep,
		logger:         o.Logger,
		rate:           pyjson.NewObject(),
	}
	if c.clock == nil {
		c.clock = time.Now
	}
	if c.sleep == nil {
		c.sleep = sleepCtx
	}
	if c.logger == nil {
		c.logger = slog.Default()
	}
	rt := o.Transport
	if rt == nil {
		dialer := &net.Dialer{Timeout: ConnectTimeout, KeepAlive: 30 * time.Second}
		rt = &http.Transport{
			Proxy:                 http.ProxyFromEnvironment, // httpx trust_env=True
			DialContext:           dialer.DialContext,
			TLSHandshakeTimeout:   ConnectTimeout,
			ResponseHeaderTimeout: ReadTimeout,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          4,
			IdleConnTimeout:       90 * time.Second,
		}
	}
	c.client = &http.Client{
		Transport: rt,
		// httpx.Client(follow_redirects=False): a 3xx is returned and then
		// rejected by raise_for_status.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return c, nil
}

// Factory is the registry entry: configuration from the environment.
func Factory(d collector.Deps) (collector.Collector, error) {
	return New(Options{Transport: d.Transport, Env: d.Env})
}

// Name implements collector.Collector.
func (c *Collector) Name() string { return Name }

// HasToken reports whether an Authorization header will be sent.
func (c *Collector) HasToken() bool { return c.token != "" }

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
