package cli

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestOriginsFromEnv(t *testing.T) {
	for _, c := range []struct {
		public, api           string
		wantPublic, wantAPI   string
		wantErr               bool
		wantLog, wantNotInLog string
	}{
		{public: "", api: "", wantLog: "single-host mode"},
		{public: "https://www.nday.land", api: "", wantPublic: "https://www.nday.land", wantLog: "api_base=https://www.nday.land/api/"},
		{public: "https://www.nday.land", api: "https://api.nday.land/", wantPublic: "https://www.nday.land",
			wantAPI: "https://api.nday.land", wantLog: "api_origin=https://api.nday.land", wantNotInLog: "WARN"},
		{public: "", api: "https://api.nday.land", wantAPI: "https://api.nday.land", wantLog: "WARN"},
		{public: "https://www.nday.land", api: "https://WWW.nday.land:443", wantPublic: "https://www.nday.land",
			wantLog: "equals NDAY_PUBLIC_URL"},
		{public: "https://www.nday.land", api: "https://api.nday.land/v1", wantErr: true},
		{public: "https://www.nday.land", api: "api.nday.land", wantErr: true},
		{public: "https://www.nday.land", api: "https://u:p@api.nday.land", wantErr: true},
		{public: "not a url", api: "", wantLog: "ignoring NDAY_PUBLIC_URL"},
	} {
		t.Setenv("NDAY_PUBLIC_URL", c.public)
		t.Setenv("NDAY_API_URL", c.api)
		var buf bytes.Buffer
		pub, api, err := originsFromEnv(slog.New(slog.NewTextHandler(&buf, nil)))
		if (err != nil) != c.wantErr || pub != c.wantPublic || api != c.wantAPI {
			t.Errorf("%q %q: %q %q %v", c.public, c.api, pub, api, err)
		}
		if err != nil && !strings.HasPrefix(err.Error(), "NDAY_API_URL: ") {
			t.Errorf("error %v", err)
		}
		if !strings.Contains(buf.String(), c.wantLog) || (c.wantNotInLog != "" && strings.Contains(buf.String(), c.wantNotInLog)) {
			t.Errorf("%q %q: log %s", c.public, c.api, buf.String())
		}
	}
}
