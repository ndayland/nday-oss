package auth

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"
)

// A request whose context ended (client gone, deadline) is a 503 busy and
// no ERROR line; any other lookup failure stays a logged 500.
func TestSessionErrorContext(t *testing.T) {
	var buf bytes.Buffer
	s := &Service{log: slog.New(slog.NewTextHandler(&buf, nil))}
	for _, err := range []error{context.Canceled, context.DeadlineExceeded, fmt.Errorf("query: %w", context.DeadlineExceeded)} {
		rec := httptest.NewRecorder()
		s.sessionError(rec, err)
		if rec.Code != 503 || !strings.Contains(rec.Body.String(), `"code":"busy"`) || rec.Header().Get("Retry-After") != "1" {
			t.Errorf("%v: %d %s", err, rec.Code, rec.Body)
		}
	}
	if buf.Len() != 0 {
		t.Errorf("logged:\n%s", buf.String())
	}
	rec := httptest.NewRecorder()
	s.sessionError(rec, errors.New("boom"))
	if rec.Code != 500 || !strings.Contains(buf.String(), "level=ERROR") {
		t.Errorf("other error: %d, log %q", rec.Code, buf.String())
	}
}

const b64Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

// Each 22-character part of a feed key (16 bytes) has 15 other spellings
// that a lenient decoder maps to the same bytes; all are refused.
func TestParseFeedKeyCanonical(t *testing.T) {
	ks, err := newKeyset([][]byte{bytes.Repeat([]byte{7}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	user := "0b8c6f0e-7f0e-4c1a-9a51-3c2f6f1d9e44"
	key := ks.feedKey(user, bytes.Repeat([]byte{1}, feedSaltLen))
	if _, _, _, ok := parseFeedKey(key); !ok {
		t.Fatalf("issued key refused: %s", key)
	}
	parts := strings.Split(key, ".")
	for idx := 1; idx <= 2; idx++ {
		orig, _ := b64.DecodeString(parts[idx])
		alt := 0
		for _, c := range b64Alphabet {
			p := append([]string(nil), parts...)
			p[idx] = p[idx][:21] + string(c)
			if p[idx] == parts[idx] {
				continue
			}
			lenient, err := b64.DecodeString(p[idx])
			if err != nil || !bytes.Equal(lenient, orig) {
				continue
			}
			alt++
			if _, _, _, ok := parseFeedKey(strings.Join(p, ".")); ok {
				t.Errorf("part %d: alternative spelling %q accepted", idx, p[idx])
			}
		}
		if alt != 15 {
			t.Errorf("part %d: %d alternative spellings, want 15", idx, alt)
		}
	}
	for _, bad := range []string{key + "=", strings.Replace(key, ".", ".\n", 1), strings.ToUpper(key[:36]) + key[36:]} {
		if _, _, _, ok := parseFeedKey(bad); ok {
			t.Errorf("accepted %q", bad)
		}
	}
	// an API token likewise has exactly one spelling and a tag
	s := &Service{keys: ks}
	tok, _, _ := s.newAPIToken()
	if len(tok) != APITokenLen || !s.validAPIToken(tok) {
		t.Fatalf("issued token refused: %s", tok)
	}
	forged := APITokenPrefix + b64.EncodeToString(bytes.Repeat([]byte{3}, apiTokenBytes+tagLen))
	if s.validAPIToken(forged) || s.validAPIToken(tok[:len(tok)-1]+"\n") {
		t.Error("forged token accepted")
	}
	other, _ := newKeyset([][]byte{bytes.Repeat([]byte{8}, 32), bytes.Repeat([]byte{7}, 32)})
	if !(&Service{keys: other}).validAPIToken(tok) {
		t.Error("token of the previous secret refused")
	}
	if (&Service{keys: &keyset{atag: other.atag[:1]}}).validAPIToken(tok) {
		t.Error("token of a secret no longer configured accepted")
	}
}
