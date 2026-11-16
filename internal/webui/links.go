package webui

import (
	"net/url"
	"regexp"
	"strings"
)

// Link is a hyperlink or, when Href is empty, plain text. External links get
// rel="noopener noreferrer" in the templates.
type Link struct {
	Text     string
	Href     string
	External bool
	Lang     string // "en" for upstream text on a non-English page
}

// SafeURL returns the canonical form of an upstream URL if, and only if, it
// is an absolute http/https URL with a host and no credentials, whitespace or
// control characters. Anything else (javascript:, data:, relative, garbage)
// must be shown as plain text.
func SafeURL(raw string) (string, bool) {
	if raw == "" || len(raw) > 2048 {
		return "", false
	}
	for _, c := range raw {
		if c <= ' ' || c == 0x7f || c == '\\' {
			return "", false
		}
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.Opaque != "" {
		return "", false
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
	default:
		return "", false
	}
	u.Scheme = strings.ToLower(u.Scheme)
	return u.String(), true
}

// ExtLink builds a link to an untrusted upstream URL: a real link only when
// SafeURL accepts it, otherwise plain text (the text defaults to the URL).
func ExtLink(text, raw string) Link {
	if text == "" {
		text = raw
	}
	if u, ok := SafeURL(raw); ok {
		return Link{Text: text, Href: u, External: true}
	}
	return Link{Text: text}
}

// shellSafe are characters that need no quoting in sh.
var shellSafe = regexp.MustCompile(`^[A-Za-z0-9_@%+=:,./-]+$`)

// ShellQuote quotes s for a POSIX shell: as is when it only has safe
// characters, else in single quotes (a ' becomes '\”).
func ShellQuote(s string) string {
	if s != "" && shellSafe.MatchString(s) {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// CmdLine is a "$ command" box: Cmd is shown bright, Pipe dimmed, Copy is
// what the copy button copies.
type CmdLine struct {
	Cmd  string
	Pipe string
	Copy string
}

func newCmd(cmd, pipe string) CmdLine {
	c := CmdLine{Cmd: cmd, Pipe: pipe, Copy: cmd}
	if pipe != "" {
		c.Copy = cmd + " " + pipe
	}
	return c
}

// CurlCmd is "curl -s <quoted url>" piped to jq with filter.
func CurlCmd(rawURL, jqFilter string) CmdLine {
	pipe := ""
	if jqFilter != "" {
		pipe = "| jq " + ShellQuote(jqFilter)
	}
	return newCmd("curl -s "+ShellQuote(rawURL), pipe)
}

var (
	ghPull   = regexp.MustCompile(`^https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)/pull/([0-9]+)/?$`)
	ghCommit = regexp.MustCompile(`^https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)/commit/([0-9a-fA-F]{7,40})/?$`)
)

// CommitLink labels a fix-commit URL like the mockup ("owner/repo#5346",
// "owner/repo@53f42a6"); other URLs keep host+path.
func CommitLink(raw string) Link {
	u, ok := SafeURL(raw)
	if !ok {
		return Link{Text: raw}
	}
	if m := ghPull.FindStringSubmatch(u); m != nil {
		return Link{Text: m[1] + "/" + m[2] + "#" + m[3], Href: u, External: true}
	}
	if m := ghCommit.FindStringSubmatch(u); m != nil {
		return Link{Text: m[1] + "/" + m[2] + "@" + strings.ToLower(m[3][:7]), Href: u, External: true}
	}
	p, _ := url.Parse(u)
	return Link{Text: truncRunes(p.Host+p.EscapedPath(), 60), Href: u, External: true}
}

var ghsaRe = regexp.MustCompile(`^GHSA(-[23456789cfghjmpqrvwx]{4}){3}$`)

// AliasLink links a GHSA alias to github.com/advisories; other aliases are text.
func AliasLink(alias, typ string) Link {
	if typ == "ghsa" && ghsaRe.MatchString(alias) {
		return Link{Text: alias, Href: "https://github.com/advisories/" + alias, External: true}
	}
	return Link{Text: alias}
}

var cweRe = regexp.MustCompile(`^CWE-([0-9]{1,6})$`)

// CWELink links "CWE-287" to its MITRE definition.
func CWELink(id string) Link {
	if m := cweRe.FindStringSubmatch(id); m != nil {
		return Link{Text: id, Href: "https://cwe.mitre.org/data/definitions/" + m[1] + ".html", External: true}
	}
	return Link{Text: id}
}

// Package names and versions we are willing to put in an upgrade command.
var (
	pkgNameRe = regexp.MustCompile(`^@?[A-Za-z0-9][A-Za-z0-9._~/-]{0,213}$`)
	versionRe = regexp.MustCompile(`^[0-9][A-Za-z0-9.+_-]{0,63}$`)
)

// UpgradeCmd forms an upgrade command for ecosystems whose syntax is certain
// (pip, npm, rubygems, nuget); "" otherwise or when name/version look odd.
func UpgradeCmd(ecosystem, name, fixed string) string {
	if !pkgNameRe.MatchString(name) || !versionRe.MatchString(fixed) {
		return ""
	}
	switch strings.ToLower(ecosystem) {
	case "pip":
		if strings.ContainsAny(name, "@/~") {
			return ""
		}
		return "pip install -U " + ShellQuote(name+">="+fixed)
	case "npm":
		if strings.Contains(name[1:], "@") || strings.Contains(name, "~") {
			return ""
		}
		return "npm install " + ShellQuote(name+"@"+fixed)
	case "rubygems":
		if strings.ContainsAny(name, "@/~") {
			return ""
		}
		return "gem install " + ShellQuote(name) + " -v " + ShellQuote(fixed)
	case "nuget":
		if strings.ContainsAny(name, "@/~") {
			return ""
		}
		return "dotnet add package " + ShellQuote(name) + " --version " + ShellQuote(fixed)
	}
	return ""
}
