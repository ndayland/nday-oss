package cli

import (
	"fmt"
	"sort"
	"strings"
)

// A tiny argparse look-alike: long options with or without "=value",
// unambiguous prefix abbreviations (argparse allow_abbrev), options mixed
// with positionals, "--" ends options. Errors are usageErrors (exit code 2).

type usageError struct {
	prog string
	msg  string
}

func (e *usageError) Error() string { return e.prog + ": error: " + e.msg }

type optSpec struct {
	name     string // "--limit"
	short    string // "-v" or ""
	hasValue bool
}

type parsed struct {
	flags map[string]string // option name -> value ("" for switches)
	pos   []string
}

func parseArgs(prog string, specs []optSpec, args []string, maxPos int) (*parsed, error) {
	p := &parsed{flags: map[string]string{}}
	onlyPos := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		if onlyPos || a == "-" || !strings.HasPrefix(a, "-") {
			if len(p.pos) >= maxPos {
				return nil, &usageError{prog, "unrecognized arguments: " + strings.Join(args[i:], " ")}
			}
			p.pos = append(p.pos, a)
			continue
		}
		if a == "--" {
			onlyPos = true
			continue
		}
		name, val, hasEq := strings.Cut(a, "=")
		spec, err := lookupOpt(prog, specs, name)
		if err != nil {
			return nil, err
		}
		if spec.hasValue {
			if !hasEq {
				if i+1 >= len(args) || (strings.HasPrefix(args[i+1], "-") && args[i+1] != "-" && !isNegNumber(args[i+1])) {
					return nil, &usageError{prog, fmt.Sprintf("argument %s: expected one argument", spec.name)}
				}
				i++
				val = args[i]
			}
		} else if hasEq {
			return nil, &usageError{prog, fmt.Sprintf("argument %s: ignored explicit argument '%s'", spec.name, val)}
		}
		p.flags[spec.name] = val
	}
	return p, nil
}

func isNegNumber(s string) bool {
	if len(s) < 2 || s[0] != '-' {
		return false
	}
	for _, c := range s[1:] {
		if (c < '0' || c > '9') && c != '.' {
			return false
		}
	}
	return true
}

func lookupOpt(prog string, specs []optSpec, name string) (optSpec, error) {
	var matches []optSpec
	for _, s := range specs {
		if s.name == name || (s.short != "" && s.short == name) {
			return s, nil
		}
		if strings.HasPrefix(name, "--") && len(name) > 2 && strings.HasPrefix(s.name, name) {
			matches = append(matches, s)
		}
	}
	switch len(matches) {
	case 1:
		return matches[0], nil
	case 0:
		return optSpec{}, &usageError{prog, "unrecognized arguments: " + name}
	}
	names := make([]string, len(matches))
	for i, m := range matches {
		names[i] = m.name
	}
	sort.Strings(names)
	return optSpec{}, &usageError{prog, fmt.Sprintf("ambiguous option: %s could match %s", name, strings.Join(names, ", "))}
}

func quoteChoices(cs []string) string {
	q := make([]string, len(cs))
	for i, c := range cs {
		q[i] = "'" + c + "'"
	}
	return strings.Join(q, ", ")
}
