package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/admin"
	"nday.land/nday/internal/audit"
	"nday.land/nday/internal/xconfig"
	"nday.land/nday/internal/xlookup"
)

// Commands for the xposts collector's database configuration
// (internal/xconfig; docs/xposts.md):
//
//	nday x-accounts-import FILE            upsert the allowlist from FILE (never deletes); handle-only
//	                                       lines are resolved through the X API (NDAY_X_BEARER_TOKEN)
//	nday x-accounts-list                   every account, enabled or not
//	nday x-accounts-enable|disable USERID  switch one account
//	nday x-settings [--enabled on|off] [--max-posts N] [--max-requests N]
//	                [--bootstrap-days N] [--max-query-length N]
//	                show the settings; with options, change them first
//	                ("default" as a value clears it back to the built-in default)
func runXCommand(ctx context.Context, env Env, cmd string, rest []string) error {
	prog := "nday " + cmd
	var p *parsed
	var err error
	settingOpts := []optSpec{{name: "--enabled", hasValue: true}, {name: "--max-posts", hasValue: true},
		{name: "--max-requests", hasValue: true}, {name: "--bootstrap-days", hasValue: true},
		{name: "--max-query-length", hasValue: true}}
	switch cmd {
	case "x-accounts-import":
		p, err = parseArgs(prog, nil, rest, 1)
		if err == nil && len(p.pos) != 1 {
			err = &usageError{prog, "usage: nday x-accounts-import FILE"}
		}
	case "x-accounts-list":
		p, err = parseArgs(prog, nil, rest, 0)
	case "x-accounts-enable", "x-accounts-disable":
		p, err = parseArgs(prog, nil, rest, 1)
		if err == nil && (len(p.pos) != 1 || !xconfig.ValidUserID(p.pos[0])) {
			err = &usageError{prog, "usage: nday " + cmd + " <numeric X user id>"}
		}
	case "x-settings":
		p, err = parseArgs(prog, settingOpts, rest, 0)
	}
	if err != nil {
		return err
	}
	var file []xconfig.FileAccount
	var looked map[int]bool
	var conn *pgx.Conn
	defer func() {
		if conn != nil {
			conn.Close(context.WithoutCancel(ctx))
		}
	}()
	if cmd == "x-accounts-import" {
		f, err := os.Open(p.pos[0])
		if err != nil {
			return err
		}
		file, err = xconfig.ParseAccountsFile(f)
		f.Close()
		if err != nil {
			return fmt.Errorf("%s: %w", p.pos[0], err)
		}
		// handle-only lines: look their ids up on X before writing anything
		// (token: the database settings, else this process's environment
		// as it was before connect loads ./.env; base URL fixed)
		var need []string
		for _, a := range file {
			if a.UserID == "" {
				need = append(need, strconv.Itoa(a.Line))
			}
		}
		if len(need) > 0 {
			envSnap := environSnapshot()
			if conn, err = connect(ctx); err != nil {
				return err
			}
			token, _ := loadSnapshot(ctx, conn).Lookup(envSnap)(xlookup.TokenEnv)
			lk, err := xlookup.New(xlookup.Options{Token: token, Transport: env.Transport})
			if err != nil {
				return err
			}
			if !lk.Configured() {
				return fmt.Errorf("%s: line(s) %s give only a handle; looking up their user ids needs %s (in the database settings or the environment; or write \"<numeric user id> <handle>\")",
					p.pos[0], strings.Join(need, ", "), xlookup.TokenEnv)
			}
			var lineErrs []*xconfig.LineError
			file, looked, lineErrs, err = admin.ResolveXImport(ctx, lk, file)
			if err != nil {
				return fmt.Errorf("%s: %w", p.pos[0], err)
			}
			if len(lineErrs) > 0 {
				for _, e := range lineErrs {
					fmt.Fprintf(env.Stderr, "%s: %v\n", p.pos[0], e)
				}
				return fmt.Errorf("%s: %d line(s) could not be resolved; nothing was imported", p.pos[0], len(lineErrs))
			}
		}
	}
	var change *xconfig.Stored
	if cmd == "x-settings" && len(p.flags) > 0 {
		change = &xconfig.Stored{}
		for _, o := range settingOpts {
			v, ok := p.flags[o.name]
			if !ok {
				continue
			}
			if err := applySetting(change, o.name, v); err != nil {
				return &usageError{prog, "argument " + o.name + ": " + err.Error()}
			}
		}
	}

	if conn == nil {
		if conn, err = connect(ctx); err != nil {
			return err
		}
	}
	switch cmd {
	case "x-accounts-import":
		// the upserts and (when anything changed) one audit row, actor
		// "cli", in one transaction (docs/admin.md)
		var res *admin.ImportResult
		err := pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
			var err error
			res, err = admin.ImportResolvedXAccounts(ctx, tx, nil, file, looked)
			return err
		})
		if err != nil {
			return err
		}
		for _, l := range res.Lines {
			if l.Result != xconfig.Unchanged {
				suffix := ""
				if l.LookedUp {
					suffix = " (id looked up)"
				}
				fmt.Fprintf(env.Stdout, "%s %s @%s%s\n", l.Result, l.UserID, l.Handle, suffix)
			}
		}
		fmt.Fprintf(env.Stdout, "x-accounts-import: inserted=%d updated=%d unchanged=%d\n", res.Inserted, res.Updated, res.Unchanged)
		return nil
	case "x-accounts-list":
		as, err := xconfig.ListAccounts(ctx, conn)
		if err != nil {
			return err
		}
		n := 0
		for _, a := range as {
			state := "enabled"
			if !a.Enabled {
				state = "disabled"
			} else {
				n++
			}
			line := fmt.Sprintf("%s @%s %s", a.UserID, a.Handle, state)
			if a.Note != "" {
				line += "  # " + a.Note
			}
			fmt.Fprintln(env.Stdout, line)
		}
		fmt.Fprintf(env.Stdout, "x-accounts: %d total, %d enabled\n", len(as), n)
		return nil
	case "x-accounts-enable", "x-accounts-disable":
		on := cmd == "x-accounts-enable"
		// the switch and its audit row (actor "cli") in one transaction;
		// an account already in that state is left alone (no row), as before
		err := pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
			return admin.SetXAccountEnabled(ctx, tx, nil, p.pos[0], on)
		})
		if errors.Is(err, xconfig.ErrNotFound) {
			return fmt.Errorf("no X account with user id %s (import it first)", p.pos[0])
		} else if err != nil && !errors.Is(err, admin.ErrNoXChange) {
			return err
		}
		fmt.Fprintf(env.Stdout, "%s: %s\n", cmd, p.pos[0])
		return nil
	}
	// x-settings
	if change != nil {
		err := pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
			if err := xconfig.LockSettings(ctx, tx); err != nil {
				return err
			}
			old, err := xconfig.LoadSettings(ctx, tx)
			if err != nil {
				return err
			}
			cur := old
			for _, o := range settingOpts {
				if v, ok := p.flags[o.name]; ok {
					if err := applySetting(&cur, o.name, v); err != nil {
						return err
					}
				}
			}
			if cur.Equal(old) {
				return nil // nothing changes: no write, no audit row
			}
			if err := xconfig.SaveSettings(ctx, tx, cur); err != nil {
				return err
			}
			return audit.Write(ctx, tx, audit.Entry{Action: audit.XSettingsUpdate, TargetType: audit.TargetXSettings,
				TargetID: "1", Details: admin.SettingsDiff(old, cur)})
		})
		if err != nil {
			return err
		}
	}
	st, err := xconfig.LoadSettings(ctx, conn)
	if err != nil {
		return err
	}
	eff, warns := st.Effective()
	src := func(set bool) string {
		if set {
			return "stored"
		}
		return "default"
	}
	onoff := "off"
	if eff.Enabled {
		onoff = "on"
	}
	fmt.Fprintf(env.Stdout, "enabled=%s (%s)\n", onoff, src(st.Enabled != nil))
	fmt.Fprintf(env.Stdout, "max_posts=%d (%s, %d..%d)\n", eff.MaxPosts, src(st.MaxPosts != nil), xconfig.MinMaxPosts, xconfig.MaxMaxPosts)
	fmt.Fprintf(env.Stdout, "max_requests=%d (%s, %d..%d)\n", eff.MaxRequests, src(st.MaxRequests != nil), xconfig.MinMaxRequests, xconfig.MaxMaxRequests)
	fmt.Fprintf(env.Stdout, "bootstrap_days=%d (%s, %d..%d)\n", eff.BootstrapDays, src(st.BootstrapDays != nil), xconfig.MinBootstrapDays, xconfig.MaxBootstrapDays)
	fmt.Fprintf(env.Stdout, "max_query_length=%d (%s, %d..%d)\n", eff.MaxQueryLength, src(st.MaxQueryLength != nil), xconfig.MinMaxQueryLength, xconfig.MaxMaxQueryLength)
	for _, w := range warns {
		fmt.Fprintln(env.Stderr, "warning: "+w)
	}
	return nil
}

// applySetting sets one option of s from its CLI value ("default" = NULL).
func applySetting(s *xconfig.Stored, opt, v string) error {
	v = strings.TrimSpace(v)
	if opt == "--enabled" {
		switch strings.ToLower(v) {
		case "default":
			s.Enabled = nil
		case "on", "true", "yes", "1":
			s.Enabled = new(bool)
			*s.Enabled = true
		case "off", "false", "no", "0":
			s.Enabled = new(bool)
		default:
			return fmt.Errorf("want on, off or default, got %q", v)
		}
		return nil
	}
	var n *int
	if v != "default" {
		i, err := strconv.Atoi(v)
		if err != nil {
			return fmt.Errorf("want an integer or default, got %q", v)
		}
		n = &i
	}
	switch opt {
	case "--max-posts":
		s.MaxPosts = n
	case "--max-requests":
		s.MaxRequests = n
	case "--bootstrap-days":
		s.BootstrapDays = n
	case "--max-query-length":
		s.MaxQueryLength = n
	}
	return s.Validate()
}
