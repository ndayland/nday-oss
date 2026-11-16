// Command nday is the Go implementation of the nday CLI (see internal/cli).
package main

import (
	"context"
	"os"

	"nday.land/nday/internal/admin"
	"nday.land/nday/internal/auth"
	"nday.land/nday/internal/cli"
	"nday.land/nday/internal/discuss"
	"nday.land/nday/internal/web"
	"nday.land/nday/internal/webui"
)

func main() {
	// `nday serve` mounts sign-in (when configured) and the discussion
	// endpoints (when also enabled) before the HTML pages, so the pages know
	// at render time which providers are enabled and whether vulnerability
	// pages carry a discussion section; the staff back office (/admin) comes
	// with sign-in.
	var accounts *auth.Service
	var discussions *discuss.Service
	var backOffice *admin.Service
	cli.AuthHook = func(s *auth.Service) { accounts = s }
	cli.DiscussHook = func(s *discuss.Service) { discussions = s }
	cli.AdminHook = func(s *admin.Service) { backOffice = s }
	cli.ServeHook = func(srv *web.Server) {
		webui.Register(srv, webui.AccountsOf(accounts), webui.DiscussionsOf(discussions), backOffice)
	}
	os.Exit(cli.Main(context.Background(), os.Args[1:], cli.Env{}))
}
