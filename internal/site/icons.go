package site

import (
	"context"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/siteicon"
	"nday.land/nday/internal/xavatar"
)

// SiteIcons returns host -> icon hash for those of hosts that have a
// stored site icon (siteicon.Lookup: one query; empty without migration
// 0028). Read-only: nothing is fetched while a page is served.
func (s *Store) SiteIcons(ctx context.Context, hosts []string) (map[string]string, error) {
	var out map[string]string
	err := s.db.WithConn(ctx, func(conn *pgx.Conn) error {
		var err error
		out, err = siteicon.Lookup(ctx, conn, hosts)
		return err
	})
	return out, err
}

// SiteIcon returns the stored icon of host (siteicon.Load), nil when
// there is none or host is not a valid icon host.
func (s *Store) SiteIcon(ctx context.Context, host string) (*siteicon.Icon, error) {
	var out *siteicon.Icon
	err := s.db.WithConn(ctx, func(conn *pgx.Conn) error {
		var err error
		out, err = siteicon.Load(ctx, conn, host)
		return err
	})
	return out, err
}

// XAvatar returns the stored X avatar whose hash is h (xavatar.Load: only
// of an author the public outline shows now), nil when there is none or h
// is not a hash.
func (s *Store) XAvatar(ctx context.Context, h string) (*xavatar.Avatar, error) {
	var out *xavatar.Avatar
	err := s.db.WithConn(ctx, func(conn *pgx.Conn) error {
		var err error
		out, err = xavatar.Load(ctx, conn, h, s.clock())
		return err
	})
	return out, err
}
