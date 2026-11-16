#!/bin/bash
# nday-backup: one verified PostgreSQL dump per day, with rotation.
#
# Installed as /opt/nday/bin/nday-backup and run by nday-backup.service
# (user nday, once a day; see deploy/README.md "Backup and restore").
#
#   $NDAY_BACKUP_DIR/daily/nday-YYYYMMDD.dump          newest KEEP_DAILY kept
#   $NDAY_BACKUP_DIR/weekly/nday-GGGG-Www.dump         Sunday's dump (a hard
#                                                      link), newest KEEP_WEEKLY kept
#   $NDAY_BACKUP_DIR/config/nday-etc-YYYYMMDD.tar.gz   /etc/nday (contains
#                                                      secrets), newest KEEP_DAILY kept
#   $NDAY_BACKUP_DIR/last-success                      time, file and size of
#                                                      the last good dump
#
# A dump is written under a temporary name, checked (readable by pg_restore,
# contains the core tables, at least MIN_BYTES) and only then moved into
# place. Old files are removed only after a new dump succeeded, only inside
# the three directories above, and only when their names match the patterns
# above exactly. Anything else under the backup directory (for example the
# hand-made nday-pre-*.dump files) is never touched.
set -euo pipefail
umask 027

ROOT=${NDAY_BACKUP_DIR:-/data/backup}
DB=${NDAY_DATABASE_URL:?NDAY_DATABASE_URL is not set}
KEEP_DAILY=${NDAY_BACKUP_KEEP_DAILY:-14}
KEEP_WEEKLY=${NDAY_BACKUP_KEEP_WEEKLY:-8}
MIN_BYTES=${NDAY_BACKUP_MIN_BYTES:-104857600} # 100 MiB: a smaller dump is not this database
MIN_FREE_KB=${NDAY_BACKUP_MIN_FREE_KB:-5242880} # 5 GiB must be free before starting

log() { printf '%s\n' "$*"; }
die() {
	printf 'nday-backup: %s\n' "$*" >&2
	exit 1
}

case "$ROOT" in
/*) ;;
*) die "NDAY_BACKUP_DIR must be an absolute path, got '$ROOT'" ;;
esac
for v in "$KEEP_DAILY" "$KEEP_WEEKLY" "$MIN_BYTES" "$MIN_FREE_KB"; do
	case "$v" in
	'' | *[!0-9]*) die "the retention and size settings must be whole numbers, got '$v'" ;;
	esac
done
[ "$KEEP_DAILY" -ge 1 ] && [ "$KEEP_WEEKLY" -ge 1 ] || die "the retention counts must be at least 1"
[ -d "$ROOT" ] || die "$ROOT does not exist (create it: nday:nday 0750)"

mkdir -p "$ROOT/daily" "$ROOT/weekly" "$ROOT/config"

free_kb=$(df -Pk "$ROOT" | awk 'NR==2 {print $4}')
[ "$free_kb" -ge "$MIN_FREE_KB" ] || die "only $free_kb KiB free under $ROOT, need $MIN_FREE_KB"

stamp=$(date +%Y%m%d)
partial="$ROOT/daily/.nday-$stamp.dump.partial"
final="$ROOT/daily/nday-$stamp.dump"

# Leftovers of a run that was killed (only this script's own temporary names).
find "$ROOT/daily" -maxdepth 1 -type f -name '.nday-????????.dump.partial' -mmin +1440 -delete

trap 'rm -f -- "$partial"' EXIT

log "dumping to $final"
start=$(date +%s)
pg_dump -Fc -Z 6 -d "$DB" -f "$partial"

size=$(stat -c %s "$partial")
[ "$size" -ge "$MIN_BYTES" ] || die "the dump is only $size bytes (minimum $MIN_BYTES)"
toc=$(pg_restore -l "$partial")
for t in vuln event raw_record schema_migrations; do
	printf '%s\n' "$toc" | grep -Eq "TABLE DATA [^ ]+ $t " || die "the dump has no data entry for table $t"
done
tables=$(printf '%s\n' "$toc" | grep -c 'TABLE DATA')

mv -f -- "$partial" "$final"
trap - EXIT
log "dump ok: $size bytes, $tables tables, $(($(date +%s) - start)) s"

# Sunday's dump is also the weekly one (a hard link: no extra space, and it
# survives the daily file being rotated out).
if [ "$(date +%u)" = 7 ]; then
	week="$ROOT/weekly/nday-$(date +%G-W%V).dump"
	ln -f -- "$final" "$week"
	log "weekly copy: $week"
fi

# Configuration (sign-in secrets, TLS key, environment files, unit files).
cfg="$ROOT/config/nday-etc-$stamp.tar.gz"
if (umask 077 && tar -czf "$cfg.partial" -C / etc/nday $(cd / && ls -d etc/systemd/system/nday-* 2>/dev/null)); then
	mv -f -- "$cfg.partial" "$cfg"
	log "config archive: $cfg ($(stat -c %s "$cfg") bytes)"
else
	rm -f -- "$cfg.partial"
	log "WARNING: the configuration archive could not be written; the database dump is fine"
fi

# prune DIR REGEX KEEP: keep the newest KEEP regular files in DIR whose names
# match REGEX exactly (names sort by date), remove the older ones.
prune() {
	local dir=$1 re=$2 keep=$3 n=0 f
	while IFS= read -r f; do
		n=$((n + 1))
		if [ "$n" -gt "$keep" ]; then
			rm -f -- "$dir/$f"
			log "removed old backup $dir/$f"
		fi
	done < <(find "$dir" -maxdepth 1 -type f -printf '%f\n' | grep -E "$re" | sort -r)
}
prune "$ROOT/daily" '^nday-[0-9]{8}\.dump$' "$KEEP_DAILY"
prune "$ROOT/weekly" '^nday-[0-9]{4}-W[0-9]{2}\.dump$' "$KEEP_WEEKLY"
prune "$ROOT/config" '^nday-etc-[0-9]{8}\.tar\.gz$' "$KEEP_DAILY"

printf '%s %s %s\n' "$(date -Is)" "$final" "$size" >"$ROOT/last-success"
log "done; free space under $ROOT: $(df -Ph "$ROOT" | awk 'NR==2 {print $4}')"
