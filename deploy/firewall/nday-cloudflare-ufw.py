#!/usr/bin/python3 -I
"""nday-cloudflare-ufw: keep the ufw allow rules for Cloudflare's ranges current.

Installed as /opt/nday/bin/nday-cloudflare-ufw and run as root by
nday-cloudflare-ufw.service (every 6 hours; see deploy/README.md
"Firewall: Cloudflare IP ranges").

The origin only accepts ports 80 and 443 from Cloudflare. This program fetches
the ranges Cloudflare publishes, compares them with the ufw rules it manages
and

  - adds a rule for every published range that has none (always);
  - removes rules for ranges that are no longer published ONLY when run with
    --prune. Without it they are listed and the run exits with status 3, so
    the unit shows up in `systemctl --failed` until someone has looked.

A rule is "managed" only if `ufw show added` prints it in exactly this form:

    ufw allow from <cidr> to any port <80|443> proto tcp comment 'cloudflare'

Every other rule (the ssh rule in particular) is never added, changed or
removed, and the program checks after each change that those rules are still
exactly what they were. Rules are never deleted by number.

Nothing is changed unless both lists were fetched over HTTPS (no redirects)
and passed validation: every line a public network of the right family and a
plausible size, no fewer ranges than half of what is allowed now, no more than
a fixed maximum. A failed fetch or a failed check exits with status 1 and
leaves the firewall as it was.

Exit status: 0 nothing to do or changes applied; 1 error, nothing or only
additions applied; 3 ranges waiting for --prune.
"""

import argparse
import fcntl
import ipaddress
import math
import os
import re
import subprocess
import sys
import tempfile
import urllib.request

SOURCES = {
    4: "https://www.cloudflare.com/ips-v4",
    6: "https://www.cloudflare.com/ips-v6",
}
PORTS = (80, 443)
COMMENT = "cloudflare"
STATE_FILE = "/etc/nday/cloudflare-ips.txt"
LOCK_FILE = "/run/nday-cloudflare-ufw.lock"
UFW = "/usr/sbin/ufw"

# Sanity limits for a fetched list. Cloudflare publishes 15 IPv4 and 7 IPv6
# ranges (2026-11); its widest are a /13 and a /29.
MAX_RANGES = {4: 64, 6: 32}
PREFIX_BOUNDS = {4: (12, 32), 6: (24, 64)}
MAX_BODY = 64 * 1024
FETCH_TIMEOUT = 30

MANAGED_RE = re.compile(
    r"^ufw allow from (\S+) to any port (\d+) proto tcp comment '"
    + re.escape(COMMENT)
    + r"'$"
)


class Fatal(Exception):
    """An error that must stop the run before (further) changes."""


def log(msg):
    print(msg, flush=True)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise Fatal("%s answered with a redirect to %s; refusing to follow" % (req.full_url, newurl))


def fetch(url):
    """Return the body of url as text. HTTPS only, certificate checked, no redirects."""
    if not url.startswith("https://"):
        raise Fatal("refusing to fetch a non-HTTPS URL: %s" % url)
    opener = urllib.request.build_opener(_NoRedirect)
    req = urllib.request.Request(url, headers={"User-Agent": "curl/8 (cloudflare-ips updater)"})
    try:
        with opener.open(req, timeout=FETCH_TIMEOUT) as resp:
            if resp.status != 200:
                raise Fatal("%s answered HTTP %s" % (url, resp.status))
            body = resp.read(MAX_BODY + 1)
            declared = resp.headers.get("Content-Length")
            if declared is not None and declared.strip() != str(len(body)):
                raise Fatal(
                    "%s: got %d bytes but Content-Length says %s (truncated?)" % (url, len(body), declared)
                )
    except Fatal:
        raise
    except Exception as e:  # URLError, timeout, TLS failure, ...
        raise Fatal("fetching %s failed: %s" % (url, e))
    if len(body) > MAX_BODY:
        raise Fatal("%s returned more than %d bytes" % (url, MAX_BODY))
    try:
        return body.decode("ascii")
    except UnicodeDecodeError:
        raise Fatal("%s returned non-ASCII data" % url)


def parse_list(text, family, current_count):
    """Validate a fetched list; return its networks in published order.

    current_count is the number of ranges of this family allowed now; the
    list must have at least half as many.
    """
    lo, hi = PREFIX_BOUNDS[family]
    nets = []
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line:
            continue
        if "/" not in line:
            # A bare address would parse as a /32 or /128: that is what a
            # response cut off in the middle of its last line looks like.
            raise Fatal("IPv%d list, line %d: no prefix length: %r" % (family, n, line[:60]))
        try:
            net = ipaddress.ip_network(line, strict=True)
        except ValueError as e:
            raise Fatal("IPv%d list, line %d: not a network: %r (%s)" % (family, n, line[:60], e))
        if net.version != family:
            raise Fatal("IPv%d list, line %d: %s is IPv%d" % (family, n, net, net.version))
        if not lo <= net.prefixlen <= hi:
            raise Fatal(
                "IPv%d list, line %d: %s has a prefix outside /%d../%d" % (family, n, net, lo, hi)
            )
        if not net.is_global:
            raise Fatal("IPv%d list, line %d: %s is not public address space" % (family, n, net))
        if net not in nets:
            nets.append(net)
    need = max(1, math.ceil(current_count / 2))
    if len(nets) < need:
        raise Fatal(
            "IPv%d list has %d range(s); at least %d expected (%d allowed now)"
            % (family, len(nets), need, current_count)
        )
    if len(nets) > MAX_RANGES[family]:
        raise Fatal("IPv%d list has %d ranges; the limit is %d" % (family, len(nets), MAX_RANGES[family]))
    return nets


def run_ufw(args):
    """Run ufw with args; return its stdout. Raises Fatal on a non-zero exit."""
    env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}
    p = subprocess.run([UFW] + args, capture_output=True, text=True, env=env, timeout=120)
    if p.returncode != 0:
        raise Fatal(
            "ufw %s failed (exit %d): %s" % (" ".join(args), p.returncode, (p.stderr or p.stdout).strip())
        )
    return p.stdout


class Rules:
    """The rules in `ufw show added`, split into managed and everything else."""

    def __init__(self, text):
        self.managed = {}  # (network, port) -> the range exactly as ufw prints it
        self.other = []  # every other rule line, in order
        lines = [l.strip() for l in text.splitlines() if l.strip().startswith("ufw ")]
        if not lines:
            raise Fatal("`ufw show added` listed no rules at all; refusing to continue")
        for line in lines:
            m = MANAGED_RE.match(line)
            if m and int(m.group(2)) in PORTS:
                try:
                    net = ipaddress.ip_network(m.group(1), strict=False)
                except ValueError:
                    raise Fatal("cannot parse the range in the ufw rule: %s" % line)
                key = (net, int(m.group(2)))
                if key in self.managed:
                    raise Fatal("two managed ufw rules describe the same range and port: %s" % line)
                self.managed[key] = m.group(1)
            else:
                self.other.append(line)

    def conflict(self, net, port):
        """Return an unmanaged rule with the same source and port as (net, port), if any.

        `ufw allow` REPLACES an existing rule that differs from the new one
        only in its action or comment (ufw 0.36 backend_iptables.set_rule), so
        adding next to such a rule would rewrite a rule that is not ours.
        """
        for line in self.other:
            m = re.search(r" from (\S+) ", line + " ")
            if not m or not re.search(r" port %d( |$)" % port, line):
                continue
            try:
                if ipaddress.ip_network(m.group(1), strict=False) == net:
                    return line
            except ValueError:
                continue
        return None

    def networks(self, port=None, family=None):
        return {
            n
            for (n, p) in self.managed
            if (port is None or p == port) and (family is None or n.version == family)
        }


def read_rules():
    return Rules(run_ufw(["show", "added"]))


def require_active():
    out = run_ufw(["status"])
    if not out.startswith("Status: active"):
        raise Fatal("ufw is not active (%r); refusing to change its rules" % out.splitlines()[:1])


def check_untouched(before, after):
    if before.other != after.other:
        raise Fatal(
            "ALARM: rules this program does not manage changed during the run.\n"
            "before: %r\nafter:  %r" % (before.other, after.other)
        )


def write_state(path, nets):
    """Write the published list to path (atomically) if it differs. Returns True if written."""
    new = "".join("%s\n" % n for n in nets)
    try:
        with open(path) as f:
            if f.read() == new:
                return False
    except FileNotFoundError:
        pass
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".cloudflare-ips.")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(new)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return True


def sort_key(item):
    net, port = item
    return (port, net.version, int(net.network_address), net.prefixlen)


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Allow Cloudflare's published ranges to ports 80/443 in ufw."
    )
    ap.add_argument("--dry-run", action="store_true", help="print what would change; change nothing")
    ap.add_argument(
        "--prune",
        action="store_true",
        help="also remove managed rules for ranges Cloudflare no longer publishes",
    )
    args = ap.parse_args(argv)

    if os.geteuid() != 0:
        raise Fatal("must run as root")

    lock = open(LOCK_FILE, "w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        raise Fatal("another run holds %s" % LOCK_FILE)

    require_active()
    before = read_rules()

    # Fetch and validate everything before touching anything.
    published = []
    for family in (4, 6):
        published += parse_list(fetch(SOURCES[family]), family, len(before.networks(family=family)))
    wanted = {(n, p) for n in published for p in PORTS}

    to_add = sorted(wanted - set(before.managed), key=sort_key)
    stale = sorted(set(before.managed) - wanted, key=sort_key)

    for net, port in to_add:
        clash = before.conflict(net, port)
        if clash:
            raise Fatal(
                "cannot add %s port %d: ufw would replace this existing rule, which this "
                "program does not manage: %s" % (net, port, clash)
            )

    if args.dry_run:
        log(
            "dry run: %d range(s) published; %d managed rule(s) present; %d other rule(s) left alone"
            % (len(published), len(before.managed), len(before.other))
        )
        for net, port in to_add:
            log("would add:    allow from %s to any port %d proto tcp" % (net, port))
        for key in stale:
            log(
                "%s allow from %s to any port %d proto tcp (no longer published)"
                % ("would delete:" if args.prune else "stale, kept: ", before.managed[key], key[1])
            )
        if not to_add and not stale:
            log("dry run: no change needed")
        return 0

    # 1. Add first.
    for net, port in to_add:
        run_ufw(["allow", "from", str(net), "to", "any", "port", str(port), "proto", "tcp", "comment", COMMENT])
        log("added: allow from %s to any port %d proto tcp" % (net, port))
    current = before
    if to_add:
        current = read_rules()
        check_untouched(before, current)
        missing = wanted - set(current.managed)
        if missing:
            raise Fatal("after adding, these rules are still missing: %s" % sorted(map(str, missing)))

    # 2. Record the published list.
    if write_state(STATE_FILE, published):
        log("updated %s (%d ranges)" % (STATE_FILE, len(published)))

    # 3. Remove what is no longer published, only when asked to.
    if not stale:
        return 0
    if not args.prune:
        for key in stale:
            log(
                "no longer published by Cloudflare, still allowed: %s port %d"
                % (current.managed[key], key[1])
            )
        print(
            "nday-cloudflare-ufw: %d rule(s) are for ranges Cloudflare no longer publishes. "
            "Review them, then run: sudo /opt/nday/bin/nday-cloudflare-ufw --prune" % len(stale),
            file=sys.stderr,
        )
        return 3
    for key in stale:
        shown, port = current.managed[key], key[1]
        run_ufw(["delete", "allow", "from", shown, "to", "any", "port", str(port), "proto", "tcp"])
        log("deleted: allow from %s to any port %d proto tcp" % (shown, port))
    after = read_rules()
    check_untouched(before, after)
    if set(after.managed) != wanted:
        raise Fatal(
            "after pruning, the managed rules are not the published set: missing %s, extra %s"
            % (sorted(map(str, wanted - set(after.managed))), sorted(map(str, set(after.managed) - wanted)))
        )
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Fatal as e:
        print("nday-cloudflare-ufw: %s" % e, file=sys.stderr)
        sys.exit(1)
    except subprocess.TimeoutExpired as e:
        print("nday-cloudflare-ufw: %s" % e, file=sys.stderr)
        sys.exit(1)
