#!/usr/bin/env python3
"""Tests for nday-cloudflare-ufw.py. Run: python3 deploy/firewall/nday_cloudflare_ufw_test.py -v

The script is loaded by path; fetch, run_ufw, os.geteuid, STATE_FILE and
LOCK_FILE are replaced. FakeUfw models the parts of ufw 0.36.2 the script
relies on, including UFWRule.match()/set_rule() semantics (src/common.py
match(): comment is compared, -2 = "match all but comment";
src/backend_iptables.py set_rule(): a delete without a comment removes a rule
that differs only by comment; an add that matches all but action/comment
REPLACES the existing rule).
"""

import importlib.util
import io
import ipaddress
import os
import re
import shlex
import tempfile
import unittest
import urllib.request
import warnings
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "nday-cloudflare-ufw.py")


def load():
    spec = importlib.util.spec_from_file_location("nday_cloudflare_ufw", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


CF4 = """173.245.48.0/20
103.21.244.0/22
103.22.200.0/22
103.31.4.0/22
141.101.64.0/18
108.162.192.0/18
190.93.240.0/20
188.114.96.0/20
197.234.240.0/22
198.41.128.0/17
162.158.0.0/15
104.16.0.0/13
104.24.0.0/14
172.64.0.0/13
131.0.72.0/22""".split()
CF6 = """2400:cb00::/32
2606:4700::/32
2803:f800::/32
2405:b500::/32
2405:8100::/32
2a06:98c0::/29
2c0f:f248::/32""".split()

MUTATING = {"allow", "deny", "reject", "limit", "delete", "insert", "prepend",
            "route", "enable", "disable", "reset", "reload", "default", "logging"}

RULE_RE = re.compile(
    r"^(allow|deny|reject|limit) from (\S+) to any port (\d+) proto (tcp|udp)(?: comment (.*))?$"
)


def norm_src(s):
    net = ipaddress.ip_network(s, strict=False)
    if net.prefixlen == net.max_prefixlen:
        return str(net.network_address)
    return str(net)


class FakeUfw:
    """In-memory ufw. Rules are dicts (structured) or ('raw', line) for opaque ones."""

    def __init__(self, mod, rules, active=True, fail=None):
        self.mod = mod
        self.rules = []
        self.active = active
        self.fail = fail  # callable(args) -> bool : make this call fail
        self.calls = []
        for line in rules:
            self.rules.append(self._parse_line(line))

    @staticmethod
    def _parse_line(line):
        assert line.startswith("ufw ")
        body = line[4:]
        m = RULE_RE.match(body)
        if m:
            c = m.group(5)
            return {"action": m.group(1), "src": norm_src(m.group(2)), "port": int(m.group(3)),
                    "proto": m.group(4), "comment": shlex.split(c)[0] if c else ""}
        return ("raw", line)

    @staticmethod
    def _fmt(r):
        if isinstance(r, tuple):
            return r[1]
        s = "ufw %s from %s to any port %d proto %s" % (r["action"], r["src"], r["port"], r["proto"])
        if r["comment"]:
            s += " comment '%s'" % r["comment"]
        return s

    def lines(self):
        return [self._fmt(r) for r in self.rules]

    def mutations(self):
        return [c for c in self.calls if c and c[0] in MUTATING]

    def _spec(self, args):
        # args: from X to any port P proto tcp [comment C]
        if len(args) < 8 or args[0] != "from" or args[2:5] != ["to", "any", "port"] or args[6] != "proto":
            raise AssertionError("fake ufw: unsupported syntax %r" % (args,))
        comment = ""
        rest = args[8:]
        if rest:
            assert rest[0] == "comment" and len(rest) == 2, args
            comment = rest[1]
        return norm_src(args[1]), int(args[5]), args[7], comment

    def __call__(self, args):
        args = list(args)
        self.calls.append(args)
        if self.fail and self.fail(args):
            raise self.mod.Fatal("ufw %s failed (exit 1): injected" % " ".join(args))
        if args == ["status"]:
            return "Status: active\n\nTo   Action   From\n" if self.active else "Status: inactive\n"
        if args == ["show", "added"]:
            ls = self.lines()
            return "Added user rules (see 'ufw status' for running firewall):\n" + (
                "\n".join(ls) + "\n" if ls else "(None)\n")
        if args[0] in ("allow", "deny", "reject", "limit"):
            src, port, proto, comment = self._spec(args[1:])
            new = {"action": args[0], "src": src, "port": port, "proto": proto, "comment": comment}
            for i, r in enumerate(self.rules):
                if isinstance(r, dict) and (r["src"], r["port"], r["proto"]) == (src, port, proto):
                    if r["action"] == args[0] and r["comment"] == comment:
                        return "Skipping adding existing rule\n"
                    self.rules[i] = new  # ufw set_rule: ret < 0 and not remove -> replace
                    return "Rule updated\n"
            self.rules.append(new)
            return "Rule added\n"
        if args[0] == "delete":
            action = args[1]
            src, port, proto, comment = self._spec(args[2:])
            for i, r in enumerate(self.rules):
                if (isinstance(r, dict) and (r["src"], r["port"], r["proto"], r["action"]) ==
                        (src, port, proto, action) and (r["comment"] == comment or comment == "")):
                    del self.rules[i]
                    return "Rule deleted\n"
            return "Could not delete non-existent rule\n"
        raise AssertionError("fake ufw: unexpected command %r" % (args,))


def managed_lines(v4=CF4, v6=CF6, ports=(443, 80)):
    out = []
    for n in list(v4) + list(v6):
        for p in ports:
            out.append("ufw allow from %s to any port %d proto tcp comment 'cloudflare'" % (n, p))
    return out


SSH = "ufw allow 22/tcp comment 'ssh'"
OTHER = [
    SSH,
    "ufw allow 8080/tcp",
    "ufw allow from 1.2.3.4 to any port 443 proto tcp comment 'office'",
]


def add_cmd(net, port):
    return ["allow", "from", net, "to", "any", "port", str(port), "proto", "tcp", "comment", "cloudflare"]


def del_cmd(net, port):
    return ["delete", "allow", "from", net, "to", "any", "port", str(port), "proto", "tcp"]


class Base(unittest.TestCase):
    def setUp(self):
        self.mod = load()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.state = os.path.join(self.tmp.name, "cloudflare-ips.txt")
        self.mod.STATE_FILE = self.state
        self.mod.LOCK_FILE = os.path.join(self.tmp.name, "lock")
        p = mock.patch.object(self.mod.os, "geteuid", return_value=0)
        p.start()
        self.addCleanup(p.stop)
        self.fetched = []

    def setup(self, rules, v4=CF4, v6=CF6, active=True, fail=None, raw4=None, raw6=None, state=True):
        self.ufw = FakeUfw(self.mod, rules, active=active, fail=fail)
        self.mod.run_ufw = self.ufw
        body = {
            self.mod.SOURCES[4]: raw4 if raw4 is not None else "\n".join(v4),
            self.mod.SOURCES[6]: raw6 if raw6 is not None else "\n".join(v6),
        }

        def fetch(url):
            self.fetched.append(url)
            b = body[url]
            if isinstance(b, Exception):
                raise b
            return b

        self.mod.fetch = fetch
        if state:
            with open(self.state, "w") as f:
                f.write("".join("%s\n" % n for n in list(v4) + list(v6)))
        self.before_other = [l for l in self.ufw.lines() if "comment 'cloudflare'" not in l]

    def run_main(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err), warnings.catch_warnings():
            warnings.simplefilter("ignore", ResourceWarning)  # main() never closes its lock file
            try:
                code = self.mod.main(list(argv))
            except self.mod.Fatal as e:
                print("FATAL: %s" % e, file=err)
                code = 1
        self.out, self.err = out.getvalue(), err.getvalue()
        return code

    def state_text(self):
        try:
            with open(self.state) as f:
                return f.read()
        except FileNotFoundError:
            return None

    def assertOthersIntact(self):
        # Requirement 1: every non-managed rule is still there, unchanged, in order.
        now_other = [l for l in self.ufw.lines() if "comment 'cloudflare'" not in l]
        self.assertEqual(now_other, self.before_other)
        for c in self.ufw.mutations():
            ok_add = (len(c) == 11 and c[0] == "allow" and c[-2:] == ["comment", "cloudflare"]
                      and c[6] in ("80", "443"))
            ok_del = (len(c) == 10 and c[:2] == ["delete", "allow"] and c[7] in ("80", "443"))
            self.assertTrue(ok_add or ok_del, "unexpected mutating command %r" % (c,))
            # never touch the office / 8080 / ssh rules
            self.assertNotIn("1.2.3.4", c)
            self.assertNotIn("8080/tcp", c)
            self.assertNotIn("22/tcp", c)


class NoChange(Base):
    def test_no_change_silent_exit0(self):
        self.setup(OTHER + managed_lines())
        self.assertEqual(self.run_main(), 0)
        self.assertEqual(self.ufw.mutations(), [])
        self.assertEqual(self.out, "")
        self.assertEqual(self.err, "")
        self.assertOthersIntact()

    def test_no_change_with_prune_silent(self):
        self.setup(OTHER + managed_lines())
        self.assertEqual(self.run_main("--prune"), 0)
        self.assertEqual(self.ufw.mutations(), [])
        self.assertEqual(self.out + self.err, "")

    def test_first_run_without_state_file_prints_update(self):
        # Rules unchanged, but the state file is created: output appears (documented minor deviation).
        self.setup(OTHER + managed_lines(), state=False)
        self.assertEqual(self.run_main(), 0)
        self.assertEqual(self.ufw.mutations(), [])
        self.assertIn("updated", self.out)


class Additions(Base):
    def test_new_v4_range(self):
        v4 = CF4 + ["104.28.0.0/16"]
        self.setup(OTHER + managed_lines(), v4=v4)
        self.assertEqual(self.run_main(), 0)
        self.assertEqual(self.ufw.mutations(), [add_cmd("104.28.0.0/16", 80), add_cmd("104.28.0.0/16", 443)])
        self.assertIn("104.28.0.0/16\n", self.state_text())
        self.assertOthersIntact()

    def test_new_v6_range(self):
        v6 = CF6 + ["2a09:bac0::/29"]
        self.setup(OTHER + managed_lines(), v6=v6)
        self.assertEqual(self.run_main(), 0)
        self.assertEqual(self.ufw.mutations(), [add_cmd("2a09:bac0::/29", 80), add_cmd("2a09:bac0::/29", 443)])
        self.assertOthersIntact()

    def test_fresh_install_adds_all_in_order(self):
        self.setup(OTHER, state=False)
        self.assertEqual(self.run_main(), 0)
        muts = self.ufw.mutations()
        self.assertEqual(len(muts), 44)
        self.assertTrue(all(c[0] == "allow" for c in muts))
        self.assertOthersIntact()

    def test_add_fails_midway_no_delete(self):
        v4 = [n for n in CF4 if n != "131.0.72.0/22"] + ["104.28.0.0/16", "104.29.0.0/16"]
        n = {"k": 0}

        def fail(args):
            if args[0] == "allow":
                n["k"] += 1
                return n["k"] == 2
            return False

        self.setup(OTHER + managed_lines(), v4=v4, fail=fail)
        state_before = self.state_text()
        self.assertEqual(self.run_main("--prune"), 1)
        # script sorts by (port, family, address): 104.28/80, 104.29/80 (fails), ...
        self.assertEqual(self.ufw.mutations(), [add_cmd("104.28.0.0/16", 80), add_cmd("104.29.0.0/16", 80)])
        self.assertEqual(self.state_text(), state_before)
        self.assertOthersIntact()


class Stale(Base):
    V4 = [n for n in CF4 if n != "131.0.72.0/22"]

    def test_removed_range_no_prune_exit3(self):
        self.setup(OTHER + managed_lines(), v4=self.V4)
        self.assertEqual(self.run_main(), 3)
        self.assertEqual(self.ufw.mutations(), [])
        self.assertIn("--prune", self.err)
        self.assertOthersIntact()

    def test_removed_range_prune(self):
        self.setup(OTHER + managed_lines(), v4=self.V4)
        self.assertEqual(self.run_main("--prune"), 0)
        self.assertEqual(self.ufw.mutations(), [del_cmd("131.0.72.0/22", 80), del_cmd("131.0.72.0/22", 443)])
        self.assertNotIn("131.0.72.0/22", "\n".join(self.ufw.lines()))
        self.assertOthersIntact()

    def test_removed_range_dry_run(self):
        for argv in ([ "--dry-run"], ["--dry-run", "--prune"]):
            with self.subTest(argv=argv):
                self.setup(OTHER + managed_lines(), v4=self.V4, state=False)
                self.assertEqual(self.run_main(*argv), 0)
                self.assertEqual(self.ufw.mutations(), [])
                self.assertIsNone(self.state_text())
                self.assertIn("131.0.72.0/22", self.out)

    def test_dry_run_with_additions_changes_nothing(self):
        self.setup(OTHER + managed_lines(), v4=CF4 + ["104.28.0.0/16"], state=False)
        self.assertEqual(self.run_main("--dry-run", "--prune"), 0)
        self.assertEqual(self.ufw.mutations(), [])
        self.assertIsNone(self.state_text())

    def test_add_and_prune_adds_first(self):
        v4 = self.V4 + ["104.28.0.0/16"]
        self.setup(OTHER + managed_lines(), v4=v4)
        self.assertEqual(self.run_main("--prune"), 0)
        self.assertEqual(self.ufw.mutations(), [
            add_cmd("104.28.0.0/16", 80), add_cmd("104.28.0.0/16", 443),
            del_cmd("131.0.72.0/22", 80), del_cmd("131.0.72.0/22", 443)])
        self.assertOthersIntact()

    def test_prune_v6(self):
        v6 = [n for n in CF6 if n != "2a06:98c0::/29"]
        self.setup(OTHER + managed_lines(), v6=v6)
        self.assertEqual(self.run_main("--prune"), 0)
        self.assertEqual(self.ufw.mutations(), [del_cmd("2a06:98c0::/29", 80), del_cmd("2a06:98c0::/29", 443)])
        self.assertOthersIntact()

    def test_prune_delete_fails_midway(self):
        self.setup(OTHER + managed_lines(), v4=self.V4,
                   fail=lambda a: a[0] == "delete" and a[7] == "443")
        self.assertEqual(self.run_main("--prune"), 1)
        self.assertEqual(self.ufw.mutations(), [del_cmd("131.0.72.0/22", 80), del_cmd("131.0.72.0/22", 443)])
        self.assertOthersIntact()

    def test_unmanaged_rules_never_deleted_even_if_cidr_unpublished(self):
        extra = [
            "ufw allow from 131.0.72.0/22 to any port 443 proto tcp",          # no comment
            "ufw allow from 5.6.7.0/24 to any port 80 proto tcp comment 'cf'",  # other comment
            "ufw allow from 9.9.9.0/24 to any port 8443 proto tcp comment 'cloudflare'",
            "ufw deny from 8.8.8.0/24 to any port 443 proto tcp comment 'cloudflare'",
        ]
        # 131.0.72.0/22 unpublished; the only managed 131 rule is port 80.
        managed = [l for l in managed_lines() if "131.0.72.0/22 to any port 443" not in l]
        self.setup(OTHER + extra + managed, v4=self.V4)
        self.assertEqual(self.run_main("--prune"), 0)
        self.assertEqual(self.ufw.mutations(), [del_cmd("131.0.72.0/22", 80)])
        self.assertOthersIntact()


class Rejects(Base):
    def check_rejected(self, argv=("--prune",), **kw):
        self.setup(OTHER + managed_lines(), **kw)
        state_before = self.state_text()
        self.assertEqual(self.run_main(*argv), 1, self.out + self.err)
        self.assertEqual(self.ufw.mutations(), [])
        self.assertEqual(self.state_text(), state_before)
        self.assertOthersIntact()

    def test_empty_v4(self):
        self.check_rejected(raw4="")

    def test_empty_v6(self):
        self.check_rejected(raw6="\n\n")

    def test_html(self):
        self.check_rejected(raw4="<!DOCTYPE html><html><body>Attention Required</body></html>")

    def test_html_v6(self):
        self.check_rejected(raw6="<html>\n<head><title>502</title></head>\n</html>\n")

    def test_less_than_half(self):
        self.check_rejected(v4=CF4[:7])

    def test_zero_route(self):
        self.check_rejected(v4=CF4 + ["0.0.0.0/0"])

    def test_v6_zero_route(self):
        self.check_rejected(v6=CF6 + ["::/0"])

    def test_private_10(self):
        self.check_rejected(v4=CF4 + ["10.0.0.0/8"])

    def test_private_small(self):
        for n in ("10.1.0.0/16", "192.168.1.0/24", "127.0.0.0/16", "100.64.0.0/16", "169.254.0.0/16"):
            with self.subTest(n=n):
                self.check_rejected(v4=CF4 + [n])

    def test_v6_in_v4(self):
        self.check_rejected(v4=CF4 + ["2400:cb00::/32"])

    def test_v4_in_v6(self):
        self.check_rejected(v6=CF6 + ["173.245.48.0/20"])

    def test_v6_ula(self):
        self.check_rejected(v6=CF6 + ["fd00::/32"])

    def test_host_bits(self):
        self.check_rejected(v4=CF4 + ["104.16.0.1/13"])

    def test_too_wide(self):
        self.check_rejected(v4=CF4 + ["104.0.0.0/8"])

    def test_over_limit(self):
        many = ["45.%d.0.0/16" % i for i in range(70)]
        self.check_rejected(v4=many)

    def test_garbage_line(self):
        self.check_rejected(raw4="\n".join(CF4[:10]) + "\n173.245.4")

    def test_fetch_failure(self):
        self.check_rejected(raw6=self.mod.Fatal("fetching failed: timed out"))

    def test_ufw_inactive(self):
        self.check_rejected(active=False, v4=CF4 + ["104.28.0.0/16"])
        self.assertEqual(self.fetched, [])

    def test_show_added_empty(self):
        self.setup([])
        self.assertEqual(self.run_main(), 1)
        self.assertEqual(self.ufw.mutations(), [])


class UfwSemanticsDefects(Base):
    """Cases where `ufw allow ... comment 'cloudflare'` hits an existing non-managed
    rule with the same src/port/proto (ufw 0.36.2 replaces it)."""

    def test_uncommented_rule_for_published_range_is_not_modified(self):
        extra = "ufw allow from 104.28.0.0/16 to any port 443 proto tcp"
        self.setup(OTHER + [extra] + managed_lines(), v4=CF4 + ["104.28.0.0/16"])
        code = self.run_main()
        self.assertIn(extra, self.ufw.lines(), "non-managed rule was rewritten")
        self.assertOthersIntact()
        self.assertNotEqual(code, 0)

    def test_deny_rule_for_published_range_is_not_turned_into_allow(self):
        extra = "ufw deny from 104.28.0.0/16 to any port 443 proto tcp comment 'blocked'"
        self.setup(OTHER + [extra] + managed_lines(), v4=CF4 + ["104.28.0.0/16"])
        self.run_main()
        self.assertIn(extra, self.ufw.lines(), "deny rule replaced by an allow rule")


class Fetch(unittest.TestCase):
    """The real fetch(), with the HTTPS transport replaced."""

    def setUp(self):
        self.mod = load()

    def fake(self, code, body, headers=None):
        import email.message
        msg = email.message.Message()
        for k, v in (headers or {}).items():
            msg[k] = v

        class H(urllib.request.HTTPSHandler):
            def https_open(self_, req):
                r = urllib.request.addinfourl(io.BytesIO(body), msg, req.full_url, code)
                r.msg = "X"
                return r

        real = urllib.request.build_opener
        return mock.patch.object(self.mod.urllib.request, "build_opener",
                                 lambda *h: real(*(list(h) + [H])))

    def test_ok(self):
        with self.fake(200, b"173.245.48.0/20\n103.21.244.0/22"):
            self.assertEqual(self.mod.fetch("https://x/ips-v4"), "173.245.48.0/20\n103.21.244.0/22")

    def test_redirect_refused(self):
        for code in (301, 302, 303, 307, 308):
            with self.subTest(code=code), self.fake(code, b"", {"Location": "https://evil.example/"}):
                with self.assertRaises(self.mod.Fatal) as cm:
                    self.mod.fetch("https://x/ips-v4")
                # 308 is only routed to the redirect handler on Python >= 3.11;
                # on older Pythons it surfaces as an HTTPError. Both are refused.
                self.assertTrue("redirect" in str(cm.exception) or "308" in str(cm.exception))

    def test_http_error(self):
        for code in (403, 404, 500, 503):
            with self.subTest(code=code), self.fake(code, b"<html>err</html>"):
                with self.assertRaises(self.mod.Fatal):
                    self.mod.fetch("https://x/ips-v4")

    def test_non_200_success(self):
        with self.fake(203, b"173.245.48.0/20"):
            with self.assertRaises(self.mod.Fatal):
                self.mod.fetch("https://x/ips-v4")

    def test_oversize(self):
        with self.fake(200, b"1" * (64 * 1024 + 10)):
            with self.assertRaises(self.mod.Fatal):
                self.mod.fetch("https://x/ips-v4")

    def test_non_ascii(self):
        with self.fake(200, "﻿173.245.48.0/20".encode()):
            with self.assertRaises(self.mod.Fatal):
                self.mod.fetch("https://x/ips-v4")

    def test_http_refused(self):
        with self.assertRaises(self.mod.Fatal):
            self.mod.fetch("http://www.cloudflare.com/ips-v4")

    def test_truncated_at_slash_is_rejected(self):
        # A body cut right before "/22" must not validate as a /32.
        with self.assertRaises(self.mod.Fatal):
            self.mod.parse_list("\n".join(CF4[:-1] + ["131.0.72.0"]), 4, 15)


class NotRoot(Base):
    def test_not_root(self):
        self.setup(OTHER + managed_lines())
        with mock.patch.object(self.mod.os, "geteuid", return_value=1000):
            self.assertEqual(self.run_main(), 1)
        self.assertEqual(self.ufw.calls, [])


if __name__ == "__main__":
    unittest.main()
