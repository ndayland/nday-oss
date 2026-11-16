// nday: keyboard navigation and copy buttons. Progressive enhancement only:
// every page works without this file.
(function () {
  'use strict';
  var d = document;
  var body = d.body;
  var nday = window.nday = window.nday || {};

  // Local time (first, so converted times are in place before the first
  // paint whenever the browser allows). The server prints every instant in
  // UTC, and that stays the no-script text. Values that show a time of day
  // are <time datetime="RFC 3339 UTC" data-lt="long|short">; this rewrites
  // their text to the visitor's time zone with the offset in force at that
  // instant, and keeps the UTC instant in the tooltip. Calendar dates (day
  // precision, upper bounds) are never marked, so they never move.
  function pad2(n) { return (n < 10 ? '0' : '') + n; }
  function offsetSuffix(off) {
    if (off === 0) return 'Z';
    var a = Math.abs(off);
    return (off < 0 ? '-' : '+') + pad2(Math.floor(a / 60)) + ':' + pad2(a % 60);
  }
  // formatTime(utcMs, offsetMinutes, style) is pure. offsetMinutes is east
  // of UTC (+480 = UTC+08:00, -210 = UTC-03:30). style 'long' keeps the year
  // (2026-11-13T16:25+08:00), 'short' drops it (11-13T16:25+08:00); seconds
  // are cut like the server does. Offset 0 gives the server's own UTC text.
  nday.formatTime = function (utcMs, off, style) {
    var t = new Date(utcMs + off * 60000);
    var s = pad2(t.getUTCMonth() + 1) + '-' + pad2(t.getUTCDate()) + 'T' + pad2(t.getUTCHours()) + ':' + pad2(t.getUTCMinutes());
    if (style !== 'short') s = t.getUTCFullYear() + '-' + s;
    return s + offsetSuffix(off);
  };
  // offsetLabel(offsetMinutes): "UTC+08:00", "UTC\u221203:30" (status bar).
  nday.offsetLabel = function (off) {
    var a = Math.abs(off);
    return 'UTC' + (off < 0 ? '\u2212' : '+') + pad2(Math.floor(a / 60)) + ':' + pad2(a % 60);
  };
  // offsetAt(utcMs): the visitor's offset east of UTC in force at that
  // instant (DST-correct; whole minutes).
  nday.offsetAt = function (utcMs) { return -Math.round(new Date(utcMs).getTimezoneOffset()) || 0; };
  // localTime(iso, style): an RFC 3339 instant in the visitor's zone ('' if
  // it does not parse).
  nday.localTime = function (iso, style) {
    var ms = iso ? Date.parse(iso) : NaN;
    return isNaN(ms) ? '' : nday.formatTime(ms, nday.offsetAt(ms), style || 'long');
  };
  (function localTimes() {
    var shifted = false;
    Array.prototype.forEach.call(d.querySelectorAll('time[data-lt]'), function (el) {
      var iso = el.getAttribute('datetime');
      var ms = Date.parse(iso);
      if (isNaN(ms)) return;
      var off = nday.offsetAt(ms);
      if (off === 0) return;
      el.textContent = nday.formatTime(ms, off, el.getAttribute('data-lt'));
      el.title = iso;
      shifted = true;
    });
    var now = nday.offsetAt(Date.now());
    if (!shifted && now === 0) return;
    // the status bar no longer says "all times UTC" (words from the page)
    var note = d.getElementById('utc');
    var text = body.getAttribute('data-t-local-time');
    if (note && text) {
      note.textContent = text.replace('{offset}', nday.offsetLabel(now));
      var lang = body.getAttribute('data-t-local-time-lang');
      if (lang) note.setAttribute('lang', lang);
    }
    // hot list: rows stay grouped under UTC dates; say so on each header
    // (not on the catalogue's "time unknown" header, which is no date)
    Array.prototype.forEach.call(d.querySelectorAll('.dgroup:not(.nodate)'), function (h) {
      var m = d.createElement('span');
      m.className = 'tz';
      m.textContent = ' UTC';
      (h.querySelector('.dgh') || h).appendChild(m);
    });
  })();

  // Phones (the stylesheet's 720px breakpoint): the list filters (hot.tmpl
  // details.flt, open in the HTML so they work without script) fold into
  // their summary line unless a selection other than the defaults is set
  // (data-keep); wide screens always show them. The page links scroll
  // sideways there; the current one is brought into view.
  (function phones() {
    if (!window.matchMedia) return;
    var mq = window.matchMedia('(max-width: 720px)');
    var flt = d.querySelector('details.flt');
    function fold() { flt.open = !mq.matches || flt.hasAttribute('data-keep'); }
    if (flt) {
      fold();
      if (mq.addEventListener) mq.addEventListener('change', fold);
    }
    // the menu rows that scroll sideways on phones (main nav, admin menu): bring the current item into view
    Array.prototype.forEach.call(d.querySelectorAll('.nav,.adm-nav'), function (nav) {
      var here = nav.querySelector('[aria-current="page"]');
      if (here && mq.matches && nav.scrollWidth > nav.clientWidth) {
        var a = here.getBoundingClientRect(), n = nav.getBoundingClientRect();
        nav.scrollLeft += (a.left - n.left) - (nav.clientWidth - a.width) / 2;
      }
    });
  })();

  var rows = Array.prototype.slice.call(d.querySelectorAll('[data-row]'));
  var cur = -1;
  var pos = d.getElementById('pos');
  var msg = d.getElementById('msg');
  var mode = d.getElementById('mode');
  var help = d.getElementById('help');
  var search = d.getElementById('q');
  // the catalogue's own search box stands in for the header's where that one is hidden
  var catq = d.getElementById('cat-q');
  if (catq && (!search || search.offsetParent === null)) search = catq;
  var reduce = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  var msgTimer = 0;
  // Words come from the page (the locale's catalog), never from this file.
  function word(name, fallback) { return body.getAttribute('data-t-' + name) || fallback; }

  function say(text) {
    if (!msg) return;
    msg.textContent = text;
    clearTimeout(msgTimer);
    msgTimer = setTimeout(function () { msg.textContent = ''; }, 2000);
  }

  function select(i, scroll) {
    if (!rows.length) return;
    i = Math.max(0, Math.min(rows.length - 1, i));
    if (cur >= 0 && rows[cur]) {
      rows[cur].classList.remove('sel');
      rows[cur].removeAttribute('aria-current');
    }
    cur = i;
    rows[i].classList.add('sel');
    rows[i].setAttribute('aria-current', 'true');
    if (pos && body.hasAttribute('data-pos')) pos.textContent = (i + 1) + '/' + rows.length;
    if (scroll) rows[i].scrollIntoView({ block: 'nearest', behavior: reduce ? 'auto' : 'smooth' });
  }

  function copy(text, done) {
    function fallback() {
      var ta = d.createElement('textarea');
      ta.value = text;
      ta.setAttribute('readonly', '');
      ta.className = 'sr';
      body.appendChild(ta);
      ta.select();
      var ok = false;
      try { ok = d.execCommand('copy'); } catch (e) { ok = false; }
      body.removeChild(ta);
      done(ok);
    }
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(function () { done(true); }, fallback);
    } else {
      fallback();
    }
  }

  // Copy buttons are hidden in the HTML; they only work with this script.
  Array.prototype.forEach.call(d.querySelectorAll('button[data-copy]'), function (b) {
    b.hidden = false;
    var label = b.textContent;
    b.addEventListener('click', function () {
      copy(b.getAttribute('data-copy'), function (ok) {
        b.textContent = ok ? word('copied', '\u2713') : word('copy-failed', '\u2717');
        setTimeout(function () { b.textContent = label; }, 1200);
      });
    });
  });

  // Clicking a row (not a link inside it) moves the cursor there (rows may
  // be reordered later: the hot list's pinned group). One listener for all
  // rows, on their container: a row moved or added later is still handled.
  if (rows.length) {
    (d.querySelector('main') || d).addEventListener('click', function (e) {
      var t = e.target;
      if (!t || !t.closest) return;
      var r = t.closest('[data-row]');
      if (!r || t.closest('a, button, summary, pre')) return;
      var i = rows.indexOf(r);
      if (i >= 0) select(i, false);
    });
  }

  if (search) {
    search.addEventListener('focus', function () { if (mode) mode.textContent = 'SEARCH'; });
    search.addEventListener('blur', function () { if (mode) mode.textContent = 'NORMAL'; });
  }

  if (rows.length && body.hasAttribute('data-autosel')) select(0, false);

  // Language suggestion: when the browser prefers another enabled locale
  // than the page's, offer one line, in THAT language, linking to the same
  // page there. No cookies, no redirect; dismissal is remembered locally.
  (function langHint() {
    var KEY = 'nday.langhint.dismissed';
    var links = Array.prototype.slice.call(d.querySelectorAll('.langs a[data-match]'));
    if (links.length < 2 || !navigator.languages) return;
    try { if (window.localStorage.getItem(KEY) === '1') return; } catch (e) { return; }
    function find(tag) {
      tag = String(tag).toLowerCase();
      for (;;) {
        for (var i = 0; i < links.length; i++) {
          if ((' ' + links[i].getAttribute('data-match') + ' ').indexOf(' ' + tag + ' ') >= 0) return links[i];
        }
        var cut = tag.lastIndexOf('-');
        if (cut < 0) return null;
        tag = tag.slice(0, cut);
      }
    }
    var want = null;
    for (var i = 0; i < navigator.languages.length && !want; i++) want = find(navigator.languages[i]);
    if (!want || want.getAttribute('aria-current') === 'true') return;
    var bar = d.createElement('div');
    bar.className = 'langhint';
    bar.setAttribute('lang', want.getAttribute('hreflang'));
    var a = d.createElement('a');
    a.href = want.getAttribute('href');
    a.hreflang = want.getAttribute('hreflang');
    a.textContent = want.getAttribute('data-hint');
    var x = d.createElement('button');
    x.type = 'button';
    x.className = 'btn sm';
    x.textContent = '\u00d7';
    x.setAttribute('aria-label', want.getAttribute('data-dismiss'));
    x.addEventListener('click', function () {
      try { window.localStorage.setItem(KEY, '1'); } catch (e) { /* private mode */ }
      bar.parentNode.removeChild(bar);
    });
    var wrap = d.createElement('div');
    wrap.className = 'wrap';
    wrap.appendChild(a);
    wrap.appendChild(x);
    bar.appendChild(wrap);
    var skip = d.querySelector('a.skip');
    body.insertBefore(bar, skip ? skip.nextSibling : body.firstChild); // the skip link stays first
  })();

  // Colour theme menu (base.tmpl details.theme). static/theme.js applies and
  // keeps the choice; this marks the current one and closes the menu on a
  // pick or on Escape, returning focus to its summary.
  // The catalogue's search area (.chero) has a backdrop (.cbg, aria-hidden):
  // columns of characters falling at different speeds, each with a bright
  // head and a fading tail, drawn on a canvas in the theme's accent colour.
  // Decoration only: nothing without JS; it runs only while the area is on
  // screen and the tab is visible, at about 14 frames a second; with
  // prefers-reduced-motion it is one still frame. CSS fades its edges.
  (function heroField() {
    var el = d.querySelector('.cbg');
    if (!el || !window.HTMLCanvasElement) return;
    var cv = d.createElement('canvas');
    var ctx = cv.getContext && cv.getContext('2d');
    if (!ctx) return;
    el.appendChild(cv);
    var glyphs = '01{}[]()<>/\\#$%&*+=-_:;|?@!0123456789ABCDEF';
    var CW = 16, CH = 18, TICK = 70;
    var cols = [], w = 0, h = 0, head = '#fff', tail = '#0f0', timer = 0, onScreen = true;
    function rnd(n) { return Math.floor(Math.random() * n); }
    function glyph() { return glyphs.charAt(rnd(glyphs.length)); }
    function colours() {
      var cs = window.getComputedStyle(el);
      head = cs.color || head;
      tail = cs.getPropertyValue('--green').trim() || tail;
    }
    function column(rowsN, anywhere) {
      var len = 6 + rnd(18), chars = [];
      for (var i = 0; i < len; i++) chars.push(glyph());
      return { y: anywhere ? rnd(rowsN + len) : -rnd(rowsN), v: 0.35 + Math.random() * 0.75, len: len, chars: chars };
    }
    function layout() {
      var r = window.devicePixelRatio || 1;
      w = el.clientWidth; h = el.clientHeight;
      if (!(w > 0 && h > 0)) return false;
      cv.width = Math.round(w * r); cv.height = Math.round(h * r);
      ctx.setTransform(r, 0, 0, r, 0, 0);
      ctx.font = '13px ' + (window.getComputedStyle(el).fontFamily || 'monospace');
      ctx.textBaseline = 'top';
      var n = Math.ceil(w / CW), rowsN = Math.ceil(h / CH);
      cols = [];
      for (var i = 0; i < n; i++) cols.push(rnd(100) < 62 ? column(rowsN, true) : null); // some columns stay empty
      return true;
    }
    function frame(move) {
      var rowsN = Math.ceil(h / CH);
      ctx.clearRect(0, 0, w, h);
      for (var i = 0; i < cols.length; i++) {
        var c = cols[i];
        if (!c) { if (move && rnd(400) === 0) cols[i] = column(rowsN, false); continue; }
        if (move) {
          c.y += c.v;
          if (rnd(6) === 0) c.chars[rnd(c.len)] = glyph();
          if (c.y - c.len > rowsN) { cols[i] = rnd(100) < 70 ? column(rowsN, false) : null; continue; }
        }
        var top = Math.floor(c.y);
        for (var k = 0; k < c.len; k++) {
          var row = top - k;
          if (row < 0 || row > rowsN) continue;
          ctx.globalAlpha = k === 0 ? 0.95 : Math.max(0.08, 0.8 * (1 - k / c.len));
          ctx.fillStyle = k === 0 ? head : tail;
          ctx.fillText(c.chars[k], i * CW + 3, row * CH + 2);
        }
      }
      ctx.globalAlpha = 1;
    }
    function running() { return onScreen && !d.hidden && !reduce; }
    function sync() {
      if (running() && !timer) timer = window.setInterval(function () { frame(true); }, TICK);
      else if (!running() && timer) { window.clearInterval(timer); timer = 0; }
    }
    function reset() { colours(); if (layout()) frame(false); sync(); }
    reset();
    if (window.ResizeObserver) new window.ResizeObserver(reset).observe(el);
    else window.addEventListener('resize', reset);
    if (window.IntersectionObserver) {
      new window.IntersectionObserver(function (es) { onScreen = es[es.length - 1].isIntersecting; sync(); }).observe(el);
    }
    d.addEventListener('visibilitychange', sync);
    d.addEventListener('nday:theme', function () { colours(); frame(false); });
  })();

  (function themeMenu() {
    var menu = d.querySelector('details.theme');
    if (!menu || !nday.theme) return;
    var sum = menu.querySelector('summary');
    var btns = menu.querySelectorAll('button[data-theme-set]');
    function mark() {
      var p = nday.theme.get();
      for (var i = 0; i < btns.length; i++) {
        btns[i].setAttribute('aria-pressed', btns[i].getAttribute('data-theme-set') === p ? 'true' : 'false');
      }
    }
    function close() {
      menu.open = false;
      if (sum) sum.focus();
    }
    for (var i = 0; i < btns.length; i++) {
      btns[i].addEventListener('click', function (e) {
        nday.theme.set(e.currentTarget.getAttribute('data-theme-set'));
        close();
      });
    }
    menu.addEventListener('keydown', function (e) {
      if (e.key === 'Escape' && menu.open) { e.preventDefault(); close(); }
    });
    d.addEventListener('nday:theme', mark);
    mark();
  })();

  // Account slot and sign-in result banner (only when accounts are enabled:
  // the page then has #acct). The HTML is the same for every visitor; the
  // state comes from GET /api/me once per page view. When the state is
  // unknown (network error, 5xx, wrong host) the plain sign-in link stays.
  // API data reaches the DOM only through textContent.
  (function account() {
    var slot = d.getElementById('acct');
    if (!slot || !window.fetch || !window.URLSearchParams) return;
    var tpl = d.getElementById('acct-msgs');
    var loginPath = slot.getAttribute('data-login');
    var accountPath = slot.getAttribute('data-account');
    var adminPath = slot.getAttribute('data-admin'); // set when the site has a back office
    var outcomes = ['ok', 'linked', 'denied', 'conflict', 'error', 'signed_in_as_other', 'reauth_required', 'suspended'];
    function src(key) { return tpl ? tpl.content.querySelector('[data-k="' + key + '"]') : null; }
    function put(el, key) {
      var s = src(key);
      el.textContent = s ? s.textContent : '';
      if (s && s.getAttribute('lang')) el.setAttribute('lang', s.getAttribute('lang'));
    }
    function clear(el) { while (el.firstChild) el.removeChild(el.firstChild); }

    // ?auth=<result> after a provider round trip: a localized banner, then
    // the parameter leaves the address bar (it never decides navigation).
    var params = new URLSearchParams(window.location.search);
    var outcome = params.get('auth');
    if (outcome !== null) {
      params.delete('auth');
      var qs = params.toString();
      try {
        window.history.replaceState(window.history.state, '', window.location.pathname + (qs ? '?' + qs : '') + window.location.hash);
      } catch (e) { /* keep the parameter */ }
      if (outcomes.indexOf(outcome) >= 0) banner(outcome);
    }

    function banner(code) {
      var bar = d.createElement('div');
      bar.className = 'authbanner';
      var wrap = d.createElement('div');
      wrap.className = 'wrap';
      var p = d.createElement('p');
      p.setAttribute('role', 'status');
      if (code === 'ok' || code === 'linked') p.className = 'ok';
      var x = d.createElement('button');
      x.type = 'button';
      x.className = 'btn sm';
      x.textContent = '×';
      var dl = src('acct.banner.dismiss');
      x.setAttribute('aria-label', dl ? dl.textContent : '×');
      x.addEventListener('click', function () { bar.parentNode.removeChild(bar); });
      wrap.appendChild(p);
      wrap.appendChild(x);
      bar.appendChild(wrap);
      var top = d.querySelector('header.top');
      top.parentNode.insertBefore(bar, top.nextSibling);
      setTimeout(function () { put(p, 'acct.banner.' + code); }, 50); // after the live region exists
    }

    // Staff accounts (moderator or admin, not suspended) get a link to the
    // back office next to the slot; the server decides access on its own.
    function adminLink(u) {
      var old = d.getElementById('acct-admin');
      if (old) old.parentNode.removeChild(old);
      if (!adminPath || !u || (u.role !== 'moderator' && u.role !== 'admin') || u.status === 'suspended') return;
      var a = d.createElement('a');
      a.id = 'acct-admin';
      a.className = 'acct';
      a.classList.add('adm-link');
      a.href = adminPath;
      put(a, 'admin.slot');
      var here = window.location.pathname;
      if (here === adminPath || here.indexOf(adminPath + '/') === 0) a.setAttribute('aria-current', 'page');
      slot.parentNode.insertBefore(a, slot.nextSibling);
    }

    function signedOut() {
      adminLink(null);
      clear(slot);
      put(slot, 'acct.slot.signin');
      slot.removeAttribute('aria-current');
      if (window.location.pathname !== loginPath) {
        slot.href = loginPath + '?return=' + encodeURIComponent(window.location.pathname + window.location.search);
      }
    }

    function signedIn(u) {
      clear(slot);
      slot.removeAttribute('lang');
      var name = u.handle ? '@' + u.handle : (u.display_name || '');
      var n = d.createElement('bdi');
      n.className = 'an';
      if (name) n.textContent = name; else put(n, 'acct.slot.account');
      slot.appendChild(n);
      if (u.role === 'moderator' || u.role === 'admin') {
        var b = d.createElement('span');
        b.className = 'rb';
        put(b, 'acct.role.badge#' + u.role);
        slot.appendChild(b);
      }
      slot.href = accountPath;
      if (window.location.pathname === accountPath) slot.setAttribute('aria-current', 'page');
      else slot.removeAttribute('aria-current');
      adminLink(u);
    }

    // render(me): me is the /api/me object, {disabled: true} for a 404
    // (accounts off) or null when the state is unknown.
    nday.render = function (me) {
      if (me && me.disabled) { slot.hidden = true; return; }
      slot.hidden = false;
      if (me && me.signed_in && me.user) signedIn(me.user); else signedOut();
    };
    nday.fetchMe = function () {
      return window.fetch('/api/me', { credentials: 'same-origin', cache: 'no-store', headers: { Accept: 'application/json' } })
        .then(function (r) {
          if (r.status === 404) return { disabled: true };
          if (!r.ok) return null;
          return r.json().then(function (j) { return j && typeof j.signed_in === 'boolean' ? j : null; });
        })
        .then(null, function () { return null; })
        .then(function (me) { nday.render(me); return me; });
    };
    nday.me = nday.fetchMe(); // this page view's state (account.js reuses it)
  })();

  // Hot list, signed in with at least one follow (docs/follows.md): rows of
  // vulnerabilities affecting a followed vendor or product move into a pinned
  // group at the top of the table, in their order, under a header like the
  // date headers (words from the table's data-pin). A date header left
  // without rows goes. Only the rows of this page are looked at. Nothing
  // moves for anyone else, and any failure leaves the list as it is.
  (function pinFollows() {
    var tbl = d.querySelector('.tbl-in[data-pin]');
    if (!tbl || !nday.me || !rows.length || !window.JSON) return;
    nday.me.then(function (me) {
      var u = me && me.signed_in && me.user;
      if (!u || !u.follows || !u.follows.length || !me.csrf_token) return null;
      var ids = [];
      rows.forEach(function (r) {
        var id = r.getAttribute('data-id');
        if (id && ids.length < 200) ids.push(id);
      });
      var path = '/account/follows/match';
      return window.fetch(path, {
        method: 'POST', credentials: 'same-origin', cache: 'no-store', redirect: 'error',
        headers: { Accept: 'application/json', 'Content-Type': 'application/json', 'X-CSRF-Token': me.csrf_token },
        body: JSON.stringify({ cve_ids: ids }),
      }).then(function (r) { return r.ok ? r.json() : null; });
    }).then(function (j) {
      if (j && j.matches && j.matches.length) regroup(j.matches);
    }).then(null, function () { /* silent: the list stays as it is */ });

    function regroup(ids) {
      var want = {};
      ids.forEach(function (id) { want[id] = true; });
      var th = tbl.querySelector('.th');
      if (!th) return;
      var selected = cur >= 0 ? rows[cur] : null;
      var first = cur === 0;
      var moved = [];
      var pending = null; // a date header whose own row moved away
      Array.prototype.slice.call(tbl.children).forEach(function (g) {
        if (!g.classList.contains('grp')) return;
        var head = g.querySelector('.dgroup');
        var row = g.querySelector('[data-row]');
        if (head) {
          if (pending && pending.parentNode) pending.parentNode.removeChild(pending); // a date with no rows left
          pending = null;
        }
        if (row && want[row.getAttribute('data-id')]) {
          if (head) pending = head;
          moved.push(row);
          g.parentNode.removeChild(g);
          if (head) g.removeChild(head);
          return;
        }
        if (pending && !head) g.insertBefore(pending, g.firstChild);
        pending = null;
      });
      if (!moved.length) return;
      var anchor = th.nextSibling;
      moved.forEach(function (row, i) {
        var g = d.createElement('div');
        g.className = 'grp';
        g.classList.add('pin');
        g.setAttribute('role', 'rowgroup');
        if (i === 0) { // same structure as the "dgroup" template (parts.tmpl)
          var h = d.createElement('div');
          h.className = 'dgroup';
          h.setAttribute('role', 'row');
          var cell = d.createElement('span');
          cell.setAttribute('role', 'cell');
          var hd = d.createElement('span');
          hd.className = 'dgh';
          hd.setAttribute('role', 'heading');
          hd.setAttribute('aria-level', '2');
          var marks = d.createElement('span');
          marks.setAttribute('aria-hidden', 'true');
          marks.textContent = '## ';
          hd.appendChild(marks);
          hd.appendChild(d.createTextNode(tbl.getAttribute('data-pin')));
          var lang = tbl.getAttribute('data-pin-lang');
          if (lang) h.setAttribute('lang', lang);
          cell.appendChild(hd);
          h.appendChild(cell);
          g.appendChild(h);
        }
        g.appendChild(row);
        tbl.insertBefore(g, anchor);
      });
      rows = Array.prototype.slice.call(d.querySelectorAll('[data-row]'));
      if (selected) {
        selected.classList.remove('sel');
        selected.removeAttribute('aria-current');
        cur = -1;
        select(first ? 0 : rows.indexOf(selected), false);
      }
    }
  })();

  function currentId() {
    if (cur >= 0 && rows[cur].getAttribute('data-id')) return rows[cur].getAttribute('data-id');
    return body.getAttribute('data-id') || '';
  }

  function toggleRaw() {
    var blocks = cur >= 0 ? rows[cur].querySelectorAll('details.raw') : d.querySelectorAll('details.raw');
    if (!blocks.length) {
      var href = body.getAttribute('data-raw');
      if (href) window.location.href = href;
      return;
    }
    var open = false;
    Array.prototype.forEach.call(blocks, function (x) { if (!x.open) open = true; });
    Array.prototype.forEach.call(blocks, function (x) { x.open = open; });
  }

  function up() {
    var ref = d.referrer;
    if (ref && ref.indexOf(window.location.origin + '/') === 0 && window.history.length > 1) {
      window.history.back();
    } else {
      window.location.href = body.getAttribute('data-up') || '/';
    }
  }

  // Single-character shortcuts can be turned off (WCAG 2.1.4) with the
  // checkbox in the help panel; the choice is kept in this browser. While
  // they are off, only ? (this help, to turn them back on), / (search) and
  // Esc still work.
  var KEYS_OFF = 'nday.keys.off';
  var keysOn = true;
  try { keysOn = window.localStorage.getItem(KEYS_OFF) !== '1'; } catch (e) { /* storage blocked: on */ }
  var keysBox = d.getElementById('keys-on');
  if (keysBox) {
    keysBox.checked = keysOn;
    keysBox.addEventListener('change', function () {
      keysOn = keysBox.checked;
      try {
        if (keysOn) window.localStorage.removeItem(KEYS_OFF); else window.localStorage.setItem(KEYS_OFF, '1');
      } catch (e) { /* this page view only */ }
    });
  }

  // The help panel is a non-modal dialog: opening it moves focus into it,
  // closing it (?, Esc) returns focus where it was.
  var helpReturn = null;
  function openHelp() {
    if (!help) return;
    helpReturn = d.activeElement;
    help.hidden = false;
    help.focus();
  }
  function closeHelp() {
    if (!help || help.hidden) return;
    var back = helpReturn;
    helpReturn = null;
    var inside = help.contains(d.activeElement);
    help.hidden = true;
    if (inside) {
      if (back && back !== body && back.isConnected && back.focus) back.focus();
      else if (d.activeElement && d.activeElement.blur) d.activeElement.blur();
    }
  }

  d.addEventListener('keydown', function (e) {
    if (e.defaultPrevented || e.isComposing) return;
    if (e.ctrlKey || e.metaKey || e.altKey) return;
    var t = e.target;
    var tag = t && t.tagName;
    if (e.key === 'Escape' && help && !help.hidden && help.contains(t)) {
      closeHelp();
      e.preventDefault();
      return;
    }
    if (t && (t.isContentEditable || tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT')) {
      if (e.key === 'Escape') { t.blur(); }
      return;
    }
    if (!keysOn && e.key !== '?' && e.key !== '/' && e.key !== 'Escape') return;
    switch (e.key) {
      case 'j': select(cur + 1, true); break;
      case 'k': select(cur < 0 ? 0 : cur - 1, true); break;
      case 'Enter': {
        if (tag === 'A' || tag === 'BUTTON' || tag === 'SUMMARY') return;
        if (cur < 0) return;
        var href = rows[cur].getAttribute('data-href');
        if (!href) return;
        window.location.href = href;
        break;
      }
      case '/':
        if (!search) return;
        search.focus();
        search.select();
        break;
      case 'y': {
        var id = currentId();
        if (!id) return;
        copy(id, function (ok) { say(ok ? word('copied-id', '{id}').replace('{id}', id) : word('copy-failed', '\u2717')); });
        break;
      }
      case 'r': toggleRaw(); break;
      case 'o': {
        if (cur < 0) return;
        var a = rows[cur].querySelector('a[data-src]');
        if (!a) return;
        window.location.href = a.href;
        break;
      }
      case 'u': up(); break;
      case '?':
        if (!help) return;
        if (help.hidden) openHelp(); else closeHelp();
        break;
      case 'Escape':
        if (help && !help.hidden) { closeHelp(); break; }
        return;
      default: return;
    }
    e.preventDefault();
  });
})();

// "Tadpole script": the speckle that stands for researcher posts and
// comments a signed-out visitor may not read (vulnerability pages;
// internal/webui/discussion.go). Each placeholder is an empty
// <span class="spk" data-size="s|m|l"> whose height the stylesheet fixes from
// the size class; this draws word-like runs of fine dots on a canvas inside
// it. The drawing is a function of the size class, the box and a random
// seed ONLY: the page holds no content to draw from. A slow shimmer runs
// while a placeholder is on screen and the tab is visible, never under
// prefers-reduced-motion, and stops (keeping its last frame) after about 5 s
// of animation; a new layout of the placeholder (a size change) redraws it
// and starts the shimmer again. The colour is read once per layout, not per
// frame (and again when the colour theme changes). Without script the
// stylesheet's dotted band stays.
(function () {
  'use strict';
  var d = document;
  var els = d.querySelectorAll('.spk');
  if (!els.length || !window.HTMLCanvasElement) return;
  var still = !!(window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches);
  var LINES = { s: 1, m: 2, l: 4 };
  var TICK = 180, FRAMES = Math.round(5000 / TICK); // shimmer frames per layout
  function rng(seed) { // mulberry32
    var a = seed >>> 0;
    return function () {
      a = (a + 0x6D2B79F5) >>> 0;
      var t = Math.imul(a ^ (a >>> 15), 1 | a);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }
  var items = [];
  function setup(el) {
    var c = d.createElement('canvas');
    c.setAttribute('aria-hidden', 'true');
    el.appendChild(c);
    el.classList.add('drawn');
    return { el: el, c: c, seed: Math.floor(Math.random() * 4294967296), frame: 0, on: true, color: '', left: FRAMES,
      lines: el.classList.contains('spk-au') ? 1 : (LINES[el.getAttribute('data-size')] || 1),
      au: el.classList.contains('spk-au') };
  }
  function draw(it) {
    var el = it.el;
    var w = el.clientWidth, h = el.clientHeight;
    if (!w || !h) return;
    var dpr = window.devicePixelRatio || 1;
    var cw = Math.round(w * dpr), ch = Math.round(h * dpr);
    if (it.c.width !== cw || it.c.height !== ch) { it.c.width = cw; it.c.height = ch; }
    var g = it.c.getContext('2d');
    if (!g) return;
    g.setTransform(dpr, 0, 0, dpr, 0, 0);
    g.clearRect(0, 0, w, h);
    if (!it.color) it.color = window.getComputedStyle(el).color;
    g.fillStyle = it.color;
    var shape = rng(it.seed); // the layout: stable
    var dots = rng(it.seed ^ (it.frame * 2654435761)); // the dots: drift per frame
    var lh = h / it.lines;
    var left = it.lines; // lines left in the current paragraph
    for (var i = 0; i < it.lines; i++) {
      if (left <= 0 || i === 0) left = 1 + Math.floor(shape() * 2);
      left--;
      var lastOfPara = left === 0 || i === it.lines - 1;
      var end = w * (it.au ? 1 : (lastOfPara && it.lines > 1 ? 0.4 + shape() * 0.4 : 0.9 + shape() * 0.1));
      var band = lh * 0.5, top = i * lh + (lh - band) / 2;
      for (var x = 0; x < end;) {
        var ww = Math.min(end - x, 14 + shape() * 52);
        var dens = 0.18 + shape() * 0.22;
        var n = Math.floor(ww * band * dens);
        for (var k = 0; k < n; k++) {
          var sz = 0.8 + dots() * 0.8; // CSS px: 1-2 device px on most screens
          g.globalAlpha = 0.35 + dots() * 0.6;
          g.fillRect(x + dots() * ww, top + dots() * band, sz, sz);
        }
        x += ww + 4 + shape() * 5;
      }
    }
    g.globalAlpha = 1;
  }
  for (var i = 0; i < els.length; i++) items.push(setup(els[i]));
  var timer = 0;
  // a new layout: read the colour again, redraw, and give the shimmer its frames back
  function relayout(it) {
    it.color = '';
    it.left = FRAMES;
    draw(it);
    kick();
  }
  function all() { for (var i = 0; i < items.length; i++) relayout(items[i]); }
  if (window.ResizeObserver) {
    var ro = new window.ResizeObserver(function (es) {
      for (var i = 0; i < es.length; i++) {
        for (var k = 0; k < items.length; k++) if (items[k].el === es[i].target) relayout(items[k]);
      }
    });
    for (var j = 0; j < items.length; j++) ro.observe(items[j].el);
  } else {
    window.addEventListener('resize', all);
  }
  // the shimmer: one timer while any placeholder has frames left, none after
  function kick() {
    if (still || timer) return;
    timer = window.setInterval(function () {
      if (d.hidden) return;
      var busy = false;
      for (var i = 0; i < items.length; i++) {
        var it = items[i];
        if (it.left <= 0 || !it.el.isConnected) continue;
        busy = true;
        if (!it.on) continue;
        it.left--;
        it.frame++;
        draw(it);
      }
      if (!busy) { window.clearInterval(timer); timer = 0; }
    }, TICK);
  }
  if (!still && window.IntersectionObserver) {
    for (var m = 0; m < items.length; m++) items[m].on = false;
    var io = new window.IntersectionObserver(function (es) {
      for (var i = 0; i < es.length; i++) {
        for (var k = 0; k < items.length; k++) if (items[k].el === es[i].target) items[k].on = es[i].isIntersecting;
      }
    });
    for (var q = 0; q < items.length; q++) io.observe(items[q].el);
  }
  all();
  d.addEventListener('nday:theme', all); // static/theme.js: the colour changed
})();
