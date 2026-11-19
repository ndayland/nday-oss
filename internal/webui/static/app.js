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
  // localTimes(root) converts the times inside root (the page, or a list
  // region that replaced another: "paging" below); the status bar note is
  // set once per page view.
  var tzOn = false;
  function localTimes(root) {
    var shifted = false;
    Array.prototype.forEach.call(root.querySelectorAll('time[data-lt]'), function (el) {
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
    if (!tzOn && !shifted && now === 0) return;
    if (!tzOn) {
      tzOn = true;
      // the status bar no longer says "all times UTC" (words from the page)
      var note = d.getElementById('utc');
      var text = body.getAttribute('data-t-local-time');
      if (note && text) {
        note.textContent = text.replace('{offset}', nday.offsetLabel(now));
        var lang = body.getAttribute('data-t-local-time-lang');
        if (lang) note.setAttribute('lang', lang);
      }
    }
    // hot list: rows stay grouped under UTC dates; say so on each header
    // (not on the catalogue's "time unknown" header, which is no date)
    Array.prototype.forEach.call(root.querySelectorAll('.dgroup:not(.nodate)'), function (h) {
      var m = d.createElement('span');
      m.className = 'tz';
      m.textContent = ' UTC';
      (h.querySelector('.dgh') || h).appendChild(m);
    });
  }
  localTimes(d);

  // escMenu(menu, when): a <details> menu that Escape closes, focus going
  // back to its summary (the share menu, the landing's header menu). An open
  // menu inside it (language, theme) closes first.
  // when(), if given, says whether it may close now. Returns close(back).
  function escMenu(menu, when) {
    var sum = menu.querySelector('summary');
    function close(back) {
      if (!menu.open || (when && !when())) return;
      menu.open = false;
      if (back && sum) sum.focus();
    }
    menu.addEventListener('keydown', function (e) {
      if (e.key !== 'Escape' || !menu.open || e.defaultPrevented || (when && !when())) return;
      e.preventDefault();
      // an open menu inside it without its own Escape (language) closes first
      var inner = e.target instanceof Element ? e.target.closest('details') : null;
      if (inner && inner !== menu && inner.open) {
        inner.open = false;
        var s = inner.querySelector('summary');
        if (s) s.focus();
        return;
      }
      close(true);
    });
    return close;
  }

  // Phones (the stylesheet's 720px breakpoint): the list filters (hot.tmpl
  // details.flt, open in the HTML so they work without script) fold into
  // their summary line unless a selection other than the defaults is set
  // (data-keep); wide screens always show them. The same for the header
  // menu of the /vuln landing (base.tmpl details.topm): folded behind its
  // ">" on phones, always open on wide screens (its summary is not shown
  // there); Escape folds it again (escMenu). The page links scroll
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
    var topm = d.querySelector('details.topm');
    function foldMenu() { topm.open = !mq.matches; }
    if (topm) {
      foldMenu();
      if (mq.addEventListener) mq.addEventListener('change', foldMenu);
      escMenu(topm, function () { return mq.matches; });
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
  // copyButtons(root) sets up those inside root (the page or a new region).
  function copyButtons(root) {
    Array.prototype.forEach.call(root.querySelectorAll('button[data-copy]'), function (b) {
      b.hidden = false;
      var label = b.textContent;
      b.addEventListener('click', function () {
        copy(b.getAttribute('data-copy'), function (ok) {
          b.textContent = ok ? word('copied', '\u2713') : word('copy-failed', '\u2717');
          setTimeout(function () { b.textContent = label; }, 1200);
        });
      });
    });
  }
  copyButtons(d);

  // Two-step confirm (admin.js, account.js, discuss.js): confirmStep(btn,
  // note) is false on a first click, which arms the button for 5 s, and true
  // on the second one. An armed button shows the word of its data-confirm
  // over its label (app.css "two-step confirm": the button is as wide as the
  // wider of the two from the start, so nothing moves); its accessible name
  // becomes "<word>: <label>" and note, if any, its title. Blur, Escape or
  // the 5 s put it back. data-confirm is rendered by the server, or set by
  // confirmable(btn) where a script builds the button.
  (function confirmSteps() {
    var tpl = d.getElementById('acct-msgs');
    var saved = new WeakMap(); // armed button -> { label, title, timer }
    function confirmWord() {
      var s = tpl && tpl.content.querySelector('[data-k="btn.confirm"]');
      return s ? s.textContent : '';
    }
    function confirmable(btn) {
      if (btn && !btn.hasAttribute('data-confirm')) btn.setAttribute('data-confirm', confirmWord());
      return btn;
    }
    function restore(btn, attr, v) {
      if (v === null) btn.removeAttribute(attr);
      else btn.setAttribute(attr, v);
    }
    function onKey(e) { if (e.key === 'Escape') disarm(e.currentTarget); }
    function onBlur(e) { disarm(e.currentTarget); }
    function disarm(btn) {
      var s = btn && saved.get(btn);
      if (!s) return;
      saved.delete(btn);
      clearTimeout(s.timer);
      btn.removeAttribute('data-armed');
      restore(btn, 'aria-label', s.label);
      restore(btn, 'title', s.title);
      btn.removeEventListener('blur', onBlur);
      btn.removeEventListener('keydown', onKey);
    }
    function confirmStep(btn, note) {
      if (saved.has(btn)) {
        disarm(btn);
        return true;
      }
      confirmable(btn);
      saved.set(btn, {
        label: btn.getAttribute('aria-label'), title: btn.getAttribute('title'),
        timer: setTimeout(function () { disarm(btn); }, 5000),
      });
      btn.setAttribute('data-armed', '1');
      btn.setAttribute('aria-label', btn.getAttribute('data-confirm') + ': ' + (btn.getAttribute('aria-label') || btn.textContent.trim()));
      if (note) btn.setAttribute('title', note);
      btn.addEventListener('blur', onBlur);
      btn.addEventListener('keydown', onKey);
      return false;
    }
    nday.confirmable = confirmable;
    nday.confirmStep = confirmStep;
    nday.disarm = disarm;
  })();

  // Clicking a row (not a link inside it) moves the cursor there (rows may
  // be reordered later: the hot list's pinned group, or replaced: another
  // page of the list). One listener for all rows, on their container: a row
  // moved or added later is still handled.
  (d.querySelector('main') || d).addEventListener('click', function (e) {
    var t = e.target;
    if (!rows.length || !t || !t.closest) return;
    var r = t.closest('[data-row]');
    if (!r || t.closest('a, button, summary, pre')) return;
    var i = rows.indexOf(r);
    if (i >= 0) select(i, false);
  });

  // rowsIn(root): the list's rows changed inside root (a region replaced by
  // another page's). The cursor stays on its row if that row is still on
  // the page; if it was on a row that went (or the page starts with one),
  // it moves to the first new row.
  function rowsIn(root) {
    var was = cur >= 0 ? rows[cur] : null;
    rows = Array.prototype.slice.call(d.querySelectorAll('[data-row]'));
    cur = was ? rows.indexOf(was) : -1;
    if (cur >= 0) {
      if (pos && body.hasAttribute('data-pos')) pos.textContent = (cur + 1) + '/' + rows.length;
      return;
    }
    var first = root.querySelector('[data-row]');
    if (first && (was || body.hasAttribute('data-autosel'))) select(rows.indexOf(first), false);
    else if (pos && body.hasAttribute('data-pos')) pos.textContent = '0/' + rows.length;
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
  // heroField(el) draws in one backdrop; it stops for good once el has
  // left the page (the area turned compact: "paging" below). On the /vuln
  // landing (body.landing) the stylesheet fixes the backdrop to the whole
  // viewport; there the columns are centred in its width, so no column is
  // cut off at either edge, and a resize or rotation lays them out again
  // (the ResizeObserver below, as everywhere).
  function heroField(el) {
    if (!el || !window.HTMLCanvasElement) return;
    var cv = d.createElement('canvas');
    var ctx = cv.getContext && cv.getContext('2d');
    if (!ctx) return;
    el.appendChild(cv);
    var glyphs = '01{}[]()<>/\\#$%&*+=-_:;|?@!0123456789ABCDEF';
    var CW = 16, CH = 18, TICK = 70;
    var full = body.classList.contains('landing');
    var cols = [], w = 0, h = 0, x0 = 3, head = '#fff', tail = '#0f0', timer = 0, onScreen = true;
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
      if (full) { n = Math.max(1, Math.floor(w / CW)); x0 = Math.floor((w - n * CW) / 2) + 4; }
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
          ctx.fillText(c.chars[k], i * CW + x0, row * CH + 2);
        }
      }
      ctx.globalAlpha = 1;
    }
    function running() { return onScreen && !d.hidden && !reduce && el.isConnected; }
    function sync() {
      if (running() && !timer) timer = window.setInterval(function () { if (el.isConnected) frame(true); else sync(); }, TICK);
      else if (!running() && timer) { window.clearInterval(timer); timer = 0; }
    }
    function reset() { if (!el.isConnected) return; colours(); if (layout()) frame(false); sync(); }
    reset();
    if (window.ResizeObserver) new window.ResizeObserver(reset).observe(el);
    else window.addEventListener('resize', reset);
    if (window.IntersectionObserver) {
      new window.IntersectionObserver(function (es) { onScreen = es[es.length - 1].isIntersecting; sync(); }).observe(el);
    }
    d.addEventListener('visibilitychange', sync);
    d.addEventListener('nday:theme', function () { if (el.isConnected) { colours(); frame(false); } });
  }
  heroField(d.querySelector('.cbg'));

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

  // Share menu next to the id on a vulnerability page (vuln.tmpl
  // details.share): a <details> like the language and theme menus. "post
  // on X" is a plain link (new tab), "copy text" a copy button (above).
  // Escape closes it and returns focus to its summary; so does following
  // the link or copying, and a click outside or focus leaving closes it.
  (function shareMenu() {
    var menu = d.querySelector('details.share');
    if (!menu) return;
    var close = escMenu(menu);
    var a = menu.querySelector('a');
    if (a) a.addEventListener('click', function () { close(false); });
    var b = menu.querySelector('button[data-copy]');
    if (b) b.addEventListener('click', function () { setTimeout(function () { close(d.activeElement === b); }, 1200); });
    menu.addEventListener('focusout', function (e) {
      if (e.relatedTarget && !menu.contains(e.relatedTarget)) close(false);
    });
    d.addEventListener('click', function (e) {
      if (menu.open && !menu.contains(e.target)) close(false);
    });
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

    // Signed in, the slot becomes a menu: a <details> like the language and
    // theme menus, built here once. Its items are the account page's
    // sections, the back office for staff (moderator or admin, not
    // suspended; the server decides access on its own) and signing out.
    var menu = null, sum = null, admItem = null, csrf = '';
    function menuItems() { return Array.prototype.slice.call(menu.querySelectorAll('[role="menuitem"]')).filter(function (el) { return !el.parentNode.hidden; }); }
    function closeMenu(back) {
      if (!menu || !menu.open) return;
      menu.open = false;
      if (back) sum.focus();
    }
    function openMenu() {
      menu.open = true;
      var it = menuItems();
      if (it.length) it[0].focus();
    }
    function li(ul, el) {
      var l = d.createElement('li');
      l.setAttribute('role', el ? 'none' : 'separator');
      if (el) {
        el.setAttribute('role', 'menuitem');
        el.tabIndex = -1;
        l.appendChild(el);
      }
      ul.appendChild(l);
      return l;
    }
    function link(ul, key, path) {
      var a = d.createElement('a');
      a.href = path;
      put(a, key);
      a.addEventListener('click', function () { closeMenu(false); });
      return li(ul, a);
    }
    function buildMenu() {
      menu = d.createElement('details');
      menu.className = 'acctm';
      sum = d.createElement('summary');
      sum.className = 'acct';
      sum.id = 'acct-m';
      sum.setAttribute('aria-haspopup', 'menu');
      sum.setAttribute('aria-expanded', 'false');
      var ul = d.createElement('ul');
      ul.setAttribute('role', 'menu');
      ul.setAttribute('aria-labelledby', 'acct-m');
      link(ul, 'acct.profile.h2', accountPath + '#profile');
      link(ul, 'acct.follows.h2', accountPath + '#follows');
      link(ul, 'acct.security.h2', accountPath + '#security');
      link(ul, 'acct.developer.h2', accountPath + '#developer');
      if (adminPath) {
        admItem = link(ul, 'admin.slot', adminPath);
        var here = window.location.pathname;
        if (here === adminPath || here.indexOf(adminPath + '/') === 0) admItem.firstChild.setAttribute('aria-current', 'page');
      }
      li(ul);
      var out = d.createElement('button');
      out.type = 'button';
      put(out, 'acct.menu.signout');
      out.addEventListener('click', function () { closeMenu(true); signOut(out); });
      li(ul, out);
      menu.appendChild(sum);
      menu.appendChild(ul);
      slot.parentNode.insertBefore(menu, slot.nextSibling);
      menu.addEventListener('toggle', function () { sum.setAttribute('aria-expanded', menu.open ? 'true' : 'false'); });
      // Enter or Space (a click without a pointer) and ArrowDown open it
      // on the first item; a pointer click only opens it
      sum.addEventListener('click', function (e) {
        if (e.detail === 0 && !menu.open) { e.preventDefault(); openMenu(); }
      });
      sum.addEventListener('keydown', function (e) {
        if (e.key === 'ArrowDown') { e.preventDefault(); openMenu(); }
      });
      ul.addEventListener('keydown', function (e) {
        var it = menuItems();
        var i = it.indexOf(d.activeElement);
        var to = -1;
        if (e.key === 'ArrowDown') to = (i + 1) % it.length;
        else if (e.key === 'ArrowUp') to = (i <= 0 ? it.length : i) - 1;
        else if (e.key === 'Home') to = 0;
        else if (e.key === 'End') to = it.length - 1;
        if (to < 0 || !it.length) return;
        e.preventDefault();
        it[to].focus();
      });
      menu.addEventListener('keydown', function (e) {
        if (e.key === 'Escape' && menu.open) { e.preventDefault(); closeMenu(true); }
      });
      // focus moving elsewhere (Tab) or a click outside closes it
      menu.addEventListener('focusout', function (e) {
        if (e.relatedTarget && !menu.contains(e.relatedTarget)) closeMenu(false);
      });
      d.addEventListener('click', function (e) {
        if (menu.open && !menu.contains(e.target)) closeMenu(false);
      });
    }
    // Signing out, as the account page does it (a same-origin POST with the
    // CSRF header), then the page loads again in the signed-out state.
    function signOut(btn) {
      if (!csrf || btn.getAttribute('aria-busy') === 'true') return;
      btn.setAttribute('aria-busy', 'true');
      var path = '/auth/signout';
      window.fetch(path, {
        method: 'POST', credentials: 'same-origin', cache: 'no-store', redirect: 'error',
        headers: { Accept: 'application/json', 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
      }).then(function (r) {
        if (r.ok) window.location.reload();
        else nday.fetchMe();
      }, function () { nday.fetchMe(); }).then(function () { btn.removeAttribute('aria-busy'); });
    }
    function showMenu(u) {
      if (!menu) buildMenu();
      clear(sum);
      var name = u.handle ? '@' + u.handle : (u.display_name || '');
      var n = d.createElement('bdi');
      n.className = 'an';
      if (name) n.textContent = name; else put(n, 'acct.slot.account');
      sum.appendChild(n);
      if (u.role === 'moderator' || u.role === 'admin') {
        var b = d.createElement('span');
        b.className = 'rb';
        put(b, 'acct.role.badge#' + u.role);
        sum.appendChild(b);
      }
      if (window.location.pathname === accountPath) sum.setAttribute('aria-current', 'page');
      else sum.removeAttribute('aria-current');
      if (admItem) admItem.hidden = (u.role !== 'moderator' && u.role !== 'admin') || u.status === 'suspended';
      menu.hidden = false;
      slot.hidden = true;
    }
    function hideMenu() {
      csrf = '';
      if (!menu) return;
      closeMenu(false);
      menu.hidden = true;
    }

    function signedOut() {
      hideMenu();
      clear(slot);
      put(slot, 'acct.slot.signin');
      slot.removeAttribute('aria-current');
      if (window.location.pathname !== loginPath) {
        slot.href = loginPath + '?return=' + encodeURIComponent(window.location.pathname + window.location.search);
      }
    }

    function signedIn(me) {
      csrf = me.csrf_token || '';
      showMenu(me.user);
    }

    // Parts of a page for signed-in readers only (data-signed-in, hidden in
    // the HTML: links to /raw/..., which needs a session) show while signed in.
    function forSignedIn(yes) {
      Array.prototype.forEach.call(d.querySelectorAll('[data-signed-in]'), function (el) { el.hidden = !yes; });
    }

    // render(me): me is the /api/me object, {disabled: true} for a 404
    // (accounts off) or null when the state is unknown.
    var known = false, last = null;
    nday.render = function (me) {
      known = true;
      last = me;
      if (me && me.disabled) { hideMenu(); slot.hidden = true; forSignedIn(false); return; }
      slot.hidden = false;
      var inn = !!(me && me.signed_in && me.user);
      if (inn) signedIn(me); else signedOut();
      forSignedIn(inn);
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
    // the address changed without a page load ("paging" below): the
    // sign-in link's return path and the signed-in-only parts of a new
    // region follow the state already known (no new request)
    nday.rerender = function () { if (known) nday.render(last); };
  })();

  // Hot list, signed in with at least one follow (docs/follows.md): rows of
  // vulnerabilities affecting a followed vendor or product move into a pinned
  // group at the top of the table, in their order, under a header like the
  // date headers (words from the table's data-pin). A date header left
  // without rows goes. Only the rows of this page are looked at. Nothing
  // moves for anyone else, and any failure leaves the list as it is.
  // pinFollows(root): the list inside root (the page, or a new region).
  function pinFollows(root) {
    var tbl = root.querySelector('.tbl-in[data-pin]');
    var mine = tbl ? Array.prototype.slice.call(tbl.querySelectorAll('[data-row]')) : [];
    if (!tbl || !nday.me || !mine.length || !window.JSON) return;
    nday.me.then(function (me) {
      var u = me && me.signed_in && me.user;
      if (!u || !u.follows || !u.follows.length || !me.csrf_token) return null;
      var ids = [];
      mine.forEach(function (r) {
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
      if (j && j.matches && j.matches.length && tbl.isConnected) regroup(j.matches);
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
  }
  pinFollows(d);

  // Paging in place (docs/pagination.md). Every paged list sits with its
  // pager in a region: an element with an id and data-page-region="<id>". A
  // plain click on a page link of a region (a link of its pager, or a link
  // to "#<id>": a filter of that list alone) loads that page in the
  // background and replaces only that region with the same region of the
  // loaded page; the address follows (history.pushState, the link's own URL)
  // and back / forward swap the regions back the same way. The rest of the
  // page keeps its state; what outside the regions depends on a list's
  // position is taken from the loaded page (outside()). Anything unexpected
  // (a network error, a status other than 200, a redirect, not HTML, the
  // region missing) loads the page normally instead. Without this script the
  // links are plain links.
  (function paging() {
    var main = d.querySelector('main');
    if (!main || !main.querySelector('[data-page-region]') || !window.fetch || !window.DOMParser || !window.URL ||
      !window.history || !window.history.pushState || !window.Promise) return;
    var KEY = 'ndayPages';
    var SKIP = '.acctm, .langhint, .authbanner'; // parts this script builds: not in a loaded page
    var here = window.location.pathname + window.location.search; // the page the regions show
    var shown = {}; // region id -> the page (path and query) its content came from
    var docs = {}, kept = []; // loaded pages by path and query, for back / forward
    var job = null; // the navigation in flight: { ctl, els }
    var seq = 0;
    function regionIds() {
      return Array.prototype.map.call(main.querySelectorAll('[data-page-region]'), function (r) { return r.id; });
    }
    regionIds().forEach(function (id) { shown[id] = here; });
    function keys() {
      var o = {};
      for (var k in shown) if (Object.prototype.hasOwnProperty.call(shown, k)) o[k] = shown[k];
      return o;
    }
    // this history entry records which page each region shows
    function record() {
      var s = {}, old = window.history.state;
      if (old && typeof old === 'object') for (var k in old) if (Object.prototype.hasOwnProperty.call(old, k)) s[k] = old[k];
      s[KEY] = keys();
      window.history.replaceState(s, '');
    }
    try { record(); } catch (e) { return; }

    // pathOf(a): the path of a same-origin link ('' for any other link)
    function pathOf(a) {
      try {
        var u = new window.URL(a.getAttribute('href'), window.location.href);
        return u.origin === window.location.origin ? u.pathname : '';
      } catch (e) { return ''; }
    }
    function regionOf(el) {
      var r = el.closest('[data-page-region]');
      return r && r.id && r.getAttribute('data-page-region') === r.id ? r : null;
    }

    function keep(path, doc) {
      if (!docs[path]) kept.push(path);
      docs[path] = doc;
      while (kept.length > 10) delete docs[kept.shift()];
    }
    function fetchDoc(path, ctl) {
      return window.fetch(path, { credentials: 'same-origin', headers: { Accept: 'text/html' }, signal: ctl ? ctl.signal : undefined })
        .then(function (r) {
          var type = (r.headers.get('Content-Type') || '').split(';')[0].trim().toLowerCase();
          if (r.status !== 200 || r.redirected || type !== 'text/html') throw new Error(String(r.status));
          return r.text();
        })
        .then(function (text) {
          var doc = new window.DOMParser().parseFromString(text, 'text/html');
          keep(path, doc);
          return doc;
        });
    }

    function stop() {
      if (!job) return;
      if (job.ctl) job.ctl.abort();
      job.els.forEach(function (x) { x.removeAttribute('aria-busy'); });
      job = null;
    }

    // go: show page path (address url; null: back / forward, the address is
    // already there) with the regions ids replaced by the loaded page's.
    function go(path, url, ids) {
      stop();
      var my = ++seq;
      var ctl = window.AbortController ? new window.AbortController() : null;
      var els = ids.map(function (id) { return d.getElementById(id); }).filter(Boolean);
      els.forEach(function (x) { x.setAttribute('aria-busy', 'true'); });
      job = { ctl: ctl, els: els };
      var pushed = false; // after this, a failure reloads the address already shown
      var got = url === null && docs[path] ? Promise.resolve(docs[path]) : fetchDoc(path, ctl);
      got.then(function (doc) {
        if (my !== seq) return;
        stop();
        ids.forEach(function (id) {
          var n = doc.getElementById(id);
          if (!n || n.getAttribute('data-page-region') !== id || !d.getElementById(id)) throw new Error(id);
        });
        if (url !== null) {
          var s = {};
          s[KEY] = keys();
          ids.forEach(function (id) { s[KEY][id] = path; });
          window.history.pushState(s, '', url);
          pushed = true;
        }
        var lost = !d.activeElement || d.activeElement === body;
        var fresh = ids.map(function (id) {
          var old = d.getElementById(id);
          if (old.contains(d.activeElement)) lost = true;
          var nw = d.importNode(doc.getElementById(id), true);
          old.parentNode.replaceChild(nw, old);
          shown[id] = path;
          init(nw);
          return nw;
        });
        here = path;
        outside(doc, ids);
        if (url === null) record();
        if (nday.rerender) nday.rerender();
        var el = fresh[0];
        if (!el) return;
        if (url !== null || lost) {
          el.setAttribute('tabindex', '-1');
          el.focus({ preventScroll: true });
        }
        if (url !== null && el.getBoundingClientRect().top < 0) el.scrollIntoView({ block: 'start', behavior: reduce ? 'auto' : 'smooth' });
        announce(el);
      }).then(null, function () {
        if (my !== seq) return; // a newer navigation took over (and aborted this one)
        stop();
        if (url !== null && !pushed) window.location.assign(url);
        else window.location.reload();
      });
    }

    // init(el): what the page's script set up at load, for a new region
    function init(el) {
      localTimes(el);
      copyButtons(el);
      rowsIn(el);
      pinFollows(el);
      if (nday.adminInit) nday.adminInit(el);
    }

    // the new position, in the status bar's live region (the pager's words)
    function announce(el) {
      var p = el.querySelector('.pager .pg-pos');
      if (!p) return;
      var parts = Array.prototype.map.call(p.children, function (s) { return s.textContent; }).filter(Boolean);
      if (parts.length) say(parts.join(', '));
    }

    // pageLinks(root, ids), hiddenFields(root, ids): the links to this same page (other positions,
    // filters) and the hidden fields of its forms, outside the regions ids
    // and the parts this script builds, in document order.
    function outsideOf(x, ids) {
      if (x.closest(SKIP)) return false;
      var r = x.closest('[data-page-region]');
      return !r || ids.indexOf(r.id) < 0;
    }
    function pageLinks(root, ids) {
      var p = window.location.pathname;
      return Array.prototype.filter.call(root.querySelectorAll('a[href]'), function (a) { return outsideOf(a, ids) && pathOf(a) === p; });
    }
    function hiddenFields(root, ids) {
      return Array.prototype.filter.call(root.querySelectorAll('input[type="hidden"]'), function (i) { return i.closest('form') && outsideOf(i, ids); });
    }
    // relink: copy the loaded page's links and hidden fields onto this page's,
    // pair by pair; false when the two pages do not have the same ones.
    function relink(doc, ids) {
      var a = pageLinks(d, ids), b = pageLinks(doc, ids);
      var f = hiddenFields(d, ids), g = hiddenFields(doc, ids);
      if (a.length !== b.length || f.length !== g.length) return false;
      for (var i = 0; i < f.length; i++) if (f[i].name !== g[i].name) return false;
      a.forEach(function (x, i) {
        var h = b[i].getAttribute('href');
        if (x.getAttribute('href') !== h) x.setAttribute('href', h);
      });
      f.forEach(function (x, i) { x.value = g[i].value; x.setAttribute('value', g[i].value); });
      return true;
    }

    // outside(doc, ids): the rest of the page after the regions ids came
    // from doc. The other regions keep their rows and selections; their
    // links that carry the swapped list's position (pagers, filters) and the
    // page's other such links and hidden fields are taken from doc. If doc
    // differs there (its lists changed meanwhile), the other regions are
    // replaced as well. Then the title, the head's links, the language
    // links and the catalogue's search area (compact after page 1).
    function outside(doc, ids) {
      if (!relink(doc, ids)) {
        var all = regionIds().filter(function (id) { return doc.getElementById(id); });
        all.forEach(function (id) {
          if (ids.indexOf(id) >= 0) return;
          var nw = d.importNode(doc.getElementById(id), true);
          var old = d.getElementById(id);
          old.parentNode.replaceChild(nw, old);
          shown[id] = here;
          init(nw);
        });
        relink(doc, all);
      }
      if (doc.title) d.title = doc.title;
      ['meta[name="robots"]', 'link[rel="canonical"]', 'meta[property="og:url"]'].forEach(function (sel) {
        var x = d.head.querySelector(sel), y = doc.head ? doc.head.querySelector(sel) : null;
        if (x && y) x.parentNode.replaceChild(d.importNode(y, true), x);
        else if (x) x.parentNode.removeChild(x);
        else if (y) d.head.appendChild(d.importNode(y, true));
      });
      var langs = {}, alts = {};
      Array.prototype.forEach.call(doc.querySelectorAll('.langs a[hreflang]'), function (a) { langs[a.getAttribute('hreflang')] = a.getAttribute('href'); });
      Array.prototype.forEach.call(doc.querySelectorAll('link[rel="alternate"][hreflang]'), function (l) { alts[l.getAttribute('hreflang')] = l.getAttribute('href'); });
      Array.prototype.forEach.call(d.querySelectorAll('a[hreflang], link[rel="alternate"][hreflang]'), function (x) {
        var h = (x.tagName === 'A' ? langs : alts)[x.getAttribute('hreflang')];
        if (h && x.getAttribute('href') !== h) x.setAttribute('href', h);
      });
      var ch = d.querySelector('.chero'), nh = doc.querySelector('.chero');
      if (ch && nh) {
        ch.className = nh.className;
        var bg = ch.querySelector('.cbg'), nb = nh.querySelector('.cbg');
        if (bg && !nb) bg.parentNode.removeChild(bg);
        else if (nb && !bg) {
          bg = d.importNode(nb, true);
          ch.insertBefore(bg, ch.firstChild);
          heroField(bg);
        }
      }
    }

    d.addEventListener('click', function (e) {
      if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
      var a = e.target && e.target.closest ? e.target.closest('a[href]') : null;
      var el = a && regionOf(a);
      if (!el || a.hasAttribute('download') || (a.getAttribute('target') && a.getAttribute('target') !== '_self')) return;
      if (!a.closest('.pager') && a.hash !== '#' + el.id) return;
      if (pathOf(a) !== window.location.pathname) return;
      var path = a.pathname + a.search;
      if (path === here) return;
      e.preventDefault();
      if (el.getAttribute('aria-busy') === 'true') return;
      go(path, path + a.hash, [el.id]);
    });

    window.addEventListener('popstate', function (e) {
      var path = window.location.pathname + window.location.search;
      if (path === here) return; // only the fragment moved
      var k = e.state && e.state[KEY];
      go(path, null, regionIds().filter(function (id) { return !k || k[id] !== shown[id]; }));
    });
  })();

  function currentId() {
    if (cur >= 0 && rows[cur].getAttribute('data-id')) return rows[cur].getAttribute('data-id');
    return body.getAttribute('data-id') || '';
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

  // Row details (parts.tmpl "rowclose"; app.css "row pattern"): the back
  // office lists, the account page and the discussion. A button data-rowx
  // with aria-expanded and aria-controls opens the detail it names (an
  // .adm-detail or .row-detail, hidden until then) right under its row; one
  // is open per list (the nearest [data-rows], paging region, table,
  // .adm-list or section). Escape inside a detail, or its data-rowx-close
  // button, closes it and gives the focus back to its button. Registered
  // before the keyboard shortcuts, so Escape closes the detail first.
  var ROWBOX = '.adm-detail, .row-detail';
  function rowList(el) {
    return el.closest('[data-rows], [data-page-region], table, .adm-list, section') || el.closest('main') || body;
  }
  function rowClose(btn, focus) {
    var box = d.getElementById(btn.getAttribute('aria-controls') || '');
    if (box) box.hidden = true;
    btn.setAttribute('aria-expanded', 'false');
    if (focus) btn.focus();
  }
  function rowToggle(btn) {
    var box = d.getElementById(btn.getAttribute('aria-controls') || '');
    if (!box) return;
    var open = btn.getAttribute('aria-expanded') !== 'true';
    rowList(btn).querySelectorAll('[data-rowx][aria-expanded="true"]').forEach(function (o) {
      if (o !== btn) rowClose(o, false);
    });
    box.hidden = !open;
    btn.setAttribute('aria-expanded', open ? 'true' : 'false');
    if (open) {
      var first = box.querySelector('input:not([type=hidden]), textarea, select, button');
      if (first) first.focus();
    }
  }
  function rowTrigger(box) {
    return box && box.id ? rowList(box).querySelector('[data-rowx][aria-controls="' + box.id + '"]') : null;
  }
  d.addEventListener('click', function (e) {
    var b = e.target instanceof Element ? e.target.closest('button') : null;
    if (!b) return;
    if (b.hasAttribute('data-rowx')) {
      rowToggle(b);
    } else if (b.hasAttribute('data-rowx-close')) {
      var o = rowTrigger(b.closest(ROWBOX));
      if (o) rowClose(o, true);
    }
  });
  d.addEventListener('keydown', function (e) {
    if (e.key !== 'Escape' || !(e.target instanceof Element)) return;
    var o = rowTrigger(e.target.closest(ROWBOX));
    if (o) {
      e.preventDefault();
      rowClose(o, true);
    }
  });
  nday.rowClose = rowClose;

  // The re-verification dialog (parts.tmpl "reauthpanel": the account page
  // and the admin pages that act), for actions that need a recent sign-in.
  // UI only: the page script keeps its CSRF token and makes the requests in
  // its callbacks:
  //   o.provider(p)  get a reauth ticket and leave for the provider (promise)
  //   o.passkey()    sign in with a passkey, reload the page's state (promise)
  //   o.say(el, key, vars, kind), o.fail(el, e)  the page's status words
  //   o.done(from)   after a passkey sign-in with nothing to continue
  //   o.webauthn     passkeys work in this browser
  // open(me, from, retry): from is the control that needed it (focus goes
  // back there on close); retry, if given, runs once after a passkey sign-in.
  nday.reauthDialog = function (o) {
    var dlg = d.getElementById('reauth');
    if (!dlg) return null;
    var st = dlg.querySelector('.acct-st');
    var none = d.getElementById('reauth-none');
    var cancel = d.getElementById('reauth-close');
    var methods = Array.prototype.slice.call(dlg.querySelectorAll('[data-reauth]'));
    var native = typeof dlg.showModal === 'function';
    var from = null;
    var retry = null;
    var busy = false;
    function shown() { return dlg.hasAttribute('open'); }
    function closed() {
      var back = from;
      from = null;
      retry = null;
      if (back && back.isConnected && back.focus) back.focus();
    }
    function close() {
      if (!shown()) return;
      if (native) dlg.close(); else dlg.removeAttribute('open');
      closed();
    }
    function open(me, f, r) {
      var u = me && me.user;
      if (!u) return;
      var linked = (u.identities || []).map(function (i) { return i.provider; });
      var enabled = me.providers || [];
      var first = null;
      methods.forEach(function (b) {
        var p = b.getAttribute('data-reauth');
        var ok = p === 'passkey'
          ? !!(o.webauthn && me.passkeys && me.passkeys.enabled && (u.passkeys || []).length > 0)
          : linked.indexOf(p) >= 0 && enabled.indexOf(p) >= 0;
        b.parentNode.hidden = !ok;
        if (ok && !first) first = b;
      });
      none.hidden = !!first;
      if (!busy) o.say(st, '');
      from = f || null;
      retry = r || null;
      if (!shown()) {
        try {
          if (native) dlg.showModal(); else dlg.setAttribute('open', '');
        } catch (e) {
          dlg.setAttribute('open', '');
        }
      }
      (first || cancel).focus();
    }
    function act(b) {
      if (busy) return;
      var p = b.getAttribute('data-reauth');
      var f = from;
      var r = retry;
      var job;
      busy = true;
      methods.forEach(function (m) { m.disabled = true; });
      b.setAttribute('aria-busy', 'true');
      o.say(st, 'acct.busy');
      try {
        job = Promise.resolve(p === 'passkey' ? o.passkey() : o.provider(p));
      } catch (e) {
        job = Promise.reject(e);
      }
      job.then(function () {
        if (p !== 'passkey') return; // on the way to the provider
        o.say(st, '');
        var still = shown() && from === f; // not cancelled (or reopened for another control) meanwhile
        if (still) close();
        if (still && r) r(); else o.done(f);
      }, function (e) {
        o.fail(st, e);
      }).then(function () {
        busy = false;
        b.removeAttribute('aria-busy');
        methods.forEach(function (m) { m.disabled = false; });
      });
    }
    methods.forEach(function (b) { b.addEventListener('click', function () { act(b); }); });
    cancel.addEventListener('click', close);
    // Esc (native: the cancel event closes it, then this) or any other close
    dlg.addEventListener('close', function () { if (from) closed(); });
    if (!native) {
      dlg.addEventListener('keydown', function (e) {
        if (e.key !== 'Escape') return;
        close();
        e.preventDefault();
      });
    }
    return { open: open, close: close };
  };

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

// Dots of the lifecycle chart (vulnerability pages; internal/webui
// chartdots.go). Each dot is <a class="dot" data-pop="<id>"> (without this
// script a link to the section that lists its items); here it becomes a
// button that shows its popover (the hidden element <id> after the chart)
// on hover, keyboard focus and tap. The popover stays open while the
// pointer moves from the dot onto it, closes on Escape, when focus leaves
// both and on a tap elsewhere, and is placed in the viewport (position:
// fixed: neither the chart's scroller nor the viewport edges cut it; below
// the dot, above when there is no room). Enter on a dot moves focus into
// its popover; Tab from the popover's last link goes on to the next dot.
(function () {
  'use strict';
  var d = document;
  var dots = Array.prototype.slice.call(d.querySelectorAll('a.dot[data-pop]'));
  if (!dots.length) return;
  var cur = null, timer = 0, touch = false;
  function popOf(a) { return d.getElementById(a.getAttribute('data-pop')); }
  function links(p) { return Array.prototype.slice.call(p.querySelectorAll('a[href]')); }
  function place(a, p) {
    var r = a.getBoundingClientRect(), w = p.offsetWidth, h = p.offsetHeight;
    var vw = d.documentElement.clientWidth, vh = d.documentElement.clientHeight;
    var cx = r.left + r.width / 2, foot = r.bottom; // the drawn dot sits at the foot of its box
    var left = Math.max(8, Math.min(cx - w / 2, vw - w - 8));
    var top = foot + 4;
    if (top + h > vh - 8 && foot - r.height - h - 4 >= 8) top = foot - r.height - h - 4;
    if (top + h > vh - 8) top = Math.max(8, vh - h - 8);
    p.style.left = Math.round(left) + 'px';
    p.style.top = Math.round(top) + 'px';
  }
  function hide() {
    window.clearTimeout(timer);
    if (!cur) return;
    popOf(cur).hidden = true;
    cur.setAttribute('aria-expanded', 'false');
    cur.removeAttribute('data-shown');
    cur = null;
  }
  function show(a) {
    window.clearTimeout(timer);
    if (cur === a) return;
    hide();
    var p = popOf(a);
    p.hidden = false;
    a.setAttribute('aria-expanded', 'true');
    cur = a;
    place(a, p);
  }
  function later() {
    window.clearTimeout(timer);
    timer = window.setTimeout(function () {
      var f = d.activeElement;
      if (cur && !(f && (cur === f || popOf(cur).contains(f)))) hide();
    }, 250);
  }
  function inside(t) { return cur && t && (cur.contains(t) || popOf(cur).contains(t)); }
  dots.forEach(function (a, i) {
    var p = popOf(a);
    if (!p) return;
    a.setAttribute('role', 'button');
    a.setAttribute('aria-expanded', 'false');
    a.setAttribute('aria-controls', p.id);
    a.addEventListener('pointerdown', function (e) { touch = e.pointerType !== 'mouse'; });
    a.addEventListener('mouseenter', function () { if (!touch) show(a); });
    a.addEventListener('mouseleave', later);
    a.addEventListener('focus', function () {
      if (a.hasAttribute('data-esc')) { a.removeAttribute('data-esc'); return; } // back from Escape: stay closed
      show(a);
    });
    a.addEventListener('click', function (e) {
      e.preventDefault();
      if (e.detail === 0) { // keyboard: into the popover
        show(a);
        var ls = links(p);
        if (ls.length) ls[0].focus();
        return;
      }
      if (touch && cur === a && a.hasAttribute('data-shown')) { hide(); return; }
      show(a);
      a.setAttribute('data-shown', '1');
    });
    a.addEventListener('keydown', function (e) {
      if (e.key === ' ') { e.preventDefault(); a.click(); }
    });
    p.addEventListener('mouseenter', function () { window.clearTimeout(timer); });
    p.addEventListener('mouseleave', later);
    p.addEventListener('keydown', function (e) {
      if (e.key !== 'Tab') return;
      var ls = links(p);
      if (e.shiftKey && e.target === ls[0]) {
        e.preventDefault();
        a.focus();
      } else if (!e.shiftKey && e.target === ls[ls.length - 1] && dots[i + 1]) {
        e.preventDefault();
        dots[i + 1].focus();
      }
    });
  });
  d.addEventListener('focusout', function (e) {
    if (!cur || !inside(e.target)) return;
    window.setTimeout(function () { if (cur && !inside(d.activeElement)) hide(); }, 0);
  });
  d.addEventListener('keydown', function (e) {
    if (e.key !== 'Escape' || !cur) return;
    var back = cur, f = d.activeElement;
    var wasIn = inside(f);
    hide();
    if (wasIn && f !== back) {
      back.setAttribute('data-esc', '1');
      back.focus();
    }
  }, true);
  d.addEventListener('pointerdown', function (e) { if (cur && !inside(e.target)) hide(); }, true);
  function again() { if (cur) place(cur, popOf(cur)); }
  window.addEventListener('resize', again);
  window.addEventListener('scroll', again, true);
})();
