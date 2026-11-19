// nday: readers' corrections on a vulnerability page (loaded with
// discuss.js on vulnerability pages when accounts are enabled; see
// internal/webui/corrview.go and docs/corrections.md). The page holds the
// same HTML for everyone: the public revision log and a hidden form. This
// script shows the part that fits the visitor (/api/me), sends the form to
// POST /api/corrections/{cve} and lists the visitor's own corrections of
// this vulnerability with their status (GET /api/corrections/mine).
//
// Rules (checked by tests in internal/webui):
//   - nothing is parsed as HTML: texts reach the DOM through textContent;
//   - every request goes to a fixed path built from the page's CVE id,
//     with credentials: same-origin; a write is a JSON POST with the CSRF
//     token as the X-CSRF-Token header only;
//   - the only navigation is dropping ?correction from the address bar
//     (history.replaceState) after signing in from here.
(() => {
  'use strict';
  const d = document;
  const nday = window.nday;
  const sec = d.getElementById('correction');
  // the entry is a closed <details>: a link to #correction (or coming back
  // from signing in with ?correction) opens it
  const entry = d.getElementById('corr-d');
  function openEntry() {
    if (!entry) return;
    if (window.location.hash === '#correction' || new URLSearchParams(window.location.search).has('correction')) {
      entry.open = true;
    }
  }
  openEntry();
  window.addEventListener('hashchange', openEntry);
  if (!sec || !nday || !nday.me || !window.fetch) return;
  // the page's vulnerability id: a CVE id, or the GHSA id of an advisory without one
  const CVE = /^(CVE-\d{4}-\d{4,19}|GHSA(-[23456789cfghjmpqrvwx]{4}){3})$/;
  const cve = sec.dataset.cve || '';
  if (!CVE.test(cve)) return;
  const tpl = d.getElementById('acct-msgs');
  const $ = (id) => d.getElementById(id);
  const maxBody = Number(sec.dataset.max) || 4000;
  const maxURL = Number(sec.dataset.maxUrl) || 2048;
  let csrf = '';
  let busy = false;

  // ---- words
  const srcOf = (key) => (tpl ? tpl.content.querySelector('[data-k="' + key + '"]') : null);
  function msg(key, vars) {
    const el = srcOf(key);
    const s = el ? el.textContent : '';
    return s.replace(/\{([a-z_]+)\}/g, (all, n) => (vars && n in vars ? String(vars[n]) : all));
  }
  function put(el, key, vars) {
    el.textContent = msg(key, vars);
    const s = srcOf(key);
    if (s && s.getAttribute('lang')) el.setAttribute('lang', s.getAttribute('lang'));
    else el.removeAttribute('lang');
  }
  function say(el, key, vars, kind) {
    if (!el) return;
    el.classList.toggle('err', kind === 'err');
    el.classList.toggle('ok', kind === 'ok');
    // a live status line: errors are alerts, anything else stays a polite status
    if (el.hasAttribute('role')) {
      el.setAttribute('role', kind === 'err' && key ? 'alert' : 'status');
      el.setAttribute('aria-live', kind === 'err' && key ? 'assertive' : 'polite');
    }
    if (!key) {
      el.textContent = '';
      return;
    }
    put(el, key, vars);
  }

  // ---- errors -> messages
  const known = new Set(['not_signed_in', 'suspended', 'handle_required', 'terms_required', 'csrf', 'cross_site',
    'bad_category', 'invalid_body', 'bad_url', 'too_many_open', 'queue_full', 'daily_limit', 'rate_limited',
    'not_found', 'too_large', 'network']);
  function errKey(e) {
    if (e && known.has(e.code)) return 'corr.err.' + e.code;
    if (e && e.status === 401) return 'corr.err.not_signed_in';
    if (e && e.status === 429) return 'corr.err.rate_limited';
    return 'corr.err.generic';
  }

  // ---- HTTP
  async function call(method, path, body) {
    const headers = { Accept: 'application/json' };
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    if (csrf) headers['X-CSRF-Token'] = csrf;
    let r;
    try {
      r = await window.fetch(path, {
        method, credentials: 'same-origin', cache: 'no-store', redirect: 'error', headers,
        body: body === undefined ? undefined : JSON.stringify(body),
      });
    } catch (_) {
      throw { code: 'network' };
    }
    let j = null;
    try {
      j = await r.json();
    } catch (_) {
      j = null;
    }
    if (!r.ok) throw Object.assign({ status: r.status }, (j && j.error) || {});
    return j || {};
  }

  // ---- which part of the section the visitor sees
  const parts = ['corr-unknown', 'corr-out', 'corr-nohandle', 'corr-terms', 'corr-susp', 'corr-form'];
  function show(id) {
    parts.forEach((p) => {
      const el = $(p);
      if (el) el.hidden = p !== id;
    });
  }
  function suspended(u) {
    if (u.status !== 'suspended') return false;
    if (!u.suspended_until) return true;
    const t = Date.parse(u.suspended_until);
    return !Number.isFinite(t) || t > Date.now();
  }

  // ---- the visitor's own corrections of this vulnerability
  async function loadMine() {
    const box = $('corr-mine');
    const list = $('corr-mine-list');
    if (!box || !list) return;
    let j;
    try {
      j = await call('GET', '/api/corrections/mine?cve=' + encodeURIComponent(cve));
    } catch (_) {
      return; // the list is a convenience: the form works without it
    }
    while (list.firstChild) list.removeChild(list.firstChild);
    const rows = Array.isArray(j.corrections) ? j.corrections : [];
    rows.forEach((c) => {
      const li = d.createElement('li');
      li.className = 'corr-item';
      const h = d.createElement('p');
      h.className = 'corr-h';
      const at = d.createElement('span');
      put(at, 'corr.mine.at', { at: String(c.created_at || '').slice(0, 10) });
      const cat = d.createElement('span');
      cat.className = 'tag';
      put(cat, 'corr.category#' + String(c.category || 'other'));
      const st = d.createElement('span');
      st.className = 'corr-st corr-st-' + (/^[a-z]+$/.test(c.status) ? c.status : 'pending');
      put(st, 'corr.status#' + String(c.status || 'pending'));
      h.append(at, cat, st);
      const body = d.createElement('p');
      body.className = 'corr-note';
      body.setAttribute('dir', 'auto');
      body.textContent = String(c.body || '');
      li.append(h, body);
      if (c.public_note) {
        const n = d.createElement('p');
        n.className = 'corr-note';
        n.setAttribute('dir', 'auto');
        put(n, 'corr.mine.note', { note: String(c.public_note) });
        li.appendChild(n);
      }
      list.appendChild(li);
    });
    box.hidden = rows.length === 0;
  }

  // ---- the form
  const form = $('corr-form');
  if (form) {
    form.addEventListener('submit', async (ev) => {
      ev.preventDefault();
      if (busy) return;
      const st = form.querySelector('.acct-st');
      const btn = form.querySelector('button[type=submit]');
      const category = $('corr-cat').value;
      const body = $('corr-body').value.trim();
      const link = $('corr-url').value.trim();
      if (!body) {
        say(st, 'corr.err.empty', null, 'err');
        return;
      }
      if (Array.from(body).length > maxBody) {
        say(st, 'corr.err.too_long', { max: maxBody }, 'err');
        return;
      }
      if (link.length > maxURL || (link && !/^https?:\/\/[^\s]+$/i.test(link))) {
        say(st, 'corr.err.bad_url', null, 'err');
        return;
      }
      busy = true;
      btn.disabled = true;
      say(st, 'corr.busy');
      const req = { category, body };
      if (link) req.evidence_url = link;
      try {
        await call('POST', '/api/corrections/' + cve, req);
        $('corr-body').value = '';
        $('corr-url').value = '';
        say(st, 'corr.done', null, 'ok');
        loadMine();
      } catch (e) {
        say(st, errKey(e), null, 'err');
        if (e && e.code === 'csrf') {
          const me = await nday.fetchMe();
          csrf = (me && me.signed_in && me.csrf_token) || '';
        }
      } finally {
        busy = false;
        btn.disabled = false;
      }
    });
  }

  // ---- start
  nday.me.then((me) => {
    if (!me) {
      show('corr-unknown');
      return;
    }
    if (me.disabled) {
      show('');
      return;
    }
    if (!me.signed_in || !me.user) {
      show('corr-out');
      return;
    }
    csrf = me.csrf_token || '';
    const u = me.user;
    if (suspended(u)) show('corr-susp');
    else if (!u.handle) show('corr-nohandle');
    else if (u.terms && u.terms.current_version && !u.terms.up_to_date) show('corr-terms');
    else show('corr-form');
    loadMine();
    // back from signing in through this section: drop ?correction, show it
    const q = new URLSearchParams(window.location.search);
    if (q.has('correction')) {
      q.delete('correction');
      const qs = q.toString();
      try {
        window.history.replaceState(null, '', window.location.pathname + (qs ? '?' + qs : '') + '#correction');
      } catch (_) {
        // keep the address as it is
      }
      sec.scrollIntoView({ block: 'start' });
    }
  });
})();
