// nday: the sign-in page, the account page and the first-sign-in page
// (loaded only there).
// Progressive enhancement over the server-rendered page (see
// internal/webui/account.go and docs/auth.md section 3, the contract).
//
// Rules (checked by tests in internal/webui):
//   - data from the API (handles, names, passkey names, provider handles) only
//     reaches the DOM through textContent and properties;
//   - navigation goes only to a start_url from the server that begins with
//     /auth/, or to a same-origin page path the server rendered into the page
//     (data-welcome of /login, data-dest of /welcome; both validated there
//     like sign-in return paths);
//   - the CSRF token lives in this closure only;
//   - every state-changing call is a same-origin POST with
//     credentials: same-origin, Content-Type: application/json, X-CSRF-Token.
(() => {
  'use strict';
  const d = document;
  const main = d.querySelector('main[data-page]');
  const nday = window.nday;
  if (!main || !nday || !nday.me) return;
  const page = main.dataset.page;
  const tpl = d.getElementById('acct-msgs');
  const slot = d.getElementById('acct');
  const accountPath = slot.dataset.account;
  let csrf = '';
  let me = null;
  let view = null; // the page's render function (refresh() redraws with it)

  // ---- words (rendered by the server into <template id="acct-msgs">)
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
  // A time to the minute in the visitor's zone (app.js nday.localTime:
  // 2026-11-13T20:15+08:00; UTC 2026-11-13T12:15Z when the offset is zero).
  function when(iso) { return nday.localTime(iso, 'long'); }
  // stamp(el, iso): el shows the time; its tooltip keeps the UTC instant.
  function stamp(el, iso) {
    el.textContent = when(iso);
    const t = iso ? new Date(iso) : null;
    if (t && !isNaN(t)) el.title = t.toISOString().replace(/\.\d+Z$/, 'Z'); // 2026-11-13T08:04:27Z
    else el.removeAttribute('title');
  }
  const $ = (id) => d.getElementById(id);

  // ---- status lines (aria-live)
  function stOf(node) {
    const box = node && node.closest('form, .acct-panel, section');
    return (box && box.querySelector('.acct-st')) || $('acct-status');
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
  const known = new Set(['suspended', 'reauth_required', 'last_identity', 'last_usable_method', 'passkey_limit',
    'passkey_exists', 'display_name_reserved', 'invalid_handle', 'handle_reserved', 'handle_taken', 'signup_limit',
    'rate_limited', 'busy', 'csrf', 'ticket_invalid', 'cross_site', 'not_signed_in', 'ceremony_invalid',
    'passkey_rejected', 'not_linked', 'not_found', 'terms_version_mismatch', 'invalid_follow', 'too_many_follows']);
  function errMsg(e) {
    if (!e) return ['acct.err.generic', { code: '?' }];
    if (e instanceof Error || (typeof DOMException !== 'undefined' && e instanceof DOMException)) {
      // WebAuthn (or a script) failure in the browser
      switch (e.name) {
        case 'NotAllowedError':
        case 'AbortError':
          return ['acct.err.webauthn_cancelled'];
        case 'InvalidStateError':
          return ['acct.err.passkey_exists'];
        case 'NotSupportedError':
        case 'SecurityError':
          return ['acct.passkeys.unsupported'];
      }
      return ['acct.err.generic', { code: e.name || '?' }];
    }
    if (e.code === 'network') return ['acct.err.network'];
    // a passkey of another account while signed in (the server keeps the
    // current session): the same words as the provider result
    if (e.code === 'signed_in_as_other') return ['acct.banner.signed_in_as_other'];
    if (e.code === 'handle_change_too_soon') {
      const m = /\d{4}-\d\d-\d\dT\d\d:\d\d(:\d\d)?Z/.exec(e.message || '');
      return ['acct.err.handle_change_too_soon',
        { time: when(me && me.user && me.user.handle_changeable_at) || when(m && m[0]) }];
    }
    if (known.has(e.code)) return ['acct.err.' + e.code];
    if (e.status === 401) return ['acct.err.not_signed_in'];
    if (e.status === 429) return ['acct.err.rate_limited'];
    if (e.status === 503) return ['acct.err.busy'];
    return ['acct.err.generic', { code: e.code || String(e.status || '?') }];
  }
  function fail(node, e) {
    const [key, vars] = errMsg(e);
    say(stOf(node), key, vars, 'err');
    if (e && e.code === 'reauth_required' && page === 'account') openReauth(node);
    if (e && (e.code === 'not_signed_in' || e.status === 401 || e.code === 'not_found' || e.code === 'not_linked')) {
      refresh();
    }
  }

  // ---- HTTP
  async function api(path, body) {
    const headers = { Accept: 'application/json', 'Content-Type': 'application/json' };
    if (csrf) headers['X-CSRF-Token'] = csrf;
    let r;
    try {
      r = await window.fetch(path, {
        method: 'POST', credentials: 'same-origin', cache: 'no-store', redirect: 'error', headers,
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
  // go navigates to a sign-in start URL from the server, or (page = true)
  // to a site page path the server rendered into this page, and nothing else.
  const pagePath = /^\/[A-Za-z0-9._~\-\/]*(\?[A-Za-z0-9._~\-=&+%]*)?$/;
  function go(url, page) {
    if (typeof url !== 'string' || (page ? !pagePath.test(url) : !url.startsWith('/auth/')) || url.startsWith('//') ||
      url.includes('\\')) {
      throw { code: 'bad_start_url' };
    }
    window.location.assign(url);
  }
  // getJSON reads a public, same-origin data endpoint.
  async function getJSON(path) {
    let r;
    try {
      r = await window.fetch(path, { method: 'GET', credentials: 'same-origin', redirect: 'error', headers: { Accept: 'application/json' } });
    } catch (_) {
      throw { code: 'network' };
    }
    if (!r.ok) throw { status: r.status };
    return r.json();
  }
  async function refresh() {
    const m = await nday.fetchMe();
    (view || render)(m);
    return m;
  }

  // busy state: one request per button at a time
  async function run(btn, fn) {
    if (!btn || btn.getAttribute('aria-busy') === 'true') return;
    const st = stOf(btn);
    btn.setAttribute('aria-busy', 'true');
    btn.disabled = true;
    say(st, 'acct.busy');
    try {
      await fn(st);
    } catch (e) {
      fail(btn, e);
    } finally {
      btn.removeAttribute('aria-busy');
      btn.disabled = btn.dataset.off === '1';
      if (st.classList.length === 1 && st.textContent === msg('acct.busy')) say(st, '');
    }
  }
  function off(el, yes) {
    if (!el) return;
    el.dataset.off = yes ? '1' : '';
    if (el.getAttribute('aria-busy') !== 'true') el.disabled = !!yes;
  }

  // ---- WebAuthn
  const PKC = window.PublicKeyCredential;
  const webauthn = !!(PKC && navigator.credentials && navigator.credentials.create && window.isSecureContext);
  const b64u = {
    dec(s) {
      s = String(s).replace(/-/g, '+').replace(/_/g, '/');
      while (s.length % 4) s += '=';
      const bin = atob(s);
      const u = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
      return u.buffer;
    },
    enc(buf) {
      const u = new Uint8Array(buf);
      let s = '';
      for (let i = 0; i < u.length; i++) s += String.fromCharCode(u[i]);
      return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    },
  };
  const withIDs = (list) => (list || []).map((c) => Object.assign({}, c, { id: b64u.dec(c.id) }));
  function creationOptions(pk) {
    if (typeof PKC.parseCreationOptionsFromJSON === 'function') return PKC.parseCreationOptionsFromJSON(pk);
    return Object.assign({}, pk, {
      challenge: b64u.dec(pk.challenge), user: Object.assign({}, pk.user, { id: b64u.dec(pk.user.id) }),
      excludeCredentials: withIDs(pk.excludeCredentials),
    });
  }
  function requestOptions(pk) {
    if (typeof PKC.parseRequestOptionsFromJSON === 'function') return PKC.parseRequestOptionsFromJSON(pk);
    return Object.assign({}, pk, { challenge: b64u.dec(pk.challenge), allowCredentials: withIDs(pk.allowCredentials) });
  }
  function credJSON(c) {
    if (typeof c.toJSON === 'function') {
      try {
        return c.toJSON();
      } catch (_) { /* build it below */ }
    }
    const r = c.response;
    const out = { id: c.id, rawId: b64u.enc(c.rawId), type: c.type, response: { clientDataJSON: b64u.enc(r.clientDataJSON) } };
    if (r.attestationObject) {
      out.response.attestationObject = b64u.enc(r.attestationObject);
      out.response.transports = typeof r.getTransports === 'function' ? r.getTransports() : [];
    }
    if (r.authenticatorData) {
      out.response.authenticatorData = b64u.enc(r.authenticatorData);
      out.response.signature = b64u.enc(r.signature);
      out.response.userHandle = r.userHandle ? b64u.enc(r.userHandle) : null;
    }
    return out;
  }
  async function passkeySignIn() {
    const { publicKey } = await api('/auth/passkey/login/begin');
    const cred = await navigator.credentials.get({ publicKey: requestOptions(publicKey) });
    await api('/auth/passkey/login/finish', credJSON(cred));
  }
  function showWebAuthn() {
    d.querySelectorAll('.acct-wa').forEach((el) => { el.hidden = !webauthn; });
    d.querySelectorAll('.acct-nowa').forEach((el) => { el.hidden = webauthn; });
  }

  const nameOf = (u) => (u.handle ? '@' + u.handle : u.display_name || '');

  // ================================================================ /login
  function loginPage() {
    const choices = $('login-choices');
    const box = $('login-me');
    const top = $('acct-status');
    showWebAuthn();
    function show(m) {
      me = m;
      const inn = !!(m && m.signed_in && m.user);
      csrf = inn ? m.csrf_token || '' : '';
      if (inn) put($('login-me-t'), 'acct.login.signed_in', { name: nameOf(m.user) || '\u2014' });
      box.hidden = !inn;
      choices.hidden = inn;
    }
    nday.me.then(show);
    const pk = $('pk-login');
    if (pk) {
      pk.addEventListener('click', () => run(pk, async () => {
        await passkeySignIn();
        show(await nday.fetchMe());
        say(top, 'acct.banner.ok', null, 'ok');
      }));
    }
    const su = $('f-signup');
    if (su) {
      su.addEventListener('submit', (ev) => {
        ev.preventDefault();
        const btn = su.querySelector('button[type=submit]');
        run(btn, async () => {
          const dn = $('in-signup-name').value.trim();
          const { publicKey } = await api('/auth/passkey/signup/begin', dn ? { display_name: dn } : undefined);
          const cred = await navigator.credentials.create({ publicKey: creationOptions(publicKey) });
          await api('/auth/passkey/signup/finish', credJSON(cred));
          // a new account: the first-sign-in page (it continues to the
          // page the visitor came from)
          if (main.dataset.welcome) {
            go(main.dataset.welcome, true);
            return;
          }
          show(await nday.fetchMe());
          say(top, 'acct.banner.ok', null, 'ok');
        });
      });
    }
  }

  // ============================================================== /account
  const recent = () => {
    const s = me && me.session;
    return !!(s && s.recent_sign_in && Date.now() < Date.parse(s.recent_sign_in_until));
  };
  let reauthFrom = null;
  let recentTimer = 0;

  // The menu: one section at a time, chosen by the URL hash (#profile,
  // #follows, ...). Any other id inside a section (#sec-terms, #h-delete,
  // #in-handle ...) selects that section; an id outside the sections (#main,
  // #reauth) keeps the current one; anything else shows the profile. A
  // section marked data-na (terms without a terms version) is out of the menu.
  const panes = () => Array.from(d.querySelectorAll('#acct-pane > section[data-pane]'));
  let paneNow = '';
  function paneWanted() {
    let h = '';
    try { h = decodeURIComponent(location.hash.slice(1)); } catch (e) { h = ''; }
    if (h === 'sec-follows') h = 'follows'; // the follows section's id before the menu
    let s = panes().find((p) => p.dataset.pane === h);
    if (!s && h) {
      const el = $(h);
      s = el ? el.closest('section[data-pane]') : null;
      if (!s && el && paneNow) return paneNow;
    }
    return s && !s.hasAttribute('data-na') ? s.dataset.pane : 'profile';
  }
  function showPane(name) {
    let want = name || paneWanted();
    const ws = panes().find((p) => p.dataset.pane === want);
    if (!ws || ws.hasAttribute('data-na')) want = 'profile';
    paneNow = want;
    panes().forEach((s) => { s.hidden = s.dataset.pane !== want || s.hasAttribute('data-na'); });
    d.querySelectorAll('.acct-menu a').forEach((a) => {
      const n = a.getAttribute('href').slice(1);
      const s = panes().find((p) => p.dataset.pane === n);
      a.parentNode.hidden = !s || s.hasAttribute('data-na');
      if (n === want) a.setAttribute('aria-current', 'page');
      else a.removeAttribute('aria-current');
    });
    // phones: the menu is one row that scrolls sideways; bring the current item into view
    const row = d.querySelector('.acct-menu>ul');
    const here = row && row.querySelector('[aria-current="page"]');
    if (here && row.scrollWidth > row.clientWidth) {
      const a = here.getBoundingClientRect();
      const r = row.getBoundingClientRect();
      if (a.left < r.left || a.right > r.right) row.scrollLeft += (a.left - r.left) - (row.clientWidth - a.width) / 2;
    }
    // an open re-verification panel left in a section that is now hidden
    // goes back above the sections; its result is then said on the top line
    const panel = $('reauth');
    const box = $('acct-pane');
    if (panel && box && panel.parentNode !== box && panel.closest('section[data-pane]').hidden) {
      box.insertBefore(panel, box.querySelector('section[data-pane]'));
      reauthFrom = null;
    }
  }
  // reveal(el): select the section el is in (pushing its hash), so that
  // focus and scrolling reach it.
  function reveal(el) {
    const s = el && el.closest('section[data-pane]');
    if (!s || !s.hidden || s.hasAttribute('data-na')) return;
    if (location.hash !== '#' + s.dataset.pane) history.pushState(null, '', '#' + s.dataset.pane);
    showPane(s.dataset.pane);
  }

  // The re-verification panel: offered before a sensitive action when the
  // session is no longer a recent sign-in (and after a 403 reauth_required).
  // It never repeats the action itself.
  function needReauth(from) {
    if (recent()) return false;
    openReauth(from);
    return true;
  }
  function openReauth(from) {
    const panel = $('reauth');
    if (!panel || !me || !me.user) return;
    reveal(from);
    reauthFrom = from;
    const sec = from && from.closest('section');
    if (sec && panel.parentNode !== sec) sec.appendChild(panel);
    const linked = new Set(me.user.identities.map((i) => i.provider));
    const enabled = new Set(me.providers || []);
    let any = false;
    panel.querySelectorAll('[data-reauth]').forEach((b) => {
      const p = b.dataset.reauth;
      const ok = p === 'passkey'
        ? webauthn && me.passkeys.enabled && me.user.passkeys.length > 0
        : linked.has(p) && enabled.has(p);
      b.parentNode.hidden = !ok;
      any = any || ok;
    });
    $('reauth-none').hidden = any;
    say(panel.querySelector('.acct-st'), '');
    panel.hidden = false;
    $('reauth-h').focus();
  }
  function closeReauth() {
    const panel = $('reauth');
    if (panel) panel.hidden = true;
    if (reauthFrom && reauthFrom.isConnected) reauthFrom.focus();
  }

  function accountPage() {
    $('acct-loading').hidden = false;
    showPane();
    window.addEventListener('hashchange', () => showPane());
    window.addEventListener('popstate', () => showPane());
    nday.me.then(render);
    // profile: handle
    $('f-handle').addEventListener('submit', (ev) => {
      ev.preventDefault();
      const btn = ev.currentTarget.querySelector('button[type=submit]');
      run(btn, async (st) => {
        const h = $('in-handle').value.trim().replace(/^@/, '');
        await api('/account/handle', { handle: h });
        $('in-handle').value = '';
        await refresh();
        say(st, 'acct.handle.saved', null, 'ok');
      });
    });
    // sign-in methods
    d.querySelectorAll('.acct-item[data-provider]').forEach((li) => {
      const p = li.dataset.provider;
      const link = li.querySelector('[data-act=link]');
      const unlink = li.querySelector('[data-act=unlink]');
      link.addEventListener('click', () => {
        if (link.disabled || needReauth(link)) return;
        run(link, async () => {
          const j = await api('/auth/' + encodeURIComponent(p) + '/ticket', { intent: 'link', return: accountPath });
          go(j.start_url);
        });
      });
      unlink.addEventListener('click', () => run(unlink, async (st) => {
        await api('/auth/' + encodeURIComponent(p) + '/unlink');
        await refresh();
        say(st, 'acct.methods.unlinked', null, 'ok');
      }));
    });
    // passkeys
    const add = $('f-pk-add');
    if (add) {
      add.addEventListener('submit', (ev) => {
        ev.preventDefault();
        const btn = add.querySelector('button[type=submit]');
        if (btn.disabled || !webauthn || needReauth(btn)) return;
        run(btn, async (st) => {
          const name = $('in-pk-name').value.trim();
          const { publicKey } = await api('/auth/passkey/register/begin');
          const cred = await navigator.credentials.create({ publicKey: creationOptions(publicKey) });
          await api('/auth/passkey/register/finish', Object.assign({}, credJSON(cred), { name }));
          $('in-pk-name').value = '';
          await refresh();
          say(st, 'acct.passkeys.added', null, 'ok');
        });
      });
    }
    // re-verification
    const panel = $('reauth');
    panel.querySelectorAll('[data-reauth]').forEach((b) => {
      b.addEventListener('click', () => run(b, async () => {
        const p = b.dataset.reauth;
        if (p !== 'passkey') {
          const j = await api('/auth/' + encodeURIComponent(p) + '/ticket', { intent: 'reauth', return: accountPath });
          go(j.start_url);
          return;
        }
        await passkeySignIn(); // another account's passkey: 409 signed_in_as_other, nothing changes
        await refresh();
        closeReauth();
        say(stOf(reauthFrom), 'acct.reauth.done', null, 'ok');
      }));
    });
    $('reauth-close').addEventListener('click', closeReauth);
    // sessions
    $('b-signout').addEventListener('click', (ev) => run(ev.currentTarget, async () => {
      await api('/auth/signout');
      await refresh();
      say($('acct-status'), 'acct.sessions.signed_out', null, 'ok');
    }));
    $('b-signout-all').addEventListener('click', (ev) => run(ev.currentTarget, async () => {
      await api('/auth/signout-all');
      await refresh();
      say($('acct-status'), 'acct.sessions.signed_out_all', null, 'ok');
    }));
    // terms
    $('b-terms').addEventListener('click', (ev) => run(ev.currentTarget, async (st) => {
      await api('/account/accept-terms', { version: ev.currentTarget.dataset.version });
      await refresh();
      say(st, 'acct.terms.saved', null, 'ok');
    }));
    // delete
    const del = $('f-delete');
    const delIn = $('in-delete');
    const delBtn = del.querySelector('button[type=submit]');
    delIn.addEventListener('input', () => off(delBtn, delIn.value !== del.dataset.word));
    del.addEventListener('submit', (ev) => {
      ev.preventDefault();
      if (delBtn.disabled || delIn.value !== del.dataset.word || needReauth(delBtn)) return;
      run(delBtn, async () => {
        await api('/account/delete', { confirm: true });
        delIn.value = '';
        await refresh();
        say($('acct-status'), 'acct.delete.done', null, 'ok');
      });
    });
  }

  function render(m) {
    me = m;
    $('acct-loading').hidden = true;
    const out = $('acct-out');
    const inn = $('acct-in');
    const top = $('acct-status');
    if (!m) { // state unknown
      csrf = '';
      out.hidden = true;
      inn.hidden = true;
      say(top, 'acct.page.unknown', null, 'err');
      return;
    }
    if (m.disabled || !m.signed_in || !m.user) {
      csrf = '';
      out.hidden = false;
      inn.hidden = true;
      return;
    }
    csrf = m.csrf_token || '';
    out.hidden = true;
    inn.hidden = false;
    const u = m.user;
    const active = u.status !== 'suspended';

    // suspension
    const susp = $('acct-susp');
    susp.hidden = active;
    if (!active) {
      if (u.suspended_until) put($('acct-susp-t'), 'acct.suspended.until', { time: when(u.suspended_until) });
      else put($('acct-susp-t'), 'acct.suspended.open');
      const r = $('acct-susp-r');
      r.hidden = !u.status_reason;
      if (u.status_reason) put(r, 'acct.suspended.reason', { reason: u.status_reason });
    }

    // profile
    if (u.handle) $('v-handle').textContent = '@' + u.handle; else put($('v-handle'), 'acct.profile.not_set');
    if (u.display_name) {
      $('v-name').textContent = u.display_name;
      $('v-name').removeAttribute('lang');
    } else put($('v-name'), 'acct.profile.not_set');
    const role = $('v-role');
    put(role, 'acct.role.name#' + u.role);
    if (u.role === 'moderator' || u.role === 'admin') {
      const b = d.createElement('span');
      b.className = 'rb';
      put(b, 'acct.role.badge#' + u.role);
      role.appendChild(b);
    }
    stamp($('v-since'), u.created_at);
    const hf = $('f-handle');
    off($('in-handle'), !active);
    off(hf.querySelector('button[type=submit]'), !active);
    $('in-handle').placeholder = u.handle || '';
    const next = $('handle-next');
    const at = u.handle_changeable_at ? Date.parse(u.handle_changeable_at) : 0;
    next.hidden = !(at > Date.now());
    if (at > Date.now()) put(next, 'acct.handle.next', { time: when(u.handle_changeable_at) });

    // sign-in methods
    d.querySelectorAll('.acct-item[data-provider]').forEach((li) => {
      const id = u.identities.find((i) => i.provider === li.dataset.provider);
      const state = li.querySelector('.acct-state');
      if (!id) put(state, 'acct.methods.not_linked');
      else if (id.handle) put(state, 'acct.methods.linked_as', { handle: id.handle });
      else put(state, 'acct.methods.linked');
      const link = li.querySelector('[data-act=link]');
      link.hidden = !!id;
      off(link, !active);
      li.querySelector('[data-act=unlink]').hidden = !id;
    });

    // passkeys
    const rows = $('pk-rows');
    if (rows) {
      while (rows.firstChild) rows.removeChild(rows.firstChild);
      const pks = u.passkeys || [];
      $('pk-none').hidden = pks.length > 0;
      $('pk-table').hidden = pks.length === 0;
      pks.forEach((pk) => rows.appendChild(passkeyRow(pk)));
      showWebAuthn();
      const add = $('f-pk-add');
      off($('in-pk-name'), !active || !webauthn);
      off(add.querySelector('button[type=submit]'), !active || !webauthn);
    }

    // sessions
    const s = m.session || {};
    put($('v-session'), 'acct.sessions.current', { time: when(s.created_at) });
    const rec = $('v-recent');
    if (recent()) put(rec, 'acct.sessions.recent', { time: when(s.recent_sign_in_until) });
    else put(rec, 'acct.sessions.not_recent');
    clearTimeout(recentTimer);
    const left = Date.parse(s.recent_sign_in_until) - Date.now();
    if (recent() && left < 864e5) recentTimer = setTimeout(() => put(rec, 'acct.sessions.not_recent'), left + 500);

    // terms (only when the site has a terms version)
    const t = u.terms || {};
    $('sec-terms').toggleAttribute('data-na', !t.current_version);
    showPane();
    if (t.current_version) {
      const btn = $('b-terms');
      if (t.up_to_date) put($('v-terms'), 'acct.terms.accepted', { version: t.accepted_version, time: when(t.accepted_at) });
      else put($('v-terms'), 'acct.terms.pending', { version: t.current_version });
      btn.hidden = !!t.up_to_date;
      btn.dataset.version = t.current_version;
      put(btn, 'acct.terms.accept', { version: t.current_version });
    }

    // follows
    const fl = $('fol-list');
    if (fl) {
      while (fl.firstChild) fl.removeChild(fl.firstChild);
      const fs = u.follows || [];
      $('fol-none').hidden = fs.length > 0;
      fl.hidden = fs.length === 0;
      fs.forEach((f) => fl.appendChild(followRow(f, active)));
    }

    // delete (typed confirmation: the handle, or DELETE without one)
    const del = $('f-delete');
    const word = u.handle || 'DELETE';
    if (del.dataset.word !== word) $('in-delete').value = '';
    del.dataset.word = word;
    put($('l-delete'), 'acct.delete.confirm_label', { word });
    off(del.querySelector('button[type=submit]'), $('in-delete').value !== word);
  }

  // One followed term on the account page; remove saves the list without it.
  // The list to save is taken from the latest /api/me state at click time
  // (not from when the row was drawn), and one removal runs at a time: the
  // other remove buttons are off until it is done (no lost update).
  let followBusy = false;
  function followRow(f, active) {
    const li = d.createElement('li');
    li.className = 'acct-item';
    li.classList.add('fol');
    const name = d.createElement('span');
    name.className = 'acct-pn';
    name.textContent = f.label;
    const acts = d.createElement('span');
    acts.className = 'acct-acts';
    const b = d.createElement('button');
    b.type = 'button';
    b.className = 'btn';
    put(b, 'acct.follows.remove');
    b.setAttribute('aria-label', msg('acct.follows.remove_label', { name: f.label }));
    off(b, !active);
    acts.appendChild(b);
    li.append(name, acts);
    b.addEventListener('click', () => {
      if (followBusy) return;
      followBusy = true;
      const others = Array.from($('fol-list').querySelectorAll('button')).filter((x) => x !== b);
      others.forEach((x) => off(x, true));
      run(b, async (st) => {
        try {
          const latest = (me && me.user && me.user.follows) || [];
          const rest = latest.filter((x) => x.term !== f.term).map((x) => ({ label: x.label }));
          await api('/account/follows', { terms: rest });
          await refresh();
          say(st, 'acct.follows.saved', null, 'ok');
        } finally {
          followBusy = false;
          const ok = !!(me && me.user && me.user.status !== 'suspended');
          others.forEach((x) => off(x, !ok));
        }
      });
    });
    return li;
  }

  // ============================================================== /welcome
  // The handle rule of the server (internal/auth/names.go handleRe); reserved
  // names are only known to the server (409 handle_reserved on save).
  const handleRe = /^[A-Za-z0-9][A-Za-z0-9_-]{2,29}$/;
  const followKey = (s) => String(s).trim().replace(/\s+/g, ' ').toLowerCase();
  const MAX_FOLLOWS = 50;

  function welcomePage() {
    const top = $('acct-status');
    const hIn = $('w-handle');
    const hSt = $('w-handle-st');
    const use = $('w-handle-use'); // offers a linked identity's username; never fills the field by itself
    const count = $('w-count');
    const presets = $('w-presets');
    const extra = $('w-extra');
    const q = $('w-q');
    const res = $('w-res');
    const accept = $('w-accept'); // null: the site has no rules version
    const rules = $('w-rules');
    const cmd = $('w-cmd');
    const base = cmd.textContent;
    const done = $('w-done');
    const presetTerms = new Set();
    presets.querySelectorAll('button[data-term]').forEach((b) => presetTerms.add(b.dataset.term));
    let chosen = new Map(); // term -> label, in the order chosen
    let saved = new Map(); // the list as stored
    let current = ''; // the handle as stored
    let loaded = false;
    view = show;

    const handleValue = () => hIn.value.trim().replace(/^@/, '');
    function checkHandle() {
      const v = handleValue();
      if (!v) say(hSt, 'acct.welcome.handle_empty');
      else if (!handleRe.test(v)) say(hSt, 'acct.err.invalid_handle', null, 'err');
      else if (v === current) say(hSt, 'acct.welcome.handle_current', null, 'ok');
      else say(hSt, 'acct.welcome.handle_ok', null, 'ok');
      echo();
    }
    // the same choices as a command line (shown only, never run)
    function echo() {
      const args = [base];
      const h = handleValue();
      if (h) args.push('--handle', h);
      if (chosen.size) {
        args.push('--follow', Array.from(chosen.values()).map((l) => (/^[A-Za-z0-9._-]+$/.test(l) ? l : JSON.stringify(l))).join(','));
      }
      if (accept && !accept.disabled && accept.checked) args.push('--accept-rules');
      cmd.textContent = args.join(' ');
    }
    function mark(b, on) {
      b.setAttribute('aria-pressed', on ? 'true' : 'false');
      const mk = b.querySelector('.wel-mk');
      if (mk) mk.textContent = on ? '[x]' : '[ ]';
    }
    function chip(term, label) {
      const li = d.createElement('li');
      const b = d.createElement('button');
      b.type = 'button';
      b.className = 'btn';
      b.classList.add('wel-chip');
      b.dataset.term = term;
      b.dataset.label = label;
      const mk = d.createElement('span');
      mk.className = 'wel-mk';
      mk.setAttribute('aria-hidden', 'true');
      b.append(mk, d.createTextNode(label));
      mark(b, true);
      li.appendChild(b);
      return li;
    }
    function sync() {
      presets.querySelectorAll('button[data-term]').forEach((b) => mark(b, chosen.has(b.dataset.term)));
      while (extra.firstChild) extra.removeChild(extra.firstChild);
      chosen.forEach((label, term) => {
        if (!presetTerms.has(term)) extra.appendChild(chip(term, label));
      });
      extra.hidden = !extra.firstChild;
      put(count, 'acct.welcome.follows_count', { n: chosen.size });
      echo();
    }
    function toggle(label) {
      const k = followKey(label);
      if (!k) return;
      if (chosen.has(k)) chosen.delete(k);
      else if (chosen.size >= MAX_FOLLOWS) {
        say(stOf(q), 'acct.err.too_many_follows', null, 'err');
        return;
      } else chosen.set(k, String(label).trim().replace(/\s+/g, ' '));
      say(stOf(q), '');
      sync();
    }
    const onChip = (ev) => {
      const b = ev.target.closest('button[data-term]');
      if (!b) return;
      const gone = b.closest('#w-extra');
      toggle(b.dataset.label);
      if (gone) q.focus(); // the button itself is gone
    };
    presets.addEventListener('click', onChip);
    extra.addEventListener('click', onChip);

    // search: GET /api/affected/suggest (public, cached), debounced
    let timer = 0;
    let seq = 0;
    async function search() {
      const text = q.value.trim().replace(/\s+/g, ' ');
      const mine = ++seq;
      const st = stOf(q);
      while (res.firstChild) res.removeChild(res.firstChild);
      res.hidden = true;
      say(st, '');
      if (Array.from(text).length < 3) return; // the server's minimum (site.MinSuggestRunes)
      let j;
      try {
        j = await getJSON('/api/affected/suggest' + '?' + new URLSearchParams({ q: text, limit: '8' }).toString());
      } catch (_) {
        if (mine === seq) say(st, 'acct.welcome.search_failed', null, 'err');
        return;
      }
      if (mine !== seq) return;
      const rows = (j && Array.isArray(j.rows)) ? j.rows : [];
      if (!rows.length) {
        say(st, 'acct.welcome.search_none');
        return;
      }
      rows.forEach((row) => {
        const li = d.createElement('li');
        const b = d.createElement('button');
        b.type = 'button';
        b.className = 'btn';
        b.classList.add('wel-chip');
        const mk = d.createElement('span');
        mk.className = 'wel-mk';
        mk.setAttribute('aria-hidden', 'true');
        mk.textContent = '+';
        const n = d.createElement('span');
        n.className = 'dim';
        put(n, 'acct.welcome.search_count', { count: row.count });
        b.append(mk, d.createTextNode(String(row.name)), n);
        b.addEventListener('click', () => {
          if (!chosen.has(followKey(row.name))) toggle(row.name);
        });
        li.appendChild(b);
        res.appendChild(li);
      });
      res.hidden = false;
    }
    q.addEventListener('input', () => {
      clearTimeout(timer);
      timer = setTimeout(search, 250);
    });
    q.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') e.preventDefault(); // nothing to submit
    });
    hIn.addEventListener('input', checkHandle);
    use.addEventListener('click', () => {
      hIn.value = use.dataset.handle || '';
      use.hidden = true;
      checkHandle();
      hIn.focus();
    });
    if (accept) accept.addEventListener('change', echo);

    function show(m) {
      me = m;
      const ld = $('acct-loading');
      if (ld) ld.hidden = true;
      const out = $('acct-out');
      const inn = $('acct-in');
      if (!m) {
        csrf = '';
        out.hidden = true;
        inn.hidden = true;
        say(top, 'acct.page.unknown', null, 'err');
        return;
      }
      if (m.disabled || !m.signed_in || !m.user) {
        csrf = '';
        out.hidden = false;
        inn.hidden = true;
        return;
      }
      csrf = m.csrf_token || '';
      out.hidden = true;
      inn.hidden = false;
      const u = m.user;
      current = u.handle || '';
      saved = new Map((u.follows || []).map((f) => [f.term, f.label]));
      if (!loaded) { // first view: fill the form from the account
        loaded = true;
        chosen = new Map(saved);
        use.hidden = true;
        // the handle already set is shown (it is only sent when changed);
        // otherwise the field stays empty (= no handle is sent) and a
        // linked identity's username is offered as a button
        if (current) hIn.value = current;
        else {
          const id = (u.identities || []).find((i) => i.handle && handleRe.test(i.handle));
          if (id) {
            const p = d.querySelector('#w-provs [data-p="' + id.provider + '"]');
            put(use, 'acct.welcome.handle_use', { provider: p ? p.textContent : id.provider, name: id.handle });
            use.dataset.handle = id.handle;
            use.hidden = false;
          }
        }
      }
      const t = u.terms || {};
      if (rules) {
        rules.hidden = !t.current_version;
        accept.dataset.version = t.current_version || '';
        if (t.up_to_date) {
          accept.checked = true;
          accept.disabled = true;
          say(stOf(accept), 'acct.welcome.rules_done', { version: t.current_version }, 'ok');
        }
      }
      checkHandle();
      sync();
    }

    done.addEventListener('click', () => run(done, async () => {
      let failed = false;
      const h = handleValue();
      if (h && h !== current) {
        try {
          await api('/account/handle', { handle: h });
          current = h;
          say(hSt, 'acct.handle.saved', null, 'ok');
        } catch (e) {
          failed = true;
          fail(hIn, e);
        }
      }
      const same = chosen.size === saved.size && Array.from(chosen.keys()).every((k) => saved.has(k));
      if (!same) {
        try {
          const j = await api('/account/follows', { terms: Array.from(chosen.values()).map((label) => ({ label })) });
          saved = new Map((j.follows || []).map((f) => [f.term, f.label]));
          chosen = new Map(saved);
          sync();
          say(stOf(q), 'acct.follows.saved', null, 'ok');
        } catch (e) {
          failed = true;
          fail(q, e);
        }
      }
      if (accept && rules && !rules.hidden && accept.checked && !accept.disabled) {
        try {
          await api('/account/accept-terms', { version: accept.dataset.version });
          accept.disabled = true;
          say(stOf(accept), 'acct.welcome.rules_done', { version: accept.dataset.version }, 'ok');
        } catch (e) {
          failed = true;
          fail(accept, e);
        }
      }
      if (failed) {
        say(top, 'acct.welcome.partial', null, 'err');
        return;
      }
      go(main.dataset.dest, true);
    }));

    $('acct-loading').hidden = false;
    nday.me.then(show);
  }

  function passkeyRow(pk) {
    const tr = d.createElement('tr');
    const cell = (text) => {
      const td = d.createElement('td');
      td.textContent = text;
      tr.appendChild(td);
      return td;
    };
    const nameTd = cell(pk.name);
    stamp(cell(''), pk.created_at);
    const used = cell('');
    stamp(used, pk.last_used_at);
    if (!pk.last_used_at) put(used, 'acct.passkeys.never');
    const bk = cell('');
    put(bk, pk.backed_up ? 'acct.yes' : 'acct.no');
    const acts = d.createElement('td');
    const box = d.createElement('span');
    box.className = 'acct-acts';
    acts.appendChild(box);
    tr.appendChild(acts);
    const button = (key) => {
      const b = d.createElement('button');
      b.type = 'button';
      b.className = 'btn';
      put(b, key);
      box.appendChild(b);
      return b;
    };
    const path = '/account/passkeys/' + encodeURIComponent(pk.id) + '/';
    const ren = button('acct.passkeys.rename');
    const del = button('acct.passkeys.delete');
    ren.addEventListener('click', () => {
      // inline rename: input + save + cancel in the name cell
      const input = d.createElement('input');
      input.type = 'text';
      input.className = 'acct-in';
      input.maxLength = 64;
      input.value = pk.name;
      input.setAttribute('aria-label', msg('acct.passkeys.rename_label'));
      const save = d.createElement('button');
      save.type = 'button';
      save.className = 'btn';
      put(save, 'acct.save');
      const cancel = d.createElement('button');
      cancel.type = 'button';
      cancel.className = 'btn';
      put(cancel, 'acct.cancel');
      const row = d.createElement('div');
      row.className = 'acct-row';
      row.append(input, save, cancel);
      nameTd.textContent = '';
      nameTd.appendChild(row);
      ren.hidden = true;
      input.focus();
      const restore = () => {
        nameTd.textContent = pk.name;
        ren.hidden = false;
        ren.focus();
      };
      cancel.addEventListener('click', restore);
      input.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') save.click();
      });
      save.addEventListener('click', () => run(save, async (st) => {
        await api(path + 'rename', { name: input.value.trim() });
        await refresh();
        say(st, 'acct.passkeys.renamed', null, 'ok');
        const n = $('in-pk-name');
        if (n) n.focus();
      }));
    });
    let armed = 0;
    del.addEventListener('click', () => {
      if (!armed) { // first click arms, second click deletes
        put(del, 'acct.passkeys.delete_confirm');
        armed = setTimeout(() => {
          armed = 0;
          put(del, 'acct.passkeys.delete');
        }, 5000);
        return;
      }
      clearTimeout(armed);
      run(del, async (st) => {
        await api(path + 'delete');
        await refresh();
        say(st, 'acct.passkeys.deleted', null, 'ok');
        const n = $('in-pk-name');
        if (n) n.focus();
      });
    });
    return tr;
  }

  if (page === 'login') loginPage();
  else if (page === 'account') accountPage();
  else if (page === 'welcome') welcomePage();
})();
