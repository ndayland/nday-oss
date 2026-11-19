// nday: the script parts of a vulnerability page (loaded on vulnerability
// pages when accounts are enabled): the researcher posts (GET /api/posts/{cve},
// signed in only) and the discussion (GET /api/discuss/{cve}, docs/discuss.md
// section 9). The page itself holds no post or comment content, only the
// outline drawn as speckle (static/app.js); this script asks the auth-class
// endpoints and renders the content in its place: the posts for a signed-in
// visitor, the comments for a signed-in visitor and, when the section says
// data-guest="1" (signed-out reading on), for a signed-out one too (without
// any writing control).
//
// Rules (checked by tests in internal/webui):
//   - nothing is ever parsed as HTML here: post texts, handles, Markdown
//     sources and hide reasons reach the DOM through textContent, text
//     nodes and .value (a post's t.co links become <a> elements built here);
//     comment bodies are built element by element from body_nodes (only the
//     md allowlist: p br pre code blockquote ul ol li em strong a);
//   - links only of the forms the server accepts, set with setAttribute;
//   - controls come from the page's own <template> elements (cloned), words
//     from <template id="acct-msgs">;
//   - after a successful write the script navigates to the same page
//     (location.pathname, ?c=<id> plus a throw-away fresh=) and #c-<id>;
//     nothing else;
//   - the CSRF token lives in this closure only;
//   - every write is a same-origin POST with credentials: same-origin,
//     Content-Type: application/json and X-CSRF-Token.
(() => {
  'use strict';
  const d = document;
  const nday = window.nday;
  if (!nday || !nday.me || !window.fetch || !window.URLSearchParams) return;
  // the page's vulnerability id: a CVE id, or the GHSA id of an advisory without one
  const CVE = /^(CVE-\d{4}-\d{4,19}|GHSA(-[23456789cfghjmpqrvwx]{4}){3})$/;
  const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
  const tpl = d.getElementById('acct-msgs');
  const $ = (id) => d.getElementById(id);
  const sec = $('discussion');
  const cve = (sec && sec.dataset.cve) || '';
  const locale = (sec && sec.dataset.locale) || '';
  const guest = !!(sec && sec.dataset.guest === '1'); // signed-out visitors may read
  const PURPOSES = new Set(['analysis', 'reproduction', 'fix', 'detection', 'question']);
  const HINTED = new Set(['reproduction', 'fix']); // purposes whose text box suggests what to include
  let csrf = '';
  let state = null; // the last GET /api/discuss/{cve}
  let limits = { max_body_chars: Number(sec && sec.dataset.max) || 10000, max_note_chars: 500, max_replies: 200 };
  let formN = 0;

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
  const chars = (s) => Array.from(String(s).trim()).length;

  // ---- the address bar: drop fresh= (after a write) and discussion (after
  // signing in from here); a #c-<id> that is gone falls back to the section.
  // (run after the comments are rendered: #c-<id> must exist by then)
  function cleanURL() {
    const q = new URLSearchParams(window.location.search);
    const toDisc = q.has('discussion');
    const toRsch = q.has('research');
    let hash = window.location.hash;
    if (/^#c-/.test(hash) && !$(hash.slice(1))) hash = '#discussion';
    if (/^#c-/.test(hash) && $(hash.slice(1))) $(hash.slice(1)).scrollIntoView({ block: 'start' });
    if (q.has('fresh') || toDisc || toRsch || hash !== window.location.hash) {
      q.delete('fresh');
      q.delete('discussion');
      q.delete('research');
      const qs = q.toString();
      try {
        window.history.replaceState(window.history.state, '', window.location.pathname + (qs ? '?' + qs : '') + hash);
      } catch (_) { /* keep it */ }
    }
    const h = (toRsch && !hash) || hash === '#research' ? $('rsch-h')
      : ((toDisc && !hash) || hash === '#discussion' ? $('disc-h') : null);
    if (h) {
      h.scrollIntoView({ block: 'start' });
      h.focus({ preventScroll: true });
    }
  }

  // ---- HTTP
  function fail(r, j) {
    return Object.assign({ status: r.status, retryAfter: r.headers.get('Retry-After') }, (j && j.error) || {});
  }
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
    if (!r.ok) throw fail(r, j);
    return j || {};
  }
  // post retries once after a csrf error with a fresh token from /api/me.
  async function post(path, body) {
    try {
      return await api(path, body);
    } catch (e) {
      if (!e || e.code !== 'csrf') throw e;
      const me = await nday.fetchMe();
      csrf = (me && me.signed_in && me.csrf_token) || '';
      return api(path, body);
    }
  }
  async function getJSON(path) {
    let r;
    try {
      r = await window.fetch(path, { credentials: 'same-origin', cache: 'no-store', redirect: 'error', headers: { Accept: 'application/json' } });
    } catch (_) {
      throw { code: 'network' };
    }
    const j = await r.json().then(null, () => null);
    if (!r.ok || !j) throw fail(r, j);
    return j;
  }
  // load asks for the comments this page shows: the same page of threads,
  // or the same continuation of a long thread.
  // load asks for the first page of comments, or (?c=<id> in the address
  // bar, a permalink or the result of a write) the page that holds that
  // comment; more pages and cut threads are appended by the buttons.
  async function load() {
    const q = new URLSearchParams({ locale });
    const c = (new URLSearchParams(window.location.search).get('c') || '').toLowerCase();
    if (UUID.test(c)) q.set('c', c);
    const j = await getJSON('/api/discuss/' + cve + '?' + q.toString());
    // signed out: the comments only while signed-out reading is on (an
    // outline answer means it was switched off meanwhile)
    if (!j.viewer || !(j.viewer.signed_in || (guest && !j.outline)) || !Array.isArray(j.comments)) throw { code: 'internal' };
    state = j;
    if (j.limits) limits = j.limits;
    return j;
  }
  async function more(params) {
    const q = new URLSearchParams(Object.assign({ locale }, params));
    const j = await getJSON('/api/discuss/' + cve + '?' + q.toString());
    if (!j.viewer || !Array.isArray(j.comments)) throw { code: 'internal' };
    return j;
  }
  const commentPath = (id, op) => '/api/discuss/comment/' + id + '/' + op;

  // reload shows the server-rendered result: this vulnerability page with
  // ?c=<id> (the server renders whichever page holds that comment, even a
  // later one), the browser cache bypassed by a throw-away parameter,
  // scrolled to the comment; without a comment, the first page.
  function reload(id) {
    const q = new URLSearchParams();
    const ok = typeof id === 'string' && UUID.test(id);
    if (ok) q.set('c', id);
    q.set('fresh', Date.now().toString(36));
    let p = window.location.pathname;
    if (!p.startsWith('/') || p.startsWith('//')) p = '/';
    window.location.assign(p + '?' + q.toString() + (ok ? '#c-' + id : '#discussion'));
  }

  // ---- errors -> messages
  const known = new Set(['not_signed_in', 'cross_site', 'csrf', 'suspended', 'handle_required', 'terms_required',
    'forbidden', 'not_author', 'own_comment', 'wrong_status', 'not_found', 'bad_cve', 'bad_parent', 'thread_full',
    'duplicate', 'bad_lang', 'bad_purpose', 'bad_reason', 'bad_note', 'bad_resolution', 'bad_cursor', 'bad_request', 'too_large',
    'busy', 'wrong_host', 'internal', 'network', 'terms_version_mismatch', 'empty', 'terms_unchecked']);
  function errMsg(e) {
    if (!e || e instanceof Error) return ['disc.err.generic', { code: (e && e.name) || '?' }];
    const wait = parseInt(e.retryAfter, 10);
    switch (e.code) {
      case 'rate_limited':
        return wait > 0 ? ['disc.err.rate_limited', { seconds: wait }] : ['disc.err.rate_limited_later'];
      case 'daily_limit':
        return wait > 0
          ? ['disc.err.daily_limit', { time: nday.localTime(new Date(Date.now() + wait * 1000).toISOString(), 'long') }]
          : ['disc.err.rate_limited_later'];
      case 'invalid_body': // too long, or nothing visible left after cleaning
        return lastLen > limits.max_body_chars ? ['disc.err.invalid_body', { max: limits.max_body_chars }] : ['disc.err.empty'];
      case 'too_long':
        return ['disc.err.too_long', { n: e.n, max: limits.max_body_chars }];
      case 'terms_required':
        return e.param ? ['disc.terms.updated', { version: e.param }] : ['disc.err.terms_required'];
    }
    if (known.has(e.code)) return ['disc.err.' + e.code];
    if (e.status === 401) return ['disc.err.not_signed_in'];
    if (e.status === 429) return ['disc.err.rate_limited_later'];
    if (e.status === 503) return ['disc.err.busy'];
    return ['disc.err.generic', { code: e.code || String(e.status || '?') }];
  }

  // run: one request per button at a time, busy text in the status line.
  async function run(btn, st, fn) {
    if (!btn || btn.getAttribute('aria-busy') === 'true') return;
    btn.setAttribute('aria-busy', 'true');
    btn.disabled = true;
    say(st, 'disc.busy');
    try {
      await fn();
    } catch (e) {
      const [key, vars] = errMsg(e);
      say(st, key, vars, 'err');
      onError(e);
    } finally {
      btn.removeAttribute('aria-busy');
      btn.disabled = false;
      if (!st.classList.contains('err') && !st.classList.contains('ok') && st.textContent === msg('disc.busy')) say(st, '');
    }
  }
  // Errors that change what the page should offer.
  function onError(e) {
    const v = state && state.viewer;
    if (!e || !v) return;
    if (e.code === 'terms_required' && e.param) {
      v.terms_version = e.param;
      v.post_refusal = 'terms_required';
      sec.querySelectorAll('form').forEach(termsBlock);
    } else if (e.code === 'terms_version_mismatch') {
      load().then(() => sec.querySelectorAll('form').forEach(termsBlock), () => {});
    } else if (e.code === 'not_signed_in' || e.status === 401 || e.code === 'suspended' || e.code === 'handle_required') {
      nday.fetchMe().then(() => load()).then(() => {
        renderList();
        render();
      }, () => {});
    }
  }

  // ---- forms (cloned from the page's templates)
  function clone(id) {
    const t = $(id);
    return t ? t.content.firstElementChild.cloneNode(true) : null;
  }
  // wire gives a form's fields ids for their labels, and its text box a
  // live counter against limits.max_body_chars.
  function wire(form) {
    const n = ++formN;
    form.querySelectorAll('[data-f]').forEach((el) => { el.id = 'disc-f' + n + '-' + el.dataset.f; });
    form.querySelectorAll('label[data-for]').forEach((l) => { l.htmlFor = 'disc-f' + n + '-' + l.dataset.for; });
    const ta = form.querySelector('textarea[data-f=body]');
    if (ta) {
      const lim = form.querySelector('[data-f=lim]');
      if (lim) ta.setAttribute('aria-describedby', lim.id);
      const cnt = form.querySelector('.disc-cnt');
      const upd = () => {
        const k = chars(ta.value);
        cnt.textContent = k + ' / ' + limits.max_body_chars;
        cnt.classList.toggle('err', k > limits.max_body_chars);
      };
      ta.addEventListener('input', upd);
      upd();
    }
    termsBlock(form);
    return form;
  }
  const needTerms = () => !!(state && state.viewer && state.viewer.post_refusal === 'terms_required');
  function termsBlock(form) {
    const box = form.querySelector('.disc-terms');
    if (!box) return;
    box.hidden = !needTerms();
    if (!box.hidden) put(box.querySelector('.disc-terms-t'), 'disc.terms.needed', { version: state.viewer.terms_version || '' });
  }
  // acceptTerms: when the rules still need accepting, the box must be
  // ticked; then POST /account/accept-terms with the current version.
  async function acceptTerms(form) {
    const box = form.querySelector('.disc-terms');
    if (!box || box.hidden || !needTerms()) return;
    if (!box.querySelector('input[type=checkbox]').checked) throw { code: 'terms_unchecked' };
    await post('/account/accept-terms', { version: state.viewer.terms_version });
    state.viewer.post_refusal = null;
    sec.querySelectorAll('form').forEach(termsBlock);
  }
  let lastLen = 0; // characters of the last body sent
  function bodyOf(form) {
    const s = form.querySelector('textarea[data-f=body]').value;
    const n = chars(s);
    lastLen = n;
    if (n === 0) throw { code: 'empty' };
    if (n > limits.max_body_chars) throw { code: 'too_long', n };
    return s;
  }
  function onSubmit(form, fn) {
    form.addEventListener('submit', (ev) => {
      ev.preventDefault();
      run(form.querySelector('button[type=submit]'), form.querySelector('.acct-st'), () => fn(form));
    });
  }

  // purposeBox wires a form's purpose drop-down (top-level comments): the
  // text box suggests what a reproduction or fix report should contain
  // (a placeholder only: nothing is required). It returns the drop-down.
  function purposeBox(form, value) {
    const sel = form.querySelector('select[data-f=purpose]');
    const ta = form.querySelector('textarea[data-f=body]');
    if (!sel || !ta) return null;
    if (typeof value === 'string' && PURPOSES.has(value)) sel.value = value;
    const upd = () => {
      if (HINTED.has(sel.value)) ta.setAttribute('placeholder', msg('disc.purpose_hint#' + sel.value));
      else ta.removeAttribute('placeholder');
    };
    sel.addEventListener('change', upd);
    upd();
    return sel;
  }
  const purposeOf = (sel) => (sel && PURPOSES.has(sel.value) ? sel.value : null);

  // ---- the compose box (new top-level comment)
  let composeWired = false;
  function compose() {
    const form = $('disc-new');
    form.hidden = false;
    if (composeWired) {
      termsBlock(form);
      return;
    }
    composeWired = true;
    wire(form);
    const sel = purposeBox(form);
    onSubmit(form, async () => {
      const body = bodyOf(form);
      await acceptTerms(form);
      const purpose = purposeOf(sel);
      const j = await post('/api/discuss/' + cve, purpose ? { body, lang: locale, purpose } : { body, lang: locale });
      reload(j.comment && j.comment.id);
    });
  }

  // ---- controls of one comment. Reply, edit, report and hide open their
  // form in a detail right under the actions (app.js "row details": one
  // open per thread, Escape or cancel closes it and gives the focus back to
  // its button, which app.js also focuses into the form). A form is built
  // on its first opening and kept, with what was typed, until the page
  // reloads.
  let subN = 0;
  function subBox(acts, from) {
    const box = el('div', 'row-detail');
    box.id = 'disc-x' + (++subN);
    box.hidden = true;
    from.setAttribute('data-rowx', '');
    from.setAttribute('aria-expanded', 'false');
    from.setAttribute('aria-controls', box.id);
    acts.parentNode.appendChild(box);
    return box;
  }
  // openSub runs on the button's click, before app.js opens the detail
  function openSub(box, tplID, setup, submit) {
    if (box.firstChild) return;
    const form = wire(clone(tplID));
    box.appendChild(form);
    if (setup) setup(form);
    onSubmit(form, submit);
  }

  function attach(c, v) {
    if (!c || typeof c.id !== 'string' || !UUID.test(c.id)) return;
    const art = $('c-' + c.id);
    if (!art) return; // not rendered (yet) on this page
    art.querySelectorAll(':scope > .cm-acts, :scope > .row-detail, :scope > .cm-note, :scope > .cm-src, :scope > .cm-revs').forEach((el) => el.remove());
    // the author of a hidden comment sees why; moderators see the source of
    // hidden and deleted comments (as text)
    if (c.status === 'hidden' && c.moderation && typeof c.moderation.hidden_reason === 'string') {
      const p = d.createElement('p');
      p.className = 'cm-note';
      put(p, 'disc.hidden_reason', { reason: c.moderation.hidden_reason });
      art.appendChild(p);
    }
    if (v.moderator && c.status !== 'visible' && typeof c.body === 'string') {
      const p = d.createElement('p');
      p.className = 'cm-note';
      put(p, 'disc.mod.source');
      const pre = d.createElement('pre');
      pre.className = 'cm-src';
      pre.setAttribute('dir', 'auto');
      pre.textContent = c.body;
      art.appendChild(p);
      art.appendChild(pre);
    }
    if (v.moderator && c.moderation && c.moderation.revisions > 0) revisions(art, c);
    const acts = clone('disc-tpl-acts');
    const st = acts.querySelector('.acct-st');
    const btn = (name, show) => {
      const b = acts.querySelector('[data-act=' + name + ']');
      b.hidden = !show;
      return b;
    };
    const top = c.parent_id === null;
    const replies = Array.isArray(c.replies) ? c.replies.length : 0;
    const reply = btn('reply', c.can_reply || (top && c.status === 'visible' && needTerms() && replies < limits.max_replies));
    const edit = btn('edit', c.can_edit && typeof c.body === 'string');
    const del = btn('delete', c.can_delete);
    const report = btn('report', c.can_report && !c.reported);
    const reported = btn('reported', !!c.reported);
    const hide = btn('hide', c.can_hide);
    const unhide = btn('unhide', c.can_unhide);
    if (![reply, edit, del, report, reported, hide, unhide].some((b) => !b.hidden)) return;
    art.appendChild(acts);
    const boxOf = (b) => (b.hidden ? null : subBox(acts, b));
    const replyBox = boxOf(reply);
    const editBox = boxOf(edit);
    const reportBox = boxOf(report);
    const hideBox = boxOf(hide);

    if (replyBox) reply.addEventListener('click', () => openSub(replyBox, 'disc-tpl-reply', null, async (form) => {
      const body = bodyOf(form);
      await acceptTerms(form);
      const j = await post('/api/discuss/' + cve, { body, lang: locale, parent_id: c.id });
      reload(j.comment && j.comment.id);
    }));
    let editSel = null;
    if (editBox) edit.addEventListener('click', () => openSub(editBox, 'disc-tpl-edit', (form) => {
      const ta = form.querySelector('textarea');
      ta.value = c.body;
      ta.dispatchEvent(new Event('input'));
      const box = form.querySelector('.disc-purpose');
      if (!top && box) box.remove(); // replies have no purpose
      editSel = top ? purposeBox(form, c.purpose) : null;
    }, async (form) => {
      const body = bodyOf(form);
      // top level: the purpose as chosen (null = none); replies: body only
      await post(commentPath(c.id, 'edit'), top ? { body, purpose: purposeOf(editSel) } : { body });
      reload(c.id);
    }));
    del.addEventListener('click', () => {
      if (!nday.confirmStep(del, msg('disc.delete_confirm'))) return; // first click arms, second click deletes
      run(del, st, async () => {
        await post(commentPath(c.id, 'delete'));
        reload(c.parent_id || c.id);
      });
    });
    if (reportBox) report.addEventListener('click', () => openSub(reportBox, 'disc-tpl-report', null, async (form) => {
      const reason = form.querySelector('[data-f=reason]').value;
      const note = form.querySelector('[data-f=note]').value.trim();
      if (chars(note) > limits.max_note_chars) throw { code: 'bad_note' };
      const j = await post(commentPath(c.id, 'report'), note ? { reason, note } : { reason });
      nday.rowClose(report, false);
      reportBox.remove();
      report.hidden = true;
      reported.hidden = false;
      reported.setAttribute('tabindex', '-1');
      reported.focus(); // the form (and the focused control) is gone
      say(st, j.already_reported ? 'disc.report.already' : 'disc.report.done', null, 'ok');
    }));
    if (hideBox) hide.addEventListener('click', () => openSub(hideBox, 'disc-tpl-hide', null, async (form) => {
      const reason = form.querySelector('[data-f=reason]').value.trim();
      if (!reason) throw { code: 'bad_reason' };
      await post(commentPath(c.id, 'hide'), { reason });
      reload(c.id);
    }));
    unhide.addEventListener('click', () => run(unhide, st, async () => {
      await post(commentPath(c.id, 'unhide'));
      reload(c.id);
    }));
  }

  // revisions: moderators see a comment's earlier texts (GET
  // /api/mod/comment/{id}/revisions, newest first) as plain text.
  function revisions(art, c) {
    const box = d.createElement('div');
    box.className = 'cm-revs';
    const b = d.createElement('button');
    b.type = 'button';
    b.className = 'btn sm';
    b.setAttribute('aria-expanded', 'false');
    put(b, 'disc.mod.revisions', { n: c.moderation.revisions });
    const st = d.createElement('p');
    st.className = 'acct-st';
    st.setAttribute('role', 'status');
    st.setAttribute('aria-live', 'polite');
    const list = d.createElement('div');
    list.className = 'cm-revs';
    list.hidden = true;
    box.appendChild(b);
    box.appendChild(list);
    box.appendChild(st);
    art.appendChild(box);
    b.addEventListener('click', () => {
      if (list.childNodes.length) {
        list.hidden = !list.hidden;
        b.setAttribute('aria-expanded', String(!list.hidden));
        return;
      }
      run(b, st, async () => {
        const j = await getJSON('/api/mod/comment/' + c.id + '/revisions');
        (j.revisions || []).forEach((rv) => {
          const p = d.createElement('p');
          put(p, 'disc.mod.revision_at', { time: nday.localTime(rv.replaced_at, 'long') });
          if (typeof rv.purpose === 'string' && PURPOSES.has(rv.purpose)) {
            const tag = d.createElement('span');
            tag.className = 'cm-purpose';
            put(tag, 'disc.purpose#' + rv.purpose);
            p.appendChild(d.createTextNode(' '));
            p.appendChild(tag);
          }
          const pre = d.createElement('pre');
          pre.className = 'cm-src';
          pre.setAttribute('dir', 'auto');
          pre.textContent = String(rv.body);
          list.appendChild(p);
          list.appendChild(pre);
        });
        list.hidden = false;
        b.setAttribute('aria-expanded', 'true');
      });
    });
  }

  const states = ['disc-out', 'disc-nohandle', 'disc-susp', 'disc-new', 'disc-unknown'];
  function only(id) {
    states.forEach((s) => { const el = $(s); if (el) el.hidden = s !== id; });
    // the formatting help goes with the compose box: only for those who can write
    const md = $('disc-md');
    if (md) md.hidden = id !== 'disc-new';
  }
  function render() {
    const v = state.viewer;
    if (!v.signed_in) only('disc-out');
    else if (v.post_refusal === 'suspended') only('disc-susp');
    else if (v.post_refusal === 'handle_required') only('disc-nohandle');
    else {
      only('disc-new');
      compose();
    }
    sec.querySelectorAll('article.cm[data-id]').forEach((art) => {
      const c = byID.get(art.dataset.id);
      if (c) attach(c, v);
    });
  }

  // ---- rendering the comments (signed in)
  const byID = new Map(); // id -> the comment's JSON
  function el(name, cls) {
    const e = d.createElement(name);
    if (cls) e.className = cls;
    return e;
  }
  const BODY = new Set(['p', 'br', 'pre', 'code', 'blockquote', 'ul', 'ol', 'li', 'em', 'strong', 'a']);
  const LINK = /^(https?:\/\/[\x21-\x7e]+|\/[A-Za-z0-9._~\-\/]*)$/;
  const REL = 'nofollow ugc noopener noreferrer';
  // away: a link off the site (not this host, the site's other hosts or a
  // subdomain of it) opens in a new tab
  const ROOT = window.location.hostname.replace(/^www\./, '');
  function away(href) {
    let h;
    try {
      h = new URL(href, window.location.origin).hostname;
    } catch (_) {
      return true;
    }
    return !(h === ROOT || h.endsWith('.' + ROOT));
  }
  // build appends body_nodes: strings become text nodes, objects elements of
  // the allowlist (a link only with an http(s) URL or a site path); anything
  // else is dropped.
  function build(parent, nodes, depth) {
    if (!Array.isArray(nodes) || depth > 64) return;
    nodes.forEach((n) => {
      if (typeof n === 'string') {
        parent.appendChild(d.createTextNode(n));
        return;
      }
      if (!n || typeof n.e !== 'string' || !BODY.has(n.e)) return;
      const target = n.e === 'a' ? n.href : null;
      if (n.e === 'a' && !(typeof target === 'string' && LINK.test(target) && !target.startsWith('//'))) {
        build(parent, n.c, depth + 1);
        return;
      }
      const e = d.createElement(n.e);
      if (n.e === 'a') {
        e.setAttribute('href', target);
        e.setAttribute('rel', REL);
        if (away(target)) e.target = '_blank';
      }
      build(e, n.c, depth + 1);
      parent.appendChild(e);
    });
  }
  const langNames = new Map();
  d.querySelectorAll('.langs a[hreflang]').forEach((a) => langNames.set(a.getAttribute('hreflang').toLowerCase(), a.textContent));
  function stamp(iso) {
    const t = el('time');
    t.setAttribute('datetime', String(iso));
    t.textContent = nday.localTime ? nday.localTime(String(iso), 'long') || String(iso) : String(iso);
    return t;
  }
  function article(c) {
    if (!c || typeof c.id !== 'string' || !UUID.test(c.id)) return null;
    byID.set(c.id, c);
    const shown = c.status === 'visible' && Array.isArray(c.body_nodes);
    const art = el('article', 'cm');
    if (c.parent_id) art.classList.add('cm-reply');
    if (!shown) art.classList.add('cm-ph');
    art.id = 'c-' + c.id;
    art.dataset.id = c.id;
    art.dataset.status = shown ? 'visible' : (c.status === 'deleted' ? 'deleted' : 'hidden');
    const h = el('p', 'cm-h');
    if (shown) {
      if (c.author && typeof c.author.handle === 'string') {
        const b = el('bdi', 'cm-au');
        b.textContent = '@' + c.author.handle;
        h.appendChild(b);
        if (c.author.role === 'moderator' || c.author.role === 'admin') {
          const rb = el('span', 'rb');
          put(rb, 'acct.role.badge#' + c.author.role);
          h.appendChild(rb);
        }
      } else {
        const g = el('span', 'cm-au');
        g.classList.add('weak');
        put(g, 'disc.comment.deleted_account');
        h.appendChild(g);
      }
      if (!c.parent_id && typeof c.purpose === 'string' && PURPOSES.has(c.purpose)) {
        const g = el('span', 'cm-purpose');
        put(g, 'disc.purpose#' + c.purpose);
        h.appendChild(g);
      }
    }
    const a = el('a', 'cm-time');
    a.setAttribute('href', (shown ? '?c=' + c.id : '') + '#c-' + c.id);
    a.setAttribute('title', msg('disc.comment.permalink'));
    a.appendChild(stamp(c.created_at));
    h.appendChild(a);
    if (shown && c.edited_at) {
      const e = el('span', 'cm-ed');
      e.setAttribute('title', String(c.edited_at));
      put(e, 'disc.comment.edited');
      h.appendChild(e);
    }
    if (shown && typeof c.lang === 'string' && c.lang && c.lang.toLowerCase() !== locale.toLowerCase()) {
      const g = el('span', 'cm-lang');
      g.setAttribute('title', msg('disc.comment.lang', { language: langNames.get(c.lang.toLowerCase()) || c.lang }));
      g.textContent = c.lang;
      h.appendChild(g);
    }
    art.appendChild(h);
    if (shown) {
      const b = el('div', 'cm-body');
      if (typeof c.lang === 'string' && /^[A-Za-z]{2,3}(-[A-Za-z0-9]{2,8})*$/.test(c.lang)) b.setAttribute('lang', c.lang);
      b.setAttribute('dir', 'auto');
      build(b, c.body_nodes, 0);
      art.appendChild(b);
    } else {
      const g = el('p', 'cm-gone');
      put(g, c.status === 'deleted' ? 'disc.comment.deleted' : 'disc.comment.hidden');
      art.appendChild(g);
    }
    return art;
  }
  // moreReplies offers the continuation of a thread the server cut.
  function moreReplies(li, ol, c) {
    li.querySelectorAll(':scope > .cm-more').forEach((x) => x.remove());
    if (!c.replies_truncated || typeof c.replies_next_cursor !== 'string') return;
    const p = el('p', 'disc-page');
    p.classList.add('cm-more');
    const b = el('button', 'btn sm');
    b.type = 'button';
    put(b, 'disc.more_replies');
    const st = el('p', 'acct-st');
    p.appendChild(b);
    p.appendChild(st);
    li.appendChild(p);
    b.addEventListener('click', () => run(b, st, () => moreRepliesNow(li, ol, c)));
  }
  async function moreRepliesNow(li, ol, c) {
    const j = await more({ thread: c.id, cursor: c.replies_next_cursor });
    const t = j.comments[0];
    if (!t || t.id !== c.id) throw { code: 'internal' };
    (t.replies || []).forEach((r) => {
      const a = article(r);
      if (!a) return;
      const item = el('li');
      item.appendChild(a);
      ol.appendChild(item);
      attach(r, state.viewer);
    });
    c.replies_truncated = t.replies_truncated;
    c.replies_next_cursor = t.replies_next_cursor;
    moreReplies(li, ol, c);
  }
  function thread(list, c) {
    const top = article(c);
    if (!top) return;
    const li = el('li', 'cm-thread');
    li.setAttribute('data-rows', ''); // one open form per thread (app.js "row details")
    li.appendChild(top);
    const ol = el('ol', 'cm-replies');
    ol.setAttribute('aria-label', msg('disc.replies_label'));
    (c.replies || []).forEach((r) => {
      const a = article(r);
      if (!a) return;
      const item = el('li');
      item.appendChild(a);
      ol.appendChild(item);
    });
    li.appendChild(ol);
    moreReplies(li, ol, c);
    list.appendChild(li);
  }
  let nextCursor = null;
  function morePages(box, list) {
    box.querySelectorAll(':scope > .disc-next').forEach((x) => x.remove());
    if (typeof nextCursor !== 'string' || !nextCursor) return;
    const p = el('p', 'disc-page');
    p.classList.add('disc-next');
    const b = el('button', 'btn sm');
    b.type = 'button';
    put(b, 'disc.more');
    const st = el('p', 'acct-st');
    p.appendChild(b);
    p.appendChild(st);
    box.appendChild(p);
    b.addEventListener('click', () => run(b, st, async () => {
      const j = await more({ cursor: nextCursor });
      j.comments.forEach((c) => thread(list, c));
      j.comments.forEach((c) => {
        attach(c, state.viewer);
        (c.replies || []).forEach((r) => attach(r, state.viewer));
      });
      nextCursor = j.next_cursor;
      morePages(box, list);
    }));
  }
  // renderList replaces the outline with the comments of state.
  function renderList() {
    const box = $('disc-list');
    const veil = $('disc-veil');
    if (veil) veil.remove();
    box.replaceChildren();
    if (state.cursor) { // a later page (a permalink): offer the first one
      const p = el('p', 'disc-page');
      const a = el('a');
      a.setAttribute('href', '#discussion');
      put(a, 'disc.first');
      a.addEventListener('click', (ev) => {
        ev.preventDefault();
        reload('');
      });
      p.appendChild(a);
      box.appendChild(p);
    }
    const list = el('ol', 'cm-list');
    state.comments.forEach((c) => thread(list, c));
    if (state.comments.length) box.appendChild(list);
    else if (!state.cursor) {
      const p = el('p', 'note');
      put(p, 'disc.empty');
      box.appendChild(p);
    }
    nextCursor = state.next_cursor;
    morePages(box, list);
  }
  // reveal: a permalinked reply cut off its thread: continue that thread
  // (at most 10 times) until the reply is there.
  async function reveal() {
    const c = (new URLSearchParams(window.location.search).get('c') || '').toLowerCase();
    for (let i = 0; i < 10 && UUID.test(c) && !$('c-' + c); i++) {
      const b = sec.querySelector('.cm-more > button');
      if (!b) return;
      const li = b.closest('.cm-thread');
      const top = li && byID.get(li.querySelector('article.cm').dataset.id);
      if (!top) return;
      try {
        await moreRepliesNow(li, li.querySelector('.cm-replies'), top);
      } catch (_) {
        return;
      }
    }
  }

  // ---- researcher posts (signed in)
  const XPOST = /^https:\/\/x\.com\/(?:[A-Za-z0-9_]{1,15}|i\/web)\/status\/[0-9]{1,20}$/;
  const XUSER = /^https:\/\/x\.com\/[A-Za-z0-9_]{1,15}$/;
  const XREL = 'noopener noreferrer nofollow';
  const SHOW = 10; // posts shown before "show more"
  function xlink(a, href) {
    a.setAttribute('href', href);
    a.setAttribute('rel', XREL);
    if (away(href)) a.target = '_blank';
  }
  // t.co links of a post text shown as where they lead (the posts
  // document of docs/, section on display): linkParts splits the text
  // into pieces, {t} as posted or {t, href} for a short link whose resolved final URL is http/https
  // (shown without the scheme, cut to LINKMAX characters); a short link
  // without such a row stays text. Pure: no DOM (tested with node).
  // linkParts-begin
  const LINKMAX = 48;
  function linkLabel(u) {
    let s = u.host + u.pathname + u.search + u.hash;
    if (u.pathname === '/' && !u.search && !u.hash) s = u.host;
    return s.length > LINKMAX ? s.slice(0, LINKMAX - 1) + '\u2026' : s;
  }
  function linkParts(text, links) {
    const subs = [];
    (Array.isArray(links) ? links : []).forEach((l) => {
      if (!l || typeof l.short_url !== 'string' || !l.short_url || typeof l.final_url !== 'string') return;
      let u;
      try {
        u = new URL(l.final_url);
      } catch (_) {
        return;
      }
      if ((u.protocol !== 'http:' && u.protocol !== 'https:') || !u.host || u.username || u.password) return;
      subs.push({ s: l.short_url, href: u.href, t: linkLabel(u) });
    });
    const out = [];
    let i = 0;
    for (;;) {
      let best = null;
      let at = -1;
      subs.forEach((x) => {
        let k = text.indexOf(x.s, i);
        // a whole short link only: not the start of a longer one
        while (k >= 0 && /[A-Za-z0-9]/.test(text.charAt(k + x.s.length))) k = text.indexOf(x.s, k + 1);
        if (k >= 0 && (at < 0 || k < at || (k === at && x.s.length > best.s.length))) {
          at = k;
          best = x;
        }
      });
      if (!best) break;
      if (at > i) out.push({ t: text.slice(i, at) });
      out.push({ t: best.t, href: best.href });
      i = at + best.s.length;
    }
    if (i < text.length || !out.length) out.push({ t: text.slice(i) });
    return out;
  }
  // linkParts-end
  function postItem(p) {
    const li = el('li', 'rp');
    const h = el('p', 'rp-h');
    const handle = typeof p.author_handle === 'string' ? p.author_handle : '';
    if (typeof p.author_url === 'string' && XUSER.test(p.author_url) && handle) {
      const a = el('a', 'rp-au');
      xlink(a, p.author_url);
      a.textContent = '@' + handle;
      h.appendChild(a);
    } else if (handle) {
      const b = el('bdi', 'rp-au');
      b.textContent = '@' + handle;
      h.appendChild(b);
    }
    const t = stamp(p.posted_at);
    t.classList.add('rp-t');
    h.appendChild(t);
    li.appendChild(h);
    const tx = el('p', 'rp-tx');
    tx.setAttribute('dir', 'auto');
    if (typeof p.lang === 'string' && /^[A-Za-z]{2,3}(-[A-Za-z0-9]{2,8})?$/.test(p.lang)) tx.setAttribute('lang', p.lang);
    linkParts(String(p.text || ''), p.links).forEach((x) => {
      if (!x.href) {
        tx.appendChild(d.createTextNode(x.t));
        return;
      }
      const a = el('a', 'rp-l');
      xlink(a, x.href);
      a.setAttribute('title', x.href);
      a.textContent = x.t;
      tx.appendChild(a);
    });
    li.appendChild(tx);
    if (typeof p.url === 'string' && XPOST.test(p.url)) {
      const a = el('a', 'rp-x');
      xlink(a, p.url);
      put(a, 'rsch.view_on_x');
      li.appendChild(a);
    }
    return li;
  }
  // the posts' dots on the lifecycle chart (app.js; chartdots.go): each
  // line of a popover names a post of the outline (data-ri, its index, and
  // data-day, its UTC day); a signed-in visitor also gets a short excerpt
  // and the link to the post, when the post at that index is of that day.
  const EXCERPT = 90;
  function enrichDots(list) {
    d.querySelectorAll('.dpop [data-ri]').forEach((li) => {
      const p = list[Number(li.dataset.ri)];
      if (!p || typeof p.posted_at !== 'string' || p.posted_at.slice(0, 10) !== li.dataset.day || li.querySelector('.dp-tx')) return;
      const text = Array.from(String(p.text || '').replace(/\s+/g, ' ').trim());
      if (text.length) {
        // the excerpt is the link to the post (no separate "view on X")
        const linked = typeof p.url === 'string' && XPOST.test(p.url);
        const tx = el(linked ? 'a' : 'span', 'dp-tx');
        if (linked) xlink(tx, p.url);
        tx.setAttribute('dir', 'auto');
        if (typeof p.lang === 'string' && /^[A-Za-z]{2,3}(-[A-Za-z0-9]{2,8})?$/.test(p.lang)) tx.setAttribute('lang', p.lang);
        tx.textContent = text.length > EXCERPT ? text.slice(0, EXCERPT - 1).join('') + '\u2026' : text.join('');
        li.appendChild(tx);
      }
    });
  }
  async function researchers(me) {
    const box = $('research');
    const rcve = (box && box.dataset.cve) || '';
    if (!box || !CVE.test(rcve) || !me || !me.signed_in) return;
    let j;
    try {
      j = await getJSON('/api/posts/' + rcve);
    } catch (_) {
      const veil = $('rsch-veil');
      if (veil) {
        const p = el('p', 'note');
        put(p, 'rsch.failed');
        veil.replaceChildren(p);
      }
      return;
    }
    if (!j.signed_in || !Array.isArray(j.posts)) return;
    const veil = $('rsch-veil');
    if (veil) veil.remove();
    let list = $('rsch-list');
    if (!list) {
      if (!j.posts.length) return; // the page already says there are none
      list = el('ol', 'rp-list');
      list.id = 'rsch-list';
      box.appendChild(list);
    }
    enrichDots(j.posts);
    list.classList.remove('veil');
    list.replaceChildren();
    j.posts.forEach((p, i) => {
      const li = postItem(p);
      if (i >= SHOW) li.hidden = true;
      list.appendChild(li);
    });
    if (!j.posts.length) {
      const p = el('p', 'note');
      put(p, 'rsch.empty');
      list.replaceWith(p);
      return;
    }
    if (j.posts.length > SHOW) {
      const b = el('button', 'btn sm');
      b.type = 'button';
      put(b, 'rsch.more', { n: j.posts.length - SHOW });
      b.addEventListener('click', () => {
        list.querySelectorAll('li[hidden]').forEach((li) => { li.hidden = false; });
        b.remove();
      });
      list.after(b);
    }
  }

  nday.me.then(async (me) => {
    researchers(me);
    if (!sec || !CVE.test(cve)) {
      cleanURL();
      return;
    }
    if (me && me.disabled) { // accounts are off: read only, no call to action
      const w = $('disc-write');
      if (w) w.hidden = true;
      cleanURL();
      return;
    }
    if ((!me || !me.signed_in) && guest) {
      // signed-out reading: the comments for everyone, no writing control
      // (the server gives an anonymous caller no can_* and no source)
      try {
        await load();
      } catch (_) {
        const t = $('disc-veil-t');
        if (t) put(t, 'disc.unavailable');
        only(me ? 'disc-out' : 'disc-unknown');
        cleanURL();
        return;
      }
      renderList();
      render();
      if (!me) only('disc-unknown');
      await reveal();
      cleanURL();
      return;
    }
    if (!me) {
      only('disc-unknown');
      cleanURL();
      return;
    }
    if (!me.signed_in) {
      if (!$('disc-veil')) only('disc-out'); // the outline already carries the call to sign in
      cleanURL();
      return;
    }
    csrf = me.csrf_token || '';
    try {
      await load();
    } catch (_) {
      only('disc-unknown');
      cleanURL();
      return;
    }
    renderList();
    render();
    await reveal();
    cleanURL();
  });
})();
