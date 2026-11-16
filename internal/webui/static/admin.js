// nday: the staff back office (loaded only on /admin pages; see
// internal/webui/admin.go and docs/admin.md). The pages are rendered by the
// server for the signed-in staff member; this script only performs the
// actions and then reloads the page.
//
// Rules (checked by tests in internal/webui):
//   - data reaches the DOM only through textContent and properties; no
//     markup is ever built from strings;
//   - the CSRF token lives in this closure only and is sent only as the
//     X-CSRF-Token header;
//   - every request is a same-origin POST to a fixed path built from a UUID
//     taken from the page, with credentials: same-origin and a JSON body;
//   - navigation: a reload of this page after a success, or a sign-in
//     start_url from the server that begins with /auth/ (re-verification).
(() => {
  'use strict';
  const d = document;
  const main = d.querySelector('main[data-page="admin"]');
  const nday = window.nday;
  if (!main || !nday || !nday.me) return;
  const tpl = d.getElementById('acct-msgs');
  const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
  let csrf = '';
  let me = null;

  // ---- words (rendered by the server into <template id="acct-msgs">)
  const srcOf = (key) => (tpl ? tpl.content.querySelector('[data-k="' + key + '"]') : null);
  function msg(key, vars) {
    const el = srcOf(key);
    const s = el ? el.textContent : '';
    return s.replace(/\{([a-z_]+)\}/g, (all, n) => (vars && n in vars ? String(vars[n]) : all));
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
    el.textContent = key ? msg(key, vars) : '';
    const s = key && srcOf(key);
    if (s && s.getAttribute('lang')) el.setAttribute('lang', s.getAttribute('lang'));
    else el.removeAttribute('lang');
  }
  const stOf = (node) => {
    const box = node && node.closest('form, .acct-panel, article, section');
    return box ? box.querySelector('.acct-st') : null;
  };

  // ---- errors -> messages
  const known = new Set(['reauth_required', 'self', 'protected', 'no_change', 'not_found', 'forbidden', 'bad_reason',
    'bad_duration', 'bad_role', 'rate_limited', 'csrf', 'cross_site', 'not_signed_in', 'wrong_status', 'suspended', 'network',
    'exists', 'bad_user_id', 'bad_handle', 'bad_note', 'bad_setting', 'bad_import', 'too_large',
    'stale_version', 'too_long', 'bad_body', 'bad_post_url',
    'x_lookup_off', 'x_not_found', 'x_unavailable', 'x_rate_limited', 'x_auth', 'x_upstream', 'no_handle',
    'settings_off', 'no_master_key', 'unknown_setting', 'secret_setting', 'not_secret', 'bad_secret', 'sign_in_off']);
  function errKey(e) {
    if (e && (e.name === 'NotAllowedError' || e.name === 'AbortError')) return ['acct.err.webauthn_cancelled'];
    if (e && (e.code === 'invalid_config' || e.code === 'not_applied')) {
      return ['admin.err.' + e.code, { keys: (Array.isArray(e.keys) ? e.keys : []).map(String).join(', ') || '\u2014' }];
    }
    if (e && e.code === 'note_required') return ['admin.corr.note_needed'];
    if (e && known.has(e.code)) return ['admin.err.' + e.code];
    if (e && e.status === 401) return ['admin.err.not_signed_in'];
    if (e && e.status === 429) return ['admin.err.rate_limited'];
    return ['admin.err.generic', { code: (e && (e.code || e.status || e.name)) || '?' }];
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
  const uuid = (s) => {
    const v = String(s || '').toLowerCase();
    if (!UUID.test(v)) throw { code: 'not_found' };
    return v;
  };
  // go navigates to a sign-in start URL from the server, and nothing else.
  function go(url) {
    if (typeof url !== 'string' || !url.startsWith('/auth/') || url.startsWith('//') || url.includes('\\')) {
      throw { code: 'bad_start_url' };
    }
    window.location.assign(url);
  }
  // the page itself, for the return after re-verification
  function here() {
    const p = window.location.pathname;
    return p.startsWith('/') && !p.startsWith('//') ? p : '/';
  }

  // one request per control at a time; success reloads the page
  async function run(btn, fn) {
    if (!btn || btn.getAttribute('aria-busy') === 'true') return;
    const st = stOf(btn);
    btn.setAttribute('aria-busy', 'true');
    btn.disabled = true;
    say(st, 'acct.busy');
    try {
      const stay = await fn();
      if (stay && stay.key) { // a preview or a result to read: show it, keep the page
        say(st, stay.key, stay.vars, 'ok');
        if (!stay.reload) return;
        await new Promise((ok) => setTimeout(ok, 2500)); // then show the new state
      } else {
        say(st, 'admin.msg.done', null, 'ok');
      }
      window.location.reload();
    } catch (e) {
      const [key, vars] = errKey(e);
      say(st, key, vars, 'err');
      if (e && e.code === 'reauth_required') openReauth(btn);
      if (e && e.code === 'csrf') refresh();
    } finally {
      btn.removeAttribute('aria-busy');
      btn.disabled = false;
    }
  }
  // a first click arms the button for 5 s, the second one acts
  function armed(btn) {
    if (btn.dataset.armed === '1') {
      clearTimeout(Number(btn.dataset.timer));
      btn.dataset.armed = '';
      btn.textContent = btn.dataset.label;
      return true;
    }
    btn.dataset.armed = '1';
    btn.dataset.label = btn.textContent;
    btn.textContent = msg('admin.msg.confirm');
    btn.dataset.timer = String(setTimeout(() => {
      btn.dataset.armed = '';
      btn.textContent = btn.dataset.label;
    }, 5000));
    return false;
  }

  async function refresh() {
    me = await nday.fetchMe();
    csrf = (me && me.signed_in && me.csrf_token) || '';
    return me;
  }

  // ---- moderation (the discussion endpoints, docs/discuss.md)
  d.querySelectorAll('form.adm-hide[data-act="hide"]').forEach((f) => {
    f.addEventListener('submit', (ev) => {
      ev.preventDefault();
      const btn = f.querySelector('button[type=submit]');
      const reason = f.querySelector('input').value.trim();
      if (!reason) {
        say(stOf(btn), 'admin.msg.reason_needed', null, 'err');
        return;
      }
      run(btn, () => api('/api/discuss/comment/' + uuid(f.dataset.id) + '/hide', { reason }));
    });
  });
  d.querySelectorAll('button[data-act="unhide"]').forEach((b) => {
    b.addEventListener('click', () => run(b, () => api('/api/discuss/comment/' + uuid(b.dataset.id) + '/unhide')));
  });
  d.querySelectorAll('button[data-act="dismiss"]').forEach((b) => {
    b.addEventListener('click', () => {
      if (!armed(b)) return;
      run(b, async () => {
        for (const id of String(b.dataset.reports || '').split(' ').filter(Boolean)) {
          try {
            await api('/api/mod/reports/' + uuid(id) + '/resolve', { resolution: 'dismissed' });
          } catch (e) {
            if (!e || e.code !== 'wrong_status') throw e; // already resolved meanwhile: fine
          }
        }
      });
    });
  });

  // ---- readers' corrections (/admin/corrections; docs/corrections.md):
  // accepting needs the public note, rejecting takes an optional internal one
  d.querySelectorAll('form.adm-corr[data-act="accept"], form.adm-corr[data-act="reject"]').forEach((f) => {
    f.addEventListener('submit', (ev) => {
      ev.preventDefault();
      const btn = f.querySelector('button[type=submit]');
      const note = f.querySelector('textarea, input').value.trim();
      const accept = f.dataset.act === 'accept';
      if (accept && !note) {
        say(stOf(btn), 'admin.corr.note_needed', null, 'err');
        return;
      }
      if (!armed(btn)) return;
      const body = accept ? { note } : (note ? { note } : {});
      run(btn, () => api('/api/corrections/item/' + uuid(f.dataset.id) + (accept ? '/accept' : '/reject'), body));
    });
  });

  // ---- user actions (/api/admin/users/{id}/..., admin only)
  const acts = d.querySelector('section.adm-actions[data-user]');
  if (acts) {
    const user = () => '/api/admin/users/' + uuid(acts.dataset.user) + '/';
    const sf = d.getElementById('f-suspend');
    if (sf) {
      sf.addEventListener('submit', (ev) => {
        ev.preventDefault();
        const btn = sf.querySelector('button[type=submit]');
        const reason = d.getElementById('in-sreason').value.trim();
        if (!reason) {
          say(stOf(btn), 'admin.msg.reason_needed', null, 'err');
          return;
        }
        if (!armed(btn)) return;
        run(btn, () => api(user() + 'suspend', { reason, duration: d.getElementById('in-sfor').value }));
      });
    }
    acts.querySelectorAll('button[data-act]').forEach((b) => {
      b.addEventListener('click', () => {
        if (!armed(b)) return;
        switch (b.dataset.act) {
          case 'unsuspend':
            run(b, () => api(user() + 'unsuspend'));
            break;
          case 'role':
            run(b, () => api(user() + 'role', { role: b.dataset.role === 'moderator' ? 'moderator' : 'user' }));
            break;
          case 'signout':
            run(b, () => api(user() + 'signout-all'));
            break;
        }
      });
    });
  }

  // ---- the X posts collector (/admin/x; /api/admin/x/..., admin only)
  const XID = /^[1-9][0-9]{0,18}$/;
  const xid = (s) => {
    const v = String(s || '');
    if (!XID.test(v)) throw { code: 'not_found' };
    return v;
  };
  const xs = d.getElementById('f-xset');
  if (xs) {
    const cost = d.getElementById('x-cost');
    const price = Number(cost.dataset.price);
    const runs = Number(cost.dataset.runs);
    const page = Number(cost.dataset.page);
    const fieldOf = (name) => xs.querySelector('.adm-field[data-field="' + name + '"]');
    // the value a numeric field will be saved with (NaN: invalid)
    const valueOf = (name) => {
      const f = fieldOf(name);
      if (f.querySelector('[data-def]').checked) return Number(f.dataset.default);
      const raw = f.querySelector('input.adm-num').value.trim();
      const n = Number(raw);
      if (!/^[0-9]+$/.test(raw) || n < Number(f.dataset.min) || n > Number(f.dataset.max)) return NaN;
      return n;
    };
    const money = (v) => (Number.isFinite(v) ? '$' + v.toFixed(2) : '\u2014');
    // worst case: max_posts, but never more than max_requests full pages
    function recompute() {
      const posts = Math.min(valueOf('max_posts'), valueOf('max_requests') * page);
      const run1 = posts * price;
      d.getElementById('x-worst-run').textContent = money(run1);
      d.getElementById('x-worst-day').textContent = money(run1 * runs);
      d.getElementById('x-worst-30').textContent = money(run1 * runs * 30);
      d.getElementById('x-worst-posts').textContent = msg('admin.x.worst_posts', { n: Number.isFinite(posts) ? posts : '\u2014' });
    }
    xs.querySelectorAll('.adm-field[data-default]').forEach((f) => {
      const inp = f.querySelector('input.adm-num');
      const def = f.querySelector('[data-def]');
      def.addEventListener('change', () => {
        inp.disabled = def.checked;
        if (def.checked) inp.value = f.dataset.default;
        recompute();
      });
      inp.addEventListener('input', recompute);
    });
    recompute();
    xs.addEventListener('submit', (ev) => {
      ev.preventDefault();
      const btn = xs.querySelector('button[type=submit]');
      xs.querySelectorAll('[data-err]').forEach((el) => say(el, ''));
      const sel = d.getElementById('x-enabled').value;
      const body = { enabled: sel === 'default' ? null : sel === 'on' };
      xs.querySelectorAll('.adm-field[data-default]').forEach((f) => {
        const raw = f.querySelector('input.adm-num').value.trim();
        body[f.dataset.field] = f.querySelector('[data-def]').checked ? null : (/^-?[0-9]{1,9}$/.test(raw) ? Number(raw) : raw);
      });
      if (!armed(btn)) return;
      run(btn, async () => {
        try {
          await api('/api/admin/x/settings', body);
        } catch (e) {
          const fields = (e && e.fields) || {};
          Object.keys(fields).forEach((k) => {
            const el = xs.querySelector('[data-err="' + k + '"]');
            if (el) say(el, 'admin.x.field_err#' + fields[k], null, 'err');
          });
          throw e;
        }
      });
    });
  }
  d.querySelectorAll('button[data-act="xenable"], button[data-act="xdisable"]').forEach((b) => {
    b.addEventListener('click', () => {
      if (!armed(b)) return;
      const verb = b.dataset.act === 'xenable' ? '/enable' : '/disable';
      run(b, () => api('/api/admin/x/accounts/' + xid(b.dataset.x) + verb));
    });
  });
  // allowlist candidates: add (stored id and handle, no lookup), dismiss, restore
  const CAND = { xcadd: '/add', xcdismiss: '/dismiss', xcrestore: '/restore' };
  d.querySelectorAll('button[data-act="xcadd"], button[data-act="xcdismiss"], button[data-act="xcrestore"]').forEach((b) => {
    b.addEventListener('click', () => {
      if (!armed(b)) return;
      run(b, () => api('/api/admin/x/candidates/' + xid(b.dataset.x) + CAND[b.dataset.act]));
    });
  });
  d.querySelectorAll('form.adm-xedit').forEach((f) => {
    f.addEventListener('submit', (ev) => {
      ev.preventDefault();
      const btn = f.querySelector('button[type=submit]');
      run(btn, () => api('/api/admin/x/accounts/' + xid(f.dataset.x) + '/update',
        { handle: f.elements.handle.value.trim(), note: f.elements.note.value.trim() }));
    });
  });
  const xa = d.getElementById('f-xadd');
  if (xa) {
    xa.addEventListener('submit', (ev) => {
      ev.preventDefault();
      const btn = xa.querySelector('button[type=submit]');
      run(btn, async () => {
        // the handle alone is enough: the server looks the id up on X
        const j = await api('/api/admin/x/accounts', { user_id: d.getElementById('x-add-id').value.trim(),
          handle: d.getElementById('x-add-handle').value.trim(), note: d.getElementById('x-add-note').value.trim() });
        const vars = { id: String(j.user_id || ''), handle: String(j.handle || ''), previous: String(j.previous_handle || '') };
        return { key: j.result === 'renamed' ? 'admin.x.add_renamed' : 'admin.x.add_done', vars, reload: true };
      });
    });
  }
  const xi = d.getElementById('f-ximport');
  if (xi) {
    const list = d.getElementById('x-import-lines');
    xi.querySelectorAll('button[data-act="ximport"]').forEach((b) => {
      b.addEventListener('click', () => {
        const dry = b.dataset.dry === '1';
        while (list.firstChild) list.removeChild(list.firstChild);
        if (!dry && !armed(b)) return;
        run(b, async () => {
          let j;
          try {
            j = await api('/api/admin/x/import', { text: d.getElementById('x-import').value, dry_run: dry });
          } catch (e) {
            ((e && e.lines) || []).forEach((l) => {
              const li = d.createElement('li');
              li.textContent = msg('admin.x.import_line', { line: l.line, message: l.message });
              list.appendChild(li);
            });
            throw e;
          }
          const vars = { inserted: j.inserted, updated: j.updated, unchanged: j.unchanged };
          if (!dry) return null;
          // the id found for each handle-only line
          (j.lines || []).filter((l) => l && l.looked_up).forEach((l) => {
            const li = d.createElement('li');
            li.textContent = msg('admin.x.import_found', { line: l.line, handle: l.handle, id: l.user_id });
            list.appendChild(li);
          });
          return { key: 'admin.x.import_preview', vars };
        });
      });
    });
  }

  // ---- draft posts for X (/admin/x/drafts; /api/admin/x/drafts/{id}/..., admin only).
  // Publishing is a plain link to X's compose window in the page; this
  // script only saves, marks posted, discards and restores.
  const DID = /^[1-9][0-9]{0,17}$/;
  const did = (s) => {
    const v = String(s || '');
    if (!DID.test(v)) throw { code: 'not_found' };
    return v;
  };
  const draft = (el) => '/api/admin/x/drafts/' + did(el.dataset.d) + '/';
  const ver = (el) => Number(el.dataset.v);
  // X's weighted length, an upper bound like the server's (internal/xdraft
  // WeightedLength) without its "sure link" rule: every code point counts on
  // its own (2 outside the light ranges, and for the emoji (c) and (r)), and
  // every dot that may end a domain name adds 19 (a link counts 23, the
  // shortest one weighs 4). It may show more than the server for text with
  // links; the server decides.
  const light = (c) => c <= 4351 || (c >= 8192 && c <= 8205) || (c >= 8208 && c <= 8223) || (c >= 8242 && c <= 8247);
  const DOT = /[.\u3002\uFF0E\uFF61]/;
  const LNM = /[\p{L}\p{N}\p{M}]/u;
  const LM = /[\p{L}\p{M}]/u;
  function weighted(text) {
    const cs = Array.from(String(text).normalize('NFC'));
    let n = 0;
    cs.forEach((ch, i) => {
      const c = ch.codePointAt(0);
      n += c === 0xA9 || c === 0xAE || !light(c) ? 2 : 1;
      if (DOT.test(ch) && i > 0 && i + 1 < cs.length && LNM.test(cs[i - 1]) && LM.test(cs[i + 1])) n += 19;
    });
    return n;
  }
  d.querySelectorAll('form.adm-xd[data-d]').forEach((f) => {
    const ta = f.elements.body;
    const len = f.querySelector('[data-len]');
    const open = f.querySelector('a[data-compose]');
    const over = f.querySelector('[data-over]');
    const unsaved = f.querySelector('[data-unsaved]');
    const max = Number(ta.dataset.max);
    const link = Number(ta.dataset.link);
    // the link opens the SAVED text (rendered by the server): hidden while
    // the text is edited and not saved, or too long
    const count = () => {
      const n = weighted(ta.value.trim()) + link;
      const tooLong = n > max;
      const dirty = ta.value !== ta.defaultValue;
      len.textContent = msg('admin.xd.length', { n, max });
      len.classList.toggle('bad', tooLong);
      if (open) open.hidden = tooLong || dirty;
      over.hidden = !tooLong;
      unsaved.hidden = !dirty || tooLong;
    };
    ta.addEventListener('input', count);
    f.addEventListener('submit', (ev) => {
      ev.preventDefault();
      const btn = f.querySelector('button[type=submit]');
      run(btn, () => api(draft(f) + 'save', { version: ver(f), body: ta.value }));
    });
  });
  d.querySelectorAll('form.adm-xdpost[data-d]').forEach((f) => {
    f.addEventListener('submit', (ev) => {
      ev.preventDefault();
      const btn = f.querySelector('button[type=submit]');
      if (!armed(btn)) return;
      run(btn, () => api(draft(f) + 'posted', { version: ver(f), post_url: f.elements.post_url.value.trim() }));
    });
  });
  d.querySelectorAll('button[data-act="xddiscard"], button[data-act="xdrestore"]').forEach((b) => {
    b.addEventListener('click', () => {
      if (!armed(b)) return;
      run(b, () => api(draft(b) + (b.dataset.act === 'xddiscard' ? 'discard' : 'restore'), { version: ver(b) }));
    });
  });

  // ---- database settings (/admin/settings; /api/admin/settings..., admin only).
  // Values are read from the form and sent once; the answer carries only
  // sources, stored plain values and the hints of secrets, shown in place
  // (no reload). A secret's input is emptied as soon as it was stored, also
  // when the answer is 500 not_applied (stored, not in force: that answer
  // carries the stored state too, and saving the form again, even
  // unchanged, asks the server to apply it again).
  const SKEY = /^NDAY_[A-Z0-9_]{1,60}$/;
  const skey = (s) => {
    const v = String(s || '');
    if (!SKEY.test(v)) throw { code: 'not_found' };
    return v;
  };
  const SRC = new Set(['db', 'env', 'default']);
  // show the state of every setting of an answer
  function showSettings(states) {
    Object.keys(states || {}).forEach((k) => {
      if (!SKEY.test(k)) return;
      const row = d.querySelector('[data-key="' + k + '"]');
      const st = states[k] || {};
      if (!row) return;
      const src = row.querySelector('[data-src]');
      if (src && SRC.has(st.source)) {
        src.className = 'adm-st ' + st.source;
        say(src, 'admin.set.source#' + st.source);
      }
      const sstate = row.querySelector('[data-sstate]');
      if (sstate) {
        if (st.set && st.hint) say(sstate, 'admin.set.secret_set_hint', { hint: String(st.hint) });
        else say(sstate, 'admin.set.secret_state#' + (st.set ? 'set' : st.stored ? 'unreadable' : 'unset'));
        const clr = row.querySelector('button[data-act="clearsecret"]');
        if (clr) {
          clr.dataset.stored = st.stored ? '1' : '';
          clr.disabled = !st.stored;
        }
        const box = d.querySelector('input[data-clear="' + k + '"]');
        if (box) {
          box.checked = false;
          box.parentNode.hidden = !st.stored;
        }
        return;
      }
      const inp = row.querySelector('[data-in]');
      if (!inp) return;
      const v = typeof st.value === 'string' ? st.value : '';
      if (inp.tagName.toLowerCase() === 'select') {
        let found = false;
        Array.from(inp.options).forEach((o) => {
          o.defaultSelected = o.value === v;
          found = found || o.value === v;
        });
        if (!found) inp.options[0].defaultSelected = true;
        inp.value = found ? v : '';
      } else {
        inp.defaultValue = v;
        inp.value = v;
      }
    });
  }
  // stored (committed) but not applied: show the stored state anyway
  const notApplied = (e) => !!(e && e.code === 'not_applied');
  function done(j) {
    showSettings(j.settings);
    const n = (j.changed || []).length;
    if (!n) return { key: 'admin.set.unchanged' };
    return { key: (j.restart || []).length ? 'admin.set.saved_restart' : 'admin.set.saved', vars: { n } };
  }
  // per-setting refusals under the fields
  function markFields(form, e) {
    const fields = (e && e.fields) || {};
    Object.keys(fields).forEach((k) => {
      const row = SKEY.test(k) && form.querySelector('[data-key="' + k + '"]');
      if (row) say(row.querySelector('[data-err]'), 'admin.set.field_err#' + (fields[k] === 'conflict' ? 'conflict' : 'value'), null, 'err');
    });
    const keys = (e && Array.isArray(e.keys) && e.keys) || [];
    if (e && e.param && !keys.includes(e.param)) keys.push(e.param);
    keys.forEach((k) => {
      const row = SKEY.test(String(k)) && form.querySelector('[data-key="' + k + '"]');
      if (row) say(row.querySelector('[data-err]'), 'admin.set.field_err#refused', null, 'err');
    });
  }
  d.querySelectorAll('form.adm-setform').forEach((f) => {
    f.addEventListener('submit', (ev) => {
      ev.preventDefault();
      const btn = f.querySelector('button[type=submit]');
      f.querySelectorAll('[data-err]').forEach((el) => say(el, ''));
      const set = {};
      const unset = [];
      f.querySelectorAll('.adm-field[data-key]').forEach((row) => {
        const inp = row.querySelector('[data-in]');
        const k = skey(row.dataset.key);
        let v;
        let was;
        if (inp.tagName.toLowerCase() === 'select') {
          v = inp.value;
          const def = Array.from(inp.options).find((o) => o.defaultSelected);
          was = def ? def.value : '';
        } else {
          v = inp.value.trim();
          was = inp.defaultValue.trim();
        }
        if (v === was) return;
        if (v === '') unset.push(k);
        else set[k] = v;
      });
      f.querySelectorAll('input[data-clear]:checked').forEach((b) => unset.push(skey(b.dataset.clear)));
      // (after a not_applied answer an unchanged save is still sent: the
      // server applies the stored state again)
      if (!Object.keys(set).length && !unset.length && main.dataset.notApplied !== '1') {
        say(stOf(btn), 'admin.set.unchanged', null, 'ok');
        return;
      }
      run(btn, async () => {
        try {
          const j = await api('/api/admin/settings', { set, unset });
          delete main.dataset.notApplied;
          return done(j);
        } catch (e) {
          if (notApplied(e)) {
            main.dataset.notApplied = '1';
            showSettings(e.settings);
          }
          markFields(f, e);
          throw e;
        }
      });
    });
  });
  d.querySelectorAll('form.adm-secret[data-key]').forEach((f) => {
    const inp = f.querySelector('input, textarea');
    f.addEventListener('submit', (ev) => {
      ev.preventDefault();
      const btn = f.querySelector('button[type=submit]');
      if (!inp.value.trim()) {
        say(stOf(btn), 'admin.set.secret_empty', null, 'err');
        return;
      }
      run(btn, async () => {
        let j;
        try {
          j = await api('/api/admin/settings/secret', { key: skey(f.dataset.key), value: inp.value });
        } catch (e) {
          if (notApplied(e)) { // stored: never keep the value in the page
            inp.value = '';
            main.dataset.notApplied = '1';
            showSettings(e.settings);
          }
          throw e;
        }
        inp.value = '';
        delete main.dataset.notApplied;
        return done(j);
      });
    });
    const clr = f.querySelector('button[data-act="clearsecret"]');
    clr.addEventListener('click', () => {
      if (!armed(clr)) return;
      // (run re-enables the button; nothing left to clear disables it again)
      run(clr, async () => {
        inp.value = '';
        let j;
        try {
          j = await api('/api/admin/settings/secret/clear', { key: skey(f.dataset.key) });
        } catch (e) {
          if (notApplied(e)) {
            main.dataset.notApplied = '1';
            showSettings(e.settings);
          }
          throw e;
        }
        delete main.dataset.notApplied;
        return done(j);
      }).then(() => {
        if (clr.dataset.stored === '') clr.disabled = true;
      });
    });
  });

  // ---- re-verification (the account page's panel; docs/auth.md section 1)
  const PKC = window.PublicKeyCredential;
  const webauthn = !!(PKC && navigator.credentials && navigator.credentials.get && window.isSecureContext);
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
  function requestOptions(pk) {
    if (typeof PKC.parseRequestOptionsFromJSON === 'function') return PKC.parseRequestOptionsFromJSON(pk);
    return Object.assign({}, pk, { challenge: b64u.dec(pk.challenge),
      allowCredentials: (pk.allowCredentials || []).map((c) => Object.assign({}, c, { id: b64u.dec(c.id) })) });
  }
  function credJSON(c) {
    if (typeof c.toJSON === 'function') {
      try {
        return c.toJSON();
      } catch (_) { /* build it below */ }
    }
    const r = c.response;
    return { id: c.id, rawId: b64u.enc(c.rawId), type: c.type, response: {
      clientDataJSON: b64u.enc(r.clientDataJSON), authenticatorData: b64u.enc(r.authenticatorData),
      signature: b64u.enc(r.signature), userHandle: r.userHandle ? b64u.enc(r.userHandle) : null } };
  }
  const panel = d.getElementById('reauth');
  let reauthFrom = null;
  function openReauth(from) {
    if (!panel || !me || !me.user) return;
    reauthFrom = from;
    const linked = new Set((me.user.identities || []).map((i) => i.provider));
    const enabled = new Set(me.providers || []);
    let any = false;
    panel.querySelectorAll('[data-reauth]').forEach((b) => {
      const p = b.dataset.reauth;
      const ok = p === 'passkey'
        ? webauthn && me.passkeys && me.passkeys.enabled && (me.user.passkeys || []).length > 0
        : linked.has(p) && enabled.has(p);
      b.parentNode.hidden = !ok;
      any = any || ok;
    });
    d.getElementById('reauth-none').hidden = any;
    say(panel.querySelector('.acct-st'), '');
    panel.hidden = false;
    d.getElementById('reauth-h').focus();
  }
  if (panel) {
    panel.querySelectorAll('[data-reauth]').forEach((b) => {
      b.addEventListener('click', async () => {
        const st = panel.querySelector('.acct-st');
        b.disabled = true;
        say(st, 'acct.busy');
        try {
          const p = b.dataset.reauth;
          if (p !== 'passkey') {
            const j = await api('/auth/' + encodeURIComponent(p) + '/ticket', { intent: 'reauth', return: here() });
            go(j.start_url);
            return;
          }
          const { publicKey } = await api('/auth/passkey/login/begin');
          const cred = await navigator.credentials.get({ publicKey: requestOptions(publicKey) });
          await api('/auth/passkey/login/finish', credJSON(cred));
          await refresh();
          panel.hidden = true;
          say(stOf(reauthFrom), 'acct.reauth.done', null, 'ok');
          if (reauthFrom && reauthFrom.isConnected) reauthFrom.focus();
        } catch (e) {
          const [key, vars] = errKey(e);
          say(st, key, vars, 'err');
        } finally {
          b.disabled = false;
        }
      });
    });
    d.getElementById('reauth-close').addEventListener('click', () => {
      panel.hidden = true;
      if (reauthFrom && reauthFrom.isConnected) reauthFrom.focus();
    });
  }

  nday.me.then((m) => {
    me = m;
    csrf = (m && m.signed_in && m.csrf_token) || '';
  });
})();

// The visitor map of the statistics page (internal/webui/worldmap.go): an
// instant tooltip for every country and marker, read from its data-tip
// attribute (text only: textContent), on mouse hover and on tap (a tap
// elsewhere closes it), kept inside the map's box. The <title>s are the
// fallback without this script; they are removed so the browser does not
// show a second, delayed tooltip. Independent of the signed-in state above.
(() => {
  'use strict';
  const fig = document.getElementById('map-cc');
  const svg = fig && fig.querySelector('svg');
  const tip = fig && fig.querySelector('.adm-map-tip');
  if (!svg || !tip) return;
  svg.querySelectorAll('[data-tip] > title').forEach((t) => t.remove());
  const first = svg.querySelector('circle');
  let on = null;
  function hide() {
    tip.hidden = true;
    if (on) on.classList.remove('on');
    on = null;
  }
  function show(el, x, y) {
    if (on !== el) {
      if (on) on.classList.remove('on');
      on = el;
      el.classList.add('on');
      if (el.tagName.toLowerCase() === 'path') svg.insertBefore(el, first); // its outline above its neighbours, below the markers
      tip.textContent = el.getAttribute('data-tip') || '';
      tip.hidden = false;
    }
    const box = fig.getBoundingClientRect();
    const w = tip.offsetWidth;
    const h = tip.offsetHeight;
    let left = x - box.left + 12;
    let top = y - box.top - h - 10;
    if (left + w > box.width) left = x - box.left - w - 12;
    left = Math.max(0, Math.min(left, box.width - w));
    if (top < 0) top = y - box.top + 16;
    tip.style.left = left + 'px';
    tip.style.top = top + 'px';
  }
  const target = (e) => (e.target && e.target.closest ? e.target.closest('[data-tip]') : null);
  svg.addEventListener('pointermove', (e) => {
    if (e.pointerType !== 'mouse') return;
    const el = target(e);
    if (el) show(el, e.clientX, e.clientY);
    else hide();
  });
  svg.addEventListener('pointerleave', (e) => {
    if (e.pointerType === 'mouse') hide();
  });
  svg.addEventListener('click', (e) => {
    const el = target(e);
    if (el) show(el, e.clientX, e.clientY);
    else hide();
  });
  document.addEventListener('click', (e) => {
    if (on && !svg.contains(e.target)) hide();
  });
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') hide();
  });
})();
