// nday: colour theme, applied before first paint (render-blocking in <head>).
// localStorage "nday.theme" = dark | light | system; absent = dark. Sets
// <html data-theme="dark|light">; app.js wires the menu via nday.theme.
(function () {
  'use strict';
  var d = document, r = d.documentElement, KEY = 'nday.theme';
  var mq = window.matchMedia ? window.matchMedia('(prefers-color-scheme: light)') : null;
  var nday = window.nday = window.nday || {};
  function stored() {
    var v = null;
    try { v = window.localStorage.getItem(KEY); } catch (e) { /* storage off */ }
    return v === 'light' || v === 'system' ? v : 'dark';
  }
  var cur = stored();
  function apply() {
    var t = cur === 'light' || (cur === 'system' && mq && mq.matches) ? 'light' : 'dark';
    r.setAttribute('data-theme', t);
    var m = d.querySelector('meta[name="color-scheme"]');
    if (m) m.setAttribute('content', t);
    m = d.querySelector('meta[name="theme-color"]');
    if (m) m.setAttribute('content', t === 'light' ? '#F6F4EE' : '#0D1117');
    if (window.CustomEvent) d.dispatchEvent(new window.CustomEvent('nday:theme', { detail: cur }));
  }
  nday.theme = {
    get: function () { return cur; },
    set: function (p) {
      cur = p === 'light' || p === 'system' ? p : 'dark';
      try { window.localStorage.setItem(KEY, cur); } catch (e) { /* this page only */ }
      apply();
    }
  };
  // "system" follows the device while the page is open. The media query's
  // change event is not delivered everywhere (a page restored from the
  // back/forward cache, a tab that was in the background when the device
  // switched, some embedded browsers), so the setting is read again whenever
  // the page is shown or focused; applying it again is cheap and idempotent.
  function sys() {
    if (cur !== 'system') return;
    var want = mq && mq.matches ? 'light' : 'dark';
    if (r.getAttribute('data-theme') !== want) apply();
  }
  if (mq && mq.addEventListener) mq.addEventListener('change', sys);
  else if (mq && mq.addListener) mq.addListener(sys);
  window.addEventListener('pageshow', sys);
  window.addEventListener('focus', sys);
  d.addEventListener('visibilitychange', sys);
  // another tab changed the choice
  window.addEventListener('storage', function (e) {
    if (e.key === KEY || e.key === null) { cur = stored(); apply(); }
  });
  apply();
})();
