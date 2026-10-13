/* Memory web UI.
 *
 * Talks to the same-origin memory API. Auth is the HttpOnly session cookie
 * issued by /auth/login, so no token is ever held in JS. Every write carries
 * X-Memory-Actor: it names the commit in git log, and its presence is what the
 * server uses to tell "our page" apart from a cross-site request.
 */
(function () {
  'use strict';

  var ACTOR = 'memory-web';
  var WARN_BYTES = 16384;   // protocol soft cap is ~20 KB; start warning early
  var CAP_BYTES = 20480;
  var STALE_DAYS = 90;
  var RECENT_MAX = 8;
  var PALETTE_MAX = 30;

  // localStorage keys. The sidebar used to keep a list of *collapsed* names in
  // 'mem.collapsed'; the tree now stores explicit open/closed choices instead,
  // under a new key, and that old key is simply never read.
  var K_TREE = 'mem.tree';
  var K_GROUPS = 'mem.nav.groups';
  var K_STARRED = 'mem.starred';
  var K_RECENT = 'mem.recent';

  var e = MD.escape;
  var $ = function (id) { return document.getElementById(id); };

  var state = {
    index: [],
    docs: [],
    cat: null,     // active category name, when kind === 'c'
    doc: null,     // active doc slug, when kind === 'd'
    kind: null,    // 'c' | 'd' | null (home/search/new)
    body: '',
    etag: null,
    dirty: false,
    editing: false,
    suppressRoute: false
  };

  // one basePath per namespace -- everything else (etag flow, editor,
  // history, diff) is identical between the two, so this is the seam.
  function basePath(kind) { return kind === 'd' ? '/docs/' : '/memory/'; }

  // the full set of category and doc names, for MD.render's opts.known --
  // whatever a [[name]] / [[doc:slug]] points to that does not exist here
  // renders as a dead ref instead of a link into a 404.
  function knownRefs() {
    return {
      cats: state.index.map(function (c) { return c.category; }),
      docs: state.docs.map(function (d) { return d.doc; })
    };
  }

  /* ---------------------------------------------------------------- utils */

  function fmtBytes(n) {
    if (n === null || n === undefined) return '–';
    if (n < 1024) return n + ' B';
    return (n / 1024).toFixed(n < 10240 ? 1 : 0) + ' KB';
  }

  function fmtAgo(iso) {
    var t = Date.parse(iso);
    if (isNaN(t)) return '';
    var s = Math.floor((Date.now() - t) / 1000);
    if (s < 90) return 'just now';
    if (s < 5400) return Math.round(s / 60) + 'm ago';
    if (s < 172800) return Math.round(s / 3600) + 'h ago';
    if (s < 2592000) return Math.round(s / 86400) + 'd ago';
    return new Date(t).toISOString().slice(0, 10);
  }

  function toast(msg, bad) {
    var el = $('toast');
    el.textContent = msg;
    el.className = 'toast' + (bad ? ' bad' : '');
    clearTimeout(toast._t);
    toast._t = setTimeout(function () { el.className = 'toast hidden'; }, bad ? 6000 : 3000);
  }

  // Storage is a convenience, never a dependency: private mode and quota
  // errors fall back to the default.
  function lsGet(key) {
    try { return localStorage.getItem(key); } catch (_) { return null; }
  }
  function lsSet(key, val) {
    try { localStorage.setItem(key, JSON.stringify(val)); } catch (_) { /* private mode */ }
  }
  // a stored list of strings; anything else reads as empty
  function lsList(key) {
    var v;
    try { v = JSON.parse(lsGet(key) || '[]'); } catch (_) { return []; }
    return Array.isArray(v) ? v.filter(function (x) { return typeof x === 'string'; }) : [];
  }

  function modal(html) {
    var bg = document.createElement('div');
    bg.className = 'modal-bg';
    bg.innerHTML = '<div class="modal">' + html + '</div>';
    $('modal-root').appendChild(bg);
    function close() { bg.remove(); document.removeEventListener('keydown', onKey); }
    function onKey(ev) { if (ev.key === 'Escape') close(); }
    bg.addEventListener('click', function (ev) { if (ev.target === bg) close(); });
    document.addEventListener('keydown', onKey);
    return { root: bg, close: close, q: function (sel) { return bg.querySelector(sel); } };
  }

  /* ------------------------------------------------------------------ api */

  function api(path, opts) {
    opts = opts || {};
    var headers = { 'X-Memory-Actor': ACTOR };
    for (var k in (opts.headers || {})) headers[k] = opts.headers[k];
    return fetch(path, {
      method: opts.method || 'GET',
      headers: headers,
      body: opts.body,
      credentials: 'same-origin',
      cache: 'no-store'
    }).then(function (res) {
      if (res.status === 401) { showLogin(); throw new Error('signed out'); }
      return res;
    });
  }

  function apiJSON(path) {
    return api(path).then(function (res) {
      if (!res.ok) return res.text().then(function (t) { throw new Error(detail(t, res.status)); });
      return res.json();
    });
  }

  function detail(text, status) {
    try { return JSON.parse(text).detail || ('HTTP ' + status); } catch (_) { return 'HTTP ' + status; }
  }

  function getItem(kind, name, rev) {
    var url = basePath(kind) + encodeURIComponent(name) + (rev ? '?rev=' + encodeURIComponent(rev) : '');
    return api(url).then(function (res) {
      if (!res.ok) return res.text().then(function (t) { throw new Error(detail(t, res.status)); });
      return res.text().then(function (body) {
        return { body: body, etag: (res.headers.get('ETag') || '').replace(/"/g, '') };
      });
    });
  }

  function getCategory(cat, rev) { return getItem('c', cat, rev); }
  function getDoc(slug, rev) { return getItem('d', slug, rev); }

  /* ----------------------------------------------------------------- auth */

  // Last answer from /auth/me, so a session that expires mid-use returns to a
  // login page that still offers the button the user actually signs in with.
  var authInfo = { providers: [] };

  function showLogin(me) {
    if (me && me.providers) authInfo = me;
    me = authInfo;
    $('app').classList.add('hidden');
    $('login').classList.remove('hidden');
    // The passkey button is the primary way in, but only when the server has
    // passkeys configured AND this browser can do WebAuthn.
    var pk = !!(me && me.passkey === true && window.PublicKeyCredential && Passkey.supported());
    $('login-passkey').classList.toggle('hidden', !pk);
    // A provider button appears only when the server says that handshake is
    // configured -- offering one that answers 503 is worse than not offering
    // it, because the token field below is the actual way in.
    var on = (me && me.providers) || [];
    var oauth = false;
    ['google', 'github'].forEach(function (name) {
      var el = $('login-' + name);
      if (!el) return;
      var ok = on.indexOf(name) !== -1;
      el.classList.toggle('hidden', !ok);
      // one primary button at a time: the passkey one outranks the redirects
      el.classList.toggle('primary', !pk);
      oauth = oauth || ok;
    });
    $('login-oauth-note').classList.toggle('hidden', !oauth);
    if (!pk && !oauth) {
      $('login-token-wrap').open = true;
      setTimeout(function () { $('login-token').focus(); }, 30);
    }
  }

  function showApp() {
    $('login').classList.add('hidden');
    $('app').classList.remove('hidden');
    return refreshIndexes().then(route);
  }

  // quiet = the user dismissed something; it reads as a note, not as a failure
  function loginMessage(text, quiet) {
    var err = $('login-error');
    err.textContent = text;
    err.className = (quiet ? 'muted' : 'error') + ' small';
  }

  $('login-passkey').addEventListener('click', function () {
    var btn = $('login-passkey');
    $('login-error').classList.add('hidden');
    btn.disabled = true;
    Passkey.login().then(function () {
      return showApp();
    }).catch(function (err) {
      var x = Passkey.explain(err, 'login');
      loginMessage(x.text, x.quiet);
    }).then(function () { btn.disabled = false; });
  });

  $('login-form').addEventListener('submit', function (ev) {
    ev.preventDefault();
    var err = $('login-error');
    var input = $('login-token');
    err.classList.add('hidden');
    fetch('/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify({ token: input.value })
    }).then(function (res) {
      if (res.ok) { input.value = ''; return showApp(); }
      return res.text().then(function (t) {
        loginMessage(res.status === 429
          ? 'Too many attempts. Wait a few minutes.'
          : detail(t, res.status));
      });
    }).catch(function () {
      loginMessage('Network error.');
    });
  });

  $('logout-btn').addEventListener('click', function () {
    // it sits a thumb's width from "+ New" on a phone, and there is no undo:
    // an accidental tap ends the session and any open edit with it
    if (state.dirty && !confirm('You have unsaved changes. Sign out anyway?')) return;
    if (!confirm('Sign out? You will need to sign in again.')) return;
    fetch('/auth/logout', { method: 'POST', credentials: 'same-origin' })
      .then(function () { location.hash = ''; showLogin(); });
  });

  /* -------------------------------------------------------------- sidebar */

  function loadIndex() {
    return apiJSON('/memory/index').then(function (idx) {
      state.index = idx;
      renderSidebar();
    }).catch(function (err) { toast(err.message, true); });
  }

  function loadDocs() {
    return apiJSON('/docs/index').then(function (idx) {
      state.docs = idx;
      renderSidebar();
    }).catch(function (err) { toast(err.message, true); });
  }

  // wherever the category index is refreshed, the doc index is too -- the
  // sidebar renders both groups from the same renderSidebar() call. The pins
  // count rides along: any edit can add or remove a pin marker.
  function refreshIndexes() { return Promise.all([loadIndex(), loadDocs(), loadPinsCount()]); }

  // slug -> [category, ...] that reference it via [[doc:slug]]. A doc absent
  // here has no owning category and falls into the "Unattached docs" group.
  function docOwnersOf(index) {
    var owners = Object.create(null);
    index.forEach(function (c) {
      (c.docs || []).forEach(function (slug) {
        (owners[slug] = owners[slug] || []).push(c.category);
      });
    });
    return owners;
  }

  // category name -> [category, ...] that reference it via [[name]]. Same
  // inversion as docOwnersOf, over the index's 'refs' key instead of 'docs' --
  // both are forward edges the server reports per-file; the "Referenced by"
  // views on category/doc pages are just this map read backwards.
  function catReferencersOf(index) {
    var referencers = Object.create(null);
    index.forEach(function (c) {
      (c.refs || []).forEach(function (name) {
        (referencers[name] = referencers[name] || []).push(c.category);
      });
    });
    return referencers;
  }

  // Shared renderer for a "Referenced by" block on a category/doc read view.
  // Omits the whole thing when nothing points here -- an always-present empty
  // heading would just be noise on the majority of pages with no backlinks.
  function referencedByHTML(names, kind) {
    if (!names || !names.length) return '';
    return '<div class="cat-docs"><span class="muted small">Referenced by:</span>' +
      names.map(function (n) {
        return '<a class="pill doclink" href="#/' + kind + '/' + encodeURIComponent(n) + '">' + e(n) + '</a>';
      }).join('') + '</div>';
  }

  /* ---- sidebar state ------------------------------------------------------
   * Everything here is per-browser and lives in localStorage:
   *   K_TREE    { name: true|false }  explicit open/closed choice per category.
   *             Only choices the user made are stored, so a category that did
   *             not exist yet still gets the default (see Nav.defaultOpen).
   *   K_GROUPS  { pinned, recent, unattached: bool }  group open/closed.
   *   K_STARRED ['c:name' | 'd:slug', ...]  the user's pins, in the order added.
   *   K_RECENT  same shape, most recent first, capped at RECENT_MAX.
   */
  var GROUP_DEFAULT = { pinned: true, recent: true, unattached: false };

  function readOverrides() { return Nav.parseOverrides(lsGet(K_TREE)); }

  function readGroups() {
    var out = {}, v;
    try { v = JSON.parse(lsGet(K_GROUPS) || '{}'); } catch (_) { v = {}; }
    Object.keys(GROUP_DEFAULT).forEach(function (k) {
      out[k] = v && typeof v[k] === 'boolean' ? v[k] : GROUP_DEFAULT[k];
    });
    return out;
  }

  function refKey(kind, name) { return kind + ':' + name; }

  function isStarred(kind, name) { return lsList(K_STARRED).indexOf(refKey(kind, name)) >= 0; }

  function toggleStar(kind, name) {
    var list = lsList(K_STARRED), k = refKey(kind, name), i = list.indexOf(k);
    if (i >= 0) list.splice(i, 1); else list.push(k);
    lsSet(K_STARRED, list.slice(-100));
    renderSidebar();
    return i < 0;
  }

  function touchRecent(kind, name) {
    if (!name) return;
    var k = refKey(kind, name);
    var list = lsList(K_RECENT).filter(function (x) { return x !== k; });
    list.unshift(k);
    lsSet(K_RECENT, list.slice(0, RECENT_MAX));
  }

  // 'c:infra' -> { kind, name, label, href }, or null when it no longer exists
  // (deleted or renamed since it was stored, or the index has not loaded yet).
  function resolveRef(ref) {
    var kind = ref.charAt(0), name = ref.slice(2);
    if (kind === 'c') {
      if (!state.index.some(function (c) { return c.category === name; })) return null;
      return { kind: 'c', name: name, label: name, href: '#/c/' + encodeURIComponent(name) };
    }
    if (kind === 'd') {
      var d = state.docs.filter(function (x) { return x.doc === name; })[0];
      if (!d) return null;
      return { kind: 'd', name: name, label: d.title || name, href: '#/d/' + encodeURIComponent(name) };
    }
    return null;
  }

  /* ---- sidebar rendering -------------------------------------------------- */

  var unforced = Object.create(null);   // forced-open ancestors the user has just collapsed by hand

  // Indent is capped: nesting is unbounded by design (the tree is derived
  // from names, not stored), but past a few levels the indent would eat the
  // 272px sidebar and leave nothing for the name.
  function guides(depth) {
    return new Array(Math.min(depth, 6) + 1).join('<i class="g"></i>');
  }

  function sizeDot(bytes) {
    if (bytes >= CAP_BYTES) {
      return '<span class="sdot over" title="' + fmtBytes(bytes) + ' — over the ' + fmtBytes(CAP_BYTES) +
        ' cap, consider splitting"></span>';
    }
    if (bytes >= WARN_BYTES) {
      return '<span class="sdot warn" title="' + fmtBytes(bytes) + ' — nearing the ' + fmtBytes(CAP_BYTES) +
        ' cap"></span>';
    }
    return '';
  }

  function leafRowHTML(href, label, title, active, depth, isDoc, flat) {
    return '<div class="catrow leaf' + (flat ? ' flat' : '') + '">' + guides(depth) + '<span class="caret ghost"></span>' +
      '<a class="cat' + (active ? ' active' : '') + '" href="' + href + '" title="' + e(title) + '"' +
      (active ? ' aria-current="page"' : '') + '>' +
      (isDoc ? '<span class="docmark" aria-hidden="true"></span>' : '') +
      '<span class="cat-name">' + e(label) + '</span></a></div>';
  }

  function docRowHTML(slug, meta, active, depth) {
    return leafRowHTML('#/d/' + encodeURIComponent(slug), meta ? meta.title : slug, slug, active, depth, true);
  }

  function catRowHTML(r, tree) {
    var nd = tree.node[r.name], c = nd.cat;
    var shown = nd.parent ? r.name.slice(nd.parent.length + 1) : r.name;
    var active = state.kind === 'c' && r.name === state.cat;
    var cnt = '';
    if (r.hidden) {
      var parts = [];
      if (r.kids) parts.push(r.kids + ' sub-categor' + (r.kids === 1 ? 'y' : 'ies'));
      if (r.docs) parts.push(r.docs + ' doc' + (r.docs === 1 ? '' : 's'));
      cnt = '<span class="cnt" title="' + parts.join(', ') + '">' + r.hidden + '</span>';
    }
    return '<div class="catrow' + (r.depth === 0 ? ' root' : '') + '">' + guides(r.depth) +
      (r.expandable
        ? '<button type="button" class="caret" data-toggle="' + e(r.name) + '" aria-expanded="' + r.open +
          '" aria-label="' + (r.open ? 'Collapse ' : 'Expand ') + e(r.name) + '"></button>'
        : '<span class="caret ghost"></span>') +
      '<a class="cat' + (active ? ' active' : '') + '" href="#/c/' + encodeURIComponent(r.name) +
      '" title="' + e(r.name) + '"' + (active ? ' aria-current="page"' : '') + '>' +
      '<span class="cat-name">' + e(shown) + '</span>' + sizeDot(c.bytes) + cnt + '</a></div>';
  }

  function groupHeadHTML(id, label, count, open) {
    return '<button type="button" class="group-head" data-group="' + id + '" aria-expanded="' + open + '">' +
      '<span class="gcaret" aria-hidden="true"></span>' + label + '<span class="gcount">' + count + '</span></button>';
  }

  // Pinned / Recent rows: flat, no tree position, so the label is the full name.
  function refRowsHTML(refs) {
    return refs.map(function (r) {
      var active = state.kind === r.kind && (r.kind === 'c' ? state.cat : state.doc) === r.name;
      return leafRowHTML(r.href, r.label, r.name, active, 0, r.kind === 'd', true);
    }).join('');
  }

  function renderSidebar(reveal) {
    var list = $('catlist'), scroll = list.scrollTop;
    var filter = ($('filter').value || '').toLowerCase().trim();
    var tree = Nav.buildTree(state.index);
    var docOwners = docOwnersOf(state.index);
    var docMeta = Object.create(null), docTitles = Object.create(null);
    state.docs.forEach(function (d) { docMeta[d.doc] = d; docTitles[d.doc] = d.title || ''; });
    var unattached = state.docs.filter(function (d) { return !docOwners[d.doc]; });
    if (filter) {
      unattached = unattached.filter(function (d) {
        return d.doc.indexOf(filter) >= 0 || (d.title || '').toLowerCase().indexOf(filter) >= 0;
      });
    }
    var activeName = state.kind === 'd' ? state.doc : state.cat;
    var groups = readGroups();

    // The active row's ancestors are open for this render only (nothing is
    // stored), and a doc opens every category that references it.
    var forced = Object.create(null);
    function forceAncestors(name) {
      for (var p = tree.node[name] ? tree.node[name].parent : null; p; p = tree.node[p].parent) forced[p] = true;
    }
    if (state.kind === 'c' && activeName && tree.node[activeName]) {
      forceAncestors(activeName);
    } else if (state.kind === 'd' && activeName) {
      (docOwners[activeName] || []).forEach(function (owner) {
        forced[owner] = true;   // open the owner itself, so its doc children render
        forceAncestors(owner);
      });
    }

    // Pinned, then Recent (minus whatever is already pinned), in their own box
    // above the tree so scrolling the tree never carries them out of sight. A
    // group with nothing in it is not drawn at all, and neither shows while
    // filtering: the filter is about the tree.
    var top = [];
    if (!filter) {
      var starredKeys = lsList(K_STARRED);
      var starred = starredKeys.map(resolveRef).filter(Boolean);
      var recent = lsList(K_RECENT).filter(function (k) { return starredKeys.indexOf(k) < 0; })
        .map(resolveRef).filter(Boolean);
      if (starred.length) {
        top.push(groupHeadHTML('pinned', 'Pinned', starred.length, groups.pinned));
        if (groups.pinned) top.push(refRowsHTML(starred));
      }
      if (recent.length) {
        top.push(groupHeadHTML('recent', 'Recent', recent.length, groups.recent));
        if (groups.recent) top.push(refRowsHTML(recent));
      }
    }
    $('navtop').innerHTML = top.join('');
    $('navtop').classList.toggle('hidden', !top.length);

    var html = [];

    Nav.rows(tree, {
      overrides: readOverrides(), forced: forced, unforced: unforced,
      visible: filter ? Nav.filterVisible(tree, filter, docTitles) : null
    }).forEach(function (r) {
      html.push(r.t === 'c'
        ? catRowHTML(r, tree)
        : docRowHTML(r.slug, docMeta[r.slug], state.kind === 'd' && r.slug === activeName, r.depth));
    });

    // docs no category references still need a home -- labelled as what they
    // are (unattached), not as "Docs", collapsed by default behind a count, and
    // omitted entirely when empty.
    if (unattached.length) {
      var uOpen = !!filter || groups.unattached ||
        (state.kind === 'd' && unattached.some(function (d) { return d.doc === activeName; }));
      html.push(groupHeadHTML('unattached', 'Unattached docs', unattached.length, uOpen));
      if (uOpen) {
        unattached.forEach(function (d) {
          html.push(docRowHTML(d.doc, d, state.kind === 'd' && d.doc === activeName, 0));
        });
      }
    }

    list.innerHTML = html.join('') ||
      '<p class="small muted" style="padding:8px">No match.</p>';
    list.scrollTop = scroll;
    if (reveal) revealActive();

    var total = state.index.reduce(function (a, c) { return a + c.bytes; }, 0);
    var over = state.index.filter(function (c) { return c.bytes >= WARN_BYTES; }).length;
    $('store-stats').innerHTML = state.index.length + ' categories · ' + fmtBytes(total) +
      (over ? ' · <a class="pill warn" href="#/health" title="Open the health view">' + over + ' near cap</a>' : '') +
      (state.docs.length ? ' · ' + state.docs.length + ' docs' : '');
  }

  // Scroll the active row into view inside the sidebar only. scrollIntoView
  // would also move every other scrollable ancestor, including the drawer.
  function revealActive() {
    // the copy in Pinned/Recent (.flat) is not where the row lives in the tree
    var list = $('catlist'), el = list.querySelector('.catrow:not(.flat) > .cat.active');
    if (!el) return;
    var r = el.getBoundingClientRect(), lr = list.getBoundingClientRect();
    if (!lr.height) return;       // drawer closed on a phone: no geometry to go by
    if (r.top < lr.top + 4) list.scrollTop -= lr.top + 4 - r.top + 24;
    else if (r.bottom > lr.bottom - 4) list.scrollTop += r.bottom - lr.bottom + 4 + 24;
  }

  function onSidebarClick(ev) {
    var head = ev.target.closest('.group-head[data-group]');
    if (head) {
      var groups = readGroups(), id = head.getAttribute('data-group');
      groups[id] = head.getAttribute('aria-expanded') !== 'true';
      lsSet(K_GROUPS, groups);
      renderSidebar();
      return;
    }
    var btn = ev.target.closest('.caret[data-toggle]');
    if (!btn) return;
    ev.preventDefault();
    // while filtering every match is open regardless; a stored choice made now
    // would only surprise the user once the filter is cleared
    if (($('filter').value || '').trim()) return;
    var name = btn.getAttribute('data-toggle');
    var wasOpen = btn.getAttribute('aria-expanded') === 'true';
    var overrides = readOverrides();
    overrides[name] = !wasOpen;
    if (state.index.length) {
      var known = Object.create(null);
      state.index.forEach(function (c) { known[c.category] = true; });
      Object.keys(overrides).forEach(function (k) { if (!known[k]) delete overrides[k]; });
    }
    lsSet(K_TREE, overrides);
    // collapsing an ancestor of the active row has to beat the force-open
    if (wasOpen) unforced[name] = true; else delete unforced[name];
    renderSidebar();
  }
  $('catlist').addEventListener('click', onSidebarClick);
  $('navtop').addEventListener('click', onSidebarClick);

  $('filter').addEventListener('input', function () { renderSidebar(); });

  $('menu-btn').addEventListener('click', function () {
    $('sidebar').classList.toggle('open');
    $('scrim').classList.toggle('hidden');
    revealActive();
  });
  $('scrim').addEventListener('click', closeDrawer);
  function closeDrawer() {
    $('sidebar').classList.remove('open');
    $('scrim').classList.add('hidden');
  }

  /* ------------------------------------------------------------- rendering */

  function main(html) { $('main').innerHTML = '<div class="wrap">' + html + '</div>'; }
  function mainWide(html) { $('main').innerHTML = '<div class="wrap wide">' + html + '</div>'; }
  // the editor needs a height-constrained wrap, not the scrolling document one
  function mainEdit(html) { $('main').innerHTML = '<div class="wrap editing">' + html + '</div>'; }
  function loading() { main('<p class="spin">Loading…</p>'); }

  function outlineHTML(text) {
    var secs = MD.sections(text);
    if (!secs.length) return '';
    // wide: a permanent sticky column (summary hidden by CSS). narrow: an
    // accordion, closed, so 20 section links do not bury the document itself.
    var open = window.matchMedia('(min-width: 1001px)').matches ? ' open' : '';
    return '<details class="outline"' + open + '><summary>Jump to section (' + secs.length +
      ')</summary><h4>Sections</h4>' + secs.map(function (s) {
      // 'never' means this fact doesn't rot -- shown as 'stable', never styled stale.
      var date = '';
      if (s.verified === 'never') {
        date = '<span class="odate">stable</span>';
      } else if (s.verified) {
        var d = MD.daysSince(s.verified);
        date = '<span class="odate' + (d > STALE_DAYS ? ' stale' : '') + '">' + e(s.verified) + '</span>';
      }
      // level 2 sits at the outline's base indent; 3 and 4 step in from there
      var indent = (s.level - 2) * 12;
      return '<a href="#' + s.id + '" style="padding-left:' + (9 + indent) + 'px">' + e(s.name) + ' ' + date + '</a>';
    }).join('') + '</details>';
  }

  function scrollToLine(n) {
    var nodes = $('main').querySelectorAll('[data-line]');
    var best = null;
    for (var i = 0; i < nodes.length; i++) {
      if (parseInt(nodes[i].getAttribute('data-line'), 10) <= n) best = nodes[i];
    }
    if (!best) return;
    best.scrollIntoView({ block: 'center' });
    best.classList.add('flash');
    setTimeout(function () { best.classList.remove('flash'); }, 1800);
  }

  // Used by the stale-sections view: it only has a section name from
  // /memory/index, not a line number, so it links to the heading's rendered
  // id (see md.js's slug export) instead of a #/l/<line> route.
  function scrollToHeadingId(id) {
    var el = document.getElementById(id);
    if (!el) return;
    el.scrollIntoView({ block: 'center' });
    el.classList.add('flash');
    setTimeout(function () { el.classList.remove('flash'); }, 1800);
  }

  /* ------------------------------------------------------------ home view */

  // An overview, not an inventory: one card per root category, then what
  // changed lately. The long lists (largest, near cap, stale) live in #/health.
  function viewHome() {
    state.cat = null;
    state.doc = null;
    state.kind = null;
    renderSidebar(true);
    var total = state.index.reduce(function (a, c) { return a + c.bytes; }, 0);
    var tree = Nav.buildTree(state.index);

    var cards = tree.roots.map(function (name) {
      var st = Nav.subtreeStats(tree, name, WARN_BYTES);
      return '<a class="rootcard" href="#/c/' + encodeURIComponent(name) + '">' +
        '<span class="rc-name">' + e(name) + '</span>' +
        '<span class="rc-meta">' + st.count + ' categor' + (st.count === 1 ? 'y' : 'ies') + ' · ' +
        fmtBytes(st.bytes) + '</span>' +
        '<span class="rc-when">' + (st.mtime ? 'changed ' + fmtAgo(new Date(st.mtime).toISOString()) : '') +
        (st.warn ? ' <span class="pill warn" title="categories at or over ' + fmtBytes(WARN_BYTES) + '">' +
          st.warn + ' near cap</span>' : '') + '</span></a>';
    }).join('');

    // categories and docs in one list, newest first
    var changed = state.index.map(function (c) {
      return { t: Date.parse(c.mtime), href: '#/c/' + encodeURIComponent(c.category), label: c.category, doc: false };
    }).concat(state.docs.map(function (d) {
      return { t: Date.parse(d.mtime), href: '#/d/' + encodeURIComponent(d.doc), label: d.title || d.doc, doc: true };
    })).sort(function (a, b) { return (b.t || 0) - (a.t || 0); }).slice(0, 8);

    main(
      '<div class="vhead"><h1>Memory store</h1></div>' +
      '<p class="vsub">' + state.index.length + ' categories · ' + fmtBytes(total) +
      (state.docs.length ? ' · ' + state.docs.length + ' docs' : '') +
      ' · <a href="#/health">Health</a></p>' +
      (cards ? '<div class="rootgrid">' + cards + '</div>' : '<p class="muted">Nothing here yet.</p>') +
      (changed.length
        ? '<h3 class="home-h">Recently changed</h3><div class="revs">' + changed.map(function (c) {
            return '<div class="rev"><a class="msg" href="' + c.href + '">' + e(c.label) + '</a>' +
              (c.doc ? '<span class="pill">doc</span>' : '') +
              '<span class="when">' + (c.t ? fmtAgo(new Date(c.t).toISOString()) : '') + '</span></div>';
          }).join('') + '</div>'
        : '')
    );
  }

  /* ------------------------------------------------------------ read view */

  // The star in a read view's header: pins the category/doc to the sidebar.
  function starButtonHTML(kind, name) {
    var on = isStarred(kind, name);
    return '<button type="button" class="btn star' + (on ? ' on' : '') + '" data-act="star" aria-pressed="' + on +
      '" aria-label="' + (on ? 'Unpin from the sidebar' : 'Pin to the sidebar') + '" title="' +
      (on ? 'Unpin from the sidebar' : 'Pin to the sidebar') + '">' + (on ? '★' : '☆') + '</button>';
  }

  function wireStar(kind, name) {
    var b = $('main').querySelector('[data-act="star"]');
    if (!b) return;
    b.onclick = function () {
      var on = toggleStar(kind, name);
      b.classList.toggle('on', on);
      b.setAttribute('aria-pressed', on);
      b.textContent = on ? '★' : '☆';
      b.title = on ? 'Unpin from the sidebar' : 'Pin to the sidebar';
      b.setAttribute('aria-label', b.title);
      toast(on ? 'Pinned' : 'Unpinned');
    };
  }

  function viewCategory(cat, line, heading) {
    state.cat = cat;
    state.kind = 'c';
    state.editing = false;
    touchRecent('c', cat);
    renderSidebar(true);
    loading();
    getCategory(cat).then(function (r) {
      state.body = r.body;
      state.etag = r.etag;
      var meta = state.index.filter(function (c) { return c.category === cat; })[0];
      var size = meta ? meta.bytes : r.body.length;
      var capPill = size >= CAP_BYTES
        ? '<span class="pill stale">over ' + fmtBytes(CAP_BYTES) + ' — consider splitting</span>'
        : size >= WARN_BYTES ? '<span class="pill warn">near cap</span>' : '';

      main(
        '<div class="vhead"><h1>' + e(cat) + '</h1>' + capPill +
        '<span class="spacer"></span><div class="actions">' + starButtonHTML('c', cat) +
        '<button class="btn" data-act="edit">Edit</button>' +
        '<a class="btn" href="#/c/' + encodeURIComponent(cat) + '/history">History</a>' +
        '<button class="btn danger" data-act="delete">Delete</button>' +
        '</div></div>' +
        '<p class="vsub">' + fmtBytes(size) + ' · ' + MD.sections(r.body).length + ' sections · etag ' +
        '<code>' + e(r.etag.slice(0, 8)) + '</code>' +
        (meta ? ' · changed ' + fmtAgo(meta.mtime) : '') + '</p>' +
        (meta && meta.docs && meta.docs.length
          ? '<div class="cat-docs"><span class="muted small">Docs:</span>' +
            meta.docs.map(function (d) {
              return '<a class="pill doclink" href="#/d/' + encodeURIComponent(d) + '">' + e(d) + '</a>';
            }).join('') + '</div>'
          : '') +
        referencedByHTML(catReferencersOf(state.index)[cat], 'c') +
        '<div class="reading"><article class="md">' +
        MD.render(r.body, { staleDays: STALE_DAYS, known: knownRefs() }) + '</article>' + outlineHTML(r.body) + '</div>'
      );

      $('main').querySelector('[data-act="edit"]').onclick = function () {
        location.hash = '#/c/' + encodeURIComponent(cat) + '/edit';
      };
      $('main').querySelector('[data-act="delete"]').onclick = function () { askDelete(cat); };
      wireStar('c', cat);

      if (line) setTimeout(function () { scrollToLine(line); }, 30);
      if (heading) setTimeout(function () { scrollToHeadingId(heading); }, 30);
    }).catch(function (err) {
      main('<div class="banner bad">' + e(err.message) + '</div>');
    });
  }

  /* ------------------------------------------------------------ doc read view */

  function viewDoc(slug, line, heading) {
    state.doc = slug;
    state.kind = 'd';
    state.editing = false;
    touchRecent('d', slug);
    renderSidebar(true);
    loading();
    getDoc(slug).then(function (r) {
      state.body = r.body;
      state.etag = r.etag;
      var meta = state.docs.filter(function (d) { return d.doc === slug; })[0];
      var size = meta ? meta.bytes : r.body.length;
      var title = meta ? meta.title : slug;

      main(
        '<div class="vhead"><h1>' + e(title) +
        (title !== slug ? ' <span class="muted small">' + e(slug) + '</span>' : '') + '</h1>' +
        '<span class="spacer"></span><div class="actions">' + starButtonHTML('d', slug) +
        '<button class="btn" data-act="edit">Edit</button>' +
        '<a class="btn" href="#/d/' + encodeURIComponent(slug) + '/history">History</a>' +
        '<button class="btn danger" data-act="delete">Delete</button>' +
        '</div></div>' +
        '<p class="vsub">' + fmtBytes(size) + ' · etag ' +
        '<code>' + e(r.etag.slice(0, 8)) + '</code>' +
        (meta ? ' · changed ' + fmtAgo(meta.mtime) : '') + '</p>' +
        referencedByHTML(docOwnersOf(state.index)[slug], 'c') +
        '<div class="reading"><article class="md">' +
        MD.render(r.body, { staleDays: STALE_DAYS, known: knownRefs() }) + '</article>' + outlineHTML(r.body) + '</div>'
      );

      $('main').querySelector('[data-act="edit"]').onclick = function () {
        location.hash = '#/d/' + encodeURIComponent(slug) + '/edit';
      };
      $('main').querySelector('[data-act="delete"]').onclick = function () { askDelete(slug, 'd'); };
      wireStar('d', slug);

      if (line) setTimeout(function () { scrollToLine(line); }, 30);
      if (heading) setTimeout(function () { scrollToHeadingId(heading); }, 30);
    }).catch(function (err) {
      main('<div class="banner bad">' + e(err.message) + '</div>');
    });
  }

  /* ------------------------------------------------------------ edit view */

  var TEMPLATE = '## Overview\n<!-- verified: DATE -->\n\n- \n';
  var DOC_TEMPLATE = '# <slug>\n\n## Where things stand\n\n## Next step\n\n## Open questions\n';

  function editorHTML(kind, cat, body, isNew) {
    var label = kind === 'd' ? 'doc' : 'category';
    return '<div class="vhead"><h1>' + (isNew ? 'New ' + label : e(cat)) +
      '<span class="dot hidden" id="dirty"> ●</span></h1>' +
      '<span class="spacer"></span><div class="actions">' +
      '<div class="seg" id="seg" role="tablist">' +
      '<button data-p="ed" class="on" role="tab">Edit</button>' +
      '<button data-p="pv" role="tab">Preview</button></div>' +
      (kind === 'd'
        ? '<input id="note" class="small" placeholder="note for this save (optional)" ' +
          'maxlength="60" spellcheck="false">'
        : '') +
      '<button class="btn primary" id="save">Save</button>' +
      '<button class="btn" id="close">Close</button></div></div>' +
      (isNew
        ? '<p class="vsub">Name must match <code>^[a-z0-9-]+$</code>. ' +
          (kind === 'd' ? 'Related docs share a prefix, e.g. ' : 'Sub-categories are named ') +
          '<code>&lt;parent&gt;-&lt;sub&gt;</code>.</p>' +
          '<p><input id="newname" placeholder="' + (kind === 'd' ? 'doc-name' : 'category-name') +
          '" spellcheck="false" aria-label="New ' + label + ' name" style="width:100%;max-width:340px"></p>'
        : '<p class="vsub">Ctrl/Cmd+S saves and keeps you here. The save carries the etag this was ' +
          'loaded at, so a change made elsewhere in the meantime is caught, not overwritten. ' +
          'The two panes scroll together.</p>') +
      '<div class="split" id="split" data-only="ed">' +
      '<div class="pane pane-ed"><h4>Markdown</h4><textarea class="editor" id="ed" spellcheck="false" ' +
      'aria-label="Markdown source">' + e(body) + '</textarea></div>' +
      '<div class="pane pane-pv"><h4>Preview</h4><div class="preview md" id="pv"></div></div></div>';
  }

  /* ---- editor <-> preview scroll sync -------------------------------------
   * Both panes are pinned to the same coordinate: the source line. Preview
   * blocks already carry data-line from the renderer. The editor side is the
   * hard half, because the textarea soft-wraps -- a long prose line occupies
   * several rows, so scrollTop / lineHeight is NOT the line number.
   *
   * So we measure instead of computing: a hidden mirror div, identical in
   * width, font, padding and wrapping to the textarea, holds one block per
   * source line. Under `pre-wrap` a source line never merges with its
   * neighbour, so each mirror block wraps exactly as the textarea does and its
   * offsetTop IS that line's y inside the textarea's scroll box.
   *
   * With both y-offsets known per anchor, scrolling is a straight interpolation
   * between the two bracketing anchors. Snapping to the nearest block instead
   * would make the other pane lurch a whole section at a time.
   */
  var editorSync = null;
  var MIRROR_COPY = ['fontFamily', 'fontSize', 'fontWeight', 'fontStyle', 'lineHeight',
    'letterSpacing', 'wordSpacing', 'textTransform', 'textIndent', 'whiteSpace',
    'wordBreak', 'overflowWrap', 'tabSize', 'paddingTop', 'paddingRight',
    'paddingBottom', 'paddingLeft'];

  function makeSync(ed, pv) {
    var marks = null;
    var driver = null, driverAt = 0;

    var mirror = document.createElement('div');
    mirror.setAttribute('aria-hidden', 'true');
    mirror.style.cssText = 'position:absolute;left:-99999px;top:0;visibility:hidden;' +
      'box-sizing:border-box;border:0;margin:0;';
    document.body.appendChild(mirror);

    function measureLines() {
      var cs = getComputedStyle(ed);
      for (var i = 0; i < MIRROR_COPY.length; i++) mirror.style[MIRROR_COPY[i]] = cs[MIRROR_COPY[i]];
      // clientWidth is content + padding, excluding border and any scrollbar --
      // exactly the width the textarea wraps its text at. The mirror carries no
      // border of its own, so border-box width == clientWidth lines them up.
      mirror.style.width = ed.clientWidth + 'px';

      var lines = ed.value.split('\n');
      var html = [];
      for (var j = 0; j < lines.length; j++) {
        // a zero-width space keeps an empty line one row tall without adding width
        html.push('<div>' + (lines[j] ? e(lines[j]) : '\u200b') + '</div>');
      }
      mirror.innerHTML = html.join('');
      return mirror.children;
    }

    function build() {
      var rows = measureLines();
      var base = pv.getBoundingClientRect().top - pv.scrollTop;
      var nodes = pv.querySelectorAll('[data-line]');
      marks = [];
      for (var i = 0; i < nodes.length; i++) {
        var line = parseInt(nodes[i].getAttribute('data-line'), 10);
        if (!line) continue;
        var row = rows[line - 1];
        marks.push({
          ed: row ? row.offsetTop : 0,
          pv: nodes[i].getBoundingClientRect().top - base
        });
      }
      marks.sort(function (a, b) { return a.ed - b.ed; });

      /* Pin both extremes. The two documents are never the same height -- a
       * heading is one row of source but 26px of rendered type, a code fence is
       * the reverse -- so "scrolled to the end" is a different pixel count on
       * each side. Anchoring maxScroll to maxScroll makes bottom mean bottom;
       * without it the region past the last heading fell back to a 1:1 pixel
       * mapping and the panes drifted apart exactly there.
       * Anchors inside the final viewport are dropped first: they sit past
       * maxScroll and would make the mapping run backwards. */
      var edMax = Math.max(0, ed.scrollHeight - ed.clientHeight);
      var pvMax = Math.max(0, pv.scrollHeight - pv.clientHeight);
      marks = marks.filter(function (m) { return m.ed > 0 && m.ed < edMax && m.pv > 0 && m.pv < pvMax; });
      marks.unshift({ ed: 0, pv: 0 });
      marks.push({ ed: edMax, pv: pvMax });
    }

    function at() { if (!marks) build(); return marks; }

    function interp(list, from, val, to) {
      var a = list[0], b = null, i;
      for (i = 0; i < list.length; i++) {
        if (list[i][from] <= val) a = list[i];
        else { b = list[i]; break; }
      }
      if (!b) return a[to] + (val - a[from]);      // past the last anchor: 1:1 tail
      var span = b[from] - a[from];
      var f = span > 0 ? (val - a[from]) / span : 0;
      return a[to] + f * (b[to] - a[to]);
    }

    function claim(who) {
      var now = Date.now();
      if (driver && driver !== who && now - driverAt < 150) return false;
      driver = who; driverAt = now;
      return true;
    }

    // On phones the panes are display:none in turn, and a hidden element has no
    // geometry -- measuring it would produce zeros and yank the other pane home.
    function bothShown() { return !!(ed.offsetParent && pv.offsetParent); }

    function fromEditor(force) {
      if (!bothShown()) return;
      if (!force && !claim('ed')) return;
      pv.scrollTop = Math.max(0, interp(at(), 'ed', ed.scrollTop, 'pv'));
    }

    function fromPreview() {
      if (!bothShown() || !claim('pv')) return;
      ed.scrollTop = Math.max(0, interp(at(), 'pv', pv.scrollTop, 'ed'));
    }

    ed.addEventListener('scroll', function () { fromEditor(false); }, { passive: true });
    pv.addEventListener('scroll', fromPreview, { passive: true });

    // any view change replaces #main, detaching these nodes; measuring a
    // detached textarea would throw rather than silently misalign
    function alive() {
      if (ed.isConnected && pv.isConnected) return true;
      if (mirror.parentNode) mirror.parentNode.removeChild(mirror);
      editorSync = null;
      return false;
    }

    return {
      invalidate: function () { if (alive()) marks = null; },
      // after a re-render the preview would otherwise sit wherever it was
      resync: function () { if (alive()) { marks = null; fromEditor(true); } },
      // used by the mobile pane switch (see $('seg') below): scroll the editor
      // to a specific source line directly, via the same mirror measurement
      // build() uses. The pixel-interpolated `marks` are no good for this --
      // they get built while pv is display:none on mobile, so every pv offset
      // captured at that point is zero and the mapping is garbage.
      scrollToLine: function (line) {
        if (!alive()) return;
        var rows = measureLines();
        var row = rows[line - 1];
        ed.scrollTop = Math.max(0, (row ? row.offsetTop : 0) - 20);
      }
    };
  }

  window.addEventListener('resize', function () {
    if (editorSync) editorSync.invalidate();
  });

  /* ---- local draft safety net ---------------------------------------------
   * The only copy of an unsaved edit is the textarea. Phone browsers evict
   * background tabs without firing beforeunload, and a failed PUT over a flaky
   * link leaves nothing but a toast. So mirror the text into localStorage as it
   * is typed, and offer it back if it differs from what the server returns. */
  function draftKey(kind, cat) { return 'mem.draft.' + (kind === 'd' ? 'doc.' : '') + (cat || '__new__'); }

  function saveDraft(kind, cat, text) {
    try { localStorage.setItem(draftKey(kind, cat), JSON.stringify({ t: text, at: Date.now() })); }
    catch (_) { /* quota or private mode: the net is a bonus, not a dependency */ }
  }
  function readDraft(kind, cat) {
    try { return JSON.parse(localStorage.getItem(draftKey(kind, cat)) || 'null'); } catch (_) { return null; }
  }
  function dropDraft(kind, cat) {
    try { localStorage.removeItem(draftKey(kind, cat)); } catch (_) { /* nothing to clean */ }
  }

  function wireEditor(kind, cat, isNew) {
    var ed = $('ed'), pv = $('pv'), timer;

    function preview() {
      pv.innerHTML = MD.render(ed.value, { staleDays: STALE_DAYS, known: knownRefs() });
      if (editorSync) editorSync.resync();
    }
    editorSync = null;          // build after the first render, so marks exist
    preview();
    editorSync = makeSync(ed, pv);

    ed.addEventListener('input', function () {
      setDirty(true);
      clearTimeout(timer);
      timer = setTimeout(function () { preview(); saveDraft(kind, cat, ed.value); }, 140);
    });

    ed.addEventListener('keydown', function (ev) {
      if (ev.key === 'Tab') {
        ev.preventDefault();
        // execCommand keeps the browser's own undo stack; assigning to .value
        // wipes it, so Ctrl+Z would throw away everything typed since load
        if (!document.execCommand || !document.execCommand('insertText', false, '  ')) {
          var s = ed.selectionStart, en = ed.selectionEnd;
          ed.value = ed.value.slice(0, s) + '  ' + ed.value.slice(en);
          ed.selectionStart = ed.selectionEnd = s + 2;
        }
        setDirty(true);
      }
      if ((ev.ctrlKey || ev.metaKey) && ev.key.toLowerCase() === 's') {
        ev.preventDefault();
        doSave(kind, cat, isNew);
      }
    });

    // phone pane switcher; inert above 860px, where both panes are visible.
    // A switch used to just flip data-only and leave scrollTop wherever it
    // was, which is 0 the first time -- on a long doc, every single toggle
    // dropped the reader back at the top. Now it carries the current line
    // across: read from whichever pane is about to hide, land on it in the
    // pane about to show.
    $('seg').addEventListener('click', function (ev) {
      var b = ev.target.closest('button[data-p]');
      if (!b) return;
      var target = b.getAttribute('data-p');
      if (target === $('split').getAttribute('data-only')) return;

      if (target === 'pv') {
        var caretLine = ed.value.slice(0, ed.selectionStart).split('\n').length;
        $('split').setAttribute('data-only', 'pv');
        preview();
        var nodes = pv.querySelectorAll('[data-line]');
        var best = null;
        for (var i = 0; i < nodes.length; i++) {
          if (parseInt(nodes[i].getAttribute('data-line'), 10) <= caretLine) best = nodes[i];
          else break;
        }
        if (best) best.scrollIntoView({ block: 'start' });
      } else {
        // whichever block sits at the top of the (about to hide) preview
        // becomes the editor's landing line
        var pvTop = pv.getBoundingClientRect().top;
        var pvNodes = pv.querySelectorAll('[data-line]');
        var atLine = 1;
        for (var j = 0; j < pvNodes.length; j++) {
          if (pvNodes[j].getBoundingClientRect().top - pvTop <= 4) {
            atLine = parseInt(pvNodes[j].getAttribute('data-line'), 10) || atLine;
          } else break;
        }
        $('split').setAttribute('data-only', 'ed');
        if (editorSync) editorSync.scrollToLine(atLine);
      }

      var all = $('seg').querySelectorAll('button');
      for (var k = 0; k < all.length; k++) all[k].classList.toggle('on', all[k] === b);
    });

    $('save').onclick = function () { doSave(kind, cat, isNew); };
    $('close').onclick = function () {
      if (state.dirty && !confirm('Discard unsaved changes?')) return;
      dropDraft(kind, cat);
      setDirty(false);
      location.hash = isNew ? '#/' : '#/' + kind + '/' + encodeURIComponent(cat);
    };
    setTimeout(function () { ed.focus(); }, 30);
  }

  /* Offer a recovered draft rather than silently overwriting either side. */
  function offerDraft(kind, cat, serverBody) {
    var d = readDraft(kind, cat);
    if (!d || typeof d.t !== 'string' || d.t === serverBody) { dropDraft(kind, cat); return; }

    var bar = document.createElement('div');
    bar.className = 'banner warn';
    bar.innerHTML = '<span>Unsaved draft from ' + e(fmtAgo(new Date(d.at).toISOString())) +
      ' found on this device, different from the saved version.</span><span class="spacer"></span>' +
      '<button class="btn small" id="draft-use">Restore draft</button>' +
      '<button class="btn small" id="draft-drop">Discard</button>';
    var wrap = $('main').querySelector('.wrap');
    wrap.insertBefore(bar, wrap.querySelector('.split'));

    $('draft-use').onclick = function () {
      var ed = $('ed');
      ed.focus();
      ed.selectionStart = 0;
      ed.selectionEnd = ed.value.length;
      // same reasoning as the Tab handler above: execCommand keeps the
      // browser's native undo stack, so restoring a draft does not silently
      // erase whatever the user had just typed before they saw this banner
      if (!document.execCommand || !document.execCommand('insertText', false, d.t)) {
        ed.value = d.t;
      }
      ed.dispatchEvent(new Event('input'));
      setDirty(true);
      bar.parentNode.removeChild(bar);
      toast('Draft restored — not saved yet');
    };
    $('draft-drop').onclick = function () {
      dropDraft(kind, cat);
      bar.parentNode.removeChild(bar);
    };
  }

  /* The Save button doubles as the save indicator. A toast is gone in three
   * seconds and cannot answer "did that actually go through?" a minute later;
   * a button reading "Saved" until the next keystroke can. */
  function setSaveState(saved) {
    var b = $('save');
    if (!b) return;
    b.textContent = saved ? 'Saved ✓' : 'Save';
    b.classList.toggle('saved', !!saved);
    b.classList.toggle('primary', !saved);
    b.disabled = !!saved;
  }

  function setDirty(v) {
    state.dirty = v;
    var d = $('dirty');
    if (d) d.classList.toggle('hidden', !v);
    if (v) setSaveState(false);          // edited again -> back to an armed Save
  }

  function viewEdit(cat) {
    state.cat = cat;
    state.kind = 'c';
    state.editing = true;
    touchRecent('c', cat);
    renderSidebar(true);
    loading();
    getCategory(cat).then(function (r) {
      state.body = r.body;
      state.etag = r.etag;
      mainEdit(editorHTML('c', cat, r.body, false));
      wireEditor('c', cat, false);
      setDirty(false);
      offerDraft('c', cat, r.body);
    }).catch(function (err) {
      main('<div class="banner bad">' + e(err.message) + '</div>');
    });
  }

  function viewDocEdit(slug) {
    state.doc = slug;
    state.kind = 'd';
    state.editing = true;
    touchRecent('d', slug);
    renderSidebar(true);
    loading();
    getDoc(slug).then(function (r) {
      state.body = r.body;
      state.etag = r.etag;
      mainEdit(editorHTML('d', slug, r.body, false));
      wireEditor('d', slug, false);
      setDirty(false);
      offerDraft('d', slug, r.body);
    }).catch(function (err) {
      main('<div class="banner bad">' + e(err.message) + '</div>');
    });
  }

  function viewNew() {
    state.cat = null;
    state.kind = 'c';
    state.editing = true;
    state.etag = null;
    renderSidebar(true);
    var seed = TEMPLATE.replace('DATE', new Date().toISOString().slice(0, 10));
    mainEdit(editorHTML('c', '', seed, true));
    wireEditor('c', null, true);
    setDirty(false);
    offerDraft('c', null, seed);
  }

  function viewNewDoc() {
    state.doc = null;
    state.kind = 'd';
    state.editing = true;
    state.etag = null;
    renderSidebar(true);
    var seed = DOC_TEMPLATE;
    mainEdit(editorHTML('d', '', seed, true));
    wireEditor('d', null, true);
    setDirty(false);
    offerDraft('d', null, seed);
  }

  function doSave(kind, cat, isNew) {
    var text = $('ed').value;
    if (isNew) {
      cat = ($('newname').value || '').trim();
      if (!/^[a-z0-9-]+$/.test(cat)) { toast('Name must match ^[a-z0-9-]+$', true); return; }
    }
    var headers = { 'Content-Type': 'text/plain; charset=utf-8' };
    if (isNew) headers['If-None-Match'] = '*';
    else headers['If-Match'] = state.etag;
    if (kind === 'd') {
      var noteEl = $('note');
      var noteVal = noteEl ? (noteEl.value || '').trim() : '';
      // Header values must be Latin-1 or fetch() throws; the server unquotes.
      if (noteVal) headers['X-Memory-Note'] = encodeURIComponent(noteVal);
    }

    $('save').disabled = true;
    api(basePath(kind) + encodeURIComponent(cat), { method: 'PUT', headers: headers, body: text })
      .then(function (res) {
        $('save').disabled = false;
        if (res.status === 409) return res.text().then(function () { showConflict(kind, cat, text); });
        if (!res.ok) return res.text().then(function (t) { toast(detail(t, res.status), true); });
        state.etag = (res.headers.get('ETag') || '').replace(/"/g, '');
        state.body = text;
        setDirty(false);
        setSaveState(true);
        dropDraft(kind, isNew ? null : cat);
        toast('Saved');
        // Stay in the editor: Ctrl+S mid-edit must not throw away the caret,
        // the scroll position and the pane split. "Close" is how you leave.
        return refreshIndexes().then(function () {
          if (isNew) {
            state.suppressRoute = true;
            location.hash = '#/' + kind + '/' + encodeURIComponent(cat);
            if (kind === 'd') state.doc = cat; else state.cat = cat;
            mainEdit(editorHTML(kind, cat, text, false));
            wireEditor(kind, cat, false);
            setDirty(false);
          }
          renderSidebar(true);
        });
      })
      .catch(function (err) { $('save').disabled = false; toast(err.message, true); });
  }

  /* -------------------------------------------------------- conflict view */

  function showConflict(kind, cat, mine) {
    getItem(kind, cat).then(function (theirs) {
      var d = Diff.render(theirs.body, mine, 3);
      var m = modal(
        '<h3>Someone else changed <code>' + e(cat) + '</code></h3>' +
        '<p class="small muted">This was loaded at etag <code>' + e((state.etag || '').slice(0, 8)) +
        '</code>; it is now <code>' + e(theirs.etag.slice(0, 8)) + '</code>. ' +
        'Below: theirs → yours (+' + d.stats.added + ' / −' + d.stats.removed + ').</p>' +
        '<div class="diff" style="max-height:46vh;overflow:auto">' + d.html + '</div>' +
        '<div class="row"><button class="btn" id="c-cancel">Keep editing</button>' +
        '<button class="btn" id="c-theirs">Load theirs</button>' +
        '<button class="btn danger" id="c-force">Overwrite with mine</button></div>'
      );
      m.q('#c-cancel').onclick = m.close;
      m.q('#c-theirs').onclick = function () {
        m.close();
        state.etag = theirs.etag;
        $('ed').value = theirs.body;
        $('ed').dispatchEvent(new Event('input'));
        setDirty(false);
        toast('Loaded their version — your text is gone from the editor');
      };
      m.q('#c-force').onclick = function () {
        m.close();
        api(basePath(kind) + encodeURIComponent(cat), {
          method: 'PUT',
          headers: { 'Content-Type': 'text/plain; charset=utf-8', 'If-Match': '*' },
          body: mine
        }).then(function (res) {
          if (!res.ok) return res.text().then(function (t) { toast(detail(t, res.status), true); });
          state.etag = (res.headers.get('ETag') || '').replace(/"/g, '');
          setDirty(false);
          toast('Overwritten. Their version is still in git history.');
          return refreshIndexes();
        });
      };
    }).catch(function (err) { toast(err.message, true); });
  }

  /* ---------------------------------------------------------- delete flow */

  function askDelete(cat, kind) {
    kind = kind || 'c';
    var label = kind === 'd' ? 'doc' : 'category';
    var m = modal(
      '<h3>Delete ' + label + ' <code>' + e(cat) + '</code>?</h3>' +
      '<p>The file is removed but the deletion is committed, so the content stays ' +
      'recoverable from history. Type the name to confirm.</p>' +
      '<input id="d-name" placeholder="' + e(cat) + '" spellcheck="false">' +
      '<div class="row"><button class="btn" id="d-cancel">Cancel</button>' +
      '<button class="btn danger" id="d-go" disabled>Delete</button></div>'
    );
    var input = m.q('#d-name'), go = m.q('#d-go');
    input.addEventListener('input', function () { go.disabled = input.value.trim() !== cat; });
    m.q('#d-cancel').onclick = m.close;
    go.onclick = function () {
      api(basePath(kind) + encodeURIComponent(cat), {
        method: 'DELETE',
        headers: { 'If-Match': state.etag }
      }).then(function (res) {
        m.close();
        if (!res.ok) return res.text().then(function (t) { toast(detail(t, res.status), true); });
        toast('Deleted ' + cat);
        return refreshIndexes().then(function () { location.hash = '#/'; viewHome(); });
      }).catch(function (err) { toast(err.message, true); });
    };
    setTimeout(function () { input.focus(); }, 30);
  }

  /* --------------------------------------------------------- history view */

  function viewHistory(kind, cat) {
    if (kind === 'd') { state.doc = cat; } else { state.cat = cat; }
    state.kind = kind;
    state.editing = false;
    renderSidebar(true);
    loading();
    var label = kind === 'd' ? 'doc' : 'category';
    apiJSON(basePath(kind) + encodeURIComponent(cat) + '/history?limit=100').then(function (revs) {
      main(
        '<div class="vhead"><h1>' + e(cat) + ' <span class="muted">history</span></h1>' +
        '<span class="spacer"></span><div class="actions">' +
        '<a class="btn" href="#/' + kind + '/' + encodeURIComponent(cat) + '">Back to ' + label + '</a></div></div>' +
        '<p class="vsub">' + revs.length + ' revisions. The newest is the live file.</p>' +
        '<div class="revs">' + revs.map(function (r, i) {
          return '<div class="rev' + (i === 0 ? ' current' : '') + '">' +
            '<a class="sha" href="#/' + kind + '/' + encodeURIComponent(cat) + '/rev/' + e(r.sha) + '">' + e(r.short) + '</a>' +
            '<span class="msg">' + e(r.message) + '</span>' +
            '<span class="when">' + fmtBytes(r.bytes) + '</span>' +
            '<span class="when" title="' + e(r.date) + '">' + fmtAgo(r.date) + '</span>' +
            '</div>';
        }).join('') + '</div>'
      );
    }).catch(function (err) {
      main('<div class="banner bad">' + e(err.message) + '</div>');
    });
  }

  function viewRev(kind, cat, sha) {
    if (kind === 'd') { state.doc = cat; } else { state.cat = cat; }
    state.kind = kind;
    state.editing = false;
    renderSidebar(true);
    loading();
    Promise.all([getItem(kind, cat, sha), getItem(kind, cat).catch(function () { return null; })])
      .then(function (r) {
        var old = r[0], cur = r[1];
        var d = cur ? Diff.render(old.body, cur.body, 3) : null;
        mainWide(
          '<div class="vhead"><h1>' + e(cat) + ' <span class="muted">@ ' + e(sha.slice(0, 8)) + '</span></h1>' +
          '<span class="spacer"></span><div class="actions">' +
          '<button class="btn" id="r-diff">Toggle diff</button>' +
          '<button class="btn" id="r-load">Load into editor</button>' +
          '<a class="btn" href="#/' + kind + '/' + encodeURIComponent(cat) + '/history">Back to history</a>' +
          '</div></div>' +
          '<div class="banner">Read-only snapshot from git.' +
          (d ? ' Against the live file: +' + d.stats.added + ' / −' + d.stats.removed + '.' : '') +
          '</div>' +
          (d ? '<div class="diff hidden" id="r-diffbox">' + d.html + '</div>' : '') +
          '<article class="md" id="r-body">' + MD.render(old.body, { staleDays: STALE_DAYS, known: knownRefs() }) + '</article>'
        );
        $('r-diff').onclick = function () {
          var box = $('r-diffbox');
          if (!box) return;
          box.classList.toggle('hidden');
          $('r-body').classList.toggle('hidden');
        };
        $('r-load').onclick = function () {
          // Restore is an ordinary forward edit: the editor keeps the *current*
          // etag, so saving commits a new revision instead of rewriting history.
          state.etag = cur ? cur.etag : null;
          state.editing = true;
          mainEdit(editorHTML(kind, cat, old.body, false));
          wireEditor(kind, cat, false);
          setDirty(true);
          state.suppressRoute = true;
          location.hash = '#/' + kind + '/' + encodeURIComponent(cat) + '/edit';
          toast('Loaded ' + sha.slice(0, 8) + ' into the editor — save to restore it');
        };
      }).catch(function (err) {
        main('<div class="banner bad">' + e(err.message) + '</div>');
      });
  }

  /* ---------------------------------------------------------- search view */

  function viewSearch(q) {
    state.cat = null;
    state.doc = null;
    state.kind = null;
    state.editing = false;
    renderSidebar(true);
    $('search-input').value = q;
    loading();
    var terms = q.split(/\s+/).filter(Boolean);
    apiJSON('/memory/search?limit=100&scope=all&q=' + encodeURIComponent(q)).then(function (hits) {
      if (!hits.length) {
        main('<div class="vhead"><h1>No hits</h1></div><p class="vsub">All terms must appear on the ' +
          'same line — try fewer words.</p>');
        return;
      }

      function renderGroups(list, kind, key) {
        var groups = Object.create(null);
        list.forEach(function (h) { (groups[h[key]] = groups[h[key]] || []).push(h); });
        return Object.keys(groups).map(function (name) {
          return '<div class="hitgroup"><h3><a href="#/' + kind + '/' + encodeURIComponent(name) + '">' +
            e(name) + '</a></h3>' +
            groups[name].map(function (h) {
              return '<a class="hit" href="#/' + kind + '/' + encodeURIComponent(name) + '/l/' + h.line + '">' +
                '<div class="where">' + (h.section ? e(h.section) + ' · ' : '') + 'line ' + h.line + '</div>' +
                '<div class="snip">' + hl(e(h.snippet || ''), terms) + '</div></a>';
            }).join('') + '</div>';
        }).join('');
      }

      // scope=all tags every hit with .kind ('memory' or 'doc'); memory hits
      // key off .category, doc hits off .doc -- grouped and headed separately
      // so a handoff never looks like it lives in the same list as a fact.
      var memHits = hits.filter(function (h) { return h.kind !== 'doc'; });
      var docHits = hits.filter(function (h) { return h.kind === 'doc'; });
      var catCount = Object.create(null); memHits.forEach(function (h) { catCount[h.category] = 1; });
      var docCount = Object.create(null); docHits.forEach(function (h) { docCount[h.doc] = 1; });

      main('<div class="vhead"><h1>' + hits.length + ' hits</h1></div>' +
        '<p class="vsub">for <code>' + e(q) + '</code> across ' + Object.keys(catCount).length + ' categories' +
        (docHits.length ? ' and ' + Object.keys(docCount).length + ' docs' : '') + '</p>' +
        (memHits.length ? renderGroups(memHits, 'c', 'category') : '') +
        (docHits.length
          ? '<h3 class="search-section">Docs</h3><div class="doc-hits">' + renderGroups(docHits, 'd', 'doc') + '</div>'
          : ''));
    }).catch(function (err) {
      main('<div class="banner bad">' + e(err.message) + '</div>');
    });
  }

  function hl(escaped, terms) {
    if (!terms.length) return escaped;
    var re = new RegExp('(' + terms.map(function (t) {
      return e(t).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    }).join('|') + ')', 'gi');
    return escaped.replace(re, '<mark>$1</mark>');
  }

  function submitSearch() {
    var q = $('search-input').value.trim();
    if (q) location.hash = '#/search/' + encodeURIComponent(q);
    else location.hash = '#/';
  }
  $('search-form').addEventListener('submit', function (ev) {
    ev.preventDefault();
    submitSearch();
  });
  // the native (X) on <input type=search> fires 'search', not 'input', when
  // it clears the box -- without this, clicking it leaves the old results
  // on screen with an empty box, which reads as broken rather than cleared
  $('search-input').addEventListener('search', submitSearch);

  /* ---------------------------------------------------------------- menus */

  // Disclosure menus ("+ New", the overflow "⋯"): the button toggles, a click
  // anywhere else or Escape closes, arrows move between items. A click that
  // came from the keyboard (detail === 0) lands focus on the first item.
  var menus = [];

  function wireMenu(btn, menu) {
    function items() { return Array.prototype.slice.call(menu.querySelectorAll('[role="menuitem"]')); }
    function isOpen() { return !menu.classList.contains('hidden'); }
    function close(refocus) {
      menu.classList.add('hidden');
      btn.setAttribute('aria-expanded', 'false');
      if (refocus) btn.focus();
    }
    function open(focusFirst) {
      closeMenus();
      menu.classList.remove('hidden');
      btn.setAttribute('aria-expanded', 'true');
      if (focusFirst) { var first = items()[0]; if (first) first.focus(); }
    }
    btn.addEventListener('click', function (ev) {
      ev.stopPropagation();
      if (isOpen()) close(false); else open(ev.detail === 0);
    });
    btn.addEventListener('keydown', function (ev) {
      if (ev.key === 'ArrowDown') { ev.preventDefault(); open(true); }
      else if (ev.key === 'Escape' && isOpen()) { ev.stopPropagation(); close(false); }
    });
    menu.addEventListener('keydown', function (ev) {
      var list = items(), i = list.indexOf(document.activeElement);
      if (ev.key === 'Escape') { ev.stopPropagation(); close(true); }
      else if (ev.key === 'ArrowDown') { ev.preventDefault(); list[(i + 1) % list.length].focus(); }
      else if (ev.key === 'ArrowUp') { ev.preventDefault(); list[(i - 1 + list.length) % list.length].focus(); }
      else if (ev.key === 'Home') { ev.preventDefault(); list[0].focus(); }
      else if (ev.key === 'End') { ev.preventDefault(); list[list.length - 1].focus(); }
      else if (ev.key === 'Tab') close(false);
    });
    // choosing an item closes the menu; the item's own link/handler still runs
    menu.addEventListener('click', function () { close(false); });
    menus.push(close);
  }

  function closeMenus() { menus.forEach(function (close) { close(false); }); }
  document.addEventListener('click', closeMenus);

  wireMenu($('new-btn'), $('new-menu'));
  wireMenu($('more-btn'), $('more-menu'));

  /* -------------------------------------------------------- quick jump */

  /* Ctrl/Cmd+K (or "/" outside a text field) opens a palette over categories,
   * docs and their "##" sections. It navigates by setting location.hash, so the
   * router's unsaved-changes guard applies to it exactly as to a link click. */
  var palette = null;
  var isMac = /Mac|iPhone|iPad/.test(navigator.platform || navigator.userAgent || '');
  var KBD_LABEL = isMac ? '⌘K' : 'Ctrl K';
  Array.prototype.forEach.call(document.querySelectorAll('.kbd'), function (k) { k.textContent = KBD_LABEL; });

  function typingIn(el) {
    var t = el && el.tagName;
    return t === 'INPUT' || t === 'TEXTAREA' || t === 'SELECT' || !!(el && el.isContentEditable);
  }

  function goTo(href) {
    // setting the same hash fires no hashchange, so a jump to where we already
    // are (e.g. the same section) has to re-run the route by hand
    if (location.hash === href) route(); else location.hash = href;
  }

  function openPalette() {
    if (palette || $('app').classList.contains('hidden')) return;
    if ($('modal-root').firstChild) return;      // never stack on another modal
    var opener = document.activeElement;
    var items = Nav.buildItems(state.index, state.docs, MD.slug);
    var byId = Object.create(null);
    items.forEach(function (it) { byId[it.id] = it; });

    var bg = document.createElement('div');
    bg.className = 'modal-bg pal-bg';
    bg.innerHTML = '<div class="pal" role="dialog" aria-modal="true" aria-label="Quick jump">' +
      '<input id="pal-input" class="pal-input" type="text" role="combobox" aria-expanded="true" ' +
      'aria-controls="pal-list" aria-autocomplete="list" autocomplete="off" spellcheck="false" ' +
      'placeholder="Jump to a category, doc or section…" aria-label="Jump to">' +
      '<div id="pal-cap" class="pal-cap"></div>' +
      '<div id="pal-list" class="pal-list" role="listbox" aria-label="Results"></div>' +
      '<div class="pal-foot">↑↓ move · Enter open · Esc close</div></div>';
    $('modal-root').appendChild(bg);

    var input = bg.querySelector('#pal-input'), list = bg.querySelector('#pal-list'), cap = bg.querySelector('#pal-cap');
    var results = [], sel = 0;

    // empty query: what you opened lately, else what you pinned, else what changed
    function idle() {
      var refs = lsList(K_RECENT);
      var label = 'Recent';
      if (!refs.length) { refs = lsList(K_STARRED); label = 'Pinned'; }
      var found = refs.map(function (k) { return byId[k]; }).filter(Boolean);
      if (!found.length) {
        label = 'Recently changed';
        found = state.index.slice().sort(function (a, b) {
          return Date.parse(b.mtime) - Date.parse(a.mtime);
        }).slice(0, RECENT_MAX).map(function (c) { return byId['c:' + c.category]; });
      }
      return { label: label, items: found.slice(0, PALETTE_MAX) };
    }

    var KIND = { c: 'cat', d: 'doc', s: 'sec' };

    function draw() {
      var q = input.value.trim();
      if (q) { results = Nav.search(items, q, PALETTE_MAX); cap.textContent = results.length ? '' : 'No matches'; }
      else { var i = idle(); results = i.items; cap.textContent = results.length ? i.label : ''; }
      if (sel >= results.length) sel = Math.max(0, results.length - 1);
      list.innerHTML = results.map(function (it, n) {
        return '<div class="pal-row' + (n === sel ? ' sel' : '') + '" role="option" id="pal-o-' + n +
          '" aria-selected="' + (n === sel) + '" data-i="' + n + '">' +
          '<span class="pal-kind k-' + it.kind + '">' + KIND[it.kind] + '</span>' +
          '<span class="pal-label">' + e(it.label) + '</span>' +
          (it.sub ? '<span class="pal-sub">' + e(it.sub) + '</span>' : '') + '</div>';
      }).join('');
      mark();
    }

    function mark() {
      var rows = list.children;
      for (var n = 0; n < rows.length; n++) {
        rows[n].classList.toggle('sel', n === sel);
        rows[n].setAttribute('aria-selected', n === sel);
      }
      if (rows[sel]) {
        input.setAttribute('aria-activedescendant', rows[sel].id);
        rows[sel].scrollIntoView({ block: 'nearest' });
      } else {
        input.removeAttribute('aria-activedescendant');
      }
    }

    function close(restore) {
      document.removeEventListener('keydown', onKey, true);
      bg.remove();
      palette = null;
      if (restore && opener && opener.isConnected && opener.focus) opener.focus();
    }

    function go(it) {
      if (!it) return;
      close(true);
      goTo(it.href);
    }

    function onKey(ev) {
      if (ev.key === 'Escape') { ev.preventDefault(); close(true); }
    }

    input.addEventListener('input', function () { sel = 0; draw(); });
    input.addEventListener('keydown', function (ev) {
      var n = results.length;
      if (ev.key === 'ArrowDown') { ev.preventDefault(); if (n) { sel = (sel + 1) % n; mark(); } }
      else if (ev.key === 'ArrowUp') { ev.preventDefault(); if (n) { sel = (sel - 1 + n) % n; mark(); } }
      else if (ev.key === 'Enter') { ev.preventDefault(); go(results[sel]); }
      else if (ev.key === 'Tab') { ev.preventDefault(); }       // the input is the only stop
    });
    list.addEventListener('mousemove', function (ev) {
      var row = ev.target.closest('.pal-row');
      if (row && +row.getAttribute('data-i') !== sel) { sel = +row.getAttribute('data-i'); mark(); }
    });
    list.addEventListener('click', function (ev) {
      var row = ev.target.closest('.pal-row');
      if (row) go(results[+row.getAttribute('data-i')]);
    });
    bg.addEventListener('mousedown', function (ev) { if (ev.target === bg) close(true); });
    document.addEventListener('keydown', onKey, true);

    palette = { close: close };
    draw();
    input.focus();
  }

  $('jump-btn').addEventListener('click', openPalette);
  $('kbd-hint').addEventListener('click', openPalette);

  document.addEventListener('keydown', function (ev) {
    if ($('app').classList.contains('hidden')) return;
    var k = ev.key;
    if ((ev.ctrlKey || ev.metaKey) && !ev.altKey && !ev.shiftKey && (k === 'k' || k === 'K')) {
      ev.preventDefault();
      if (palette) palette.close(true); else openPalette();
    } else if (k === '/' && !ev.ctrlKey && !ev.metaKey && !ev.altKey && !palette && !typingIn(ev.target)) {
      ev.preventDefault();
      openPalette();
    }
  });

  /* ----------------------------------------------------------------- pins */

  // The topbar count is a plain pill, not a red nag badge -- pins are normal,
  // expected content (a store with none is the unusual case), so this is
  // "here's how many" not "something is wrong."
  function updatePinsBadge(n) {
    var b = $('pins-count');
    if (!b) return;
    b.textContent = n;
    b.classList.toggle('hidden', !n);
  }

  function loadPinsCount() {
    return apiJSON('/memory/pins').then(function (list) {
      updatePinsBadge(list.length);
    }).catch(function () { /* topbar count is a bonus, not load-bearing */ });
  }

  function viewPins() {
    state.cat = null;
    state.doc = null;
    state.kind = null;
    state.editing = false;
    renderSidebar(true);
    loading();
    apiJSON('/memory/pins').then(function (list) {
      updatePinsBadge(list.length);

      if (!list.length) {
        main('<div class="vhead"><h1>Pins</h1></div>' +
          '<p class="vsub">No retraction or decision markers in the store.</p>');
        return;
      }

      // category -> section -> [pin, ...], in the order scan_pins() returned
      // them (file order, then line order within a file).
      var byCat = Object.create(null);
      var order = [];
      list.forEach(function (p) {
        if (!byCat[p.category]) { byCat[p.category] = Object.create(null); order.push(p.category); }
        var sec = p.section || '(preamble)';
        (byCat[p.category][sec] = byCat[p.category][sec] || []).push(p);
      });

      var html = ['<div class="vhead"><h1>Pins</h1></div>',
        '<p class="vsub">' + list.length + ' retraction / decision marker' +
        (list.length === 1 ? '' : 's') + ' across the store. Legacy prose markers ' +
        '(RETRACTED, CORRECTED, "do not re-open"…) are worth converting to an ' +
        'explicit <code>&lt;!-- pin: kind --&gt;</code> comment.</p>'];

      order.forEach(function (cat) {
        html.push('<h3 class="search-section"><a href="#/c/' + encodeURIComponent(cat) + '">' + e(cat) + '</a></h3>');
        Object.keys(byCat[cat]).forEach(function (sec) {
          html.push(
            '<div class="pill sec-tag">' + e(sec) + '</div>' +
            '<div class="revs" style="margin-bottom:14px">' + byCat[cat][sec].map(function (p) {
              return '<div class="rev pin-row">' +
                '<a class="pin-kind pill' + (p.legacy ? ' warn' : ' ok') + '" ' +
                'href="#/c/' + encodeURIComponent(p.category) + '/l/' + p.line + '" ' +
                'title="' + (p.legacy ? 'legacy prose marker' : 'explicit pin marker') + '">' +
                e(p.kind) + '</a>' +
                '<span class="pin-text md">' + MD.render(p.text, { known: knownRefs() }) + '</span>' +
                '</div>';
            }).join('') + '</div>'
          );
        });
      });

      main(html.join(''));
    }).catch(function (err) {
      main('<div class="banner bad">' + e(err.message) + '</div>');
    });
  }

  /* ---------------------------------------------------------------- stale */

  var STALE_THRESHOLDS = [30, 90, 180];

  function staleThreshold() {
    var v;
    try { v = parseInt(localStorage.getItem('mem.staleThreshold') || '', 10); } catch (_) { v = NaN; }
    return STALE_THRESHOLDS.indexOf(v) >= 0 ? v : STALE_DAYS;
  }

  function setStaleThreshold(v) {
    try { localStorage.setItem('mem.staleThreshold', String(v)); } catch (_) { /* private mode */ }
  }

  /* --------------------------------------------------------------- keys */

  function viewKeys() {
    state.cat = null;
    state.doc = null;
    state.kind = null;
    state.editing = false;
    renderSidebar(true);
    loading();
    api('/auth/keys').then(function (res) {
      if (!res.ok) {
        return res.text().then(function (t) {
          main('<div class="vhead"><h1>MCP access</h1></div>' +
               '<p class="vsub error">' + e(detail(t, res.status)) + '</p>');
        });
      }
      return res.json().then(renderKeys);
    }).catch(function (err) { toast(err.message, true); });
  }

  function renderKeys(data) {
    var rows = data.keys || [];
    var mcpUrl = location.origin + '/mcp';
    var html = ['<div class="vhead"><h1>MCP access</h1></div>',
      '<p class="vsub">Claude reads and writes this store through its MCP server at ' +
      '<code>' + e(mcpUrl) + '</code>. Two ways to connect:</p>',
      '<ul class="vsub mcphow">',
      '<li><strong>claude.ai / the Claude apps</strong> — Settings → Connectors ' +
      '→ Add custom connector with that URL, then sign in here and click Allow. ' +
      'It shows up under <em>Connected apps</em> below.</li>',
      '<li><strong>Claude Code</strong> — create a key below and paste the command ' +
      'it comes with. Without <code>--header</code> the same command goes through ' +
      'the sign-in page instead.</li>',
      '</ul>',
      '<h2 class="keyh2">Keys</h2>',
      '<p class="vsub">A key is a bearer credential for one device or agent: it ' +
      'reads and writes the store exactly as the master token does, but deleting ' +
      'it disturbs nothing else. Keys cannot mint or delete other keys \u2014 that ' +
      'needs a signed-in browser.</p>',
      '<form id="key-new" class="keyform">',
      '  <input id="key-name" type="text" placeholder="Name this key (e.g. phone, laptop)" ' +
      'maxlength="40" spellcheck="false">',
      '  <button type="submit" class="btn primary">Create key</button>',
      '</form>',
      '<p id="key-err" class="error small hidden"></p>',
      '<div id="key-fresh"></div>'];

    if (!rows.length) {
      html.push('<p class="vsub">No keys yet.</p>');
    } else {
      html.push('<table class="keytable"><thead><tr><th>Name</th><th>Created</th>' +
                '<th>Last used</th><th></th></tr></thead><tbody>');
      rows.forEach(function (k) {
        html.push('<tr><td>' + e(k.name) + '</td><td class="muted small">' +
          e((k.created || '').slice(0, 10)) + '</td><td class="muted small">' +
          e(k.last_used ? k.last_used.slice(0, 10) : 'never') +
          '</td><td><button class="btn small danger" data-del="' + e(k.id) +
          '" data-name="' + e(k.name) + '">Delete</button></td></tr>');
      });
      html.push('</tbody></table>');
    }

    var grants = data.grants || [];
    html.push('<h2 class="keyh2">Connected apps</h2>',
      '<p class="vsub">MCP connectors you allowed through the sign-in page ' +
      '(claude.ai, the Claude apps, Claude Code). Each one reaches only ' +
      '<code>/mcp</code>. Disconnecting takes effect at its next request.</p>');
    if (!grants.length) {
      html.push('<p class="vsub">None connected.</p>');
    } else {
      html.push('<table class="keytable"><thead><tr><th>App</th><th>Allowed by</th>' +
                '<th>Created</th><th>Last refreshed</th><th></th></tr></thead><tbody>');
      grants.forEach(function (g) {
        html.push('<tr><td>' + e(g.client_name) + '</td><td class="muted small">' +
          e(g.email || '') + '</td><td class="muted small">' +
          e((g.created || '').slice(0, 10)) + '</td><td class="muted small">' +
          e(g.last_used ? g.last_used.slice(0, 10) : 'never') +
          '</td><td><button class="btn small danger" data-grant="' + e(g.id) +
          '" data-name="' + e(g.client_name) + '">Disconnect</button></td></tr>');
      });
      html.push('</tbody></table>');
    }
    // Passkeys are a section of this page rather than a page of their own: the
    // keys above and the passkeys below are both "ways in", managed together.
    // The server reports whether it is configured; when it is not, nothing here.
    if (authInfo.passkey === true) html.push(passkeysSectionHTML());

    main(html.join(''));
    if (authInfo.passkey === true) wirePasskeys();

    Array.prototype.forEach.call(document.querySelectorAll('[data-grant]'), function (b) {
      b.onclick = function () {
        if (!confirm('Disconnect "' + b.getAttribute('data-name') + '"?')) return;
        api('/auth/grants/' + encodeURIComponent(b.getAttribute('data-grant')),
            { method: 'DELETE' })
          .then(function (res) {
            if (!res.ok) return res.text().then(function (t) { throw new Error(detail(t, res.status)); });
            toast('Disconnected');
            viewKeys();
          })
          .catch(function (err2) { toast(err2.message, true); });
      };
    });

    $('key-new').addEventListener('submit', function (ev) {
      ev.preventDefault();
      var err = $('key-err');
      err.classList.add('hidden');
      api('/auth/keys', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: $('key-name').value })
      }).then(function (res) {
        if (!res.ok) {
          return res.text().then(function (t) {
            err.textContent = detail(t, res.status);
            err.classList.remove('hidden');
          });
        }
        return res.json().then(function (k) {
          // Shown once and never again: only the hash is stored. Rendering it
          // here rather than in a toast is deliberate -- it has to survive long
          // enough to be copied onto another machine.
          $('key-fresh').innerHTML =
            '<div class="keyshow"><p><strong>' + e(k.name) + '</strong> created. ' +
            'Copy it now \u2014 it is never shown again.</p>' +
            '<code id="key-val">' + e(k.value) + '</code>' +
            '<p class="muted small">Add it to Claude Code (user scope, every project):</p>' +
            '<code>' + e('claude mcp add --transport http --scope user memory ' +
              location.origin + '/mcp --header "Authorization: Bearer ' + k.value + '"') +
            '</code></div>';
          viewKeysRefresh();
        });
      }).catch(function (e2) {
        err.textContent = e2.message;
        err.classList.remove('hidden');
      });
    });

    Array.prototype.forEach.call(document.querySelectorAll('[data-del]'), function (b) {
      b.onclick = function () {
        if (!confirm('Delete key "' + b.getAttribute('data-name') +
                     '"? Anything using it stops working immediately.')) return;
        api('/auth/keys/' + encodeURIComponent(b.getAttribute('data-del')),
            { method: 'DELETE' })
          .then(function (res) {
            if (!res.ok) return res.text().then(function (t) { throw new Error(detail(t, res.status)); });
            toast('Key deleted');
            viewKeys();
          })
          .catch(function (err2) { toast(err2.message, true); });
      };
    });
  }

  /* ------------------------------------------------------------ passkeys */

  function passkeysSectionHTML() {
    return '<h2 class="keyh2">Passkeys</h2>' +
      '<p class="vsub">Sign in with this device\'s own unlock (Windows Hello, Touch ID, a phone or a ' +
      'security key) instead of the master token. Adding one needs a sign-in from the last 15 minutes.</p>' +
      (Passkey.supported()
        ? '<form id="pk-new" class="keyform">' +
          '<input id="pk-name" type="text" placeholder="Name this passkey (e.g. laptop, phone)" ' +
          'maxlength="40" spellcheck="false" aria-label="Passkey name">' +
          '<button type="submit" class="btn primary" id="pk-add">Add a passkey</button></form>'
        : '<p class="vsub">This browser does not support passkeys (WebAuthn), so one cannot be added ' +
          'from here. Existing passkeys can still be removed.</p>') +
      '<p id="pk-err" class="error small hidden"></p>' +
      '<div id="pk-list"><p class="vsub">Loading…</p></div>';
  }

  function passkeyMessage(text, quiet) {
    var el = $('pk-err');
    if (!el) return;
    el.textContent = text;
    el.className = (quiet ? 'muted' : 'error') + ' small';
  }

  function loadPasskeys() {
    return api('/auth/passkeys').then(function (res) {
      var box = $('pk-list');
      if (!box) return;
      if (!res.ok) {
        return res.text().then(function (t) {
          box.innerHTML = '<p class="vsub error">' + e(detail(t, res.status)) + '</p>';
        });
      }
      return res.json().then(function (data) {
        var list = data.passkeys || [];
        if (!list.length) { box.innerHTML = '<p class="vsub">No passkeys yet.</p>'; return; }
        box.innerHTML = '<table class="keytable"><thead><tr><th>Name</th><th>Created</th>' +
          '<th>Last used</th><th></th></tr></thead><tbody>' + list.map(function (k) {
            return '<tr><td>' + e(k.name) + '</td><td class="muted small">' +
              e((k.created || '').slice(0, 10)) + '</td><td class="muted small">' +
              e(k.last_used ? k.last_used.slice(0, 10) : 'never') +
              '</td><td><button class="btn small danger" data-pkdel="' + e(k.id) +
              '" data-name="' + e(k.name) + '">Delete</button></td></tr>';
          }).join('') + '</tbody></table>';
      });
    }).catch(function (err) { if ($('pk-list')) $('pk-list').innerHTML = '<p class="vsub error">' + e(err.message) + '</p>'; });
  }

  function wirePasskeys() {
    loadPasskeys();

    var form = $('pk-new');
    if (form) form.addEventListener('submit', function (ev) {
      ev.preventDefault();
      var name = $('pk-name').value.trim(), btn = $('pk-add');
      $('pk-err').classList.add('hidden');
      if (!name) { passkeyMessage('Give the passkey a name first.'); return; }
      btn.disabled = true;
      Passkey.register(name).then(function () {
        $('pk-name').value = '';
        toast('Passkey added');
        return loadPasskeys();
      }).catch(function (err) {
        if (err && err.status === 401) { showLogin(); return; }
        var x = Passkey.explain(err, 'register');
        passkeyMessage(x.text, x.quiet);
      }).then(function () { btn.disabled = false; });
    });

    $('pk-list').addEventListener('click', function (ev) {
      var b = ev.target.closest('[data-pkdel]');
      if (!b) return;
      if (!confirm('Delete passkey "' + b.getAttribute('data-name') +
                   '"? It can no longer be used to sign in.')) return;
      api('/auth/passkeys/' + encodeURIComponent(b.getAttribute('data-pkdel')), { method: 'DELETE' })
        .then(function (res) {
          if (!res.ok) return res.text().then(function (t) { throw new Error(detail(t, res.status)); });
          toast('Passkey deleted');
          return loadPasskeys();
        })
        .catch(function (err) { toast(err.message, true); });
    });
  }

  // Re-list without wiping the freshly shown secret above it.
  function viewKeysRefresh() {
    api('/auth/keys').then(function (res) {
      if (!res.ok) return;
      return res.json().then(function (data) {
        var fresh = $('key-fresh').innerHTML;
        renderKeys(data);
        $('key-fresh').innerHTML = fresh;
      });
    });
  }

  // The one place that answers "what needs attention": size first, then
  // freshness. #/stale (the old route) lands here too.
  function viewHealth() {
    state.cat = null;
    state.doc = null;
    state.kind = null;
    state.editing = false;
    renderSidebar(true);

    var threshold = staleThreshold();
    var rows = [];
    var stableCount = 0;
    var noMarkerCount = 0;

    state.index.forEach(function (c) {
      c.sections.forEach(function (s) {
        // 'verified: never' means this fact doesn't rot -- excluded from the
        // list entirely and reported only as a count, per spec: that marker
        // exists so this list can reach zero.
        if (s.verified === 'never') { stableCount++; return; }
        if (!s.verified) {
          noMarkerCount++;
          rows.push({ cat: c.category, name: s.name, verified: null, age: Infinity });
          return;
        }
        var age = MD.daysSince(s.verified);
        if (age !== null && age > threshold) {
          rows.push({ cat: c.category, name: s.name, verified: s.verified, age: age });
        }
      });
    });
    rows.sort(function (a, b) { return b.age - a.age; });

    var big = state.index.slice().sort(function (a, b) { return b.bytes - a.bytes; }).slice(0, 10);
    var over = state.index.filter(function (c) { return c.bytes >= CAP_BYTES; }).length;
    var near = state.index.filter(function (c) { return c.bytes >= WARN_BYTES && c.bytes < CAP_BYTES; }).length;

    var html = [
      '<div class="vhead"><h1>Health</h1></div>',
      '<p class="vsub">' + state.index.length + ' categories · ' + over + ' over the ' + fmtBytes(CAP_BYTES) +
      ' soft cap · ' + near + ' near it (from ' + fmtBytes(WARN_BYTES) + ')</p>',
      '<h2 class="keyh2 first">Largest</h2>',
      '<div class="revs">' + big.map(function (c) {
        var pct = Math.min(100, Math.round(c.bytes / CAP_BYTES * 100));
        var cls = c.bytes >= CAP_BYTES ? ' over' : c.bytes >= WARN_BYTES ? ' warn' : '';
        return '<div class="rev"><a class="msg" href="#/c/' + encodeURIComponent(c.category) + '">' +
          e(c.category) + '</a><div class="bar hbar' + cls + '"><i style="width:' + pct + '%"></i></div>' +
          '<span class="when">' + fmtBytes(c.bytes) + '</span>' +
          (c.bytes >= CAP_BYTES ? '<span class="pill stale">split</span>'
            : c.bytes >= WARN_BYTES ? '<span class="pill warn">near cap</span>' : '') + '</div>';
      }).join('') + '</div>',
      '<div class="vhead stalehead"><h2 class="keyh2">Stale sections</h2><span class="spacer"></span>' +
      '<div class="seg always" id="stale-seg" role="tablist" aria-label="Staleness threshold">' +
      STALE_THRESHOLDS.map(function (d) {
        return '<button data-d="' + d + '" class="' + (d === threshold ? 'on' : '') +
          '" role="tab" aria-selected="' + (d === threshold) + '">' + d + 'd</button>';
      }).join('') + '</div></div>',
      '<p class="vsub">' + rows.length + ' section' + (rows.length === 1 ? '' : 's') +
      ' unverified for over ' + threshold + ' days' +
      (noMarkerCount ? ' (' + noMarkerCount + ' with no &lt;!-- verified: --&gt; marker at all)' : '') +
      ' · ' + stableCount + ' section' + (stableCount === 1 ? '' : 's') + ' marked stable</p>'
    ];

    if (!rows.length) {
      html.push('<p class="muted">Nothing stale at this threshold.</p>');
    } else {
      html.push('<div class="revs">' + rows.map(function (r) {
        var id = MD.slug(r.name);
        return '<div class="rev"><a class="msg" href="#/c/' + encodeURIComponent(r.cat) + '/h/' + encodeURIComponent(id) + '">' +
          e(r.cat) + ' <span class="muted">›</span> ' + e(r.name) + '</a>' +
          '<span class="when">' + (r.verified ? e(r.verified) : 'no marker') + '</span></div>';
      }).join('') + '</div>');
    }

    main(html.join(''));

    var seg = $('stale-seg');
    if (seg) seg.addEventListener('click', function (ev) {
      var b = ev.target.closest('button[data-d]');
      if (!b) return;
      setStaleThreshold(parseInt(b.getAttribute('data-d'), 10));
      viewHealth();
    });
  }

  /* --------------------------------------------------------------- router */

  function route() {
    if (state.suppressRoute) { state.suppressRoute = false; return; }
    unforced = Object.create(null);
    closeDrawer();
    var h = location.hash.replace(/^#/, '');

    // in-page anchor to a heading: let the browser handle it. Ids are text-
    // derived now (see md.js slug()), not line-derived, so they no longer
    // reliably start with a digit -- 'h-' alone is what every route below
    // never starts with, so it is what marks this as an anchor, not a route.
    if (/^h-/.test(h)) {
      var target = document.getElementById(h);
      if (target) target.scrollIntoView({ block: 'start' });
      return;
    }

    var parts = h.split('/').filter(Boolean);   // ['c','infra','edit']
    if (!parts.length) return viewHome();

    if (parts[0] === 'new') return viewNew();
    if (parts[0] === 'newdoc') return viewNewDoc();

    if (parts[0] === 'search') return viewSearch(decodeURIComponent(parts.slice(1).join('/')));

    if (parts[0] === 'pins') return viewPins();
    if (parts[0] === 'keys') return viewKeys();
    // #/stale predates the health view and stays valid for old links
    if (parts[0] === 'health' || parts[0] === 'stale') return viewHealth();

    if (parts[0] === 'c' && parts[1]) {
      var cat = decodeURIComponent(parts[1]);
      if (parts[2] === 'edit') return viewEdit(cat);
      if (parts[2] === 'history') return viewHistory('c', cat);
      if (parts[2] === 'rev' && parts[3]) return viewRev('c', cat, parts[3]);
      if (parts[2] === 'l' && parts[3]) return viewCategory(cat, parseInt(parts[3], 10));
      if (parts[2] === 'h' && parts[3]) return viewCategory(cat, null, decodeURIComponent(parts[3]));
      return viewCategory(cat);
    }

    if (parts[0] === 'd' && parts[1]) {
      var slug = decodeURIComponent(parts[1]);
      if (parts[2] === 'edit') return viewDocEdit(slug);
      if (parts[2] === 'history') return viewHistory('d', slug);
      if (parts[2] === 'rev' && parts[3]) return viewRev('d', slug, parts[3]);
      if (parts[2] === 'l' && parts[3]) return viewDoc(slug, parseInt(parts[3], 10));
      if (parts[2] === 'h' && parts[3]) return viewDoc(slug, null, decodeURIComponent(parts[3]));
      return viewDoc(slug);
    }
    return viewHome();
  }

  var lastHash = location.hash;
  window.addEventListener('hashchange', function () {
    // leaving the editor with unsaved text: ask, and put the hash back if declined
    if (state.dirty && state.editing && !/\/edit$/.test(location.hash)) {
      if (!confirm('Discard unsaved changes?')) {
        state.suppressRoute = true;
        location.hash = lastHash;
        return;
      }
      setDirty(false);
    }
    lastHash = location.hash;
    route();
  });

  window.addEventListener('beforeunload', function (ev) {
    if (state.dirty) { ev.preventDefault(); ev.returnValue = ''; }
  });

  /* ----------------------------------------------------------------- boot */

  fetch('/auth/me', { credentials: 'same-origin', cache: 'no-store' })
    .then(function (r) { return r.json(); })
    .then(function (me) {
      // Remember it even when signed in: this is the only time the page learns
      // whether Google is configured, and showLogin() needs it later if the
      // session expires while the tab is open.
      if (me && me.providers) authInfo = me;
      if (me.email) $('logout-btn').title = 'Sign out (signed in as ' + me.email + ')';
      return me.authenticated ? showApp() : showLogin(me);
    })
    .catch(function () { showLogin(); });
})();
