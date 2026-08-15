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

  var e = MD.escape;
  var $ = function (id) { return document.getElementById(id); };

  var state = {
    index: [],
    cat: null,
    body: '',
    etag: null,
    dirty: false,
    editing: false,
    suppressRoute: false
  };

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

  function getCategory(cat, rev) {
    var url = '/memory/' + encodeURIComponent(cat) + (rev ? '?rev=' + encodeURIComponent(rev) : '');
    return api(url).then(function (res) {
      if (!res.ok) return res.text().then(function (t) { throw new Error(detail(t, res.status)); });
      return res.text().then(function (body) {
        return { body: body, etag: (res.headers.get('ETag') || '').replace(/"/g, '') };
      });
    });
  }

  /* ----------------------------------------------------------------- auth */

  function showLogin() {
    $('app').classList.add('hidden');
    $('login').classList.remove('hidden');
    setTimeout(function () { $('login-token').focus(); }, 30);
  }

  function showApp() {
    $('login').classList.add('hidden');
    $('app').classList.remove('hidden');
    return loadIndex().then(route);
  }

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
        err.textContent = res.status === 429
          ? 'Too many attempts. Wait a few minutes.'
          : detail(t, res.status);
        err.classList.remove('hidden');
      });
    }).catch(function () {
      err.textContent = 'Network error.';
      err.classList.remove('hidden');
    });
  });

  $('logout-btn').addEventListener('click', function () {
    // it sits a thumb's width from "+ New" on a phone, and there is no undo:
    // an accidental tap ends the session and any open edit with it
    if (state.dirty && !confirm('You have unsaved changes. Sign out anyway?')) return;
    if (!confirm('Sign out? You will need the API token again.')) return;
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

  /* The store is flat -- names must match ^[a-z0-9-]+$ -- but the convention is
   * `<parent>-<sub>`, so the hierarchy is recoverable from the names alone.
   * Parent = the LONGEST existing category that is a prefix of this one, which
   * is what puts infra-pc-tuning under infra-pc rather than under infra. A name
   * whose prefix has no category of its own just stays at the root. */
  function buildTree(index) {
    var node = {};
    index.forEach(function (c) { node[c.category] = { cat: c, kids: [], parent: null, depth: 0 }; });
    var names = Object.keys(node).sort();

    names.forEach(function (n) {
      var best = null;
      names.forEach(function (p) {
        if (p !== n && n.indexOf(p + '-') === 0 && (!best || p.length > best.length)) best = p;
      });
      if (best) { node[n].parent = best; node[best].kids.push(n); }
    });
    names.forEach(function (n) {
      var d = 0, p = node[n].parent;
      while (p) { d++; p = node[p].parent; }
      node[n].depth = d;
    });
    return { node: node, roots: names.filter(function (n) { return !node[n].parent; }) };
  }

  function collapsedSet() {
    try { return JSON.parse(localStorage.getItem('mem.collapsed') || '[]'); } catch (_) { return []; }
  }
  function setCollapsed(list) {
    try { localStorage.setItem('mem.collapsed', JSON.stringify(list)); } catch (_) { /* private mode */ }
  }

  function renderSidebar() {
    var filter = ($('filter').value || '').toLowerCase().trim();
    var tree = buildTree(state.index);
    var collapsed = collapsedSet();

    // ancestors of the open category are forced open, without editing the
    // stored preference -- the user's collapse survives navigating into a sub
    var forced = {};
    for (var p = state.cat && tree.node[state.cat] ? tree.node[state.cat].parent : null; p; p = tree.node[p].parent) {
      forced[p] = true;
    }

    // filtering: keep matches plus every ancestor, and open everything shown
    var visible = null;
    if (filter) {
      visible = {};
      Object.keys(tree.node).forEach(function (n) {
        if (n.indexOf(filter) < 0) return;
        visible[n] = true;
        for (var a = tree.node[n].parent; a; a = tree.node[a].parent) visible[a] = true;
      });
    }

    function isOpen(n) {
      return !!filter || forced[n] || collapsed.indexOf(n) < 0;
    }

    var html = [];
    function walk(name) {
      if (visible && !visible[name]) return;
      var nd = tree.node[name], c = nd.cat;
      var pct = Math.min(100, Math.round(c.bytes / CAP_BYTES * 100));
      var cls = c.bytes >= CAP_BYTES ? ' over' : c.bytes >= WARN_BYTES ? ' warn' : '';
      var shown = nd.parent ? name.slice(nd.parent.length + 1) : name;
      var open = isOpen(name);
      var kids = visible ? nd.kids.filter(function (k) { return visible[k]; }) : nd.kids;

      html.push(
        // indent is capped: nesting is unbounded by design (the tree is derived
        // from names, not stored), but past a few levels the indent would eat
        // the 272px sidebar and the name would wrap to nothing
        '<div class="catrow" style="padding-left:' + (Math.min(nd.depth, 5) * 13) + 'px">' +
        (kids.length
          ? '<button class="caret" data-toggle="' + e(name) + '" title="' +
            (open ? 'Collapse' : 'Expand') + '">' + (open ? '▾' : '▸') + '</button>'
          : '<span class="caret ghost">·</span>') +
        '<a class="cat' + (name === state.cat ? ' active' : '') + '" href="#/c/' +
        encodeURIComponent(name) + '" title="' + e(name) + '">' +
        '<div class="cat-name">' + e(shown) +
        (kids.length && !open ? ' <span class="pill sub">' + kids.length + '</span>' : '') + '</div>' +
        '<div class="bar' + cls + '"><i style="width:' + pct + '%"></i></div>' +
        '<div class="cat-meta"><span>' + fmtBytes(c.bytes) + ' · ' + c.sections.length + ' §</span>' +
        '<span>' + fmtAgo(c.mtime) + '</span></div></a></div>'
      );
      if (open) kids.forEach(walk);
    }
    tree.roots.forEach(walk);

    $('catlist').innerHTML = html.join('') ||
      '<p class="small muted" style="padding:8px">No match.</p>';

    var total = state.index.reduce(function (a, c) { return a + c.bytes; }, 0);
    var over = state.index.filter(function (c) { return c.bytes >= WARN_BYTES; }).length;
    $('store-stats').innerHTML = state.index.length + ' categories · ' + fmtBytes(total) +
      (over ? ' · <span class="pill warn">' + over + ' near cap</span>' : '');
  }

  $('catlist').addEventListener('click', function (ev) {
    var btn = ev.target.closest('.caret[data-toggle]');
    if (!btn) return;
    ev.preventDefault();
    var name = btn.getAttribute('data-toggle');
    var list = collapsedSet();
    var i = list.indexOf(name);
    if (i >= 0) list.splice(i, 1); else list.push(name);
    setCollapsed(list);
    renderSidebar();
  });

  $('filter').addEventListener('input', renderSidebar);

  $('menu-btn').addEventListener('click', function () {
    $('sidebar').classList.toggle('open');
    $('scrim').classList.toggle('hidden');
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
      var d = s.verified ? MD.daysSince(s.verified) : null;
      var date = s.verified
        ? '<span class="odate' + (d > STALE_DAYS ? ' stale' : '') + '">' + e(s.verified) + '</span>'
        : '';
      return '<a href="#' + s.id + '">' + e(s.name) + ' ' + date + '</a>';
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

  /* ------------------------------------------------------------ home view */

  function viewHome() {
    state.cat = null;
    renderSidebar();
    var total = state.index.reduce(function (a, c) { return a + c.bytes; }, 0);
    var big = state.index.slice().sort(function (a, b) { return b.bytes - a.bytes; }).slice(0, 5);
    var recent = state.index.slice().sort(function (a, b) {
      return Date.parse(b.mtime) - Date.parse(a.mtime);
    }).slice(0, 5);

    var stale = [];
    state.index.forEach(function (c) {
      c.sections.forEach(function (s) {
        if (s.verified && MD.daysSince(s.verified) > STALE_DAYS) {
          stale.push({ cat: c.category, name: s.name, verified: s.verified });
        }
      });
    });

    function rows(items, right) {
      return '<div class="revs">' + items.map(function (c) {
        return '<div class="rev"><a class="msg" href="#/c/' + encodeURIComponent(c.category) + '">' +
          e(c.category) + '</a><span class="when">' + right(c) + '</span></div>';
      }).join('') + '</div>';
    }

    main(
      '<div class="vhead"><h1>Memory store</h1></div>' +
      '<p class="vsub">' + state.index.length + ' categories · ' + fmtBytes(total) +
      ' · soft cap ' + fmtBytes(CAP_BYTES) + ' per category</p>' +
      '<h3>Largest</h3>' + rows(big, function (c) {
        return fmtBytes(c.bytes) + (c.bytes >= CAP_BYTES ? ' <span class="pill stale">split</span>'
          : c.bytes >= WARN_BYTES ? ' <span class="pill warn">near cap</span>' : '');
      }) +
      '<h3 style="margin-top:22px">Recently changed</h3>' + rows(recent, function (c) { return fmtAgo(c.mtime); }) +
      (stale.length
        ? '<h3 style="margin-top:22px">Sections unverified for over ' + STALE_DAYS + ' days</h3>' +
          '<div class="revs">' + stale.slice(0, 12).map(function (s) {
            return '<div class="rev"><a class="msg" href="#/c/' + encodeURIComponent(s.cat) + '">' +
              e(s.cat) + ' <span class="muted">›</span> ' + e(s.name) + '</a>' +
              '<span class="when">' + e(s.verified) + '</span></div>';
          }).join('') + '</div>'
        : '')
    );
  }

  /* ------------------------------------------------------------ read view */

  function viewCategory(cat, line) {
    state.cat = cat;
    state.editing = false;
    renderSidebar();
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
        '<span class="spacer"></span><div class="actions">' +
        '<button class="btn" data-act="edit">Edit</button>' +
        '<a class="btn" href="#/c/' + encodeURIComponent(cat) + '/history">History</a>' +
        '<button class="btn danger" data-act="delete">Delete</button>' +
        '</div></div>' +
        '<p class="vsub">' + fmtBytes(size) + ' · ' + MD.sections(r.body).length + ' sections · etag ' +
        '<code>' + e(r.etag.slice(0, 8)) + '</code>' +
        (meta ? ' · changed ' + fmtAgo(meta.mtime) : '') + '</p>' +
        '<div class="reading"><article class="md">' +
        MD.render(r.body, { staleDays: STALE_DAYS }) + '</article>' + outlineHTML(r.body) + '</div>'
      );

      $('main').querySelector('[data-act="edit"]').onclick = function () {
        location.hash = '#/c/' + encodeURIComponent(cat) + '/edit';
      };
      $('main').querySelector('[data-act="delete"]').onclick = function () { askDelete(cat); };

      if (line) setTimeout(function () { scrollToLine(line); }, 30);
    }).catch(function (err) {
      main('<div class="banner bad">' + e(err.message) + '</div>');
    });
  }

  /* ------------------------------------------------------------ edit view */

  var TEMPLATE = '## Overview\n<!-- verified: DATE -->\n\n- \n';

  function editorHTML(cat, body, isNew) {
    return '<div class="vhead"><h1>' + (isNew ? 'New category' : e(cat)) +
      '<span class="dot hidden" id="dirty"> ●</span></h1>' +
      '<span class="spacer"></span><div class="actions">' +
      '<div class="seg" id="seg" role="tablist">' +
      '<button data-p="ed" class="on" role="tab">Edit</button>' +
      '<button data-p="pv" role="tab">Preview</button></div>' +
      '<button class="btn primary" id="save">Save</button>' +
      '<button class="btn" id="close">Close</button></div></div>' +
      (isNew
        ? '<p class="vsub">Name must match <code>^[a-z0-9-]+$</code>. Sub-categories are named ' +
          '<code>&lt;parent&gt;-&lt;sub&gt;</code>.</p>' +
          '<p><input id="newname" placeholder="category-name" spellcheck="false" ' +
          'aria-label="New category name" style="width:100%;max-width:340px"></p>'
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
      resync: function () { if (alive()) { marks = null; fromEditor(true); } }
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
  function draftKey(cat) { return 'mem.draft.' + (cat || '__new__'); }

  function saveDraft(cat, text) {
    try { localStorage.setItem(draftKey(cat), JSON.stringify({ t: text, at: Date.now() })); }
    catch (_) { /* quota or private mode: the net is a bonus, not a dependency */ }
  }
  function readDraft(cat) {
    try { return JSON.parse(localStorage.getItem(draftKey(cat)) || 'null'); } catch (_) { return null; }
  }
  function dropDraft(cat) {
    try { localStorage.removeItem(draftKey(cat)); } catch (_) { /* nothing to clean */ }
  }

  function wireEditor(cat, isNew) {
    var ed = $('ed'), pv = $('pv'), timer;

    function preview() {
      pv.innerHTML = MD.render(ed.value, { staleDays: STALE_DAYS });
      if (editorSync) editorSync.resync();
    }
    editorSync = null;          // build after the first render, so marks exist
    preview();
    editorSync = makeSync(ed, pv);

    ed.addEventListener('input', function () {
      setDirty(true);
      clearTimeout(timer);
      timer = setTimeout(function () { preview(); saveDraft(cat, ed.value); }, 140);
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
        doSave(cat, isNew);
      }
    });

    // phone pane switcher; inert above 860px, where both panes are visible
    $('seg').addEventListener('click', function (ev) {
      var b = ev.target.closest('button[data-p]');
      if (!b) return;
      $('split').setAttribute('data-only', b.getAttribute('data-p'));
      var all = $('seg').querySelectorAll('button');
      for (var i = 0; i < all.length; i++) all[i].classList.toggle('on', all[i] === b);
      if (b.getAttribute('data-p') === 'pv') preview();
    });

    $('save').onclick = function () { doSave(cat, isNew); };
    $('close').onclick = function () {
      if (state.dirty && !confirm('Discard unsaved changes?')) return;
      dropDraft(cat);
      setDirty(false);
      location.hash = isNew ? '#/' : '#/c/' + encodeURIComponent(cat);
    };
    setTimeout(function () { ed.focus(); }, 30);
  }

  /* Offer a recovered draft rather than silently overwriting either side. */
  function offerDraft(cat, serverBody) {
    var d = readDraft(cat);
    if (!d || typeof d.t !== 'string' || d.t === serverBody) { dropDraft(cat); return; }

    var bar = document.createElement('div');
    bar.className = 'banner warn';
    bar.innerHTML = '<span>Unsaved draft from ' + e(fmtAgo(new Date(d.at).toISOString())) +
      ' found on this device, different from the saved version.</span><span class="spacer"></span>' +
      '<button class="btn small" id="draft-use">Restore draft</button>' +
      '<button class="btn small" id="draft-drop">Discard</button>';
    var wrap = $('main').querySelector('.wrap');
    wrap.insertBefore(bar, wrap.querySelector('.split'));

    $('draft-use').onclick = function () {
      $('ed').value = d.t;
      $('ed').dispatchEvent(new Event('input'));
      setDirty(true);
      bar.parentNode.removeChild(bar);
      toast('Draft restored — not saved yet');
    };
    $('draft-drop').onclick = function () {
      dropDraft(cat);
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
    state.editing = true;
    renderSidebar();
    loading();
    getCategory(cat).then(function (r) {
      state.body = r.body;
      state.etag = r.etag;
      mainEdit(editorHTML(cat, r.body, false));
      wireEditor(cat, false);
      setDirty(false);
      offerDraft(cat, r.body);
    }).catch(function (err) {
      main('<div class="banner bad">' + e(err.message) + '</div>');
    });
  }

  function viewNew() {
    state.cat = null;
    state.editing = true;
    state.etag = null;
    renderSidebar();
    var seed = TEMPLATE.replace('DATE', new Date().toISOString().slice(0, 10));
    mainEdit(editorHTML('', seed, true));
    wireEditor(null, true);
    setDirty(false);
    offerDraft(null, seed);
  }

  function doSave(cat, isNew) {
    var text = $('ed').value;
    if (isNew) {
      cat = ($('newname').value || '').trim();
      if (!/^[a-z0-9-]+$/.test(cat)) { toast('Name must match ^[a-z0-9-]+$', true); return; }
    }
    var headers = { 'Content-Type': 'text/plain; charset=utf-8' };
    if (isNew) headers['If-None-Match'] = '*';
    else headers['If-Match'] = state.etag;

    $('save').disabled = true;
    api('/memory/' + encodeURIComponent(cat), { method: 'PUT', headers: headers, body: text })
      .then(function (res) {
        $('save').disabled = false;
        if (res.status === 409) return res.text().then(function () { showConflict(cat, text); });
        if (!res.ok) return res.text().then(function (t) { toast(detail(t, res.status), true); });
        state.etag = (res.headers.get('ETag') || '').replace(/"/g, '');
        state.body = text;
        setDirty(false);
        setSaveState(true);
        dropDraft(isNew ? null : cat);
        toast('Saved');
        // Stay in the editor: Ctrl+S mid-edit must not throw away the caret,
        // the scroll position and the pane split. "Close" is how you leave.
        return loadIndex().then(function () {
          if (isNew) {
            state.suppressRoute = true;
            location.hash = '#/c/' + encodeURIComponent(cat);
            state.cat = cat;
            mainEdit(editorHTML(cat, text, false));
            wireEditor(cat, false);
            setDirty(false);
          }
          renderSidebar();
        });
      })
      .catch(function (err) { $('save').disabled = false; toast(err.message, true); });
  }

  /* -------------------------------------------------------- conflict view */

  function showConflict(cat, mine) {
    getCategory(cat).then(function (theirs) {
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
        api('/memory/' + encodeURIComponent(cat), {
          method: 'PUT',
          headers: { 'Content-Type': 'text/plain; charset=utf-8', 'If-Match': '*' },
          body: mine
        }).then(function (res) {
          if (!res.ok) return res.text().then(function (t) { toast(detail(t, res.status), true); });
          state.etag = (res.headers.get('ETag') || '').replace(/"/g, '');
          setDirty(false);
          toast('Overwritten. Their version is still in git history.');
          return loadIndex();
        });
      };
    }).catch(function (err) { toast(err.message, true); });
  }

  /* ---------------------------------------------------------- delete flow */

  function askDelete(cat) {
    var m = modal(
      '<h3>Delete <code>' + e(cat) + '</code>?</h3>' +
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
      api('/memory/' + encodeURIComponent(cat), {
        method: 'DELETE',
        headers: { 'If-Match': state.etag }
      }).then(function (res) {
        m.close();
        if (!res.ok) return res.text().then(function (t) { toast(detail(t, res.status), true); });
        toast('Deleted ' + cat);
        return loadIndex().then(function () { location.hash = '#/'; viewHome(); });
      }).catch(function (err) { toast(err.message, true); });
    };
    setTimeout(function () { input.focus(); }, 30);
  }

  /* --------------------------------------------------------- history view */

  function viewHistory(cat) {
    state.cat = cat;
    state.editing = false;
    renderSidebar();
    loading();
    apiJSON('/memory/' + encodeURIComponent(cat) + '/history?limit=100').then(function (revs) {
      main(
        '<div class="vhead"><h1>' + e(cat) + ' <span class="muted">history</span></h1>' +
        '<span class="spacer"></span><div class="actions">' +
        '<a class="btn" href="#/c/' + encodeURIComponent(cat) + '">Back to category</a></div></div>' +
        '<p class="vsub">' + revs.length + ' revisions. The newest is the live file.</p>' +
        '<div class="revs">' + revs.map(function (r, i) {
          return '<div class="rev' + (i === 0 ? ' current' : '') + '">' +
            '<a class="sha" href="#/c/' + encodeURIComponent(cat) + '/rev/' + e(r.sha) + '">' + e(r.short) + '</a>' +
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

  function viewRev(cat, sha) {
    state.cat = cat;
    state.editing = false;
    renderSidebar();
    loading();
    Promise.all([getCategory(cat, sha), getCategory(cat).catch(function () { return null; })])
      .then(function (r) {
        var old = r[0], cur = r[1];
        var d = cur ? Diff.render(old.body, cur.body, 3) : null;
        mainWide(
          '<div class="vhead"><h1>' + e(cat) + ' <span class="muted">@ ' + e(sha.slice(0, 8)) + '</span></h1>' +
          '<span class="spacer"></span><div class="actions">' +
          '<button class="btn" id="r-diff">Toggle diff</button>' +
          '<button class="btn" id="r-load">Load into editor</button>' +
          '<a class="btn" href="#/c/' + encodeURIComponent(cat) + '/history">Back to history</a>' +
          '</div></div>' +
          '<div class="banner">Read-only snapshot from git.' +
          (d ? ' Against the live file: +' + d.stats.added + ' / −' + d.stats.removed + '.' : '') +
          '</div>' +
          (d ? '<div class="diff hidden" id="r-diffbox">' + d.html + '</div>' : '') +
          '<article class="md" id="r-body">' + MD.render(old.body, { staleDays: STALE_DAYS }) + '</article>'
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
          mainEdit(editorHTML(cat, old.body, false));
          wireEditor(cat, false);
          setDirty(true);
          state.suppressRoute = true;
          location.hash = '#/c/' + encodeURIComponent(cat) + '/edit';
          toast('Loaded ' + sha.slice(0, 8) + ' into the editor — save to restore it');
        };
      }).catch(function (err) {
        main('<div class="banner bad">' + e(err.message) + '</div>');
      });
  }

  /* ---------------------------------------------------------- search view */

  function viewSearch(q) {
    state.cat = null;
    state.editing = false;
    renderSidebar();
    $('search-input').value = q;
    loading();
    var terms = q.split(/\s+/).filter(Boolean);
    apiJSON('/memory/search?limit=100&q=' + encodeURIComponent(q)).then(function (hits) {
      if (!hits.length) {
        main('<div class="vhead"><h1>No hits</h1></div><p class="vsub">All terms must appear on the ' +
          'same line — try fewer words.</p>');
        return;
      }
      var groups = {};
      hits.forEach(function (h) { (groups[h.category] = groups[h.category] || []).push(h); });

      main('<div class="vhead"><h1>' + hits.length + ' hits</h1></div>' +
        '<p class="vsub">for <code>' + e(q) + '</code> across ' + Object.keys(groups).length + ' categories</p>' +
        Object.keys(groups).map(function (cat) {
          return '<div class="hitgroup"><h3><a href="#/c/' + encodeURIComponent(cat) + '">' + e(cat) + '</a></h3>' +
            groups[cat].map(function (h) {
              return '<a class="hit" href="#/c/' + encodeURIComponent(cat) + '/l/' + h.line + '">' +
                '<div class="where">' + (h.section ? e(h.section) + ' · ' : '') + 'line ' + h.line + '</div>' +
                '<div class="snip">' + hl(e(h.snippet || ''), terms) + '</div></a>';
            }).join('') + '</div>';
        }).join(''));
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

  $('search-form').addEventListener('submit', function (ev) {
    ev.preventDefault();
    var q = $('search-input').value.trim();
    if (q) location.hash = '#/search/' + encodeURIComponent(q);
  });

  $('new-btn').addEventListener('click', function () { location.hash = '#/new'; });

  /* --------------------------------------------------------------- router */

  function route() {
    if (state.suppressRoute) { state.suppressRoute = false; return; }
    closeDrawer();
    var h = location.hash.replace(/^#/, '');

    // in-page anchor to a heading: let the browser handle it
    if (/^h-\d/.test(h)) {
      var target = document.getElementById(h);
      if (target) target.scrollIntoView({ block: 'start' });
      return;
    }

    var parts = h.split('/').filter(Boolean);   // ['c','infra','edit']
    if (!parts.length) return viewHome();

    if (parts[0] === 'new') return viewNew();

    if (parts[0] === 'search') return viewSearch(decodeURIComponent(parts.slice(1).join('/')));

    if (parts[0] === 'c' && parts[1]) {
      var cat = decodeURIComponent(parts[1]);
      if (parts[2] === 'edit') return viewEdit(cat);
      if (parts[2] === 'history') return viewHistory(cat);
      if (parts[2] === 'rev' && parts[3]) return viewRev(cat, parts[3]);
      if (parts[2] === 'l' && parts[3]) return viewCategory(cat, parseInt(parts[3], 10));
      return viewCategory(cat);
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
    .then(function (me) { return me.authenticated ? showApp() : showLogin(); })
    .catch(showLogin);
})();
