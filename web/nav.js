/* Navigation logic for the memory web UI: the category tree and the quick-jump
 * matcher. Kept free of DOM and storage access so rendertest.js can exercise it
 * in node; app.js owns rendering and localStorage.
 */
window.Nav = (function () {
  'use strict';

  /* ------------------------------------------------------------------ tree */

  /* The store is flat -- names must match ^[a-z0-9-]+$ -- but the convention is
   * `<parent>-<sub>`, so the hierarchy is recoverable from the names alone.
   * Parent = the LONGEST existing category that is a prefix of this one, which
   * is what puts infra-pc-tuning under infra-pc rather than under infra. A name
   * whose prefix has no category of its own just stays at the root. */
  function buildTree(index) {
    var node = Object.create(null);
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

  // Roots are open (so their direct children show); everything deeper is
  // closed until the user opens it. Explicit overrides beat the default, which
  // is why a category created later still gets the default.
  function defaultOpen(depth) { return depth === 0; }

  // The stored overrides come from localStorage, i.e. from anything that ever
  // wrote that key. Keep only { string: boolean } pairs.
  function parseOverrides(raw) {
    var out = Object.create(null), v;
    try { v = JSON.parse(raw || '{}'); } catch (_) { return out; }
    if (!v || typeof v !== 'object' || Array.isArray(v)) return out;
    Object.keys(v).forEach(function (k) { if (typeof v[k] === 'boolean') out[k] = v[k]; });
    return out;
  }

  // category -> true for every category matching `filter` (name, or the slug /
  // title of an attached doc) and each of its ancestors.
  function filterVisible(tree, filter, docTitles) {
    var visible = Object.create(null);
    Object.keys(tree.node).forEach(function (n) {
      var docMatch = (tree.node[n].cat.docs || []).some(function (d) {
        return d.indexOf(filter) >= 0 || ((docTitles && docTitles[d]) || '').toLowerCase().indexOf(filter) >= 0;
      });
      if (n.indexOf(filter) < 0 && !docMatch) return;
      visible[n] = true;
      for (var a = tree.node[n].parent; a; a = tree.node[a].parent) visible[a] = true;
    });
    return visible;
  }

  /* The flat list of rows to draw, in order.
   *   o.overrides  { name: bool }  explicit open/closed choices
   *   o.forced     { name: true }  ancestors of the active row: open for this
   *                                render only, nothing is stored
   *   o.unforced   { name: true }  forced nodes the user just collapsed by hand
   *   o.visible    { name: true }  filter result, or null for no filter
   * With a filter active every visible node is open: a match hidden inside a
   * collapsed branch would defeat the point of filtering.
   * A category row is { t:'c', name, depth, open, expandable, hidden } where
   * `hidden` is how many children (sub-categories + docs) the row is hiding.
   * A doc row is { t:'d', slug, depth, owner }. */
  function rows(tree, o) {
    var out = [];
    var overrides = o.overrides || Object.create(null), forced = o.forced || Object.create(null), unforced = o.unforced || Object.create(null);
    function isOpen(name) {
      if (o.visible) return true;
      if (forced[name] && !unforced[name]) return true;
      if (Object.prototype.hasOwnProperty.call(overrides, name)) return overrides[name];
      return defaultOpen(tree.node[name].depth);
    }
    function walk(name) {
      if (o.visible && !o.visible[name]) return;
      var nd = tree.node[name];
      var kids = o.visible ? nd.kids.filter(function (k) { return o.visible[k]; }) : nd.kids;
      var docs = nd.cat.docs || [];
      var n = kids.length + docs.length;
      var open = n > 0 && isOpen(name);
      out.push({ t: 'c', name: name, depth: nd.depth, open: open, expandable: n > 0,
                 hidden: open ? 0 : n, kids: kids.length, docs: docs.length });
      if (!open) return;
      kids.forEach(walk);
      docs.forEach(function (slug) { out.push({ t: 'd', slug: slug, depth: nd.depth + 1, owner: name }); });
    }
    tree.roots.forEach(walk);
    return out;
  }

  // Size / freshness of a category and everything below it, for the home cards.
  function subtreeStats(tree, name, warnBytes) {
    var s = { count: 0, bytes: 0, mtime: 0, warn: 0 };
    (function walk(n) {
      var c = tree.node[n].cat, t = Date.parse(c.mtime);
      s.count++;
      s.bytes += c.bytes;
      if (!isNaN(t) && t > s.mtime) s.mtime = t;
      if (c.bytes >= warnBytes) s.warn++;
      tree.node[n].kids.forEach(walk);
    })(name);
    return s;
  }

  /* ----------------------------------------------------------------- fuzzy */

  function boundary(t, i) {
    if (i === 0) return true;
    var p = t.charAt(i - 1);
    return p === '-' || p === ' ' || p === '/' || p === '_' || p === '.' || p === ':';
  }

  // One lowercase needle against one lowercase haystack: a score, or null for
  // no match. A contiguous hit always outranks a scattered subsequence, and
  // starting at a word start (after '-' or a space) outranks starting mid-word.
  function token(q, t) {
    var idx = t.indexOf(q);
    if (idx >= 0) {
      var at = idx;
      while (at >= 0 && !boundary(t, at)) at = t.indexOf(q, at + 1);
      var s = 500 - (at >= 0 ? at : idx) * 2 - (t.length - q.length) * 0.5;
      if (at >= 0) s += 100;
      if (at === 0) s += 60;
      if (t === q) s += 400;
      return s;
    }
    var pos = 0, prev = -2, score = 100;
    for (var i = 0; i < q.length; i++) {
      var f = t.indexOf(q.charAt(i), pos);
      if (f < 0) return null;
      score += f === prev + 1 ? 12 : -Math.min(f - pos, 8);
      if (boundary(t, f)) score += 8;
      prev = f;
      pos = f + 1;
    }
    return Math.min(score, 250) - t.length * 0.3;
  }

  // Whitespace-separated words must each match somewhere in `text`.
  function fuzzy(query, text) {
    var words = String(query).toLowerCase().split(/\s+/).filter(Boolean);
    if (!words.length) return 0;
    var t = String(text).toLowerCase(), sum = 0;
    for (var i = 0; i < words.length; i++) {
      var s = token(words[i], t);
      if (s === null) return null;
      sum += s;
    }
    return sum;
  }

  // Everything the quick-jump palette can land on. slugFn turns a section name
  // into the heading id render() gives it (MD.slug), so that this file does not
  // need to know about the markdown renderer.
  function buildItems(index, docs, slugFn) {
    var items = [];
    var enc = encodeURIComponent;
    index.forEach(function (c) {
      items.push({ kind: 'c', id: 'c:' + c.category, label: c.category, sub: '', alt: '',
                   href: '#/c/' + enc(c.category), bias: 0 });
      (c.sections || []).forEach(function (s) {
        items.push({ kind: 's', id: 'c:' + c.category + '#' + s.name, label: s.name, sub: c.category,
                    alt: c.category + ' ' + s.name,
                    href: '#/c/' + enc(c.category) + '/h/' + enc(slugFn(s.name)), bias: -6 });
      });
    });
    docs.forEach(function (d) {
      var title = d.title || d.doc;
      items.push({ kind: 'd', id: 'd:' + d.doc, label: title, sub: title !== d.doc ? d.doc : '',
                   alt: d.doc, href: '#/d/' + enc(d.doc), bias: -3 });
      (d.sections || []).forEach(function (s) {
        items.push({ kind: 's', id: 'd:' + d.doc + '#' + s.name, label: s.name, sub: d.doc,
                    alt: d.doc + ' ' + s.name,
                    href: '#/d/' + enc(d.doc) + '/h/' + enc(slugFn(s.name)), bias: -6 });
      });
    });
    return items;
  }

  // Best matches first; ties go to the shorter label, then alphabetical.
  function search(items, query, limit) {
    var hits = [];
    items.forEach(function (it) {
      var s = fuzzy(query, it.label);
      if (it.alt) {
        var a = fuzzy(query, it.alt);
        if (a !== null && (s === null || a - 15 > s)) s = a - 15;
      }
      if (s !== null) hits.push({ item: it, score: s + it.bias });
    });
    hits.sort(function (x, y) {
      return (y.score - x.score) || (x.item.label.length - y.item.label.length) ||
        (x.item.label < y.item.label ? -1 : x.item.label > y.item.label ? 1 : 0) ||
        (x.item.sub < y.item.sub ? -1 : x.item.sub > y.item.sub ? 1 : 0);
    });
    return hits.slice(0, limit || 30).map(function (h) { return h.item; });
  }

  return {
    buildTree: buildTree, defaultOpen: defaultOpen, parseOverrides: parseOverrides,
    filterVisible: filterVisible, rows: rows, subtreeStats: subtreeStats,
    fuzzy: fuzzy, buildItems: buildItems, search: search
  };
})();
