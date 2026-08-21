/* Minimal markdown renderer for the memory store.
 *
 * Deliberately not a general-purpose library. The store is machine-written in
 * a narrow style, so a small renderer covers it, and writing it here buys two
 * things a dependency would not:
 *   - escape-by-default. Nothing in a memory file can ever become live HTML.
 *   - `<!-- verified: DATE -->` renders as a staleness badge on the heading
 *     above it instead of disappearing like a normal comment.
 *
 * Notably absent: `_underscore_` emphasis. The corpus is full of snake_case
 * identifiers and mangling them would be worse than lacking a second italic.
 */
window.MD = (function () {
  'use strict';

  var VERIFIED = /^\s*<!--\s*verified:\s*(\d{4}-\d{2}-\d{2}|never)\s*-->\s*$/;
  var COMMENT = /^\s*<!--[\s\S]*?-->\s*$/;
  var HEADING = /^(#{1,6})\s+(.*?)\s*#*\s*$/;
  var BULLET = /^(\s*)([-*+]|\d+[.)])\s+(.*)$/;
  var FENCE = /^\s*(```|~~~)(.*)$/;
  var HR = /^\s*(-{3,}|\*{3,}|_{3,})\s*$/;
  var TABLE_SEP = /^\s*\|?[\s:|-]+\|[\s:|-]*$/;
  var SAFE_URL = /^(https?:\/\/|mailto:|#|\/)/i;

  function esc(s) {
    return String(s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }

  // Text-derived, not line-derived: an id used to be 'h-<line>-<text>', so
  // editing anything above a heading silently changed every id below it and
  // broke every existing link to that section. Same text now always yields
  // the same id, and only an actual duplicate heading gets a '-2', '-3', ...
  // suffix -- `seen` is one counter map per render()/sections() call, so two
  // calls over the same document produce the same ids independently.
  function slug(s, seen) {
    var base = String(s).toLowerCase().replace(/[^\w一-鿿]+/g, '-').replace(/^-|-$/g, '').slice(0, 40);
    var id = base ? 'h-' + base : 'h-section';
    if (seen) {
      var n = (seen[id] = (seen[id] || 0) + 1);
      if (n > 1) id += '-' + n;
    }
    return id;
  }

  function link(url, text) {
    // url is already escaped; unescape the ampersands only to test the scheme
    var probe = url.replace(/&amp;/g, '&');
    if (!SAFE_URL.test(probe)) return text;
    var ext = /^https?:/i.test(probe) ? ' target="_blank" rel="noopener noreferrer"' : '';
    return '<a href="' + url + '"' + ext + '>' + text + '</a>';
  }

  // known.cats / known.docs may be an Array or a Set -- either works as a
  // membership check without forcing every caller to build a Set.
  function has(set, name) {
    if (!set) return false;
    if (typeof set.has === 'function') return set.has(name);
    for (var i = 0; i < set.length; i++) if (set[i] === name) return true;
    return false;
  }

  /* inline ---------------------------------------------------------------- */
  function inline(src, known) {
    var out = esc(src);

    // pull code spans out first so nothing below rewrites their contents
    var codes = [];
    out = out.replace(/`([^`]+)`/g, function (_, c) {
      codes.push(c);
      return '\u0000' + (codes.length - 1) + '\u0000';
    });

    // Inline HTML comments. The block scanner strips only comments that occupy
    // a whole line, but `protocol-write` explicitly allows a pin marker on the
    // SAME line as the fact it marks, and those fell through to esc() and
    // rendered as literal `<!-- pin: corrected -->` text. A comment is invisible
    // in markdown wherever it sits. `pin:` is the one kind worth surfacing to a
    // human -- it marks a retraction or a standing decision -- so it becomes a
    // small badge; every other comment is dropped. This runs after the code-span
    // extraction above, so a comment inside backticks is already a placeholder
    // and survives untouched.
    out = out.replace(/&lt;!--([\s\S]*?)--&gt;/g, function (m, body) {
      var pin = /^\s*pin:\s*([a-z][a-z-]*)\s*$/.exec(body);
      return pin ? '<span class="pinbadge" title="pin marker">' + pin[1] + '</span>' : '';
    });

    // [[doc:slug]] -> in-app link to a working document. Checked first so
    // 'doc:' is consumed here rather than falling through to the plain
    // [[category]] rule below (which would otherwise treat 'doc' as a scheme
    // prefix baked into an invalid category name and leave it unlinked).
    // When `known` is supplied, a slug not in known.docs renders as inert
    // text instead of a link to a document that does not exist.
    out = out.replace(/\[\[doc:([a-z][a-z0-9-]*)\]\]/g, function (m, slug) {
      if (known && !has(known.docs, slug)) {
        return '<span class="xref dead" title="no such document">doc:' + slug + '</span>';
      }
      return '<a href="#/d/' + slug + '" class="xref">doc:' + slug + '</a>';
    });

    // [[category]] -> in-app link. The store is full of these as cross-references
    // and they used to render as literal brackets. Only a valid category name is
    // linked, so ordinary double brackets in prose are left alone. Same dead-ref
    // handling as [[doc:slug]] above, against known.cats.
    out = out.replace(/\[\[([a-z][a-z0-9-]*)\]\]/g, function (m, cat) {
      if (known && !has(known.cats, cat)) {
        return '<span class="xref dead" title="no such category">' + cat + '</span>';
      }
      return '<a href="#/c/' + cat + '" class="xref">' + cat + '</a>';
    });

    out = out.replace(/\[([^\]]*)\]\(([^)\s]+)\)/g, function (m, t, u) { return link(u, t || u); });
    out = out.replace(/(^|[\s(])((?:https?:\/\/)[^\s<>()\[\]]+)/g, function (m, pre, u) {
      return pre + link(u, u);
    });
    out = out.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
    out = out.replace(/(^|[^*])\*([^*\n]+)\*/g, '$1<em>$2</em>');
    out = out.replace(/~~([^~]+)~~/g, '<del>$1</del>');

    return out.replace(/\u0000(\d+)\u0000/g, function (_, i) {
      return '<code>' + codes[i] + '</code>';
    });
  }

  /* section list (also used for the outline) -------------------------------
   * Scans every heading line (## through ######, same as render()'s HEADING
   * match) so the `seen` dedup counter stays in lockstep with the ids render()
   * assigns -- an H1 or H5 sharing text with a later H3 still has to consume
   * a slot in the counter, even though only H2-H4 are emitted here as outline
   * entries. Levels 2-4 only: the client-side outline covers section-shaped
   * headings, not the document title (H1) or deep sub-points (H5/H6). This is
   * the browser's own outline -- main.py's server-side sections_of() stays
   * '##'-only, its own contract for /memory/index and search attribution. */
  function sections(text) {
    var lines = String(text).split('\n');
    var out = [];
    var seen = {};
    for (var i = 0; i < lines.length; i++) {
      var m = HEADING.exec(lines[i]);
      if (!m) continue;
      var lvl = m[1].length;
      var id = slug(m[2], seen);
      if (lvl < 2 || lvl > 4) continue;
      var verified = null;
      for (var j = i + 1; j < Math.min(i + 3, lines.length); j++) {
        var v = VERIFIED.exec(lines[j]);
        if (v) { verified = v[1]; break; }
      }
      out.push({ name: m[2], verified: verified, line: i + 1, id: id, level: lvl });
    }
    return out;
  }

  function daysSince(iso) {
    var t = Date.parse(iso + 'T00:00:00Z');
    if (isNaN(t)) return null;
    return Math.floor((Date.now() - t) / 86400000);
  }

  function badge(date, staleDays) {
    // 'never' means this fact doesn't rot -- never styled stale, no age shown.
    if (date === 'never') {
      return ' <span class="vbadge pill">stable</span>';
    }
    var d = daysSince(date);
    var cls = d !== null && d > staleDays ? 'pill stale' : 'pill';
    return ' <span class="vbadge ' + cls + '">verified ' + esc(date) + '</span>';
  }

  /* blocks ---------------------------------------------------------------- */
  function render(text, opts) {
    opts = opts || {};
    var staleDays = opts.staleDays || 90;
    var known = opts.known;
    var lines = String(text).replace(/\u0000/g, '').replace(/\r\n?/g, '\n').split('\n');
    var html = [];
    var para = [];
    var paraLine = 0;
    var headSeen = {};    // heading-id dedup counter -- see slug()
    var listStack = [];   // [{indent, tag}]
    var lastHeading = -1; // index in html[] of the heading tag still open to a badge
    var lastHeadingLine = -1;
    var i;

    function flushPara() {
      if (!para.length) return;
      html.push('<p data-line="' + paraLine + '">' + inline(para.join(' '), known) + '</p>');
      para = [];
    }

    function closeLists(toIndent) {
      while (listStack.length && listStack[listStack.length - 1].indent >= toIndent) {
        html.push('</li></' + listStack.pop().tag + '>');
      }
    }

    function flushAll() { flushPara(); closeLists(0); }

    for (i = 0; i < lines.length; i++) {
      var raw = lines[i];
      var line = raw.replace(/\s+$/, '');
      var n = i + 1;
      var m;

      // fenced code
      if ((m = FENCE.exec(line))) {
        flushAll();
        var fence = m[1];
        var lang = (m[2] || '').trim().split(/\s+/)[0];
        var buf = [];
        for (i++; i < lines.length; i++) {
          if (lines[i].trim().indexOf(fence) === 0) break;
          buf.push(lines[i]);
        }
        html.push('<pre data-line="' + n + '"><code' +
          (lang ? ' class="lang-' + esc(lang) + '"' : '') + '>' +
          esc(buf.join('\n')) + '</code></pre>');
        continue;
      }

      // verified marker attaches to the heading directly above it
      if ((m = VERIFIED.exec(line))) {
        if (lastHeading >= 0 && n - lastHeadingLine <= 2) {
          html[lastHeading] = html[lastHeading].replace(/<\/h(\d)>$/, badge(m[1], staleDays) + '</h$1>');
        }
        continue;
      }
      if (COMMENT.test(line)) continue;

      if (!line.trim()) { flushPara(); continue; }

      // heading
      if ((m = HEADING.exec(line))) {
        flushAll();
        var lvl = Math.min(m[1].length, 4);
        html.push('<h' + lvl + ' id="' + slug(m[2], headSeen) + '" data-line="' + n + '">' +
          inline(m[2], known) + '</h' + lvl + '>');
        lastHeading = html.length - 1;
        lastHeadingLine = n;
        continue;
      }

      if (HR.test(line)) { flushAll(); html.push('<hr data-line="' + n + '">'); continue; }

      // blockquote (consecutive '>' lines)
      if (/^\s*>\s?/.test(line)) {
        flushAll();
        var quote = [];
        for (; i < lines.length && /^\s*>\s?/.test(lines[i]); i++) {
          quote.push(lines[i].replace(/^\s*>\s?/, ''));
        }
        i--;
        html.push('<blockquote data-line="' + n + '">' + inline(quote.join(' '), known) + '</blockquote>');
        continue;
      }

      // table: a pipe row followed by a separator row
      if (line.indexOf('|') === 0 && i + 1 < lines.length && TABLE_SEP.test(lines[i + 1])) {
        flushAll();
        var cells = function (row) {
          return row.replace(/^\s*\|/, '').replace(/\|\s*$/, '').split('|').map(function (c) {
            return inline(c.trim(), known);
          });
        };
        var t = ['<table data-line="' + n + '"><thead><tr>'];
        cells(line).forEach(function (c) { t.push('<th>' + c + '</th>'); });
        t.push('</tr></thead><tbody>');
        for (i += 2; i < lines.length && lines[i].trim().indexOf('|') === 0; i++) {
          t.push('<tr>');
          cells(lines[i]).forEach(function (c) { t.push('<td>' + c + '</td>'); });
          t.push('</tr>');
        }
        i--;
        t.push('</tbody></table>');
        html.push(t.join(''));
        continue;
      }

      // list item
      if ((m = BULLET.exec(line))) {
        flushPara();
        var indent = m[1].replace(/\t/g, '  ').length;
        var tag = /^\d/.test(m[2]) ? 'ol' : 'ul';
        var top = listStack[listStack.length - 1];

        // every item carries its own line: these lists run to dozens of entries
        // between headings, and the editor/preview scroll sync interpolates
        // between data-line anchors -- sparse anchors mean visible drift.
        if (!top || indent > top.indent) {
          listStack.push({ indent: indent, tag: tag });
          html.push('<' + tag + ' data-line="' + n + '"><li data-line="' + n + '">');
        } else {
          while (listStack.length > 1 && listStack[listStack.length - 1].indent > indent) {
            html.push('</li></' + listStack.pop().tag + '>');
          }
          html.push('</li><li data-line="' + n + '">');
        }
        html.push(inline(m[3], known));
        continue;
      }

      // indented continuation of the current list item
      if (listStack.length && /^\s{2,}/.test(raw)) {
        html.push(' ' + inline(line.trim(), known));
        continue;
      }

      closeLists(0);
      if (!para.length) paraLine = n;
      para.push(line.trim());
    }

    flushAll();
    var out = html.join('\n');
    if (opts.highlight && opts.highlight.length) out = highlight(out, opts.highlight);
    return out;
  }

  /* highlight search terms in already-rendered html, skipping tags --------- */
  function highlight(html, terms) {
    var safe = terms.filter(Boolean).map(function (t) {
      return esc(t).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    });
    if (!safe.length) return html;
    var re = new RegExp('(' + safe.join('|') + ')', 'gi');
    return html.replace(/>([^<]+)</g, function (m, text) {
      return '>' + text.replace(re, '<mark>$1</mark>') + '<';
    });
  }

  // Exposed for the stale-sections view: it only has {name, verified} from
  // /memory/index (no line numbers), so it links to a heading id computed
  // the same way render()/sections() compute one, rather than a line route.
  // Called with no `seen` map -- so, unlike an in-document render, it can't
  // disambiguate two same-named headings in one category. That's the one
  // corner case this shortcut accepts.
  return {
    render: render, sections: sections, escape: esc, inline: inline,
    daysSince: daysSince, slug: function (s) { return slug(s, null); }
  };
})();
