/* Line diff for the history and conflict views.
 *
 * Plain LCS. Common prefix and suffix are trimmed first, which is what keeps
 * it cheap here: two revisions of a memory category differ in a handful of
 * lines, so the quadratic middle is almost always tiny.
 */
window.Diff = (function () {
  'use strict';

  var MAX_CELLS = 4000000; // ~2000x2000 lines before we give up on exactness

  function lcs(a, b) {
    var n = a.length, m = b.length;
    var dp = new Uint32Array((n + 1) * (m + 1));
    var i, j;
    for (i = n - 1; i >= 0; i--) {
      for (j = m - 1; j >= 0; j--) {
        dp[i * (m + 1) + j] = a[i] === b[j]
          ? dp[(i + 1) * (m + 1) + j + 1] + 1
          : Math.max(dp[(i + 1) * (m + 1) + j], dp[i * (m + 1) + j + 1]);
      }
    }
    var ops = [];
    i = 0; j = 0;
    while (i < n && j < m) {
      if (a[i] === b[j]) { ops.push({ op: ' ', text: a[i] }); i++; j++; }
      else if (dp[(i + 1) * (m + 1) + j] >= dp[i * (m + 1) + j + 1]) { ops.push({ op: '-', text: a[i] }); i++; }
      else { ops.push({ op: '+', text: b[j] }); j++; }
    }
    while (i < n) ops.push({ op: '-', text: a[i++] });
    while (j < m) ops.push({ op: '+', text: b[j++] });
    return ops;
  }

  function diffLines(aText, bText) {
    var a = String(aText).replace(/\r\n?/g, '\n').split('\n');
    var b = String(bText).replace(/\r\n?/g, '\n').split('\n');

    var head = [];
    while (a.length && b.length && a[0] === b[0]) { head.push({ op: ' ', text: a.shift() }); b.shift(); }
    var tail = [];
    while (a.length && b.length && a[a.length - 1] === b[b.length - 1]) {
      tail.unshift({ op: ' ', text: a.pop() }); b.pop();
    }

    var mid;
    if ((a.length + 1) * (b.length + 1) > MAX_CELLS) {
      mid = a.map(function (t) { return { op: '-', text: t }; })
        .concat(b.map(function (t) { return { op: '+', text: t }; }));
    } else {
      mid = lcs(a, b);
    }
    return head.concat(mid, tail);
  }

  function stats(ops) {
    var add = 0, del = 0;
    ops.forEach(function (o) { if (o.op === '+') add++; else if (o.op === '-') del++; });
    return { added: add, removed: del };
  }

  /* Render as html, collapsing runs of unchanged lines to `context` either side. */
  function render(aText, bText, context) {
    var ops = diffLines(aText, bText);
    var st = stats(ops);
    if (!st.added && !st.removed) {
      return { html: '<div class="gap">    identical</div>', stats: st };
    }
    var ctx = context === undefined ? 3 : context;
    var keep = new Array(ops.length);
    var i, j;
    for (i = 0; i < ops.length; i++) {
      if (ops[i].op === ' ') continue;
      for (j = Math.max(0, i - ctx); j <= Math.min(ops.length - 1, i + ctx); j++) keep[j] = true;
    }

    var out = [], hidden = 0;
    function flushGap() {
      if (hidden) out.push('<div class="gap">    … ' + hidden + ' unchanged line' + (hidden === 1 ? '' : 's') + ' …</div>');
      hidden = 0;
    }
    for (i = 0; i < ops.length; i++) {
      if (!keep[i]) { hidden++; continue; }
      flushGap();
      var cls = ops[i].op === '+' ? 'add' : ops[i].op === '-' ? 'del' : '';
      out.push('<div class="' + cls + '">' + window.MD.escape(ops[i].op + ' ' + ops[i].text) + '</div>');
    }
    flushGap();
    if (!out.length) out.push('<div class="gap">    identical</div>');
    return { html: out.join(''), stats: stats(ops) };
  }

  return { diffLines: diffLines, render: render, stats: stats };
})();
