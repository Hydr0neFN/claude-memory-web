/* Node harness: exercise md.js + diff.js against real memory content, and the
 * DOM-free logic of nav.js (tree, quick-jump matcher) and passkey.js. */
const fs = require('fs');
const vm = require('vm');

const ctx = { window: {}, console, Date, Math, RegExp, JSON, String, Array, Number, Uint32Array, setTimeout,
  Uint8Array, atob, btoa, Object, Promise, Error };
ctx.globalThis = ctx;
vm.createContext(ctx);
for (const f of ['md.js', 'diff.js', 'nav.js', 'passkey.js']) {
  vm.runInContext(fs.readFileSync(__dirname + '/web/' + f, 'utf8'), ctx, f);
}
const FIX = __dirname + '/';
const MD = ctx.window.MD, Diff = ctx.window.Diff, Nav = ctx.window.Nav, Passkey = ctx.window.Passkey;

let pass = 0, fail = 0;
function check(desc, cond, extra) {
  if (cond) { pass++; console.log('PASS: ' + desc); }
  else { fail++; console.log('FAIL: ' + desc + (extra ? '  -> ' + extra : '')); }
}

/* --- XSS / escaping ---------------------------------------------------- */
const nasty = [
  '# <script>alert(1)</script>',
  '',
  'text with <img src=x onerror=alert(2)> inline',
  '',
  '- [click](javascript:alert(3))',
  '- [ok](https://example.com/a?b=1&c=2)',
  '',
  '`<b>code</b>` and **<i>bold</i>**',
  '',
  '> quote with <svg onload=alert(4)>',
  '',
  '| a | <b>b</b> |',
  '| --- | --- |',
  '| <x> | y |'
].join('\n');
const out = MD.render(nasty);
check('no <script> survives', !/<script/i.test(out), out.match(/.{0,40}<script.{0,40}/i));
// the payloads must survive only as inert escaped text, never as live tags
check('<img> neutered', !/<img/i.test(out) && /&lt;img/.test(out), out.match(/.{0,30}img.{0,30}/i));
check('<svg> neutered', !/<svg/i.test(out) && /&lt;svg/.test(out), out.match(/.{0,30}svg.{0,30}/i));
check('no javascript: href', !/href="javascript:/i.test(out));
check('safe https link kept', /href="https:\/\/example\.com\/a\?b=1&amp;c=2"/.test(out), out.match(/.{0,60}example.{0,60}/));
check('code span content escaped', /<code>&lt;b&gt;code&lt;\/b&gt;<\/code>/.test(out), out.match(/.{0,60}code.{0,60}/));
check('table rendered', /<table/.test(out) && /<td>&lt;x&gt;<\/td>/.test(out));

/* --- code spans are not re-processed ----------------------------------- */
const cs = MD.render('use `a **b** c` and `x*y*z` here');
check('no bold inside code span', /<code>a \*\*b\*\* c<\/code>/.test(cs), cs);
check('no em inside code span', /<code>x\*y\*z<\/code>/.test(cs), cs);
check('placeholder sentinel gone', cs.indexOf('\u0000') === -1);

/* --- link attribute breakout (audit 2026-09-26, Critical 1) -------------
 * The autolink rule used to rescan the [t](u) rule's output and insert a
 * second <a href="..."> inside the first href, closing it early. */
// every '<a ' must open a tag whose attributes are exactly the ones link() writes
function anchorsWellFormed(html) {
  const tags = html.match(/<a\s[^>]*>/g) || [];
  return tags.every(t => /^<a href="[^"<>]*"( target="_blank" rel="noopener noreferrer")?( class="xref")?>$/.test(t));
}
const breakout = MD.render('[x](https://a.example/(https://b.example/"onmouseover=alert`1`)');
check('no attribute breakout from nested autolink', anchorsWellFormed(breakout) && !/onmouseover=/.test(breakout.replace(/&quot;onmouseover=/g, '')), breakout);
const breakout2 = MD.render('see [t](http://x/(http://y/x"autofocus/onfocus=alert`1`) now');
check('no attribute breakout, http variant', anchorsWellFormed(breakout2) && !/ onfocus=/.test(breakout2), breakout2);
const lt = MD.render('[**bold** and `code`](https://ok.example/) then https://auto.example/ end');
check('link text keeps emphasis and code', /<a href="https:\/\/ok\.example\/"[^>]*><strong>bold<\/strong> and <code>code<\/code><\/a>/.test(lt), lt);
check('autolink still works outside links', /<a href="https:\/\/auto\.example\/"/.test(lt) && anchorsWellFormed(lt), lt);
check('link placeholder sentinel gone', lt.indexOf('\u0000') === -1, lt);
const pr = MD.render('[a](//evil.example/) [b](/\\evil.example/) [c](/c/protocol)');
check('protocol-relative // and /\\ not linked', !/href="\/\//.test(pr) && !/href="\/\\/.test(pr), pr);
check('same-origin /path still linked', /href="\/c\/protocol"/.test(pr), pr);

/* --- snake_case must not become emphasis -------------------------------- */
const snake = MD.render('call git_commit and check_write_auth now');
check('snake_case untouched', /git_commit/.test(snake) && !/<em>/.test(snake), snake);

/* --- [[doc:slug]] cross-reference, and [[category]] still works --------- */
const xrefs = MD.render('see [[doc:tourplan-handoff]] and [[protocol]] for details');
check('[[doc:slug]] renders a doc link', /href="#\/d\/tourplan-handoff" class="xref">doc:tourplan-handoff<\/a>/.test(xrefs), xrefs);
check('[[category]] still renders a category link', /href="#\/c\/protocol" class="xref">protocol<\/a>/.test(xrefs), xrefs);
check('doc link uses #/d/, not #/c/', !/#\/c\/tourplan-handoff/.test(xrefs), xrefs);

/* --- opts.known: dead xref handling -------------------------------------
 * Absent -> today's behaviour (always link), for every caller that does not
 * pass it. Present -> a name missing from the known set renders inert. */
const xrefsNoKnown = MD.render('see [[doc:ghost-doc]] and [[ghost-cat]] here');
check('opts.known absent: [[doc:slug]] still links', /href="#\/d\/ghost-doc" class="xref">doc:ghost-doc<\/a>/.test(xrefsNoKnown), xrefsNoKnown);
check('opts.known absent: [[category]] still links', /href="#\/c\/ghost-cat" class="xref">ghost-cat<\/a>/.test(xrefsNoKnown), xrefsNoKnown);

const known = { cats: ['protocol'], docs: ['tourplan-handoff'] };
const xrefsKnownLive = MD.render('see [[doc:tourplan-handoff]] and [[protocol]] here', { known });
check('opts.known present: known doc still links', /href="#\/d\/tourplan-handoff" class="xref">doc:tourplan-handoff<\/a>/.test(xrefsKnownLive), xrefsKnownLive);
check('opts.known present: known category still links', /href="#\/c\/protocol" class="xref">protocol<\/a>/.test(xrefsKnownLive), xrefsKnownLive);

const xrefsKnownDead = MD.render('see [[doc:ghost-doc]] and [[ghost-cat]] here', { known });
check('opts.known present: unknown doc renders dead span, not a link', /<span class="xref dead" title="no such document">doc:ghost-doc<\/span>/.test(xrefsKnownDead) && !/href="#\/d\/ghost-doc"/.test(xrefsKnownDead), xrefsKnownDead);
check('opts.known present: unknown category renders dead span, not a link', /<span class="xref dead" title="no such category">ghost-cat<\/span>/.test(xrefsKnownDead) && !/href="#\/c\/ghost-cat"/.test(xrefsKnownDead), xrefsKnownDead);

// Set instances must work identically to plain arrays for known.cats/docs
const xrefsKnownSet = MD.render('see [[doc:tourplan-handoff]] and [[ghost-cat]] here', {
  known: { cats: new Set(['protocol']), docs: new Set(['tourplan-handoff']) }
});
check('opts.known accepts a Set: known doc links', /href="#\/d\/tourplan-handoff"/.test(xrefsKnownSet), xrefsKnownSet);
check('opts.known accepts a Set: unknown category is dead', /class="xref dead"/.test(xrefsKnownSet), xrefsKnownSet);

/* --- heading ids are text-derived, not line-derived --------------------- */
const headA = MD.render('## Overview\n\nbody\n\n## Endpoint\n\nmore');
const idOverview = /id="(h-overview)"/.exec(headA);
const idEndpoint = /id="(h-endpoint)"/.exec(headA);
check('heading id has no line-number prefix', !!idOverview && !!idEndpoint, headA);

// inserting a line above a heading must not change that heading's id
const headB = MD.render('New line up top\n\n## Overview\n\nbody\n\n## Endpoint\n\nmore');
check('id stable when a line is inserted above it',
  /id="h-overview"/.test(headB) && /id="h-endpoint"/.test(headB), headB);

// two headings with the same text get distinct ids, in order
const dupHeads = MD.render('## Notes\n\na\n\n## Notes\n\nb\n\n## Notes\n\nc');
check('duplicate headings get distinct ids',
  /id="h-notes"/.test(dupHeads) && /id="h-notes-2"/.test(dupHeads) && /id="h-notes-3"/.test(dupHeads),
  dupHeads);

// sections() and render() must assign the same id to the same heading,
// independently -- this is what outline links actually depend on
const dupSrc = '# Title\n\n## Notes\n\na\n\n### Notes\n\nb\n\n## Notes\n\nc';
const dupSecs = MD.sections(dupSrc);
const dupHtml = MD.render(dupSrc);
check('sections() ids match render() ids for duplicate headings',
  dupSecs.every(s => dupHtml.indexOf('id="' + s.id + '"') >= 0), JSON.stringify(dupSecs));

/* --- sections() covers H2-H4, with level, but not H1/H5/H6 -------------- */
const levels = MD.sections(
  '# Title\n\n## Two\n\n### Three\n\n#### Four\n\n##### Five\n\n###### Six\n'
);
check('H2 included', levels.some(s => s.name === 'Two' && s.level === 2), JSON.stringify(levels));
check('H3 included', levels.some(s => s.name === 'Three' && s.level === 3), JSON.stringify(levels));
check('H4 included', levels.some(s => s.name === 'Four' && s.level === 4), JSON.stringify(levels));
check('H1 excluded from outline', !levels.some(s => s.name === 'Title'), JSON.stringify(levels));
check('H5 excluded from outline', !levels.some(s => s.name === 'Five'), JSON.stringify(levels));
check('H6 excluded from outline', !levels.some(s => s.name === 'Six'), JSON.stringify(levels));
check('sections() covers exactly H2-H4', levels.length === 3, JSON.stringify(levels));

// an H1/H5 sharing text with a later H2 must still consume a counter slot,
// so sections() and render() ids stay in lockstep (see the shared `seen`
// map in md.js) even though the H1/H5 itself is not an outline entry
const crossLevelSrc = '# Notes\n\nintro\n\n##### Notes\n\nx\n\n## Notes\n\ny\n';
const crossSecs = MD.sections(crossLevelSrc);
const crossHtml = MD.render(crossLevelSrc);
check('cross-level duplicate: outline id is h-notes-3 (H1 and H5 each took a slot)',
  crossSecs.length === 1 && crossSecs[0].id === 'h-notes-3', JSON.stringify(crossSecs));
check('cross-level duplicate: render() assigns the same id to the H2',
  crossHtml.indexOf('id="h-notes-3"') >= 0, crossHtml);

/* --- scope guard: main.py's sections_of() stays '##'-only --------------- */
const mainPy = fs.readFileSync(FIX + 'main.py', 'utf8');
check("main.py SECTION_RE is unchanged ('## ' only, not H3/H4)",
  /SECTION_RE = re\.compile\(r"\^##\\s\+\(\.\*\?\)\\s\*\$"\)/.test(mainPy), 'SECTION_RE line missing or changed');

/* --- verified badge ----------------------------------------------------- */
const ver = MD.render('## Endpoint\n<!-- verified: 2026-07-27 -->\n\nbody\n\n## Old\n<!-- verified: 2020-01-01 -->\n\nx');
check('fresh verified badge', /verified 2026-07-27<\/span><\/h2>/.test(ver), ver);
check('stale verified badge marked', /pill stale">verified 2020-01-01/.test(ver), ver);
check('other comments dropped', MD.render('<!-- hi -->\ntext').indexOf('hi') === -1);

/* --- 'never' verified marker: renders 'stable', never styled stale ------ */
const never = MD.render('## Permanent\n<!-- verified: never -->\n\nbody\n\n## Fresh\n<!-- verified: 2026-07-27 -->\n\nx\n\n## Old\n<!-- verified: 2020-01-01 -->\n\ny');
check('never marker renders a stable badge', /class="vbadge pill">stable<\/span><\/h2>/.test(never), never);
check('never marker is never styled stale', !/pill stale">stable/.test(never), never);
// a dated section elsewhere in the same document still renders as today
check('dated section next to a never section: fresh badge unaffected', /verified 2026-07-27<\/span><\/h2>/.test(never), never);
check('dated section next to a never section: stale badge still marked', /pill stale">verified 2020-01-01/.test(never), never);

const neverSecs = MD.sections('## Permanent\n<!-- verified: never -->\n\nbody');
check("sections() reports verified: 'never' for a never-marked heading",
  neverSecs.length === 1 && neverSecs[0].verified === 'never', JSON.stringify(neverSecs));

/* --- structure balance on documents -------------------------------------
 * fixtures/ is the committed synthetic corpus. Real categories dropped beside
 * this file are picked up too when present, but are gitignored -- the tests
 * must never depend on personal notes being in the repository. */
const CORPUS = fs.readdirSync(FIX + 'fixtures').filter(f => f.endsWith('.md')).map(f => FIX + 'fixtures/' + f)
  .concat(fs.readdirSync(FIX).filter(f => f.endsWith('.md') && f !== 'README.md').map(f => FIX + f));

for (const f of CORPUS) {
  const src = fs.readFileSync(f, 'utf8');
  const html = MD.render(src);
  const name = f.split('/').pop();
  const count = (s, re) => (s.match(re) || []).length;
  check(name + ': renders non-empty', html.length > src.length / 2);
  check(name + ': ul balanced', count(html, /<ul[ >]/g) === count(html, /<\/ul>/g),
    count(html, /<ul[ >]/g) + ' vs ' + count(html, /<\/ul>/g));
  check(name + ': ol balanced', count(html, /<ol[ >]/g) === count(html, /<\/ol>/g),
    count(html, /<ol[ >]/g) + ' vs ' + count(html, /<\/ol>/g));
  check(name + ': li balanced', count(html, /<li[ >]/g) === count(html, /<\/li>/g),
    count(html, /<li[ >]/g) + ' vs ' + count(html, /<\/li>/g));
  check(name + ': no raw < from source', !/<(?!\/?(h[1-6]|p|ul|ol|li|code|pre|em|strong|del|a|blockquote|hr|table|thead|tbody|tr|th|td|span|mark)[ >/])/.test(html),
    (html.match(/<(?!\/?(h[1-6]|p|ul|ol|li|code|pre|em|strong|del|a|blockquote|hr|table|thead|tbody|tr|th|td|span|mark)[ >/])[^>]{0,40}/g) || []).slice(0, 3).join(' | '));
  const secs = MD.sections(src);
  // sections() now covers H2-H4 (see below), not '##' alone
  const rawSecs = src.split('\n').filter(l => /^#{2,4}\s+\S/.test(l)).length;
  check(name + ': section count matches ' + rawSecs, secs.length === rawSecs, secs.length);
  check(name + ': every section has an id in html', secs.every(s => html.indexOf('id="' + s.id + '"') >= 0));
  check(name + ': data-line present', /data-line="\d+"/.test(html));
}

/* --- diff --------------------------------------------------------------- */
const a = fs.readFileSync(CORPUS[0], 'utf8');
const b = a.replace('## Endpoint', '## Endpoints').replace(/\n/, '\nEXTRA LINE\n');
const d = Diff.render(a, b, 3);
check('diff finds changes', d.stats.added > 0 && d.stats.removed > 0, JSON.stringify(d.stats));
check('diff collapses context', /unchanged lines/.test(d.html));
check('diff of identical is empty', Diff.render(a, a, 3).stats.added === 0 &&
  /identical/.test(Diff.render(a, a, 3).html));
const dl = Diff.diffLines('x\ny\nz', 'x\nQ\nz');
check('diff line ops correct', JSON.stringify(dl) ===
  JSON.stringify([{op:' ',text:'x'},{op:'-',text:'y'},{op:'+',text:'Q'},{op:' ',text:'z'}]), JSON.stringify(dl));
check('diff escapes html', /&lt;script/.test(Diff.render('a', '<script>', 3).html));

/* --- MD.slug (stale-view heading links) --------------------------------- */
// same derivation render()/sections() use internally, exposed for the stale
// view which only has a section name (no line number) to link from.
check('MD.slug matches the id render() assigns the same heading',
  MD.slug('Rpi remote access') === /id="([^"]+)"/.exec(MD.render('## Rpi remote access'))[1],
  MD.slug('Rpi remote access'));
check('MD.slug is stable for the same input', MD.slug('Foo Bar') === MD.slug('Foo Bar'));
check('MD.slug handles CJK', MD.slug('揪日子') === 'h-' + '揪日子');

/* --- inline HTML comments ----------------------------------------------- */
// Regression for 2026-08-20: the block scanner strips only whole-line comments,
// so a pin marker written on the same line as its fact (which protocol-write
// explicitly allows) rendered as literal `<!-- pin: corrected -->` text.
{
  const h = MD.render('- **CORRECTED** <!-- pin: corrected --> the old number was wrong');
  check('inline pin marker is not rendered as literal text', !/&lt;!--/.test(h), h);
  check('inline pin marker renders as a badge', /class="pinbadge"[^>]*>corrected</.test(h), h);
  check('the fact around an inline pin survives', /the old number was wrong/.test(h), h);

  const g = MD.render('alpha <!-- some private note --> omega');
  check('a non-pin inline comment is dropped entirely',
    !/&lt;!--/.test(g) && !/private note/.test(g) && /alpha/.test(g) && /omega/.test(g), g);

  const BQ = String.fromCharCode(96);
  const cs = MD.render('use ' + BQ + '<!-- pin: decided -->' + BQ + ' as the marker');
  check('a comment inside a code span is left visible',
    /<code>&lt;!-- pin: decided --&gt;<\/code>/.test(cs), cs);

  const wl = MD.render('## H\n<!-- verified: 2026-08-20 -->\n\ntext');
  check('whole-line verified marker still becomes a heading badge',
    /vbadge/.test(wl) && !/&lt;!--/.test(wl), wl);

  // An opener with no closer must stay visible as literal text and must NOT
  // swallow the rest of the paragraph looking for one. Found by review after
  // the first version matched across newlines while flushPara() joined
  // paragraph lines with a space -- so one mistyped '<!--' silently deleted
  // every following line up to the next '-->' (an arrow in prose counts).
  const un = MD.render('line one <!-- oops\nline two <!-- pin: decided --> end');
  check('an unterminated comment stays literal', /&lt;!-- oops/.test(un), un);
  check('text after an unterminated comment survives', /line two/.test(un) && /end/.test(un), un);
  check('a pin later in the same paragraph still renders', /pinbadge/.test(un), un);
  const solo = MD.render('risk <!-- fixme');
  check('an unterminated comment alone is left alone', /&lt;!-- fixme/.test(solo), solo);
  check('an ascii arrow in prose is untouched',
    /--&gt; 2ms/.test(MD.render('latency 5ms --> 2ms')), MD.render('latency 5ms --> 2ms'));
  check('emphasis still spans a wrapped source line',
    /<strong>alpha\nbeta<\/strong>/.test(MD.render('**alpha\nbeta**')), MD.render('**alpha\nbeta**'));

  const multi = MD.render('a <!-- pin: retracted --> b <!-- pin: decided --> c');
  check('two inline pins on one line both render',
    (multi.match(/pinbadge/g) || []).length === 2, multi);
}

/* --- perf sanity -------------------------------------------------------- */
const t0 = Date.now();
for (let i = 0; i < 20; i++) MD.render(a);
check('20 renders under 1s', Date.now() - t0 < 1000, (Date.now() - t0) + 'ms');

/* --- sidebar tree: parent derivation and default expansion ---------------- */
const cat = (category, extra) => Object.assign(
  { category, bytes: 1000, mtime: '2026-10-01T00:00:00Z', sections: [], docs: [] }, extra || {});
const TREE_INDEX = [
  cat('infra'), cat('infra-pc'), cat('infra-pc-tuning', { bytes: 17000 }), cat('infra-pc-gpu'),
  cat('infra-unifi'), cat('personal'),
  cat('projects'), cat('projects-web', { docs: ['web-notes'] }), cat('projects-web-denba'),
  cat('projects-web-denba-api'), cat('solo', { docs: ['solo-doc'] })
];
const tree = Nav.buildTree(TREE_INDEX);
const names = (rows) => rows.filter(r => r.t === 'c').map(r => r.name);
const rowOf = (rows, n) => rows.filter(r => r.t === 'c' && r.name === n)[0];

check('parent is the LONGEST existing prefix', tree.node['infra-pc-tuning'].parent === 'infra-pc' &&
  tree.node['infra-pc'].parent === 'infra' && tree.node['infra-pc-tuning'].depth === 2);
check('a name with no category prefix is a root', tree.roots.join() === 'infra,personal,projects,solo', tree.roots.join());

const def = Nav.rows(tree, {});
check('default: roots and their direct children are visible',
  ['infra', 'infra-pc', 'infra-unifi', 'personal', 'projects', 'projects-web', 'solo'].every(n => names(def).indexOf(n) >= 0),
  names(def).join());
check('default: depth 2 and deeper are hidden',
  ['infra-pc-tuning', 'infra-pc-gpu', 'projects-web-denba', 'projects-web-denba-api'].every(n => names(def).indexOf(n) < 0),
  names(def).join());
check('default: a collapsed depth-1 row reports its hidden children',
  rowOf(def, 'infra-pc').hidden === 2 && !rowOf(def, 'infra-pc').open && rowOf(def, 'infra').hidden === 0);
check('default: roots are open, depth >= 1 are closed',
  rowOf(def, 'infra').open && rowOf(def, 'projects-web').open === false);
check('default: docs of a collapsed depth-1 category are not listed',
  !def.some(r => r.t === 'd' && r.slug === 'web-notes') && rowOf(def, 'projects-web').hidden === 2 &&
  rowOf(def, 'projects-web').docs === 1);
check('default: a depth-1 category with only docs is collapsed', (function () {
  const t = Nav.buildTree([cat('a'), cat('a-b', { docs: ['x'] })]);
  const r = Nav.rows(t, {});
  return r.length === 2 && r[1].t === 'c' && !r[1].open && r[1].expandable && r[1].hidden === 1;
})());
check('default: a root with docs is open and lists them',
  def.some(r => r.t === 'd' && r.slug === 'solo-doc' && r.owner === 'solo' && r.depth === 1));

const opened = Nav.rows(tree, { overrides: { 'infra-pc': true } });
check('opening one caret reveals exactly one more layer',
  names(opened).indexOf('infra-pc-tuning') >= 0 && names(opened).indexOf('infra-pc-gpu') >= 0 &&
  names(opened).indexOf('projects-web-denba') < 0, names(opened).join());
const deep = Nav.rows(tree, { overrides: { 'projects-web': true } });
check('the revealed children are themselves collapsed',
  rowOf(deep, 'projects-web-denba') && !rowOf(deep, 'projects-web-denba').open &&
  names(deep).indexOf('projects-web-denba-api') < 0 && deep.some(r => r.t === 'd' && r.slug === 'web-notes'),
  names(deep).join());
const rootClosed = Nav.rows(tree, { overrides: { infra: false } });
check('a root can be collapsed', names(rootClosed).indexOf('infra-pc') < 0 && rowOf(rootClosed, 'infra').hidden === 2);
check('an explicit choice beats the default for a new category too',
  Nav.rows(tree, { overrides: { 'no-such-category': true } }).length === def.length);

const forced = Nav.rows(tree, { forced: { 'projects-web': true, 'projects-web-denba': true } });
check('forced ancestors open the chain down to the active row', names(forced).indexOf('projects-web-denba-api') >= 0);
check('forcing does not need (or write) any override', JSON.stringify(Nav.rows(tree, {})) === JSON.stringify(def));
const unforced = Nav.rows(tree, { forced: { 'projects-web': true }, unforced: { 'projects-web': true } });
check('a hand-collapsed forced ancestor stays collapsed', names(unforced).indexOf('projects-web-denba') < 0);

const filtered = Nav.rows(tree, { visible: Nav.filterVisible(tree, 'tuning', {}) });
check('filter force-opens the matches and their ancestors only',
  names(filtered).join() === 'infra,infra-pc,infra-pc-tuning', names(filtered).join());
check('filter matches an attached doc by slug or title',
  Nav.filterVisible(tree, 'web-notes', {})['projects-web'] === true &&
  Nav.filterVisible(tree, 'handbook', { 'solo-doc': 'The Handbook' }).solo === true);

check('parseOverrides keeps only name -> boolean',
  JSON.stringify(Nav.parseOverrides('{"a":true,"b":false,"c":1,"d":"x","e":null}')) === '{"a":true,"b":false}');
check('parseOverrides survives garbage and the old collapsed-list shape',
  ['', null, undefined, 'not json', '[1,2]', '["c:infra"]', '7', '"s"', 'null'].every(v => {
    const o = Nav.parseOverrides(v);
    return o && typeof o === 'object' && Object.keys(o).length === 0;
  }));

const st = Nav.subtreeStats(tree, 'infra', 16384);
check('subtreeStats counts the whole subtree', st.count === 5 && st.bytes === 21000 && st.warn === 1, JSON.stringify(st));
check('subtreeStats reports the newest mtime', st.mtime === Date.parse('2026-10-01T00:00:00Z'));

/* --- quick jump: fuzzy matcher ------------------------------------------- */
const F = (q, t) => Nav.fuzzy(q, t);
check('fuzzy: no match is null', F('xyz', 'infra') === null && F('infrax', 'infra') === null);
check('fuzzy: empty query matches everything', F('', 'anything') === 0 && F('   ', 'anything') === 0);
check('fuzzy: case-insensitive', F('INFRA', 'Infra-PC') !== null);
check('fuzzy: subsequence matches', F('ipt', 'infra-pc-tuning') !== null && F('tuni', 'infra-pc-tuning') !== null);
check('fuzzy: order matters for a subsequence', F('tpi', 'infra-pc-tuning') === null);
check('fuzzy: ranking exact > prefix > word start > mid-word > subsequence', (function () {
  const exact = F('pc', 'pc'), prefix = F('pc', 'pcb-notes'), word = F('pc', 'infra-pc'),
    mid = F('pc', 'tipcx'), sub = F('pc', 'p-c');
  return exact > prefix && prefix > word && word > mid && mid > sub;
})());
check('fuzzy: every word must match', F('pc tun', 'infra-pc-tuning') !== null && F('pc zzz', 'infra-pc-tuning') === null &&
  F('tun pc', 'infra-pc-tuning') !== null);

const SEARCH_IDX = [
  cat('infra', { sections: [{ name: 'Overview' }, { name: 'Tuning notes' }] }),
  cat('infra-pc', { sections: [{ name: 'GPU' }] }),
  cat('infra-pc-tuning', { sections: [{ name: 'Fan curves' }, { name: 'Overview' }] }),
  cat('tuning')
];
const SEARCH_DOCS = [{ doc: 'tourplan-handoff', title: 'Tourplan handoff', sections: [{ name: 'Next step' }] }];
const items = Nav.buildItems(SEARCH_IDX, SEARCH_DOCS, MD.slug);
const top = (q, n) => Nav.search(items, q, n || 30);
check('search: an exact category name ranks first', top('infra')[0].id === 'c:infra', top('infra').map(i => i.id).join());
check('search: a category outranks a section of the same name', top('tuning')[0].id === 'c:tuning',
  top('tuning').map(i => i.id).join());
check('search: finds sections by name', top('fan').some(i => i.kind === 's' && i.label === 'Fan curves'));
check('search: section result carries its category and the stale view\'s link',
  top('fan')[0].sub === 'infra-pc-tuning' &&
  top('fan')[0].href === '#/c/infra-pc-tuning/h/' + encodeURIComponent(MD.slug('Fan curves')), top('fan')[0].href);
check('search: category + section words combine', top('tuning overview')[0].id === 'c:infra-pc-tuning#Overview',
  top('tuning overview').map(i => i.id).join());
check('search: docs are found by title and by slug',
  top('handoff')[0].id === 'd:tourplan-handoff' && top('tourplan-h')[0].id === 'd:tourplan-handoff');
check('search: doc section links use the doc route',
  top('next step').some(i => i.href === '#/d/tourplan-handoff/h/' + encodeURIComponent(MD.slug('Next step'))));
check('search: result count is capped',
  Nav.search(Nav.buildItems(Array.from({ length: 100 }, (_, i) => cat('cat-' + i)), [], MD.slug), 'cat', 30).length === 30);
check('search: nothing matches -> empty', top('qqqzzz').length === 0);

/* --- passkey client ---------------------------------------------------- */
check('b64url: no padding, url-safe alphabet', (function () {
  const raw = new Uint8Array([0xfb, 0xff, 0xfe, 0x00, 0x01]);
  const enc = Passkey.bufToB64u(raw.buffer);
  return enc === '-__-AAE' && !/[+/=]/.test(enc);
})());
check('b64url: round trip of every length mod 3', [0, 1, 2, 3, 4, 5, 250].every(n => {
  const raw = new Uint8Array(n).map((_, i) => (i * 37 + 11) & 255);
  const back = new Uint8Array(Passkey.b64uToBuf(Passkey.bufToB64u(raw.buffer)));
  return back.length === n && back.every((v, i) => v === raw[i]);
}));
check('b64url: null stays null (absent userHandle)', Passkey.bufToB64u(null) === null);
check('Passkey.supported() is false without WebAuthn', Passkey.supported() === false);

const E = (status, name, extra) => Passkey.explain(Object.assign(new Error('m'), { status, name: name || 'Error' }, extra), 'register');
check('explain: cancelling the OS sheet is quiet', Passkey.explain({ cancelled: true }, 'login').quiet === true);
check('explain: 403 on add says to sign in again',
  /sign out and sign in again, then add the passkey/.test(E(403).text) && !E(403).quiet, E(403).text);
check('explain: 403 means something else on login',
  !/sign out and sign in again/.test(Passkey.explain(Object.assign(new Error('nope'), { status: 403 }), 'login').text));
const E503 = (msg) => Passkey.explain(Object.assign(new Error(msg), { status: 503 }), 'login').text;
check('explain: 429 and 503 have their own wording',
  /Too many/.test(E(429).text) && /not enabled/.test(E503('HTTP 503')));
check('explain: a 503 with a server detail shows that detail',
  /the passkey store is unavailable/.test(E503('the passkey store is unavailable')), E503('the passkey store is unavailable'));
// a category literally named "constructor" is valid (^[a-z0-9-]+$) and must
// not resolve through Object.prototype in the tree/filter maps
(function () {
  const idx = [{ category: 'constructor', bytes: 1, mtime: '2026-10-13T00:00:00Z', sections: [], docs: [] },
               { category: 'infra', bytes: 1, mtime: '2026-10-13T00:00:00Z', sections: [], docs: [] }];
  const t = Nav.buildTree(idx);
  const rows = Nav.rows(t, { visible: Nav.filterVisible(t, 'zzzq', {}) }).map(r => r.name || r.slug);
  check('nav: a filter does not match a category named constructor', rows.length === 0, JSON.stringify(rows));
})();
check('explain: server detail passes through', Passkey.explain(new Error('name already used'), 'register').text === 'name already used');

async function passkeyFlows() {
  // a fake server and a fake authenticator, enough to check what goes on the wire
  const calls = [];
  const bytes = (...v) => new Uint8Array(v).buffer;
  let reply;
  ctx.fetch = (url, init) => {
    calls.push({ url, init, body: JSON.parse(init.body) });
    const r = reply(url);
    return Promise.resolve({ ok: r.status < 400, status: r.status, text: () => Promise.resolve(JSON.stringify(r.json)) });
  };
  ctx.window.PublicKeyCredential = function () {};
  ctx.navigator = { credentials: { create: () => {}, get: () => {} } };
  const b64u = (...v) => Passkey.bufToB64u(bytes(...v));

  // --- register
  let created;
  ctx.navigator.credentials.create = (o) => {
    created = o;
    return Promise.resolve({
      rawId: bytes(9, 8, 7), response: {
        clientDataJSON: bytes(1, 2), getAuthenticatorData: () => bytes(3, 4),
        getPublicKey: () => bytes(5, 6), getPublicKeyAlgorithm: () => -7, getTransports: () => ['internal']
      }
    });
  };
  reply = (url) => url.endsWith('/options')
    ? { status: 200, json: { publicKey: { challenge: b64u(1, 2, 3), rp: { id: 'x', name: 'x' },
        user: { id: b64u(4, 5), name: 'u', displayName: 'u' }, pubKeyCredParams: [],
        excludeCredentials: [{ type: 'public-key', id: b64u(7, 7) }] } } }
    : { status: 200, json: { id: 'abc', name: 'laptop', created: 'now' } };
  const out = await Passkey.register('laptop');
  const pk = created.publicKey, v = calls[1].body;
  check('register: challenge, user.id and excludeCredentials are decoded to buffers',
    new Uint8Array(pk.challenge).join() === '1,2,3' && new Uint8Array(pk.user.id).join() === '4,5' &&
    new Uint8Array(pk.excludeCredentials[0].id).join() === '7,7' && pk.excludeCredentials[0].type === 'public-key');
  check('register: posts to the contract routes with credentials and the actor header',
    calls[0].url === '/auth/passkey/register/options' && calls[1].url === '/auth/passkey/register/verify' &&
    calls.every(c => c.init.credentials === 'same-origin' && c.init.headers['X-Memory-Actor'] === 'memory-web' &&
      c.init.headers['Content-Type'] === 'application/json' && c.init.method === 'POST'));
  check('register: verify body carries every field of the contract, base64url',
    v.name === 'laptop' && v.id === b64u(9, 8, 7) && v.clientDataJSON === b64u(1, 2) &&
    v.authenticatorData === b64u(3, 4) && v.publicKey === b64u(5, 6) && v.publicKeyAlgorithm === -7 &&
    v.transports.join() === 'internal', JSON.stringify(v));
  check('register: resolves with the server record', out.id === 'abc');

  // getPublicKey() can legitimately be null; missing accessors mean an old browser
  ctx.navigator.credentials.create = () => Promise.resolve({ rawId: bytes(1), response: {
    clientDataJSON: bytes(1), getAuthenticatorData: () => bytes(1), getPublicKey: () => null,
    getPublicKeyAlgorithm: () => -7 } });
  const n0 = calls.length;
  let err = await Passkey.register('x').then(() => null, e => e);
  check('register: a null public key fails with a clear message and posts nothing',
    err && /public key/.test(err.message) && calls.length === n0 + 1, err && err.message);
  ctx.navigator.credentials.create = () => Promise.resolve({ rawId: bytes(1), response: { clientDataJSON: bytes(1) } });
  err = await Passkey.register('x').then(() => null, e => e);
  check('register: missing WebAuthn L2 accessors fail with a clear message',
    err && /cannot export the passkey public key/.test(err.message), err && err.message);

  // a stale session surfaces as .status 403 for the caller to explain
  reply = () => ({ status: 403, json: { detail: 'recent sign-in required' } });
  err = await Passkey.register('x').then(() => null, e => e);
  check('register: HTTP errors carry status and detail', err && err.status === 403 && err.message === 'recent sign-in required');

  // cancelling the OS sheet
  reply = (url) => ({ status: 200, json: { publicKey: { challenge: b64u(1), user: { id: b64u(1) } } } });
  ctx.navigator.credentials.create = () => Promise.reject(Object.assign(new Error('x'), { name: 'NotAllowedError' }));
  err = await Passkey.register('x').then(() => null, e => e);
  check('register: dismissing the OS sheet is a quiet cancel', err && err.cancelled === true &&
    Passkey.explain(err, 'register').quiet === true);

  // --- login
  let got;
  ctx.navigator.credentials.get = (o) => {
    got = o;
    return Promise.resolve({ rawId: bytes(9), response: {
      clientDataJSON: bytes(1), authenticatorData: bytes(2), signature: bytes(3), userHandle: bytes(4) } });
  };
  calls.length = 0;
  reply = (url) => url.endsWith('/options')
    ? { status: 200, json: { publicKey: { challenge: b64u(8, 8), rpId: 'x', userVerification: 'required',
        allowCredentials: [], timeout: 1 } } }
    : { status: 200, json: { authenticated: true, via: 'passkey' } };
  const res = await Passkey.login();
  const lv = calls[1].body;
  check('login: options then verify, challenge decoded', calls[0].url === '/auth/passkey/login/options' &&
    calls[1].url === '/auth/passkey/login/verify' && new Uint8Array(got.publicKey.challenge).join() === '8,8' &&
    got.publicKey.rpId === 'x' && got.publicKey.userVerification === 'required');
  check('login: verify body carries id, clientDataJSON, authenticatorData, signature, userHandle',
    lv.id === b64u(9) && lv.clientDataJSON === b64u(1) && lv.authenticatorData === b64u(2) &&
    lv.signature === b64u(3) && lv.userHandle === b64u(4), JSON.stringify(lv));
  check('login: resolves on 200', res.authenticated === true);
  ctx.navigator.credentials.get = () => Promise.resolve({ rawId: bytes(9), response: {
    clientDataJSON: bytes(1), authenticatorData: bytes(2), signature: bytes(3), userHandle: null } });
  await Passkey.login();
  check('login: an absent userHandle is sent as null', calls[calls.length - 1].body.userHandle === null);
  reply = (url) => url.endsWith('/options') ? { status: 200, json: { publicKey: { challenge: b64u(1) } } }
    : { status: 401, json: { detail: 'Authentication failed' } };
  err = await Passkey.login().then(() => null, e => e);
  check('login: a 401 is an error with status 401', err && err.status === 401 &&
    /not accepted/.test(Passkey.explain(err, 'login').text));
}

function finish() {
  console.log('----');
  console.log('PASS=' + pass + ' FAIL=' + fail);
  process.exit(fail ? 1 : 0);
}
passkeyFlows().then(finish, (err) => {
  console.log('FAIL: passkey flow threw  -> ' + (err && err.stack || err));
  fail++;
  finish();
});
