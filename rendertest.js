/* Node harness: exercise md.js + diff.js against real memory content. */
const fs = require('fs');
const vm = require('vm');

const ctx = { window: {}, console, Date, Math, RegExp, JSON, String, Array, Number, Uint32Array, setTimeout };
ctx.globalThis = ctx;
vm.createContext(ctx);
for (const f of ['md.js', 'diff.js']) {
  vm.runInContext(fs.readFileSync(__dirname + '/web/' + f, 'utf8'), ctx, f);
}
const FIX = __dirname + '/';
const MD = ctx.window.MD, Diff = ctx.window.Diff;

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

/* --- perf sanity -------------------------------------------------------- */
const t0 = Date.now();
for (let i = 0; i < 20; i++) MD.render(a);
check('20 renders under 1s', Date.now() - t0 < 1000, (Date.now() - t0) + 'ms');

console.log('----');
console.log('PASS=' + pass + ' FAIL=' + fail);
process.exit(fail ? 1 : 0);
