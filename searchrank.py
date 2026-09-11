"""Ranked search over '## ' sections: the mode=rank half of /memory/search.

The default AND search has two failure modes this exists for. One term the
text happens not to use ("NAS" where the section says "storage") and the
whole query returns nothing -- a zero-hit cliff an agent reads as "the store
knows nothing about this". And when many lines match, they come back in file
order, not by relevance.

This is BM25 over sections with OR semantics, a light suffix stemmer, CJK
bigrams, and extra weight for the section heading and the category name.
Pure Python, no dependencies, no I/O: main.py reads the files and hands over
lines plus section spans.

Dense embeddings were weighed and deferred (2026-09-11): ~150 MB of ONNX
runtime on a Pi shared with the trading bots, for a ~1 MB corpus whose
reader is an LLM that can rephrase its own query. Revisit only if logged
rank-mode queries still miss on genuine paraphrase, not on vocabulary.
"""
import math
import re
from collections import Counter, namedtuple

K1 = 1.2
B = 0.75
HEADING_WEIGHT = 3   # a term in the '## ' heading counts as this many body occurrences
NAME_WEIGHT = 2      # ...and a term in the category/doc name (split on '-')

CJK = "\u3400-\u9fff\uf900-\ufaff"   # CJK unified ideographs + ext. A + compatibility
KANA_HANGUL = "\u3040-\u30ff\uac00-\ud7af"
BIGRAM = CJK + KANA_HANGUL   # scripts tokenised as overlapping character pairs
LATIN = "a-z0-9\u00c0-\u00d6\u00d8-\u00f6\u00f8-\u024f"   # ASCII + accented Latin, minus × and ÷
WORD_RE = re.compile(r"[" + LATIN + r"]+|[" + BIGRAM + r"]+")
CJK_RE = re.compile(r"[" + BIGRAM + r"]")

Hit = namedtuple("Hit", "unit score matched line")


def stem(word: str) -> str:
    """Conservative suffix stripping so 'cache'/'caching'/'cached'/'caches'
    and 'category'/'categories' meet. Applied identically to the query and
    the text, so an imperfect stem only ever costs a missed conflation --
    the exact word always still matches itself. Words with digits (rpi4,
    sha256) and words of three letters or fewer are left alone."""
    if len(word) <= 3 or not word.isalpha():
        return word
    if word.endswith("ies") and len(word) > 4:
        word = word[:-3] + "y"
    elif word.endswith(("sses", "xes", "zes", "ches", "shes")):
        word = word[:-2]
    elif word.endswith("s") and not word.endswith(("ss", "us", "is")):
        word = word[:-1]
    if word.endswith("ing") and len(word) > 5:
        word = word[:-3]
    elif word.endswith("ed") and not word.endswith("eed") and len(word) > 4:
        word = word[:-2]
    if word.endswith("e") and len(word) > 3:
        word = word[:-1]
    return word


def tokenize(text: str) -> list:
    """Lowercased Latin words (accents kept), stemmed; CJK, kana and Hangul
    runs as overlapping bigrams (a lone character stays a unigram).
    Everything else -- punctuation,
    '-', '/', '`' -- is a separator, so 'infra-pc-tuning' and `If-Match`
    split into their parts."""
    out = []
    for run in WORD_RE.findall(text.lower()):
        if CJK_RE.match(run):
            if len(run) == 1:
                out.append(run)
            else:
                out.extend(run[i : i + 2] for i in range(len(run) - 1))
        else:
            out.append(stem(run))
    return out


class Unit:
    """One searchable section. lines is the whole file (shared, not copied);
    start/end bound this section within it, end exclusive."""

    __slots__ = ("kind", "name", "section", "start", "end", "lines", "tf", "length")


def make_units(kind: str, name: str, lines: list, spans: list) -> list:
    """spans: [(start, end, section_name)] as main.section_spans computes
    them. A named span's first line is its '## ' heading, counted through
    HEADING_WEIGHT rather than as body text; an unnamed span is preamble."""
    name_tokens = tokenize(name)
    units = []
    for start, end, section in spans:
        tf = Counter()
        for line in lines[start + 1 if section else start : end]:
            tf.update(tokenize(line))
        for tok in tokenize(section):
            tf[tok] += HEADING_WEIGHT
        for tok in name_tokens:
            tf[tok] += NAME_WEIGHT
        u = Unit()
        u.kind, u.name, u.section = kind, name, section
        u.start, u.end, u.lines = start, end, lines
        u.tf, u.length = tf, sum(tf.values())
        units.append(u)
    return units


class Index:
    def __init__(self, units: list):
        self.units = units
        self.df = Counter()
        for u in units:
            self.df.update(u.tf.keys())
        self.avgdl = sum(u.length for u in units) / len(units) if units else 0.0

    def idf(self, tok: str) -> float:
        n = len(self.units)
        df = self.df.get(tok, 0)
        return math.log(1 + (n - df + 0.5) / (df + 0.5))

    def search(self, q: str, limit: int) -> list:
        """Top `limit` sections for the space-separated terms in q, best
        first; ties keep file order. Each Hit carries the query terms the
        section matched (so a caller can see a partial match for what it
        is) and the index of its best line."""
        terms, seen = [], set()
        for t in q.split():
            toks = frozenset(tokenize(t))
            if toks and toks not in seen:   # a repeated term must not buy coverage
                seen.add(toks)
                terms.append((t, toks))
        if not terms or not self.units:
            return []
        qtoks = set().union(*(toks for _t, toks in terms))
        idf = {tok: self.idf(tok) for tok in qtoks}
        scored = []
        for u in self.units:
            score = 0.0
            for tok in qtoks:
                f = u.tf.get(tok)
                if f:
                    norm = K1 * (1 - B + B * u.length / self.avgdl)
                    score += idf[tok] * f * (K1 + 1) / (f + norm)
            if score <= 0:
                continue
            # A term is matched only when all of its tokens are present: a CJK
            # phrase is one whitespace term but several bigrams, and sharing
            # one bigram is not containing the phrase. Coverage is fractional,
            # so a partial phrase still earns partial credit. OR semantics end
            # the zero-hit cliff; coverage keeps a section that matches every
            # term above one that repeats a single term a lot.
            covered = [sum(tok in u.tf for tok in toks) / len(toks) for _t, toks in terms]
            matched = [t for (t, _toks), c in zip(terms, covered) if c == 1]
            score *= 0.5 + 0.5 * sum(covered) / len(terms)
            scored.append((score, u, matched))
        scored.sort(key=lambda s: -s[0])
        return [Hit(u, score, matched, best_line(u, qtoks)) for score, u, matched in scored[:limit]]


def best_line(u: Unit, qtoks: set) -> int:
    """Index (into u.lines) of the line in u holding the most distinct query
    tokens; the first such line on a tie, the first non-blank line if none
    does (a match through the category name alone)."""
    best = next((i for i in range(u.start, u.end) if u.lines[i].strip()), u.start)
    best_n = 0
    for i in range(u.start, u.end):
        n = len(qtoks.intersection(tokenize(u.lines[i])))
        if n > best_n:
            best, best_n = i, n
    return best
