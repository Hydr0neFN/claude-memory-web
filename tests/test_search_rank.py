#!/usr/bin/env python3
"""Unit tests for searchrank.py -- tokenising, stemming, ranking. No network.

    python tests/test_search_rank.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import searchrank as sr  # noqa: E402

PASS = FAIL = 0


def check(name, got, want=True):
    global PASS, FAIL
    if got == want:
        print("PASS: %s" % name)
        PASS += 1
    else:
        print("FAIL: %s (expected %r, got %r)" % (name, want, got))
        FAIL += 1


def spans(lines):
    """Minimal stand-in for main.section_spans: '## ' headings only."""
    heads = [i for i, line in enumerate(lines) if line.startswith("## ")]
    return [
        (i, heads[n + 1] if n + 1 < len(heads) else len(lines), lines[i][3:].strip())
        for n, i in enumerate(heads)
    ]


def units(name, text, kind="memory"):
    lines = text.splitlines()
    return sr.make_units(kind, name, lines, spans(lines))


# -- stemming and tokenising ------------------------------------------------

check("cache/caching/cached/caches share a stem",
      len({sr.stem(w) for w in ("cache", "caching", "cached", "caches")}), 1)
check("category/categories share a stem", sr.stem("categories"), sr.stem("category"))
check("speed/speeds share a stem", sr.stem("speeds"), sr.stem("speed"))
check("string/strings share a stem", sr.stem("strings"), sr.stem("string"))
check("write/writes/writing share a stem",
      len({sr.stem(w) for w in ("write", "writes", "writing")}), 1)
check("status is not singularised", sr.stem("status"), "status")
check("short and alphanumeric words are untouched",
      [sr.stem(w) for w in ("ssd", "rpi4", "sha256")], ["ssd", "rpi4", "sha256"])
check("hyphenated names split into parts",
      sr.tokenize("infra-pc-tuning"), ["infra", "pc", sr.stem("tuning")])
check("backtick/punctuation are separators", sr.tokenize("`If-Match`: *"), ["if", "match"])
check("CJK runs become bigrams", sr.tokenize("硬碟壓縮"), ["硬碟", "碟壓", "壓縮"])
check("a lone CJK character stays a unigram", sr.tokenize("碟"), ["碟"])
check("ASCII and CJK in one run are split", sr.tokenize("SSD硬碟"), ["ssd", "硬碟"])

# -- ranking ----------------------------------------------------------------

store = (
    units("infra-rpi4-storage", "## SSD mount\n"
          "USB SSD mounted at /mnt/ssd/live, ext4.\n"
          "\n"
          "## Backups\n"
          "Nightly rsync of the storage volume to the SSD.\n")
    + units("projects-trading", "## Deploy\n"
            "Bots deployed with scp and systemctl restart.\n"
            "\n"
            "## Caching\n"
            "The dashboard caches quotes for 60 seconds.\n")
    + units("infra-media", "## Film library\n"
            "Films live on the SD card, not network storage.\n")
    + units("personal-health", "## 健康\n"
            "睡眠與壓力紀錄。\n")
)
idx = sr.Index(store)


def top(q, n=10):
    return [(h.unit.name, h.unit.section) for h in idx.search(q, n)]


hits = idx.search("NAS storage", 10)
check("zero-hit cliff: one absent term no longer empties the result", len(hits) > 0)
check("zero-hit cliff: every hit reports only the term it matched",
      {tuple(h.matched) for h in hits}, {("storage",)})
check("a term in the category name lifts that category's sections",
      hits[0].unit.name, "infra-rpi4-storage")

check("stemming: 'cached' finds the 'Caching' section",
      top("cached")[0], ("projects-trading", "Caching"))
check("heading weight: 'ssd' ranks the SSD heading above a body mention",
      top("ssd")[0], ("infra-rpi4-storage", "SSD mount"))

hits = idx.search("ssd backups", 10)
check("coverage: the section matching both terms ranks first",
      (hits[0].unit.section, hits[0].matched), ("Backups", ["ssd", "backups"]))
check("coverage: a one-term match reports that it is partial",
      [h.matched for h in hits if h.unit.section == "SSD mount"], [["ssd"]])

h = idx.search("rsync", 5)[0]
check("best line points at the line holding the term", "rsync" in h.unit.lines[h.line])
h = idx.search("trading", 5)[0]
check("a match through the name alone points at the heading",
      h.unit.lines[h.line], "## " + h.unit.section)

check("CJK query finds CJK text", top("壓力")[0], ("personal-health", "健康"))
check("scores come back best first",
      [h.score for h in idx.search("the storage ssd", 10)]
      == sorted((h.score for h in idx.search("the storage ssd", 10)), reverse=True))
check("limit is honoured", len(idx.search("the", 2)) <= 2)
check("a query with no word tokens returns nothing", idx.search("-- ** //", 5), [])
check("an empty index returns nothing", sr.Index([]).search("storage", 5), [])

tie = sr.Index(units("a", "## One\nsame text\n") + units("b", "## One\nsame text\n"))
check("ties keep file order", [h.unit.name for h in tie.search("same", 5)], ["a", "b"])

# -- regressions from review ------------------------------------------------

check("size/sizes share a stem", sr.stem("sizes"), sr.stem("size"))
check("tune/tuning share a stem", sr.stem("tuning"), sr.stem("tune"))
check("accented Latin stays one word", sr.tokenize("München één"), ["münchen", "één"])
check("× is still a separator", sr.tokenize("heading×3"), [sr.stem("heading"), "3"])
check("kana is kept, as bigrams", sr.tokenize("メモリ"), ["メモ", "モリ"])

cj = sr.Index(units("x", "## 影像\n影像壓縮設定\n") + units("y", "## 硬碟\n硬碟壓縮已開啟\n"))
hits = cj.search("硬碟壓縮", 5)
check("CJK phrase: the section holding the whole phrase ranks first", hits[0].unit.name, "y")
check("CJK phrase: sharing one bigram is not matching the phrase",
      [h.matched for h in hits if h.unit.name == "x"], [[]])

h = idx.search("storage storage storage NAS", 10)[0]
check("a repeated term is counted once", h.matched, ["storage"])
check("a repeated term does not raise the score",
      round(h.score, 6), round(idx.search("storage NAS", 10)[0].score, 6))

pre = sr.make_units("p", "p", ["", "preamble text", "", "## S", "body"], [(0, 2, ""), (3, 5, "S")])
h = sr.Index(pre).search("p", 5)[0]
check("a name-only match never points at a blank line", h.unit.lines[h.line] != "", True)

print("\n%d passed, %d failed" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
