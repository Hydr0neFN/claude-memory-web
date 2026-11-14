# The API

[← README](../README.md) · [English](api.md) · [繁體中文](api.zh-TW.md)

Underneath the MCP tools and the browser UI is one REST API; both call it, and
neither reimplements any of its rules. It stores one Markdown file per category,
guarded by a single bearer token, and git-commits every write so any edit is
recoverable. Reads are `GET /memory/{category}`; writes need `If-Match` with the
ETag you read, which is the git blob SHA of the body. `main.py` and `webauth.py`
here are the whole server.

That ETag is the blob SHA of the bytes **on disk**, and every read path — the
category, the doc, and both index listings — computes it the same way the write
guard does. Getting this wrong is subtle and unpleasant: hash the *decoded* text
instead and universal-newline translation applies, so a file stored with CRLF is
served as LF and hashed over the LF form. A client that faithfully returns the
ETag it was handed is then refused `409 etag mismatch` forever, with no
concurrent writer anywhere. Request bodies are therefore normalised to LF, and
must be valid UTF-8 or the write is refused `400` — without that check one bad
body would break `index`, `search` and `pins` for the whole store, since all
three read every file. `tests/test_etag_crlf.py` holds the contract down.

There are three namespaces. `/memory/{category}` holds facts — short, deduplicated,
one topic each. `/docs/{slug}` holds working documents — handoffs, runbooks,
audit reports: long, project-scoped, superseded rather than accumulated. Docs
live in `data/docs/`, which every `/memory` endpoint is blind to because its
glob is non-recursive. `/memory/search` skips docs unless you pass
`&scope=docs|all`, so handoff prose never swamps a fact lookup.

A third namespace, `/skills/{domain}`, holds reusable procedures: one
`data/skills/<domain>.md` file per domain, one `## msk-<12 hex> <title>` section
per skill. Sections are addressed by id (`?section=msk-<id>`), so renaming a
skill does not break a caller. `GET /skills/index` lists the parsed metadata
(status, refs, uses, last use) and `GET /skills/backlinks?ref=<category>` finds
the skills that reference a category or one of its sections; both are computed
from the files, never from a second index. `&scope=skills|all` adds skills to
search, and MCP accepts `namespace="skills"` wherever it accepts memory or docs.

By default search returns every line containing all the terms. `&mode=rank`
instead ranks whole sections by BM25 with OR semantics, light stemming and CJK
bigrams (`searchrank.py`, pure Python), so one term the text happens not to use
no longer empties the result, and each hit lists the terms it `matched`. The
index is derived from the markdown and rebuilt when a file changes. Dense
embeddings were considered and deferred: a ~150 MB runtime on a shared Pi buys
little over BM25 for a ~1 MB corpus whose reader can rephrase its own query.

Both namespaces support `?section=<name>` on GET, PUT and DELETE, addressing a
single `## ` block: read three lines out of a 20 KB file, or splice three lines
back in without touching another byte. The locking unit stays the whole file —
`If-Match` still carries the whole-file ETag — only the *editing* unit becomes
the section. That matters for LLM callers, which otherwise load an entire
category to change one line and hand-roll a whole-file patch to write it back.
A body whose heading does not match the section is a `400`, never an implicit
rename, because a silent rename would break every existing reference to the old
name.
