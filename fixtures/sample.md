# Sample Category

A synthetic stand-in for a real memory category. It exists to exercise every
construct `md.js` claims to support, so the render tests have something to
assert against without committing personal notes to the repository.

## Endpoint
<!-- verified: 2026-08-15 -->

Base URL: https://example.invalid/api
Auth: bearer token, read from the environment. Never inline it in a file.

- `GET /thing` — list things
- `GET /thing/{id}` — read one, returns an `ETag`
- `PUT /thing/{id}` — requires `If-Match`; missing precondition is a `428`
  - stale etag → `409` plus the current etag in the response header
  - `If-Match: *` forces, discarding the other writer's change
- `DELETE /thing/{id}` — same precondition rules

## Stale On Purpose
<!-- verified: 2019-03-04 -->

This section carries an ancient date so the staleness badge has something to
mark. Identifiers like `snake_case_name`, `check_write_auth` and `git_commit`
must survive untouched — no accidental *emphasis* from the underscores.

Inline forms: **bold**, *italic*, ~~struck~~, `code span with **markup** inside`,
a [labelled link](https://example.invalid/docs) and a bare
https://example.invalid/bare one.

## Code And Quotes

```python
def blob_sha(data: bytes) -> str:
    h = hashlib.sha1()
    h.update(b"blob %d\0" % len(data))
    return h.hexdigest()
```

> A blockquote, wrapped across
> two source lines.

---

## Table

| Field | Type | Note |
| --- | --- | --- |
| `id` | string | matches `^[a-z0-9-]+$` |
| `bytes` | int | soft cap is ~20 KB |
| `<raw>` | text | angle brackets must be escaped, not rendered |

## Long List

1. first ordered item
2. second ordered item
3. third, with a nested branch
   - nested bullet one
   - nested bullet two
     - deeper still
4. fourth

- a plain bullet after an ordered list
- another, long enough to wrap on a narrow pane so the editor mirror and the
  rendered block disagree about height, which is exactly the case the scroll
  sync has to interpolate through
- last one
