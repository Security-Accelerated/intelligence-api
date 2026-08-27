---
paths:
  - "internal/handler/docs*"
  - "internal/handler/render.go"
  - "internal/handler/openapi.go"
  - "internal/handler/changelog.go"
  - "internal/handler/changelog.yaml"
---

# Docs pages

Templates are `internal/handler/docs_*.html`, `go:embed`ed, sharing `docs_styles.css` and
`docs.js`. The reasoning behind every rule here is in `docs/decisions.md` under "Docs
pages"; each one was invisible on a desktop screen and broke the site on a phone.

## `docsPages` is the canonical page set

One table in `docs.go`. Routes are registered by looping it; tests derive their page lists
from it. **Adding a page is one table row.** Tests that apply to only some pages select
(`docsPagesWithLanguageTabs()`) rather than re-list. Do not spell the page set out anywhere
else — not in the router, not in a test, not in a template's nav.

## Layout rules — pinned by `docs_layout_test.go`

- **Every table is wrapped in `<div class="table-scroll">`.** `docs.js` gives the wrapper
  a tab stop only while it actually overflows.
- **No grid track carries a minimum the container cannot honour.** A collapsed grid uses
  `minmax(0, 1fr)`, never bare `1fr`. An `auto-fit` grid uses `minmax(min(<track>, 100%),
  1fr)`, never a bare length.
- Below 860px the topbar is a two-row grid with the section nav on the second row.
  `--topbar-height` changes with it and everything positioned against the bar — including
  `scroll-padding-top` — derives from that variable. Never hard-code the bar's height.

## Injected controls — pinned by `docs_controls_test.go`

The copy button and the page search are **injected by `docs.js`, never written into
templates.** The test fails if either control's class names appear in a template or
diverge between script and stylesheet.

- **Copy** wraps each `<pre>` in `.code-block` and puts the button in the wrapper, never
  inside the `<pre>` (it is its own scroll container). Room for it is *top* padding on the
  block. It copies `textContent`. No `navigator.clipboard` → no button at all.
- **Search** indexes the rendered DOM (`h2`/`h3`/`h4` and each table row's first cell) and
  shows the section per hit. Heading labels are cut at the dash so a lookup name outranks
  a row that mentions it. `/` or ⌘K opens, arrows move, Enter jumps, Escape closes. The
  overlay uses `body.search-open`, **not** `body.shell-open` (that slides the mobile
  drawer).

## The 404

`Handler.NotFound` is the engine's `NoRoute` handler. Paths under `/v1` or `/billing` get
the JSON `{"error": "not found"}` envelope; everything else renders `docs_404.html`. **The
requested path is never echoed back.**

## Changelog on the docs pages

`internal/handler/changelog.yaml` (symlinked from the repo root) is parsed at startup.
Docs pages render only entries with `audience: public` in "What's New". The admin endpoint
`GET /v1/admin/changelog` returns everything. The release flow in `RELEASE.md` says when
entries are written and which audience to use.

## CSP

HTML pages override the API's `default-src 'none'` CSP with `htmlPageCSP`. No inline JS —
page scripts are served at `/docs/*.js`. Adding an inline `<script>` will be blocked
silently by the browser, not by a test.
