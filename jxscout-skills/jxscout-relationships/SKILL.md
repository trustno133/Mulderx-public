---
name: jxscout-relationships
description: Query jxscout for asset relationships -- which JS files and iframes a page loads, lazy-loaded chunks, reversed source maps, and how assets relate to each other. Use when mapping the attack surface of a specific page or understanding how assets are connected.
---

# jxscout Asset Relationships

jxscout tracks how web assets relate to each other: which JS files an HTML page loads, which iframes it embeds, which chunks were discovered from a script, and which source maps were reversed. Use these commands to map the attack surface of a specific page or trace how assets are connected.

## Prerequisites

All commands use `jxscout-pro-v2 -c` (client mode). The project name is resolved automatically from the `.env` file in the working directory. You can override it with `--project-name <name>` or by setting `JXSCOUT_PROJECT_NAME` in the environment.

## Commands

### Get JS files loaded by a page

```bash
jxscout-pro-v2 -c get-loaded-js-files <url_or_path> [--include-reversed-sources] [--json]
```

Lists all JS files loaded by an HTML page. Pass either the URL or the local file path.

- `--include-reversed-sources` -- also include file paths of reversed source map files
- `--json` -- structured output with `js_files` and optionally `reversed_sources` arrays

This is useful for scoping your analysis to the JS that actually runs on a specific page, rather than searching the entire project.

### Get loader page for a JS file

```bash
jxscout-pro-v2 -c get-js-file-loader-page <url_or_path> [--json]
```

Returns the HTML page(s) that load a given JS file. This is the reverse of `get-loaded-js-files`. Pass either the URL or the local file path of the JS file.

Also works with reversed source files -- it follows the chain (reversed source -> source map -> JS file) to find the pages that load the original JS file the reversed source was extracted from.

- `--json` -- structured output with a `loader_pages` array

This is useful for impact assessment: given a JS file with a vulnerability or interesting code, find which pages are affected.

### Get iframes loaded by a page

```bash
jxscout-pro-v2 -c get-loaded-iframes <url_or_path> [--json]
```

Lists all iframes embedded by an HTML page. Relevant for:
- **postMessage analysis**: iframes are common postMessage targets and sources
- **Cross-origin interactions**: understanding which origins are framed
- **Clickjacking assessment**: identifying framed content

## Workflow

1. **Start with a page**: use `get-loaded-js-files` to see what JS runs on a specific page
2. **Check iframes**: use `get-loaded-iframes` to understand cross-origin framing
3. **Follow the chain**: reversed sources often have more readable code -- check those for sensitive logic
4. **Trace back to pages**: use `get-js-file-loader-page` to find which pages load a specific JS file or reversed source -- useful when you find something interesting and need to know the affected pages

## Use cases

- **Scoping analysis to a page**: instead of searching the entire project, find exactly which JS files power a specific page and focus your review there
- **Finding hidden code**: lazy-loaded chunks often contain admin panels, internal tools, or feature-flagged code that isn't loaded by default
- **postMessage research**: mapping which iframes a page loads helps identify cross-origin messaging patterns
- **Understanding dependencies**: tracing which pages load a vulnerable script helps assess impact
- **Impact assessment**: given a JS file or reversed source with a finding, use `get-js-file-loader-page` to determine which pages are affected and prioritize accordingly

## Troubleshooting

**Symptom: `get-loaded-js-files`/`get-loaded-iframes` returns empty for a page you know loads scripts**
Cause: the page was never actually captured by jxscout's proxy -- either it's out of the configured ingestion scope, or it was browsed before jxscout started intercepting, so no relationship data was ever recorded.
Solution: confirm the exact URL appears under `http_requests/` or in prior static-analysis output; if it doesn't, browse the page again through the proxy before querying relationships for it.

**Symptom: `get-js-file-loader-page` returns no pages for a file you're sure is loaded somewhere**
Cause: usually a path mismatch -- you passed a guessed or reconstructed path instead of the exact `file_path` jxscout stored, or (for reversed sources) the source-map chain was never fully reversed/ingested.
Solution: take the exact `file_path` from a prior `get-matches --json` result rather than typing it from memory; for reversed sources, confirm the underlying source map was actually ingested first.

**Symptom: results look stale -- a page you just re-browsed doesn't show newly loaded scripts**
Cause: the relationship graph reflects what was captured at ingestion time; re-browsing a page through the proxy adds new traffic but doesn't retroactively update earlier queries you're still looking at.
Solution: re-run the relationship query after the new traffic has been ingested, not just after re-browsing.

## Related skills

- `jxscout-static-analysis` -- once you've scoped to the right JS files, query matches within them.
- `jxscout-bookmarks` -- document multi-step cross-page or cross-iframe flows once you've mapped them here.
- `jxscout-security-research` -- how asset-relationship mapping fits into the overall research workflow.
