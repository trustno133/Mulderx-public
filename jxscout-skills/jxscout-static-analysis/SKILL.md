---
name: jxscout-static-analysis
description: Query and manage jxscout static analysis matches -- list match kinds, get matches with filters, mark matches as seen/unseen. Use when investigating code patterns, exploring the attack surface, or tracking review progress across match results.
---

# jxscout Static Analysis (Matches)

jxscout runs static analyzers on every JS and HTML file it ingests. The results are called **matches** -- structured data pointing to specific patterns in the code (paths, URLs, secrets, sinks, etc.).

Use matches as a tool during your investigation -- query them when they're relevant, not only when explicitly asked. They're efficient for pinpointing specific patterns across a large codebase. But always supplement with grepping and manual code review for patterns the analyzers don't cover.

## Prerequisites

All commands use `jxscout-pro-v2 -c` (client mode). The project name is resolved automatically from the `.env` file in the working directory. You can override it with `--project-name <name>` or by setting `JXSCOUT_PROJECT_NAME` in the environment.

## Commands

### List available match kinds

```bash
jxscout-pro-v2 -c list-match-kinds --json
```

Returns a JSON array of all enabled match kind strings for the project. Run this to know what's available -- the list depends on the project's analyzer configuration and may include custom match kinds.

Common built-in match kinds: `path`, `api_path`, `hostname`, `url`, `secret`, `onmessage`, `html_manipulation`, `npm_package`, `url_search_params`, `location_assignment`.

### Get matches

```bash
jxscout-pro-v2 -c get-matches --match-kind <kind> [options]
```

**Required:**
- `--match-kind <kind>` -- the match kind to query (from `list-match-kinds`)

**Options:**
- `--json` -- output as JSON array with file paths, positions, values, and seen status (strongly recommended)
- `--limit <n>` -- max number of matches to return (JSON mode only)
- `--offset <n>` -- skip first n matches (JSON mode only)
- `--file-path-include <pattern>` -- only include matches from files matching this pattern (repeatable)
- `--file-type <type>` -- filter by file type: `js`, `html` (repeatable)
- `--value-include <substring>` -- only include matches whose value contains this substring (repeatable)
- `--show-only-unseen` -- only return matches that have not been marked as seen
- `--show-only-seen` -- only return matches that have been marked as seen
- `--show-only-interesting` -- only show interesting matches (this is the default behavior, flag exists for explicitness)
- `--show-only-uninteresting` -- only show matches that have been marked as uninteresting

Without `--json`, the command outputs deduplicated match values (one per line). With `--json`, each match includes:

```json
{
  "id": 42,
  "match_kind": "path",
  "match_value": "/api/v2/users",
  "position": { "start": { "line": 42, "column": 10 }, "end": { "line": 42, "column": 26 } },
  "file_type": "js",
  "file_path": "/path/to/file.js",
  "seen": false
}
```

### Mark matches as seen

```bash
jxscout-pro-v2 -c mark-matches-seen --match-ids 1,2,3
```

Mark specific matches by ID. Use this after reviewing matches to track progress.

**Bulk mode** -- mark all matches of a kind (with optional filters):

```bash
jxscout-pro-v2 -c mark-matches-seen --match-kind path
jxscout-pro-v2 -c mark-matches-seen --match-kind path --value-include "admin"
jxscout-pro-v2 -c mark-matches-seen --match-kind path --file-path-include "auth"
```

Bulk mode supports the same filters as `get-matches`: `--file-path-include`, `--file-type`, `--value-include`.

Returns JSON: `{"updated_count": N}`

### Mark matches as unseen

```bash
jxscout-pro-v2 -c mark-matches-unseen --match-ids 4,5,6
```

Same interface as `mark-matches-seen`. Use this to re-mark matches for review.

**Bulk mode:**

```bash
jxscout-pro-v2 -c mark-matches-unseen --match-kind path
```

Returns JSON: `{"updated_count": N}`

### Mark matches as uninteresting

```bash
jxscout-pro-v2 -c mark-matches-uninteresting --match-ids 1,2,3
```

Mark specific matches as uninteresting by ID. Uninteresting matches are hidden from `get-matches` by default. Use this to declutter results by dismissing noise.

**Bulk mode** -- mark all matches of a kind (with optional filters):

```bash
jxscout-pro-v2 -c mark-matches-uninteresting --match-kind path
jxscout-pro-v2 -c mark-matches-uninteresting --match-kind path --value-include "static"
jxscout-pro-v2 -c mark-matches-uninteresting --match-kind path --file-path-include "vendor"
```

Bulk mode supports the same filters as `get-matches`: `--file-path-include`, `--file-type`, `--value-include`.

Returns JSON: `{"updated_count": N}`

### Mark matches as interesting

```bash
jxscout-pro-v2 -c mark-matches-interesting --match-ids 4,5,6
```

Same interface as `mark-matches-uninteresting`. Use this to undo an uninteresting marking and restore matches to the default view.

**Bulk mode:**

```bash
jxscout-pro-v2 -c mark-matches-interesting --match-kind path
```

Returns JSON: `{"updated_count": N}`

## Workflow

1. **Discover match kinds**: `jxscout-pro-v2 -c list-match-kinds --json`
2. **Query relevant kinds**: start with high-value kinds like `path`, `api_path`, `secret`, `onmessage`, `html_manipulation`
3. **Use filters** to focus on what matters:
   - `--value-include "admin"` to find admin-related paths
   - `--value-include "internal"` to find internal endpoints
   - `--file-path-include "auth"` to scope to auth-related files
   - `--show-only-unseen` to focus on unreviewed matches
4. **Read the code** at the match positions to understand context
5. **Mark as seen** after reviewing: `mark-matches-seen --match-ids <ids>`
6. **Dismiss noise** with `mark-matches-uninteresting` to hide irrelevant matches from future queries
7. **Restore dismissed matches** with `mark-matches-interesting` if you change your mind
8. **Grep for more**: matches only cover what analyzers are configured to find -- search the codebase directly for patterns you care about that aren't covered

## HTTP request context

If `http_requests/` exists in the project working directory, jxscout has captured raw HTTP traffic from the target. The files are organized as `http_requests/{host}/{path}/{METHOD}/{timestamp}_{status}.req|.res` and contain raw HTTP request/response pairs.

Use these alongside static analysis to:
- **Cross-reference API calls**: match `path` or `api_path` results against actual captured requests to see real parameters, headers, and auth tokens in use
- **Discover endpoints not in JS**: some endpoints are only visible in server responses or redirects, not in client-side code
- **Understand real request patterns**: see actual `Content-Type`, auth headers, cookies, and request bodies that the application sends
- **Validate findings**: check if a pattern found via static analysis is actually exercised in real traffic

Browse `http_requests/` with `ls` / `find` and read individual `.req`/`.res` files to enrich your analysis.

## Limitations

Matches are only as good as the configured analyzers. Things that matches will NOT catch include:
- Dynamically constructed URLs or paths (e.g. `base + "/api/" + endpoint`)
- Patterns not covered by any enabled analyzer
- Logic bugs, race conditions, or business logic flaws

When investigating a specific area, always combine match queries with direct code search (grep/ripgrep) to get the full picture. If you find a pattern worth tracking systematically, consider creating a custom analyzer for it (see `jxscout-custom-analyzers`).

## Troubleshooting

**Symptom: `get-matches` returns nothing for a match kind you know exists**
Cause: the kind isn't enabled in this project's analyzer config, or everything of that kind got bulk-marked uninteresting earlier in the session.
Solution: run `list-match-kinds --json` first to confirm it's actually enabled; try `--show-only-uninteresting` to check if results are hiding there instead of being genuinely empty.

**Symptom: output is too large to work with**
Cause: querying a high-volume match kind (e.g. `path` on a large app) without narrowing filters.
Solution: add `--limit`, `--value-include`, `--file-path-include`, or `--show-only-unseen` to cut down the result set before reading it.

**Symptom: `mark-matches-seen`/`mark-matches-uninteresting --match-ids ...` has no visible effect**
Cause: the IDs came from a stale `get-matches` query -- IDs can shift after a `retrigger-events` run regenerates matches.
Solution: re-run `get-matches` immediately before marking to get current IDs, rather than reusing IDs from earlier in a long session.

## Related skills

- `jxscout-custom-analyzers` -- when the built-in match kinds don't cover a pattern you care about, or you need code-semantic (not just regex) matching.
- `jxscout-relationships` -- scope which files/matches actually matter by first mapping what a specific page loads.
- `jxscout-bookmarks` -- once a match leads you to something worth keeping, bookmark it with a note explaining why it matters.
