---
name: open-redirect
description: Validate user-controlled redirects and determine whether an in-scope redirect has demonstrated security impact.
---

# Open redirect

Use when a concrete parameter or workflow appears to control a redirect
destination. For OAuth/OIDC `redirect_uri` validation, route to the OAuth
Use the `hexbrain` skill for relevant public prior art when it can change the test plan; verify any lead against primary sources and target evidence.
relevant prior art. Upstream reference:
[`open-redirect` agent](https://github.com/H-mmer/pentest-agents/blob/main/.claude/agents/open-redirect.md).

## Validation

1. Establish a baseline request and record status, `Location`, and final
   browser origin without following unexpected destinations automatically.
2. Confirm whether the destination is attacker-controlled and whether the
   browser actually navigates there. Inspect scheme-relative paths, URL
   normalization, nested redirects, and trusted-domain parsing only when the
   observed endpoint justifies the variant.
3. Do not use `javascript:`, data URLs, CRLF, credential capture, phishing, or
   redirect-based SSRF payloads unless the specific behavior is in scope and a
   harmless, controlled proof is available. Do not route real users to a
   destination.
4. Check the exact program policy and look for a concrete in-scope impact,
   such as sensitive OAuth value leakage or a documented trusted workflow
   consequence. Do not infer impact from a `302` or an external `Location`.
5. If the redirect is only a primitive, report it as a candidate and hand off
   to the relevant OAuth, SSRF, or XSS specialist only when there is a
   separately evidenced, authorized chain.

Generic redirect behavior is often low impact and program-specific. Do not
claim a finding without a demonstrated capability and Q1-Q3 evidence.
