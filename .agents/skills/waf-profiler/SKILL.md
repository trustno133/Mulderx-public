---
name: waf-profiler
description: Profile observable WAF and CDN behavior on an explicitly in-scope host; record evidence and adapt authorized tests without evading operational controls.
---

# WAF profiler

Use this skill when responses show a WAF, CDN challenge, denial page, or a security control that changes how an authorized test is handled. This is a profiling and decision skill, not blanket authorization to bypass controls.

## Workflow

1. Confirm the exact host and endpoint are in scope and that the operator permits the relevant active request. If not, use only existing response evidence and mark further checks pending.
2. Record passive indicators: response headers, cookies by name only, block/challenge page markers, edge/CDN signals, status, and request context. Never copy cookie values, challenge tokens, or credentials into notes.
3. Establish a benign baseline and compare only the minimum authorized request needed to understand the observed behavior. Keep method, path, headers, body, response code, and timing attributable to each observation.
4. Separate CDN presence from confirmed WAF vendor/product. Label fingerprints as tentative unless multiple independent indicators agree; do not infer a product version from generic headers.
5. If the signal is XSS, route the vulnerability analysis through `xss-hunt` and its one relevant subtype. Consult the legacy WAF reference only for a specific, observed filter behavior and only within the approved test boundary.
6. Stop that path on CAPTCHA/managed challenge, rate limiting, ban, explicit denial of testing, or sustained errors. Do not rotate IPs, impersonate users/devices, automate challenge solving, probe origin IPs to get around the edge, or try alternate ports/protocols to evade the control.
7. Return the observed protection profile, confidence, exact evidence, permitted next check, and any blocked/pending work. A WAF block is not a vulnerability finding; a payload reflected through a WAF is not XSS until browser execution and impact are demonstrated.

## Handoff

Return host and endpoint, scope basis, observation vs. inference, response evidence with secrets redacted, control confidence, status (`OBSERVADO`, `CANDIDATO`, `BLOQUEADO`), stop signal if any, and next authorized step. Do not report a bypass solely because a request received a different status or body.
