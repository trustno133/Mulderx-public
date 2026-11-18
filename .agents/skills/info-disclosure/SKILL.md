---
name: info-disclosure
description: Assess unintended exposure of sensitive application data, source, diagnostics, configuration, or private records beyond standalone secret detection.
---

# Information disclosure

Use for a concrete unintended data exposure. Route credential/key findings to
`exposed-secrets`; route object ownership issues to `idor-bola`; keep this skill
for data or diagnostics exposed without the intended authorization or
redaction. Read only the relevant Information Disclosure section of
Use the `hexbrain` skill for relevant public prior art when it can change the test plan; verify any lead against primary sources and target evidence.

## Validate the exposure

1. Establish what the response should contain for the tested actor and
   endpoint. Use a benign baseline and only authorized accounts.
2. Identify the data class, owner, visibility expectation, and whether the
   data is already intentionally public. Do not copy sensitive values into
   notes; mask them and retain the minimum evidence needed.
3. Verify access control, redaction, caching, and whether the behavior is
   repeatable. A stack trace, banner, public configuration value, or response
   status alone does not establish impact.
4. Demonstrate the minimum safe consequence. Do not use exposed credentials,
   enumerate users, dump records, access cloud accounts, or read unrelated
   files as proof. If a separate capability needs validation, hand it to the
   appropriate specialist with explicit scope and authorization.
5. Use `mulderx-rules` chain guidance only after the exposed data yields a
   demonstrated capability. A possible secret or internal hostname is not a
   proven chain.

## Handoff

Record endpoint, actor, sanitized before/after evidence, data category,
visibility expectation, impact demonstrated, and remaining uncertainty.
Apply Q1-Q3; classify a theoretical or nonsensitive disclosure no higher than
the available evidence supports.
