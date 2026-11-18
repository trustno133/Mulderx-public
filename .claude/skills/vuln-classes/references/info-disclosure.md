# Information disclosure

Use `info-disclosure` / `info_disclosure_specialist` for unintended exposure
of private records, diagnostics, source, or configuration. Use
`exposed-secrets` / `exposed_secrets_specialist` for keys, tokens, and
credentials; use IDOR/BOLA when object ownership is the broken boundary.

Identify the intended visibility, data owner, and least sensitive proof. Mask
values in artifacts. Do not use credentials, dump unrelated records, or assume
that internal-looking data is sensitive. Route any demonstrated next
capability through the pass-signal chain gate.
