# Mulderx usage

Start Claude Code or Codex from this project root. Provide the program scope, exclusions, policy source, allowed actions, and test limits before active work.

For a new authorized domain, ask Mulderx to perform domain recon. It can inventory subdomains, observed stack, versions, CDN/WAF signals, and first-party JavaScript, then route concrete leads to the relevant specialist. Active route and parameter discovery is conditional on explicit authorization.

For a concrete lead, provide the exact in-scope host, endpoint, request/response or source evidence, authorized account state, and what validation is permitted. Mulderx should return evidence, uncertainty, coverage, blockers, and next steps.

Store per-target notes under `targets/<program>/` and credentials under `.credentials/`. Both are ignored by Git. Do not commit private findings, credentials, cookies, tokens, or target data.
