# Remote code execution

Use `rce` / `rce_specialist` for a concrete input-to-command or input-to-code
execution lead. Route an evidenced SSTI or unsafe deserialization primitive
to `deserialization-ssti`; file/parser ingestion goes to `file-upload` or
`xxe` when that is the primary weakness. Exact-version CVE research belongs to
`cve_research_specialist` before any validation.

Require an in-scope entry point, demonstrated reachability, and the smallest
safe proof. No persistence, destructive commands, reverse shells, credential
access, or data exfiltration. A dangerous sink, version banner, or error alone
is only a candidate.
