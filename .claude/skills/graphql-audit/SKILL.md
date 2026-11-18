---
name: graphql-audit
description: Assess a concrete, observed GraphQL API for resolver authorization, schema exposure, variables, subscriptions, and bounded query-abuse signals.
---

# GraphQL API audit

Use when GraphQL protocol behavior is the lead. Start from an observed or
documented in-scope endpoint; do not discover endpoints by fuzzing unless the
operator separately requests that work. Upstream reference:
[`graphql-audit` agent](https://github.com/H-mmer/pentest-agents/blob/main/.claude/agents/graphql-audit.md).

Use the `hexbrain` skill for relevant public prior art when it can change the test plan; verify any lead against primary sources and target evidence.
category. Load `vuln-classes/references/graphql.md` and only the matching
section of `pentest-agents/rules/techniques.md` when a concrete protocol signal
needs it.

## Method

1. Record endpoint, account/role, baseline operation, and expected owner or
   capability. Use the program's approved accounts only.
2. If permitted, use introspection to map operations, object IDs, nested
   relations, sensitive fields, mutations, and subscriptions. Introspection,
   suggestions, Playground, or internal type names alone are not findings.
3. Compare resolver and field authorization across the authorized roles. Test
   nested paths and mutations only when they follow from an observed schema
   and the lead. For object ownership, route the finding owner to
   `idor-bola`; for workflow invariants, use `business-logic`.
4. Check REST/API parity when the same operation exists over both transports.
   Record response and durable-state differences; a status code alone is not
   proof.
5. Treat variables and directives as class-specific inputs: SQL/NoSQL
   injection goes to the injection specialist; subscription-origin issues go
   to WebSocket/CSWSH specialists as applicable.
6. Query depth, complexity, batching, aliases, and rate-limit behavior can
   create load or bypass controls. Do not send large batches, stress queries,
   or expensive nested selections. Test only a small bounded request when the
   policy explicitly permits it, stop at any degradation or rate signal, and
   require a concrete security impact rather than theoretical resource use.
7. Keep each confirmed class as a separate lead with its own evidence and
   owner; this agent does not absorb IDOR, SQLi, OAuth, or business-logic
   findings merely because they use GraphQL.

## Handoff

Include the endpoint, operation, sanitized variables, identity/role, relevant
schema path, authorization expectation, response/read-back evidence, impact,
and the specialist owner for any class-specific follow-up. Apply the relevant
skill's evidence gate and Q1-Q3 before confirmation.
