---
name: web3-audit
description: Review explicitly in-scope smart-contract or DeFi source for reachable authorization, asset-flow, oracle, upgrade, and invariant failures.
---

# Web3 and smart-contract review

Use only when the operator identifies an authorized Web3 program or provides
source code explicitly for review. Confirm the current program scope for each
contract/address and chain before proposing interaction. Upstream reference:
[`web3-auditor`](https://github.com/H-mmer/pentest-agents/blob/main/.claude/agents/web3-auditor.md).

Use the `hexbrain` skill for relevant public prior art when it can change the test plan; verify any lead against primary sources and target evidence. Use the upstream agent as a checklist source, not as
permission to run Foundry PoCs or transact against live contracts.

## Review method

1. Identify the in-scope repository, compiler/version, deployed contract and
   chain references supplied by the operator, roles, upgrade controls, pause
   state, and asset/invariant model.
2. Map external/public entry points, authorization modifiers, state changes,
   external calls, token transfers, oracle reads, callbacks, and upgrade paths.
   Cite exact source paths and line numbers; distinguish observed facts from
   inferred reachability.
3. Check class-relevant invariants: accounting and solvency, access control,
   reentrancy and callback ordering, oracle assumptions, signature/replay
   checks, initialization and upgrade safety, and cross-contract trust.
4. Do not treat grep hits, suspicious `call`/`delegatecall`, an owner-only
   function, or a theoretical flash-loan path as a vulnerability. Trace the
   reachable transaction sequence and state/value change required.
5. Static review produces candidates only. Do not send transactions, alter
   live state, run a fork or PoC, acquire assets, or deploy contracts unless a
   separate task explicitly authorizes the exact test environment and method.
   A local simulation alone does not prove a live-target finding.
6. Quantify only what the supplied evidence supports: affected assets,
   invariant break, attacker prerequisites/capital, and possible loss or
   governance effect. Keep speculative maximum loss separate from demonstrated
   impact.

## Handoff

Return contract/function, source references, trust assumptions, invariant,
transaction sequence, guards, counterevidence, impact hypothesis, and the
minimum authorized validation needed. Label static-only work `CANDIDATO` and
apply Q1-Q3 before confirmation.
