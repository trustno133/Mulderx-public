---
name: rce
description: Hunt a concrete remote code execution or command injection lead on an authorized web, service, CI/CD, file-processing, or runtime surface.
---

# Remote code execution

Use for a concrete signal that attacker-controlled input may reach command
execution, dynamic evaluation, an unsafe parser, or a privileged workflow.
This skill fills the command-execution gap; route confirmed SSTI or unsafe
deserialization mechanisms to `deserialization-ssti`, and upload/parser issues
to `file-upload` or `xxe` when those are the primary weakness.

## Start from evidence

Use the `hexbrain` skill for relevant public prior art when it can change the test plan; verify any lead against primary sources and target evidence. Use the upstream
[`hunt-rce` playbook](https://github.com/H-mmer/pentest-agents/blob/main/skills/hunt-rce/SKILL.md)
as a pattern source, not as target evidence or authorization.

Identify the exact in-scope feature, input, execution boundary, observed
technology/version, actor, and permitted test method. Useful surfaces include
server-side command wrappers, archive or document processors, CI/CD and
GitOps workflows, container/runtime interfaces, build/inference services,
and network-facing parsers. A technology fingerprint alone is not a lead.

## Validation approach

1. State the source-to-sink hypothesis and a benign expected observation.
2. Check the exact product/component/version and reachable feature before
   researching CVEs; route version research to `cve_research_specialist`.
3. Prefer static evidence or the smallest harmless canary that demonstrates
   the suspected behavior. Avoid persistence, destructive commands, reverse
   shells, credential access, broad file reads, or data exfiltration.
4. Stop if confirmation would require an unsafe side effect, an unapproved
   environment, or a live service outside the written scope. Do not create a
   mock/stand-in target to claim a live-target result.
5. Separate code-path evidence from reachability and demonstrated impact. A
   dangerous function call, error, version banner, or theoretical chain is a
   candidate only.
6. For a demonstrated capability, consult `mulderx-rules` pass-signal guidance
   and the relevant `chain-table.md` row. Test at most the next authorized,
   evidence-linked step; do not build speculative chains.

## Handoff

Return the exact input and sink, code/request evidence, prerequisites,
validation performed, safe impact demonstrated, uncertainty, and whether the
lead should move to another specialized skill. Apply Q1-Q3 and Mulderx's
evidence gate before calling anything confirmed.
