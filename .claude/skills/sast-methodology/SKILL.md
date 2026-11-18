---
name: sast-methodology
description: Perform a staged, evidence-led static security review of source code provided or explicitly authorized for review.
---

# Static source review

Use only when relevant source code is available and the operator has asked for
or authorized code review. This workflow adapts the upstream
[`sast-methodology`](https://github.com/H-mmer/pentest-agents/blob/main/skills/sast-methodology/SKILL.md)
and its decomposed pipeline; it does not authorize testing a deployed system,
installing dependencies, changing source, or running payloads against a live
target.

## Pipeline and handoffs

Keep each stage narrow and pass evidence forward rather than asking one agent
to invent an entire vulnerability end-to-end:

1. **Map** (`sast_mapper_specialist`): identify high-risk files, trust
   boundaries, externally controlled entry points, and dangerous operations.
   Return exact paths/lines and why they are relevant.
2. **Trace** (`sast_flow_specialist`): for a selected entry/sink pair, follow
   the same value across calls/files, record transformations and each check,
   and determine whether the path is reachable from an untrusted actor.
3. **Review** (`sast_review_specialist`): independently challenge a concrete
   flow. Check wrappers, callers, macros, framework middleware, build flags,
   test-only code, feature gates, and sanitizers that could invalidate it.
4. **Validate**: if the candidate survives, route it to its vulnerability
   specialist. Dynamic confirmation, compilation, or a PoC requires a separate
   authorized task and must use the real supplied project/target context; do
   not build a mock stand-in or make source edits without request.

## Working method

- Begin with the requested subsystem and repository boundaries. Do not perform
  broad recon, access unrelated projects, or read credentials/secrets.
- Use deterministic static tools only if already available and appropriate;
  do not install packages or run untrusted build scripts without authorization.
- Prioritize trust boundaries and source-to-sink paths over pattern counts.
  Distinguish externally reachable entry points from tests, examples, dead
  code, and internal-only callers.
- For each candidate, cite file and line, input source, sink, complete path,
  validation chain, preconditions, and realistic impact. Keep verified facts
  separate from inference.
- A dangerous API call or missing-looking check is not enough. Look for
  wrappers, framework validation, generated code, build configuration, and
  runtime reachability before proposing a finding.
- Do not treat two model passes as proof. Independent review can reduce
  hallucination risk but only concrete code evidence and authorized validation
  establish a finding.

## Stage output

```text
Stage: MAP | TRACE | REVIEW
Scope/repository boundary:
Files and line references:
Entry point and trust boundary:
Sink and validation chain:
Reachability evidence:
Candidate / counterevidence:
Impact hypothesis:
Missing proof / next owner:
Status: CANDIDATO | DESCARTADO | BLOQUEADO
```

Static review alone produces at most a candidate. Apply the relevant class
skill, authorization gates, and Q1-Q3 before any validation or reporting.
