---
name: race-condition
description: Validate a concrete timing or concurrency flaw in an authorized non-idempotent workflow with bounded requests and observable state.
---

# Race conditions

Use for an evidenced TOCTOU or concurrent state-transition hypothesis, such
as duplicate redemption, quota consumption, invite acceptance, or balance
changes. Ordinary workflow/state logic belongs to `business-logic`. See also the upstream
[`race-condition` agent](https://github.com/H-mmer/pentest-agents/blob/main/.claude/agents/race-condition.md).

## Safe validation

1. Confirm written authorization for concurrency, the exact endpoint, actor,
   and test resource. Prefer a test account and reversible synthetic object.
2. Establish the sequential baseline and record relevant state before and
   after one operation. Confirm whether idempotency keys or server-side limits
   are expected.
3. Use the smallest concurrent batch likely to answer the hypothesis. Do not
   use a fixed request count, stress test, or high-volume timing loop. Stop on
   service degradation, rate limits, unexpected charges, duplicate external
   notifications, or other unintended side effects.
4. Verify durable state with a read-back from an authorized perspective.
   Record parallelism, order/timing, success rate, final state, and cleanup.
5. Repeat only if necessary to distinguish a race from ordinary retries and
   while still within the authorized risk budget. One lucky response is not
   proof; do not keep retrying a blocked or destructive operation.

A `2xx` response or duplicate UI message is only a signal. Confirm a durable,
unauthorized state change and operational impact. Apply the business-logic
evidence gate and Q1-Q3 before confirming.
