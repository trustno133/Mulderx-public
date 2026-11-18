# Race condition

Use `race-condition` / `race_condition_specialist` only when a non-idempotent
operation or check/use window provides a concrete concurrency hypothesis.
General workflow invariants remain with `business-logic` /
`business_logic_specialist`.

Require explicit authorization for concurrent requests, a sequential baseline,
a small adaptive batch, durable-state read-back, and safe cleanup. Do not use a
fixed request count or stress traffic. Stop on side effects, rate limits, or
service degradation.
