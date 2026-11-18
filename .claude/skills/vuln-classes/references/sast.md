# Static source analysis

Use `sast-methodology` only for source code the operator supplied or
explicitly authorized for review. Delegate in sequence:

1. `sast_mapper_specialist` maps entry points, trust boundaries, and sinks.
2. `sast_flow_specialist` traces one selected source-to-sink flow and checks.
3. `sast_review_specialist` challenges the concrete candidate and searches for
   wrappers, guards, dead code, or missing reachability.

Static evidence is a candidate, not a confirmed live finding. Do not install
dependencies, run untrusted build scripts, edit source, or test a deployed
service without a separate authorized task. Route any surviving candidate to
the appropriate vulnerability specialist.
