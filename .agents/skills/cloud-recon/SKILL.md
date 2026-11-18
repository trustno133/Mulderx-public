---
name: cloud-recon
description: Map explicitly in-scope cloud-hosted assets and exposed service relationships from supplied scope and observed evidence; use when cloud infrastructure is a concrete part of the authorized target.
---

# Cloud recon

Use only when the program scope or operator explicitly includes the relevant cloud assets. A DNS record, provider hostname, bucket name, tenant identifier, or shared CDN does not establish ownership or authorization.

## Workflow

1. Start from the written scope and supplied asset inventory. Separate owned assets from third-party providers and mark uncertain ownership as unresolved.
2. Inventory observed cloud signals per in-scope host: DNS/CNAME relationships, TLS and HTTP metadata, public service endpoints, storage references, API origins, identity/login providers, and region hints when directly evidenced.
3. Classify evidence as observed, inferred, or unverified. Do not enumerate cloud accounts, tenants, regions, buckets, or control-plane APIs unless the program explicitly authorizes those exact actions.
4. Correlate assets only when a concrete relationship is evidenced. Do not transfer scope from one region, account, hostname, or vendor to another.
5. Route a concrete issue to its canonical owner: exposed data to `info-disclosure` or `exposed-secrets`; access-control signals to `idor-bola`/`business-logic`; SSRF to `ssrf`; dangling records to `hunt-external-takeover`; exposed management interfaces to `infra-panels-default-creds`.
6. Stop active checks on rate limits, challenges, bans, explicit exclusions, or service degradation.

## Output

Provide an asset table with hostname/resource, provider (confidence), scope evidence, observed relationship, exposure, source, and next safe step. This skill maps a surface; it does not confirm cloud compromise or authorize access to data.
