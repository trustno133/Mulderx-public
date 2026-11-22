---
name: auth-bypass
description: Assess concrete authentication and recovery-flow bypasses with an evidence-led, bounded test plan outside dedicated OAuth, SAML, JWT, and session-fixation specialists.
---

# Authentication bypass

Use for a concrete login, password-reset, MFA, account-recovery, or identity
binding signal that is not primarily OAuth/OIDC, SAML, JWT validation, or
session fixation. Route those classes to their existing dedicated skills.

Use the `hexbrain` skill for relevant public prior art when it can change the
test plan. Check primary references and the target's own client/API behavior;
keep prior art separate from target evidence. Upstream test ideas never override
program policy or Mulderx stop conditions.

## Method

1. Map the identity state machine relevant to the lead: initiation,
   verification, account linking, recovery, MFA enrollment/challenge, password
   change, logout, or session revocation.
2. Compare only operator-provided, authorized identity lanes. Record the
   expected principal/role and a baseline for each relevant transition.
3. If the evidence supports multiple distinct checks, prepare a short matrix.
   Each row should state the hypothesis, authorized actor/account, one request
   or state transition, expected server-side observation, possible side effect,
   and stop condition. Include only meaningful cases; do not pad to a fixed
   payload count.
4. Verify current scope and policy before active requests. Test one transition
   at a time and keep request volume low. A suggested payload or matrix is not
   permission to send it. Do not parallelize non-idempotent recovery, email,
   MFA, or password-change actions unless a bounded race test is explicitly
   authorized.
5. Avoid password guessing, OTP brute force, push fatigue, unsolicited
   messages, or account-lockout tests unless policy explicitly allows a bounded
   test. For email recovery, use only operator-controlled registered accounts,
   label actions that may send mail, and inspect only controlled inboxes. Stop
   on CAPTCHA, lockout, rate limit, ban, challenge, or service degradation.
   For email-routing cases, read
   [`references/recovery-email-payloads.md`](references/recovery-email-payloads.md).
6. Verify from the resulting session or a second authorized account. A response
   difference, missing rate limit, account-enumeration signal, or client-side
   navigation alone is not a bypass finding.
7. Route OAuth/OIDC/JWT details to `oauth`, SAML validation to
   `saml-auth-bypass`, and session identifier rotation to
   `hunt-session-fixation`.

## Handoff

Include the tested state transition, actor/role, exact sanitized evidence,
capability gained, impact, stop conditions, and missing proof. Keep secrets out
of artifacts. Apply Q1-Q3 and the program's policy before confirming.
