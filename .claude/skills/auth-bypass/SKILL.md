---
name: auth-bypass
description: Assess concrete authentication and recovery-flow bypasses outside dedicated OAuth, SAML, JWT, and session-fixation specialists.
---

# Authentication bypass

Use for a concrete login, password-reset, MFA, account-recovery, or identity
binding signal that is not primarily OAuth/OIDC, SAML, JWT validation, or
session fixation. Route those classes to their existing dedicated skills.

Use the `hexbrain` skill for relevant public prior art when it can change the test plan; verify any lead against primary sources and target evidence. The upstream
[`auth-tester`](https://github.com/H-mmer/pentest-agents/blob/main/.claude/agents/auth-tester.md)
as a coverage reference; its brute-force and bypass suggestions do not override
program policy or Mulderx stop conditions.

## Method

1. Map the intended identity state machine: initiation, verification, account
   linking, recovery, MFA enrollment/challenge, password change, logout, and
   session revocation as relevant to the lead.
2. Compare only operator-provided, authorized identity lanes. Record the
   expected principal/role and a baseline for each relevant step.
3. Test one evidenced transition at a time. Focus on a server-side capability
   boundary: wrong account authenticated, protected action reached without
   required verification, recovery changed another account, or revoked session
   remained usable.
4. Avoid password guessing, OTP brute force, push fatigue, unsolicited
   messages, or account lockout tests unless the policy explicitly permits a
   bounded test. Stop on CAPTCHA, lockout, rate limit, or challenge.
5. Verify from the resulting session or a second authorized account. A
   response difference, missing rate limit, account enumeration signal, or
   client-side navigation alone is not a bypass finding.
6. Route OAuth/OIDC/JWT details to `oauth`, SAML validation to
   `saml-auth-bypass`, and session identifier rotation to
   `hunt-session-fixation`.

## Handoff

Include the tested state transition, actor/role, exact sanitized evidence,
capability gained, impact, stop conditions, and missing proof. Keep all secrets
out of artifacts. Apply Q1-Q3 and the program's policy before confirming.
