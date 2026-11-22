# Password-recovery email routing matrix

Use this reference only when evidence points to parsing, normalization, or
recipient handling in a password-reset email flow. Replace `<A>` and `<B>` with
two registered addresses controlled by the operator. Never use a third-party
address. These are candidate probes, not a requirement to send all of them.

Before sending any candidate, record the program's request limits and confirm
that recovery-email tests are allowed. Establish that ordinary single-address
requests reach each controlled inbox. Every candidate below may cause a reset
email if accepted; run stateful cases sequentially, inspect both inboxes, and
stop on throttling, challenge, delayed delivery, or service degradation. Do not
click reset links or store them in evidence.

| # | Candidate request value | Hypothesis | Expected observable |
|---|---|---|---|
| 1 | `{"email":"<A>"}` | Normal baseline and delivery control. | One recovery email to A. |
| 2 | `{"email":"<B>"}` | Confirm the second controlled account is independently deliverable. | One recovery email to B. |
| 3 | `{"email":"<A>\r\n<B>"}` | Newline-separated recipient parsing. | Whether either or both receive a message. |
| 4 | `{"email":"<A>\r\nCc: <B>"}` | CRLF `Cc` header handling. | Whether B receives a message associated with A's recovery. |
| 5 | `{"email":"<A>\r\nBcc: <B>"}` | CRLF `Bcc` header handling. | Same; B's delivered message may omit a visible Bcc header. |
| 6 | `{"email":"<A>\nCc: <B>"}` | LF-only header parsing where target evidence supports it. | Whether the server normalizes LF into a header boundary. |
| 7 | `{"email":"<A>\rCc: <B>"}` | CR-only header parsing where target evidence supports it. | Whether the server normalizes CR into a header boundary. |
| 8 | `{"email":"<A>, <B>"}` | Comma-separated mailbox-list parsing. | Whether a recipient collection accepts both addresses. |
| 9 | `{"email":"<A>; <B>"}` | Semicolon-list parsing, only if the observed mail stack supports it. | Whether the target accepts this mailbox-list syntax. |
| 10 | `{"email":"<A>","email":"<B>"}` | Duplicate JSON property resolution. | Which value the server binds; this should not be treated as proof of dual delivery. |
| 11 | `{"email":["<A>","<B>"]}` | JSON type-confusion/binding behavior. | Validation or binding result; do not infer mail delivery from status alone. |
| 12 | `{"email":" <A> "}` | Leading/trailing whitespace normalization. | Whether the app trims and sends to the registered address. |

Use the target's observed method, endpoint, anti-forgery mechanism, and
`Content-Type`; do not guess alternate media types unless response evidence
supports a parser discrepancy. Keep raw request and response evidence sanitized.
For a positive routing result, verify delivery in both controlled inboxes and
compare message timestamps, account identity in the body, and sanitized raw
headers. A response such as `200 true` is only acceptance, not delivery. A
delivery to B is a candidate routing issue; it does not alone prove account
takeover. Stop after a bounded positive result or after the supported matrix is
exhausted; do not continue with arbitrary encodings or header-name spraying.
