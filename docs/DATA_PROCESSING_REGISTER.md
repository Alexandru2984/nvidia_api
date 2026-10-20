# AI Chat Hub technical data-processing register

Version: `2026-10-20.1`  
Public notice: `/privacy/`  
Scope: AI Chat Hub in `/home/micu/nvidia`

This is a technical record of processing derived from the application and its
reviewed production configuration. It is not legal advice, a lawful-basis
assessment, a vendor contract, or a completed GDPR Article 30 record. Where the
repository does not contain evidence, the register says so rather than inferring
an answer.

## Processing inventory

| Data/category | Purpose and trigger | Destination/storage | Implemented retention | Technical controls | Unresolved governance evidence |
|---|---|---|---|---|---|
| Username, email, password hash | Registration, authentication, recovery | PostgreSQL on the self-hosted service | Account lifetime; deletion with account | Password validation/hash, anti-enumeration responses, CSRF, quotas, rate limits | Controller identity, lawful basis, age/jurisdiction policy |
| Verification/reset state and codes | Verify address or reset password | PostgreSQL; email delivered through self-hosted mailcow | Codes expire after 30 minutes and scheduled maintenance removes expired rows | Hashed codes, transactional state, bounded attempts, generic responses, STARTTLS | Mail log retention, mail DPA/incident terms |
| 2FA secret and recovery-code hashes | Strong authentication | PostgreSQL; enrollment QR is displayed to the owner | Account lifetime or until disabled/regenerated | Recent password confirmation, encrypted 2FA secret, one-use recovery hashes | User-rights procedure and controller contact |
| Authenticated-session metadata | Session management, owner review, abuse/security response | PostgreSQL and session store | 14-day sliding cookie, absolute maximum 30 days; expired rows cleaned daily | Opaque owner-scoped handles, secure/HTTP-only cookies, revocation, maximum active sessions | Exact journal/off-host security retention |
| Prompts, assistant responses, titles and conversation settings | Provide and preserve chat functionality | PostgreSQL on the self-hosted service | Active chats until owner deletion; archived-chat choice is manual or 30/90/180/365 inactive days | Owner scoping, CSRF, object/byte quotas, export/delete controls, transaction boundaries | Lawful basis; formal rights-response process |
| Uploaded documents/images, extracted text and generated images | Model context, preview, download and generation | Restricted local attachment storage; metadata/text in PostgreSQL | Linked files follow their conversation/account; unattached files default to 30 days | Owner-scoped access, no public media route, ClamAV, isolated document parser, type/size/count limits, content-disposition | Whether accepted content categories need additional policy restrictions |
| Selected prompt, relevant context, included documents/images, image prompt/settings | User-triggered chat or image generation | NVIDIA HTTPS endpoints | Local copy follows chat rules; NVIDIA retention/training is not evidenced | Versioned acknowledgement before egress, explicit attachment inclusion, exact endpoint allowlist, bounded response parsing, quotas/kill-switch | NVIDIA DPA, retention, training use, region, incident terms, production entitlement and real monetary cap |
| Email address and verification/reset content | Account email delivery | Self-hosted mailcow at `mail.micutu.com` | Application rows as above; mail-system retention not evidenced | Dedicated application credential, STARTTLS, bounded sends, generic responses | Mail-system logs, DPA applicability, breach notification terms |
| Network/request/security metadata | Public delivery, origin protection, abuse response | Cloudflare edge/Tunnel; privacy-minimized local security events | Cloudflare retention not evidenced; routine nginx access logging is disabled | Tunnel/origin boundary, CSP, HSTS, bounded proxy behavior, pseudonymous security correlation | Cloudflare DPA/account settings/retention; remove Browser Insights dashboard injection |
| Upload-attempt metadata | Idempotent upload safety and abuse controls | PostgreSQL | 24 hours | Owner binding, UUID tokens, shape and quota validation | No separate decision currently evidenced |
| AI request/token counters | Enforce user/global cost and abuse budgets | PostgreSQL | User-linked rows 90 days; global aggregate rows 400 days | Transactional reservations/reconciliation, per-user/global limits, kill-switch | Map provider contract/cost to a hard monetary budget |
| Generation request/lease metadata | Idempotency, replay, interruption and concurrency safety | PostgreSQL | Terminal job metadata 7 days; expired leases cleaned daily | HMAC-bound request shape, lease fencing, exact stored-result replay, no automatic failed-job retry | Provider-side reconciliation procedure remains operational responsibility |
| Invitation audit | Track invite use and registration abuse | PostgreSQL | 90 days | Hashed invite values, atomic consumption, privacy-minimized audit | Formal access/review policy |
| Privileged admin audit | Accountability for sensitive administration | PostgreSQL with chained integrity evidence | 365 days | Password plus 2FA step-up, keyed integrity, independent alerts, least-privilege DB roles | Cloudflare Access/VPN, minimal-superuser review, external retention |
| Local database backups | Disaster recovery | Root-restricted local compressed PostgreSQL dumps | Newest 7 daily dumps by default | Mode `0600`, directory `0700`, validated isolated restore drills | Encryption at rest, off-host copy, independent credentials, deletion reapplication, recovery objectives |
| Model-availability probe results | Hide broken/retired provider models safely | Signed local state read by the app | Current signed state; freshness fails closed after 8 days | Dedicated identity/credential, Ed25519 signature, schema/freshness validation | Provider credential blast radius and external signing boundary |
| Application/security journals | Availability and incident detection | systemd journal and privacy-minimized monitor state | Exact journal/off-host retention is not documented | No routine nginx access log; Gunicorn excludes IP, user agent, referrer, cookies and query; monitor state contains issue identifiers | Define and verify retention, access, export minimization and alert destination |

GitHub stores source and CI metadata but is not a routine destination for user
chat/account content. Security reports submitted through GitHub are a separate,
reporter-initiated disclosure.

## Data-subject controls implemented

- Account export produces an owner-only JSON stream with account, chat,
  preferences, usage and attachment-manifest data; it excludes file bodies and
  authentication secrets and requires recent strong authentication.
- Individual conversations can be exported from the authenticated interface.
- Conversations and eligible files can be deleted by their owner. Account
  deletion can be immediate or scheduled with a 7-day grace period.
- Owners can choose archived-chat deletion after 30, 90, 180 or 365 inactive
  days, or retain chats until manual deletion.
- Owners can review and revoke sessions, enable 2FA, and regenerate recovery
  codes.
- A user may cancel before the first NVIDIA request and may include or exclude
  compatible attachments from an individual prompt.

Live deletion does not rewrite already-created backups. Deleted records may
remain until the newest-seven-dumps rotation expires. Any restoration procedure
must identify and reapply deletion obligations before restored data is returned
to normal service.

## Required operator and legal decisions

The following items are deliberately not marked complete:

1. Publish the responsible operator/controller identity, jurisdiction and a
   dedicated privacy contact.
2. Record the lawful basis for each processing purpose, applicable rights,
   response workflow, age restrictions and complaint/escalation route.
3. Obtain and record NVIDIA's actual retention/training, processing-region,
   DPA, subprocessor, breach-notification and production-entitlement terms.
4. Review Cloudflare and mail-system contract/DPA, account controls, retention,
   subprocessors and incident terms.
5. Disable Cloudflare Browser Insights injection at the dashboard and verify its
   absence at the public edge; do not weaken CSP to admit it.
6. Define exact journal and external security-event retention, then enforce it
   without exporting raw IP, query, cookie, referrer or user-agent data.
7. Add encrypted off-host backup storage with independent credentials, a
   deletion-reapplication procedure and approved RPO/RTO.
8. Establish a reviewed privacy-incident and data-subject-request process with
   named responsible people and exercise evidence.

## Change and release rule

The public notice version must change when a data category, purpose,
destination/provider, provider payload, retention period, user control, or
operator identity/contact materially changes. A change requires all of the
following in the same release process:

1. update this register and `frontend/src/PrivacyNotice.jsx` together;
2. decide whether the NVIDIA provider-disclosure version must also increase;
3. add or update browser/operational regression coverage;
4. run frontend lint, production build, browser tests and policy checks;
5. deploy an immutable signed release and verify `/privacy/` at origin and edge;
6. exercise rollback and record the exact commit/release evidence in the audit;
7. obtain appropriate legal/vendor review for claims that code alone cannot prove.

The public notice is informational and deliberately does not record a blanket
privacy consent. The separate NVIDIA acknowledgement remains narrowly scoped to
provider-bound content and must be versioned when that flow materially changes.
