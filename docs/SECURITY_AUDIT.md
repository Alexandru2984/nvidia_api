# Security audit

> Superseded for current risk decisions by
> [SECURITY_AUDIT_2026-10-07.md](SECURITY_AUDIT_2026-10-07.md). The new
> end-to-end audit changes the production verdict to **RED** after confirming
> shared-host privilege-collapse and browser supply-chain paths that were not
> included in this 2026-10-06 assessment.

Date: 2026-10-06
Scope: Django/DRF backend, React/Vite frontend, PostgreSQL data path, attachment
processing, nginx, systemd, backup automation, Cloudflare Tunnel, and CI.  
Decision: **YELLOW — mitigate then ship**. The repository fixes are deployed and
the request budgets are durable across processes and the request-serving process
has a dedicated Unix identity. The production verdict remains yellow until
security-event alerting is retained externally, staff access is also restricted
at the edge, and encrypted off-site recovery is proven.

This is a technical risk assessment, not legal advice. No secrets are reproduced
in this document.

## Executive summary

The most material pre-audit risks were authenticated-file bypass through a public
`/media/` route, untrusted PDF/DOCX parsing inside the web process, non-atomic
file-backed rate counters, insufficient isolation of the shared service account,
and world-readable database backups. Authentication also had anonymous CSRF and
session-identifier disclosure weaknesses. Dependency scans found known advisories
in both Python and Node development dependencies.

The repository now contains ownership-checked attachment downloads, signature and
archive validation, serialized resource-bounded document parsing in a dedicated
credential-free/network-denied service identity, atomic
rate counters, stronger authentication/recovery transactions, cleaned session
handles, updated dependencies, model payload budgets, sanitized upstream errors,
responsive browser coverage, and hardened nginx/systemd templates. Runtime
application of the templates is tracked separately because a committed template
does not secure a running server. Privileged admin changes are now mirrored into
a privacy-minimized, HMAC-validated 365-day audit trail and monitored for changes,
missing mirrors, and integrity failures. Attachment duplicate detection now uses
secret-keyed, owner-scoped fingerprints, while document previews are owner-scoped,
truncated, no-store responses rendered as inert browser text.

Point-in-time production inventory observed during the audit: 3 active users,
6 conversations, 16 messages, no attachments, no enabled 2FA records, and one
staff/superuser account. These counts are operational context, not permanent
limits.

## Highest risks (STRIDE)

| Priority | Threat | Likelihood | Impact | Blast radius | State |
|---|---|---:|---:|---|---|
| 1 | **Elevation/tampering:** a malicious document exploits the parser or web process | Low/Medium | High | The AI Chat Hub database, runtime files and provider/mail credentials; other projects are outside the service sandbox | Resource-bounded parser plus dedicated non-login identity and systemd sandbox deployed |
| 2 | **Information disclosure:** direct media URLs or permissive backup modes expose private content | Low | High | Attachment owners or the complete database, depending on path reached | Ownership-checked API and nginx denial are deployed; backup/media modes are private and monitored |
| 3 | **Denial of service/cost abuse:** registrations and model generation consume mail, CPU, storage, or NVIDIA quota | Medium | Medium/High | Availability and provider budget for all users | Durable request/token quotas and invite-only signup bound anonymous consumption; monetary enforcement remains open |

STRIDE coverage also identified spoofing risk at the reverse-proxy boundary,
repudiation from limited security audit events, and disclosure through raw
upstream errors. `X-Real-IP` is accepted only from loopback or the permissioned
nginx-to-Gunicorn Unix socket; a missing/malformed address on that socket fails
closed and alerts, while untrusted TCP peers cannot override their source.
Upstream responses are logged server-side while clients receive generic text.

## Findings register

| ID | Severity | Finding | Repository control | Residual action |
|---|---|---|---|---|
| A-01 | Critical | `/media/` could bypass object ownership | Authenticated download endpoint and deployed nginx denial | Keep the external `/media/*` 404 regression probe in every rollout |
| A-02 | High | PDF/DOCX handled in the request process | Deployed sequential Unix-socket parser under dedicated `aichat-parser`; no app secrets/network/capabilities; strict protocol plus child/cgroup time, CPU, memory, file, descriptor and task limits; outage fails closed | Keep limits low; move large asynchronous jobs to a durable queue before raising the 10 MB boundary |
| A-03 | High | Shared service user had broad host reach | Dedicated non-login `aichat` web/timer identity, separate root-owned application/dependency releases, narrowly bound runtime paths, unprivileged app database role and restrictive systemd sandbox | Move file-based secrets to systemd credentials during a controlled rotation |
| A-04 | High | Existing backups were mode `0664` in a `0755` directory | Private modes, `umask 077`, atomic output, locks, gzip verification, and scheduled restore drills are deployed | Add encryption and a tested off-site copy |
| A-05 | High | Anonymous session auth did not uniformly enforce CSRF | Strict session authentication and object-only JSON parser | Keep regression tests in CI |
| A-06 | High | Raw session keys were returned to the browser and long-lived stolen sessions could invoke session controls without fresh proof | HMAC-derived opaque non-bearer handles backed by an indexed owner/session registry; fixed absolute expiry/account caps; five-minute user/session/password-bound recent authentication with required 2FA and responsive step-up before revocation; permanent account deletion removes every indexed parent session row before the owner cascade | Rotate sessions after any suspected historic disclosure; retain recent-auth and expiry regressions |
| A-07 | High | Dependency advisories in runtime/tooling packages | Pinned upgrades, SHA-256-locked production wheels with a release-embedded CycloneDX SBOM, full-commit-SHA CI Actions, plus weekly `pip-audit` and `npm audit` | Review failed scheduled jobs; use an update bot with controlled merges and retain signed provenance evidence |
| A-08 | Medium | File-cache increments were not safe under concurrency | `flock`-serialized cache add/increment with multiprocess test | Replace with Redis/PostgreSQL counters before horizontal scaling |
| A-09 | Medium | Declared MIME/extension or model capability could be misleading | Local fail-closed ClamAV scanning before parsing/dedup/storage, isolated document parsing, file signatures, safe stored names, PNG validation, download headers, and server-side per-model MIME/size/count enforcement | Keep official signatures current; signature scanning cannot establish that novel content is benign |
| A-10 | Medium | Model history, repeated calls or malformed provider responses could multiply payload, memory and cost | Per-message/history caps; model-specific image-count caps and incompatible-history filtering; PostgreSQL daily request and actual-token budgets per-user/globally; pre-call token reservations reconciled from terminal provider usage; exact NVIDIA endpoint validation; no redirects; bounded/shape-validated SSE and image JSON; kill-switch | Map the actual contract/GPU cost into a hard monetary limit and add administrative override audit |
| A-11 | Medium | Registration and recovery can be automated or used for account enumeration | Invite/open/closed modes; 100-bit one-time codes stored only as HMAC; atomic consumption/mail rollback; expiry and 90-day audit retention; IP throttles; uniform duplicate/recovery responses; case-insensitive database uniqueness | Keep production invite-only; add Turnstile only before reopening public signup; assess timing side channels under load |
| A-12 | Medium | Security event detection was incomplete | Structured events and five-minute alerts cover auth/rate/admin-denial bursts, valid admin access, privileged changes and audit-integrity failures, 2FA disable/key failures, invite rejection/consumption and verified signup, completed/bound-breaking account exports, every authorized conversation export, immediate and scheduled/canceled/executed account deletion, invalid proxy/socket client identity, incompatible attachment/model bursts, malware detections, scanner outage/health/signature freshness, parser outage/health/failure correlation, failed/degraded/unauthorized model probes and independent signed-state health, committed attachment-file deletion failures, chat-object quota blocks, generation interruptions/mismatched idempotency reuse, session registry mismatches/cap pressure, global budget, missing/malformed provider usage, token reservation overruns, errors, scheduled-maintenance or restore-drill failure, protected dotenv/vhost/unit/monitor changes, all three active release manifests, executable-release retention, backup and restore freshness | Add external retention and contract-spend correlation; tabletop the alert path |
| A-13 | Medium | TOTP secrets and recovery hashes depended directly on `DJANGO_SECRET_KEY`, and invalid ciphertext could fall through as plaintext | Independent bounded keyring; purpose-separated derivation; versioned TOTP/recovery envelopes; strict base32/digest validation; fail-closed unknown/corrupt artifacts; transactional and lazy secret rewrap; inventory/audit gate; five-minute key-error alert | Move root keys from dotenv to systemd credentials or KMS/HSM; retain an old key until every recovery hash dependency is consumed or regenerated |
| A-14 | Low | No public coordinated disclosure path | `SECURITY.md` and `/.well-known/security.txt` added | Test after every frontend deploy |
| A-15 | High | Django admin's stock login accepted only a password even when application 2FA was enabled | Direct/password-only access is denied; current staff session must verify application 2FA and refresh a five-minute password-plus-2FA window; expired mutations fail closed; access and privacy-minimized add/change/delete events are alerted and HMAC-audited for 365 days with an independent versioned keyring and fail-closed inventory/rotation controls | Add Cloudflare Access/VPN, minimize superusers, move audit roots to systemd credentials or KMS/HSM, and retain security events externally |
| A-16 | High | Production entitlement for the NVIDIA-hosted API is not evidenced; NVIDIA describes Developer Program endpoints as prototyping access | Durable request/token ceilings, fail-closed metering and global kill-switch bound technical consumption | Confirm and record an appropriate production license/contract, or restrict the deployment to private evaluation use; implement its real monetary/GPU budget |
| A-17 | Medium | Content hashes or extracted-text previews could correlate files across users, disclose private text, or race under parallel uploads | HMAC-SHA256 fingerprints are secret-keyed and owner-scoped, never serialized/logged, and unique only for unlinked files per owner; preview lookup is owner-scoped, truncated to 4,000 characters, rate-limited and `private, no-store`; the browser renders it as text; a user-row lock plus a partial PostgreSQL unique constraint closes concurrent duplicate creation | Treat fingerprint-key rotation as a deduplication reset; retain malware/ownership/cache/XSS regressions |
| A-18 | Medium | A missing/stale/tampered runtime model-status file could reactivate retired endpoints, while transient NVIDIA failures could hide working models for a week or leave permanently broken models trusted forever, leak provider failure details, or present volatile latency as model quality | A dedicated credential-minimal identity writes exact-owner/mode `0640` state signed with Ed25519; the web identity has only read/public-key access. Signature, file shape, schema/catalog/range/time and eight-day freshness fail closed and alert independently every five minutes. Deployment validates the complete boundary before switching. Definitive failures change availability; transient outcomes preserve a trusted decision twice, hide on the third and recover on success. The API exposes only aggregate state and rounded successful samples labeled as synthetic | A compromised probe/signing key can forge availability and consume the shared provider credential; rotate both after compromise, move the signing root to a hardware/external trust boundary before multi-host scaling, and never treat one sample as an SLA or quality score |
| A-19 | High | Production workers imported application code and dependencies from mutable checkout paths, allowing old/new mixtures or local tampering | Deploys use separate root-owned, manifest-verified application and SHA-256-locked minimal dependency releases with an embedded CycloneDX SBOM, atomically switch trusted symlinks, hide checkout source/venv from the service, restore prior targets on failed probes, bound executable roots to the active plus two rollbacks, and have passed a controlled production rollback/restore drill for both release families | Add signed builder provenance and define the supplemental-archive lifecycle plus off-host evidence retention |
| A-20 | Medium | Users could send prompts, history and selected files to NVIDIA without a durable, current disclosure acknowledgement | A versioned, owner-bound timestamp is stored without prompt/file/IP data; chat, regeneration and image generation return `428` before leases, budget reservations, message writes or provider egress until the current disclosure is accepted. The keyboard-accessible mobile UI names each data class, links official NVIDIA privacy/terms pages and offers an equal cancel path. Public `/privacy/` plus a technical processing register now consolidate verified data categories, destinations, retention, backup lag and controls while explicitly naming unsupported governance claims | Publish the operator/controller identity and privacy contact; obtain legal review of basis/rights and NVIDIA/Cloudflare/mail retention, training, DPA, region, incident and entitlement terms; disable edge Browser Insights; bump the applicable notice/disclosure version when its flow materially changes |
| A-21 | Medium | Retried or concurrent chat generation could duplicate provider cost or mutate history ambiguously | Owner-scoped UUID idempotency, HMAC-bound request shape, durable job outcomes, lease/job fencing, stored-result SSE replay, attachment/message reconciliation, bounded retention and interruption/conflict alerts are deployed | NVIDIA cannot join the local database transaction; keep automatic retries disabled for failed/interrupted jobs and reconcile provider evidence before an explicit new-key attempt |
| A-22 | Medium | Authenticated accounts could grow saved message text until database/egress pressure affected every tenant | PostgreSQL-generated UTF-8 byte counts; transactionally serialized 16 MiB/conversation, 64 MiB/user and 1 GiB/service ceilings; worst-case in-flight reservations; net-growth regeneration; owner-only usage UI; generic global response; monitored quota events; read-only message admin; owner-configurable bounded deletion of inactive archived chats after 30/90/180/365 days; 90-day user-linked and 400-day aggregate-only AI-usage retention | Publish the operator-wide legal/default schedule before materially raising account or quota volume |
| A-23 | Medium | React inline styles required a broad CSP style exception, leaving a weaker defense against injected markup | All application styles use static classes; ESLint forbids JSX `style` and `dangerouslySetInnerHTML`; deployed CSP is `style-src 'self'`; origin browser smoke reports zero inline styles/violations at 320 and 1440 px | Disable Cloudflare Browser Insights injection at the edge; keep its currently blocked scripts out of `script-src` and retain real-browser CSP regression probes |
| A-24 | Medium | Passwords used a CPU-only PBKDF2 default, while Django's automatic lazy upgrade could rewrite a valid legacy credential before required 2FA and invalidate active sessions | Memory-hard scrypt is preferred; legacy PBKDF2 remains verifiable; a dedicated Django backend defers upgrades until password plus required 2FA succeeds under an owner-row lock while preserving failed-login signals; failed/incomplete authentication is read-only; invalidated indexed sessions are removed explicitly | A database copy still enables offline guessing; retain strong-password policy and breach response, monitor authentication capacity, and benchmark parameters before materially increasing traffic or worker concurrency |
| A-25 | Low/Medium | Routine nginx/Gunicorn access logs duplicated raw IP, User-Agent, Referer and query data, increasing privacy and incident scope | This vhost opts out of the shared combined log; Gunicorn keeps only time, method, path without query, protocol, status, bytes and latency; CI rejects sensitive access-log atoms | Preserve the minimized field set in any external sink; static/edge traffic has no local per-request record, so document the intended external evidence and retention boundary |

## Quantitative risk view

There is no measured incident-loss history, so the following is an explicit
planning estimate rather than an accounting forecast. Assume a 20% annual chance
of a material abuse or disclosure event before P0 controls, with a single-loss
expectancy of EUR 12,500 (response time, credential rotation, service disruption,
provider charges, and professional review). The illustrative annualized loss
expectancy is therefore `0.20 × EUR 12,500 = EUR 2,500/year`. Recalculate with
actual provider spend, labor rates, contractual exposure, and user count before
using it for a budget decision.

## Detection, response, and recovery

The one-minute availability probe gives an outage MTTD near one minute when the
alert path works. The security timer targets MTTD under six minutes for repeated
login failures, unexpected admin access, rate-limit spikes, backup/restore
failures, 2FA disable, backend error bursts, missing provider usage, token
reservation overruns, privileged admin changes or audit-integrity failures, and
global NVIDIA budget exhaustion. Five incompatible attachment/model rejections in
six minutes, any invalid runtime model-status file and any degraded scheduled
model probe use the same alert path. Any malware detection or scanner outage,
proactive scanner health failure, or ClamAV daily-signature age over 30 hours also
alerts without forwarding content or filenames. Parser socket failure, any
fail-closed parser request and privacy-minimized worker failures also alert; no
document bytes, extracted text, filename or owner metadata enters those events.
External log retention and contractual/GPU-spend signals remain open. Target
containment time is 60 minutes after a confirmed high-severity alert.

The response procedure is in [INCIDENT_RESPONSE.md](INCIDENT_RESPONSE.md). It must
be exercised with a tabletop and a database restore test; an untested runbook is
not evidence of recoverability. Under GDPR Article 33, a qualifying personal-data
breach generally must be notified to the supervisory authority without undue
delay and, where feasible, within 72 hours after awareness. Preserve the awareness
timestamp and obtain appropriate legal/privacy review.

## Vendors and data flows

- NVIDIA receives prompts, selected conversation context, and user-selected
  images/documents included in model calls. Confirm retention/training terms,
  regional processing, DPA availability, incident notification obligations, and
  production entitlement. NVIDIA's published FAQ describes Developer Program
  hosted endpoints as prototyping access and production NIM use as requiring an
  NVIDIA AI Enterprise license; no such entitlement is evidenced in-repository.
  The app now requires a minimal versioned disclosure acknowledgement before the
  first provider request, but this does not replace the missing legal/vendor evidence.
- Cloudflare carries public traffic through Tunnel and may process network and
  request metadata. Review account security, access logs, DPA, and breach terms.
- The self-hosted mail system handles addresses and OTP/reset messages. Restrict
  logs, monitor delivery abuse, and ensure credentials are unique to this app.
- GitHub hosts source and CI metadata. Keep production secrets out of repository
  variables unless required and use least-privilege workflow permissions.

No vendor review was evidenced in-repository during this audit; owner confirmation
is required before describing those controls as complete.

## Verification evidence

- 340 backend tests pass, including ownership, CSRF, concurrency, recovery,
  anti-enumeration, transactional mail-failure, provider token reconciliation,
  fail-closed usage validation, atomic invite consumption, privacy-safe admin
  auditing and tamper detection, SSE byte parsing, retired-model handling,
  payload, per-model attachment capabilities, and generated-image boundary tests.
- Frontend lint/build, twenty-five responsive Playwright checks (320–1440 px), and
  Python/Node dependency audits passed during remediation.
- Django deploy checks, nginx syntax, systemd isolation, backup restoration, and
  external route/header probes must be repeated during each production rollout.

### Production rollout — 2026-10-05

- Deployed repository state through `7061771`; database migrations reported no
  pending operations and the production dependency environment passed `pip check`.
- `pip-audit` and `npm audit --audit-level=low` reported no known vulnerabilities.
- Applied the nginx template after a successful syntax test. Public and origin
  probes returned 200 for health and `security.txt`, 404 for arbitrary `/media/`
  paths, 403 for `.env`/`.git` paths, and 403 for an unauthenticated private-file
  download.
- Applied the systemd sandbox after a successful transient-unit preflight. The
  service remained active with three workers and zero automatic restarts; its
  `systemd-analyze security` exposure score improved from 9.2 `UNSAFE` to 2.9
  `OK`.
- Migrated the web master/workers and application maintenance jobs from the
  shared `micu` account to the non-login `aichat` identity. Live mount-namespace
  probes confirmed that other projects under `/home/micu` are absent while the
  app's read-only source and private writable runtime paths remain available.
  The existing `nvidia_user` database role is not a superuser and cannot create
  databases or roles. The mail/provider environment is group-readable by
  `aichat` but not writable by it.
- Replaced the shared-user cleanup/model-probe cron entries with sandboxed
  systemd timers. The security monitor alone receives supplementary
  `systemd-journal` access, and its post-separation execution completed
  successfully so five-minute detection remains operational.
- Corrected the backup directory and media directory to mode `0700`, and existing
  database dumps/runtime logs to `0600`.
- A live anonymous CSRF probe was rejected with 403. A same-origin browser-shaped
  request with the CSRF cookie/header passed CSRF and reached payload validation.
- Timestamped rollback copies of the prior nginx vhost, systemd unit, and frontend
  webroot were retained on the host. No rollback was required.
- The newest compressed backup was restored into an isolated scratch database;
  schema/migration checks and row-count queries passed (28 migrations, 3 users,
  6 conversations, 16 messages), and the scratch database was removed. A weekly
  logged drill is now scheduled and its freshness/success marker is monitored.
- Before the token-budget rollout, retained database dump
  `nvidia_db_20261005_215934_407285381.sql.gz` and private frontend snapshot
  `aichat.micutu.com_20261005_215934`. Migration `0012_ai_token_budgets` then
  applied successfully under the dedicated `aichat` identity.
- Effective production ceilings are 500,000 tokens per user/day, 2,500,000
  globally/day, with a 32,768-token fail-closed reservation per streamed call.
  A synthetic provider probe confirmed terminal prompt/completion/total usage;
  no user content was used or logged.
- The updated frontend and security monitor were deployed. Public HTML, current
  JS/CSS, health, and `security.txt` returned 200; `/media/` returned 404 and
  `/.env` returned 403. The backend remained active with zero restarts and no
  warning-or-higher journal events after rollout; the monitor completed
  successfully and retained its five-minute schedule.
- Live availability data marked 33 catalog entries unavailable, including the
  former default, and identified two existing conversations using unavailable
  models. New chats now select an available fallback, while affected existing
  chats require an explicit available-model choice before any budget is consumed.
- Deployed the retired-model recovery UI after ten responsive Playwright checks.
  Prior frontend snapshot `aichat.micutu.com_20261005_220524` is private; the
  current public JS/CSS (`index-D9ELShym.js`, `index-Bwtt96bY.css`) and HTML all
  returned 200 while the backend remained active with zero restarts.
- Before enabling invite-only registration, retained database dump
  `nvidia_db_20261005_221712_905527868.sql.gz`, frontend snapshot
  `aichat.micutu.com_20261005_221712`, and a private copy of the prior systemd
  drop-in. Migration `0013_registration_invite` applied successfully.
- Production now receives `REGISTRATION_MODE=invite` through its root-owned
  systemd drop-in. One 72-hour invitation was generated into an owner-only
  `0600` handoff file; the database contains only its HMAC and metadata.
- A public synthetic invalid-invite request returned 403, created no account,
  and did not consume the real invitation. `/auth/me/` advertised invite mode;
  the new HTML/JS/CSS, health, and `security.txt` returned 200, while `/media/`
  remained 404 and `/.env` 403. The backend retained zero restarts and no
  warning-or-higher events, and the updated monitor completed successfully.

### Privileged-audit rollout — 2026-10-06

- Deployed repository state `db50d51` after retaining database dump
  `nvidia_db_20261006_025817_106974728.sql.gz`; migration
  `0014_admin_audit_event` applied successfully under the dedicated `aichat`
  identity. There were no historical Django admin rows requiring sanitization.
- Every registered admin model now uses the privacy-audit mixin, including users
  and groups. Object representations and change messages are stripped to model,
  pseudonymous/numeric object reference, action, actor ID, and field names before
  persistence; bulk deletions are logged individually. No changed values, titles,
  emails, filenames, prompts, or message content are stored or alerted.
- Daily maintenance reported zero invalid HMACs and zero missing mirrors. The
  monitor now reads both backend and maintenance journals and alerts on every
  privileged change or integrity failure; its post-install execution succeeded.
- The backend remained active with zero automatic restarts, the systemd exposure
  score remained 2.9 `OK`, and no warning-or-higher journal events appeared.
  Public probes returned 200 for health/security.txt, 403 for anonymous admin and
  `.env`, and 404 for arbitrary `/media/` paths.
- The trail is tamper-evident rather than independently immutable. Deleting both
  local copies could evade the database consistency check, so external log
  retention remains required. This paragraph records the original rollout state;
  the later versioned audit-key rollout removed the retained-row dependency on
  `DJANGO_SECRET_KEY`.

### Model-capability rollout — 2026-10-06

- Deployed repository states `87e03b3` and `b7d419a` after retaining database dump
  `nvidia_db_20261006_031801_600666837.sql.gz`, frontend snapshot
  `aichat.micutu.com_20261006_031806_155909071`, and a private copy of the prior
  runtime model status. There were no schema changes or pending migrations.
- The catalog now treats capabilities as a server-enforced security contract:
  purpose/recommendation metadata, document-as-text behavior, image MIME allowlist,
  image-count ceiling, and provider-specific byte ceiling. Upload and send paths
  reject incompatible combinations before persistence or provider dispatch;
  history keeps document text but strips images unsupported by the current model.
- The responsive attachment picker shows only applicable image/document actions,
  limits, context and model purpose. Model changes surface incompatible pending
  files and allow their removal instead of silently sending or discarding them.
- A fresh production probe found 4/39 endpoints responding: Meta Llama 3.2 11B
  Vision, Meta Llama 3.2 90B Vision, NVIDIA Nemotron 3 Super 120B, and OpenAI
  GPT-OSS 20B. The other 35 are hidden fail-closed after 410, 500, or repeated
  timeout results; the recommended default is Llama 3.2 11B Vision.
- Public health, HTML, hashed JS/CSS and `security.txt` returned 200. Anonymous
  `/api/models/`, `/admin/`, `.env`, and `.git` probes returned 403; arbitrary
  `/media/` returned 404. The monitor completed successfully, backend logs had no
  warning-or-higher entries, automatic restarts remained zero, and systemd
  exposure remained 2.9 `OK`.
- Residual risks are unchanged in class: untrusted parsers still need stronger
  isolation/malware scanning before public uploads, provider capability metadata
  can drift between catalog updates, and model probing cannot distinguish a
  sustained transient outage from retirement. Runtime probing therefore hides
  failures rather than widening accepted inputs.

### Model-explorer rollout — 2026-10-06

- Deployed frontend state `d4c0f63` after retaining private webroot snapshot
  `aichat.micutu.com_20261006_163705_455483222`; no backend, schema, provider, or
  server-side user-data change was required.
- Search, purpose filters, favorites, recent models, three-way comparison, and the
  live availability timestamp are keyboard-accessible and responsive from 320 to
  1440 px. The native model selector remains available for a minimal fallback.
- Browser persistence is versioned, size-bounded, schema-sanitized, and restricted
  to public model IDs (24 favorites and 6 recent entries). Corrupt or oversized
  preferences fail empty, and no account identifier, prompt, title, attachment,
  or message content is stored. The server remains authoritative for availability
  and rejects stale/tampered model choices.
- Public HTML, the new hashed JS/CSS, health, and `security.txt` returned 200;
  `/media/` remained 404 and anonymous admin/model/configuration probes remained
  403. CSP and security headers were unchanged, the backend retained zero
  automatic restarts, and no warning-or-higher journal entries appeared.

### Resilient-upload rollout — 2026-10-06

- Deployed frontend state `c721a6f` after retaining private webroot snapshot
  `aichat.micutu.com_20261006_164607_199242552`; the backend schema and services
  were unchanged.
- Picker, drag/drop, and clipboard file paths now converge on the same bounded,
  model-aware queue. XMLHttpRequest is used only to expose per-file progress and
  cancellation while retaining same-origin credentials and CSRF protection;
  server-side signature, ownership, storage, count, byte, and capability checks
  remain authoritative.
- Failed uploads can be retried without reselecting the local file, and canceled
  or failed jobs reserve their client-side file/byte slots until dismissed. A
  session logout or authentication failure aborts active upload/generation work,
  clears retained `File` objects, pending attachment previews, drafts, and private
  image-gallery state, preventing browser-memory state from crossing accounts.
- A late cancel can race with a server commit. Such a file remains owner-scoped,
  unlinked, visible through the private attachment library, manually deletable,
  and eligible for the daily 30-day orphan cleanup; instant deletion is not
  claimed. A future upload-attempt identifier could close this residual window.
- Public HTML, the new hashed JS/CSS, health, and `security.txt` returned 200;
  `/media/` remained 404 and anonymous admin/model/configuration probes remained
  403. The backend remained active with zero automatic restarts and no
  warning-or-higher journal entries.

### Attachment-control rollout — 2026-10-06

- Deployed repository states `e15df8d` and `11966a9` after retaining database dump
  `nvidia_db_20261006_170649_134260332.sql.gz` and private frontend snapshot
  `aichat.micutu.com_20261006_170701_161075609`. Migration
  `0015_attachment_content_sha256` applied successfully under the dedicated
  `aichat` identity; PostgreSQL introspection confirmed the owner/fingerprint
  partial unique constraint. Production contained no attachment rows requiring a
  legacy-fingerprint transition.
- Identical unlinked uploads are reused only within the authenticated owner. The
  stored value is HMAC-SHA256 over a versioned owner domain and file bytes, keyed
  by the server secret, so identical content cannot be correlated across account
  rows and known files cannot be confirmed from a leaked fingerprint list. It is
  excluded from every serializer and log path.
- Document preview fetches only the owner's extracted text, caps the response at
  4,000 characters, rate-limits requests, and sends `private, no-store`. React
  inserts the response into a `pre` text node; an executable-tag regression test
  confirms it remains inert. The responsive modal traps focus, closes with Escape,
  and restores focus to its trigger.
- Pending files can be excluded and re-included without deletion. Excluded files
  do not trigger model-capability blocks and their IDs are omitted from provider
  requests; logout/session loss clears this state. Duplicate responses reuse one
  tile and explain that the private copy was reused.
- All 297 backend tests and 25 browser tests passed, along with lint, build,
  migration-drift, Django system, and import checks. Public HTML and the new
  `index-CfhHbnZW.js`/`index-oeSxBa46.css` assets returned 200; `/media/` returned
  404 and anonymous preview/model/admin/configuration probes returned 403. The
  backend and security monitor remained healthy with zero automatic restarts.
- The first public health request issued immediately after the deliberate backend
  restart landed inside its startup window and returned 502; the retry returned
  200 and remained stable. Deploy automation should poll local backend readiness
  before considering a restart complete. Django's deploy check otherwise reported
  only the deliberate `SECURE_HSTS_PRELOAD=False` warning; one-year HSTS with
  subdomains is active, while preload enrollment remains a separate domain-wide
  owner decision.

### Guided-model rollout — 2026-10-06

- Deployed repository state `fbef342` after retaining private frontend snapshot
  `aichat.micutu.com_20261006_223738_022319541` and checksum-identical copies of
  the prior runtime model status and installed security monitor under
  `model_guidance_20261006_223738_022319541`. No database migration or user-data
  rewrite was required.
- The runtime status reader now bounds file size, validates timestamps, catalog
  IDs, outcomes, integer latency and retry counts, caches by path plus nanosecond
  mtime, and atomically writes mode `0600`. A missing file remains a bootstrap
  state; an existing unreadable, malformed, or oversized file fails closed by
  hiding every model and emits `model_status_invalid`, which the five-minute
  privacy-minimized monitor alerts on during its next run.
- The authenticated API exposes no provider failure outcome. It returns only a
  successful 1-token probe sample rounded to 100 ms with a coarse band. The UI
  states that this is not a quality benchmark, adds capability-derived “best for”
  guidance, and supports recommendation, last-probe, context, and name sorting in
  the responsive explorer and comparison view.
- The fresh sandboxed production probe completed successfully in 92 seconds and
  found 5/39 available endpoints: Meta Llama 3.2 11B Vision (0.2 s rounded), Meta
  Llama 3.2 90B Vision (5.4 s), NVIDIA Llama 3.1 Nemotron Safety Guard 8B V3
  (17.0 s), NVIDIA Nemotron 3 Super 120B (0.4 s), and OpenAI GPT-OSS 20B (1.2 s).
  These are point-in-time availability samples, not performance guarantees.
- All 301 backend tests, six monitor tests, 25 responsive browser tests, lint,
  build, migration-drift, and Django checks passed. Public health, HTML,
  `security.txt`, and `index-6ov-4KtR.js`/`index-CzoCFMoC.css` returned 200;
  `/media/` returned 404 and anonymous model/admin/configuration probes returned
  403. Backend and security monitor remained healthy with zero automatic restarts.

### Conversation-organization rollout — 2026-10-06

- Deployed repository states `545005e`, `c4130a3`, and `8dc3aaa` after retaining
  validated database dump `nvidia_db_20261006_225408_099541025.sql.gz` and private
  frontend snapshot `aichat.micutu.com_20261006_225413_398232334`. Migration
  `0016_conversation_archived_at_conversation_is_pinned_and_more` applied under
  the dedicated `aichat` identity and created the owner/view/order index.
- Pin, archive, restore, filter, search, count, detail, and mutation paths remain
  scoped to the authenticated owner. Archive is reversible and clears pin state;
  archived rows cannot be pinned until restored. JSON booleans are validated
  strictly, destructive deletion remains separately confirmed, and archive never
  claims to be retention or secure erasure.
- The new counted response is opt-in through `include_counts=1`; the default list
  response remains compatible with already-loaded clients during a rolling
  deploy. Counts are computed from the complete owner-scoped set rather than the
  current search result, making moves between Active and Archived explicit.
- The 320 px UI uses two labeled folders and a single contextual action trigger
  per row. Expanded actions use full labels and large touch targets, status text
  explains each move, empty states name the selected folder, Escape closes the
  action panel and restores focus, and permanent deletion explicitly states that
  it cannot be undone.
- All 315 backend tests and 26 responsive browser tests passed, along with lint,
  production build, migration-drift, and the targeted legacy-contract test. A
  read-only live check across two accounts confirmed exact owner results/counts
  and returned 404 for a cross-owner detail lookup.
- Public health, HTML, `security.txt`, and the new
  `index-CFbkpR-l.js`/`index-DiXTS-q9.css` assets returned 200; `/media/` remained
  404 and anonymous model/conversation/configuration probes remained 403. CSP,
  one-year HSTS with subdomains, Permissions Policy, referrer policy, and MIME
  sniffing protection remain present. Backend and security monitor completed
  healthy with zero automatic restarts.

### Conversation-pagination rollout — 2026-10-06

- Deployed repository states `0182007`, `012f9f0`, and `167e038` after retaining
  validated database dump `nvidia_db_20261006_230809_724835472.sql.gz` and private
  frontend snapshot `aichat.micutu.com_20261006_230817_783214284`. Migration
  `0017_conversation_search_indexes` applied successfully.
- Cursors are opaque Django signatures with a 24-hour timestamp and are bound to
  user ID, Active/Archived view, and a SHA-256-derived search identifier. Their
  timestamp, pin flag, and row ID are type-checked; invalid, expired, oversized,
  cross-owner, cross-view, or cross-search cursors receive the same generic 400.
- New clients request 30 rows and may choose only 1–50. Search is capped at 200
  characters and list GETs at 120/user/minute. The compatibility list remains
  available for already-loaded clients but is capped at 100 rows, removing the
  prior unbounded response and serializer N+1 query pattern.
- PostgreSQL `pg_trgm` 1.6 was installed once by the DBA. The unprivileged
  `nvidia_user` role was not granted database `CREATE`. Migration indexes on
  conversation titles and message content were built concurrently; live
  `EXPLAIN` checks confirmed both GIN indexes are usable by their `ILIKE` paths.
- The mobile sidebar deduplicates appended pages, discards late responses after a
  folder/search change, resets stale cursors, limits search input, and exposes a
  labeled loading action. A 35-row 320 px browser scenario completed without
  document overflow.
- All 319 backend tests and 27 responsive browser tests passed, along with lint,
  production build, migration-drift, Django system checks, and cursor isolation
  tests. A read-only live probe returned disjoint pages and rejected reuse of one
  account's cursor by another account with 400.
- Public health, HTML, `security.txt`, and the new
  `index-N-hIImMG.js`/`index-C7ogxLB2.css` assets returned 200; `/media/` remained
  404 and anonymous conversation/configuration probes remained 403. Backend and
  security monitor remained healthy with zero automatic restarts.
- Cursor pagination is a moving view, not a snapshot transaction. Concurrent
  updates can move rows between page boundaries; the client deduplicates repeated
  IDs and a filter/search refresh obtains a new first page. No data is deleted or
  made inaccessible by cursor expiry.

### Private-history pagination rollout — 2026-10-07

- Deployed repository states `f844926` and `9aa9976` after retaining validated
  database dump `nvidia_db_20261007_033430_984814350.sql.gz` and private frontend
  snapshot `aichat.micutu.com_20261007_033434_051328188`. Migration
  `0018_history_pagination_indexes` applied successfully.
- New conversation detail requests return the latest 50 messages in chronological
  order. Earlier pages use a 24-hour signed cursor bound to both user and
  conversation; type-invalid, oversized, expired, tampered, cross-account, and
  cross-conversation cursors receive the same generic 400. The legacy detail
  shape remains available but is bounded to the latest 200 messages.
- Attachment-library and generated-image requests return 30 rows and accept at
  most 50. Their signed cursor is bound to user and attachment type. Invalid
  kinds are rejected, legacy lists are capped at 100, and every download remains
  behind the existing owner-scoped endpoint rather than public `/media/`.
- The message, unfiltered attachment, and kind-filtered attachment indexes use
  stable descending timestamp/ID ordering. Migration creation and removal are
  PostgreSQL-concurrent to avoid holding normal writes behind an index build;
  live `EXPLAIN` checks confirmed the message and attachment indexes are usable.
- Chat prepends older messages without losing the reader's scroll position and
  deduplicates IDs. Storage & files and generated-image history append pages with
  ID deduplication. Labeled loading controls remain usable at 390 px, and logout
  clears page cursors and loading state along with other private browser state.
- All 327 backend tests and 29 responsive browser tests passed, along with lint,
  production build, migration-drift, and Django system checks. A read-only live
  probe returned disjoint message pages and rejected cross-owner cursor reuse
  with 400; the production attachment library was empty, while owner/type cursor
  isolation is covered by backend tests.
- Public health, HTML, `security.txt`, and the new `index-uI41V_kv.js`,
  `index-PA0NMRBJ.css`, and `Settings-DYxq0WAU.js` assets returned 200. `/media/`
  remained 404 and anonymous attachment/message/configuration probes remained
  403. Backend and security monitor remained healthy with zero automatic
  restarts.
- Message and attachment cursors are moving views rather than snapshot
  transactions. Concurrent writes can shift page boundaries; clients deduplicate
  repeated IDs, and re-opening a conversation or settings obtains a fresh first
  page. Cursor expiry never deletes data or prevents a new traversal.

### Cancellable-upload rollout — 2026-10-12

- Deployed repository state `e571c7f` after retaining pre-migration database
  dump `nvidia_db_20261012_192614_328639300.sql.gz`. Migration
  `0019_attachment_upload_attempt` applied under the dedicated `aichat` identity;
  the backend restarted with three workers and zero automatic restarts.
- Every browser upload now carries a cryptographically random UUID. A durable,
  owner-bound attempt row serializes completion and cancellation across Gunicorn
  workers: cancellation before commit blocks the late write, while cancellation
  after commit removes the new unlinked attachment. Replays return the same row
  rather than consuming storage twice.
- An attempt records whether it created its attachment. When content
  deduplication reuses an older owner-scoped file, canceling the newer attempt
  cannot delete that existing file. Cross-owner UUID reuse receives a generic
  denial, and linked message attachments remain protected from cancellation.
- Retry creates a fresh attempt; explicit cancel, dismiss, logout and component
  teardown request server cleanup with keepalive semantics. The browser reports
  when server cleanup cannot be confirmed instead of claiming success. Stale
  coordination rows expire through daily maintenance after 24 hours; normal
  orphan-file retention remains unchanged.
- All 340 backend tests and 31 responsive Playwright tests passed, along with
  migration-drift, Django, compile, lint, production-build and npm-audit gates.
  The production deploy check reported only the deliberate HSTS-preload warning.
- Frontend release
  `/var/www/aichat-releases/release-20261012T162631_053280375` activated
  atomically with the 2026-10-07 release retained as rollback. Public health and
  `security.txt` returned 200, `/media/` returned 404, and anonymous conversation
  and upload-cancellation requests returned 403. CSP, HSTS, MIME, frame,
  referrer and permissions headers were each present once.
- Post-migration dump `nvidia_db_20261012_192642_189457187.sql.gz` restored into
  an isolated scratch database with `37` migrations, `3` users, `6`
  conversations and `16` messages; cleanup removed the scratch database. The
  maintenance, model-probe and security-monitor timers are active, the monitor
  completed successfully, and the backend journal contained no rollout warning.

### Resilient model-status rollout — 2026-10-13

- Deployed repository state `20badbf` without a database migration or user-data
  write. Production now requires a timezone-aware model-status file no older than
  eight days; missing, corrupt, stale or implausibly future-dated state hides all
  chat models until a trusted probe succeeds.
- Probe reconciliation distinguishes definitive retirement/contract rejection
  from timeout, throttling, network and provider failures. A transient result
  preserves an existing verified decision, but cannot activate a new or
  previously unavailable model. Aggregate `verified/degraded` state and an
  inconclusive count reach the authenticated UI; provider failure details remain
  server-side.
- The security monitor now reads the sandboxed model-probe journal and alerts a
  degraded run. Its installed root-owned copy matches the repository and the
  manual post-deploy execution completed successfully; model-probe and monitor
  timers remain active.
- All 345 backend tests, 32 responsive Playwright tests and 10 monitor tests
  passed, along with lint, production build, compile, migration-drift, Django,
  `pip check` and npm-audit gates. The production deploy check reported only the
  deliberate HSTS-preload warning.
- Frontend release
  `/var/www/aichat-releases/release-20261012T224959_108218921` activated
  atomically with the preceding release retained for rollback. The first switch
  encountered a backend-startup `502`, rolled back automatically, and its staged
  release was moved intact to the private operations backup directory.
- The authenticated read-only production contract reported three available
  models, five inconclusive historical probe results, a degraded state and an
  available fallback default. Public health returned 200, `/media/` returned 404,
  anonymous model access returned 403, nginx validation passed, the backend had
  zero automatic restarts and no warning-level entries after restart.

### Hosted-model catalog rollout — 2026-10-13

- Deployed repository states `eb4dbbc`, `4849a91`, and `8b0f17c` without a
  database migration or user-data write. A root-owned `0600` copy of the prior
  runtime status is retained at
  `/home/micu/backups/nvidia_ops/model_status.pre-4849a91.json`.
- Catalog refresh reduced 39 mostly retired entries to 20 currently documented
  NVIDIA-hosted chat endpoints. The production probe completed successfully in
  93 seconds and exposes 12 live models, with Nemotron 3.5 Lightning 30B A3B as
  the available default. Eight remain hidden: one current `404` retirement and
  seven inconclusive timeouts.
- Five exposed models accept images. Before rollout, six then-live multimodal
  endpoints accepted a synthetic 186,695-byte inline PNG with `200`; Muse Glimmer
  subsequently changed from `200` to `404` and is correctly hidden. Capability
  metadata stays conservative at one JPEG/PNG unless an official hosted contract
  documents more; GLM 5.3 Flash alone declares up to eight JPEG/PNG/WebP images.
- A catalog ID absent from the private probe file is now automatically hidden and
  counted as awaiting verification. This closes the deployment window where new
  code could previously expose an unprobed endpoint before the scheduled status
  refresh.
- Probe classification now treats only `404/410` as retired and `400/422` as
  app-contract rejection. Authentication, entitlement, throttling, timeout,
  network, ambiguous 4xx and 5xx failures preserve trusted prior decisions;
  authorization/entitlement failures emit a separate privacy-minimized alert.
- All 358 backend tests, 32 responsive Playwright tests and 10 monitor tests
  passed, with lint, production build, compile, migration-drift, Django,
  `pip check` and npm audit also clean. The deploy check retained only the
  deliberate HSTS-preload warning.
- Root-owned frontend release
  `/var/www/aichat-releases/release-20261012T230158_666603612` is active with the
  previous release retained for rollback. Public health returned 200, `/media/`
  returned 404, anonymous model access returned 403, nginx validation passed,
  all application timers are active, both probe and monitor completed with exit
  status zero, and the backend has zero automatic restarts or post-boot warnings.

### Streaming and generation-contract rollout — 2026-10-13

- Deployed repository states `7e3d276`, `dfc30b9`, and `c390e8f`. Migration
  `0020` first normalizes legacy generation values, then enforces temperature
  `0..1`, global output-token `64..8192`, and Riva Translate v2's documented
  `4096` ceiling with PostgreSQL constraints. All six production conversations
  satisfied the new constraints without normalization loss.
- The availability probe and live chat now build one shared NVIDIA request:
  streaming enabled, terminal usage requested, temperature present, and SSE
  accepted. Availability requires a valid event, usage object, and `[DONE]`;
  200 responses with the wrong content type, error events, malformed/truncated
  streams, and missing metering are inconclusive rather than healthy.
- Live chat rejects non-SSE 200 responses, privacy-sanitizes provider error
  events, and rejects streams that end without `[DONE]`. Missing usage remains
  cost-fail-closed through the existing durable token reservation. Regeneration
  now also rejects historical model IDs removed from the catalog before a
  provider reservation or call.
- The authenticated model contract publishes per-model temperature and output
  bounds. Conversation creation uses model defaults; switching or request-time
  override clamps older saved settings atomically. The responsive UI derives its
  controls and output-limit badge from the same contract. A live edge probe
  confirmed the common `8192` ceiling on 11 models and isolated Riva's official
  `4096` limit and `0/512` defaults.
- Pre-migration PostgreSQL backup
  `nvidia_db_20261013_134018_942072312.sql.gz` passed gzip validation. Private
  root-owned status snapshots are retained as
  `model_status.pre-7e3d276.json` and `model_status.pre-c390e8f.json`. Frontend
  release `/var/www/aichat-releases/release-20261013T104046_858573441` is active;
  `/var/www/aichat-releases/release-20261012T230158_666603612` remains the
  validated atomic rollback target.
- All 373 backend and 33 responsive Playwright tests passed with lint, production
  build, Django deploy/migration checks, and PostgreSQL constraint inspection.
  The strengthened production probe completed successfully with 13/20 fully
  metered streams, seven transient failures, zero protocol errors and no
  unverified IDs. Public/origin health returned 200, `/media/` returned 404,
  anonymous private/configuration routes returned 403, the security monitor and
  all timers are healthy, and the backend has zero restarts or warning-level
  rollout entries.

### Request-type and identifier boundary rollout — 2026-10-13

- Deployed repository state `0ef3faa` without a migration or user-data write.
  The shared JSON parser now rejects coercion-prone structured values: booleans
  cannot become integer IDs/counts, fractional numbers cannot be truncated,
  non-finite temperatures are invalid, flags require booleans, and attachment
  lists contain only positive signed-64-bit IDs. Invitation codes also cross the
  same text-type boundary as other credentials.
- Persistence URL parameters use a positive PostgreSQL `BIGINT` converter.
  Values outside `1..9223372036854775807` fail at URL resolution before any ORM
  query. Session revocation routes accept only the 64-character lowercase-hex
  opaque handle, so malformed attacker input cannot trigger a global active-
  session decode/scan.
- All 403 backend tests passed with Django and diff checks. Production probes
  returned 404 for oversized conversation/message/attachment IDs and malformed
  session handles. Authenticated no-write probes returned parser-specific 400s
  for boolean token and attachment IDs and persisted no message. The backend
  restarted cleanly at the second readiness attempt, has zero automatic restarts
  or warning-level journal entries, and the security monitor completed with
  exit status zero.

### Conversation-generation integrity rollout — 2026-10-13

- Deployed repository state `f9db80a` with migration
  `0021_conversationgenerationlease`. A token-owned, expiring PostgreSQL lease
  permits one send or regeneration per conversation across every Gunicorn
  worker; conflicts return stable `409 generation_in_progress` and
  `Retry-After`. Long streams heartbeat the lease, token-matched release cannot
  delete a newer claimant, and daily maintenance removes expired crash residue.
- The stream wrapper finalizes the lease and provider budget exactly once on
  success, provider failure, application exception, Stop/disconnect, and even a
  response closed before its first iteration. No-provider paths reconcile with
  zero usage and remove the pending user message; provider-started calls retain
  the existing fail-closed missing-usage behavior.
- Pending attachments are re-resolved with `SELECT FOR UPDATE` immediately
  before the user-message link, closing cross-conversation double claims.
  Regeneration no longer deletes the old branch before dispatch: provider error,
  empty output or an unstarted response preserves it, while success or an
  explicitly stopped partial atomically replaces it. Conversation mutation and
  source-message edits are fenced for the same lease lifetime.
- All 415 backend tests passed with Django checks, compile, migration-drift,
  dependency consistency and diff checks. The pre-migration gzip-validated
  rollback dump is
  `/home/micu/backups/nvidia_db/nvidia_db_20261013_183544_680447112.sql.gz`.
- Production applied `0021` under `aichat`; the primary key, expiry index and
  foreign key were inspected. A rollback-only live smoke transaction proved
  acquire, conflicting `409`, token-owned release and zero residual rows.
  Origin/public health returned 200; private/config/media probes retained
  403/404 boundaries; nginx validated; all three application timers are active;
  the security monitor exited successfully; the backend remains active with
  three workers and zero automatic restarts. No error-level post-restart journal
  entries appeared; the only warning was the intentional anonymous private-route
  probe. Rollback is the retained dump plus code rollback and reverse migration
  to `0020`; no rollback was required.

### Chat storage and egress quota rollout — 2026-10-13

- Deployed repository state `0337508` with migration
  `0022_conversationgenerationlease_reserved_messages_and_more`. Owner-row locks
  serialize conversation creation and cross-conversation message accounting;
  active generation leases reserve up to two projected rows so concurrent workers
  cannot collectively exceed 500 conversations/user, 10,000 messages/user or
  2,000 messages/conversation. Regenerating a trailing user message reserves its
  one possible new row, while replacing an existing branch remains possible at
  the quota.
- Assistant output is capped at 64,000 characters. Owner-scoped Markdown export
  is streamed only below a conservative 25 MiB estimate and limited to 10/hour;
  private attachment downloads are limited to 120/hour. Session list/revocation
  endpoints are throttled, daily maintenance deletes expired database sessions,
  quota blocks feed the five-minute monitor, and the responsive Storage panel
  exposes saved-object limits at 320, 390, 768 and 1440 px.
- All 427 backend, 33 Playwright and 10 monitor tests passed with lint, production
  build, compile, Django/migration checks, `pip check`, zero npm advisories and
  clean diffs. The deploy check reported only the deliberate HSTS-preload warning.
  The pre-migration rollback dump is
  `/home/micu/backups/nvidia_db/nvidia_db_20261013_190012_583858358.sql.gz`
  (`SHA-256 019e71b1753630d7b282c357d2d347e38e03478a3921668f861c9029f7b0f558`,
  mode `0600`).
- Production had 6 conversations and 16 messages, with observed per-owner/per-
  conversation maxima of 4/13/4, below the new 500/10,000/2,000 limits. PostgreSQL
  column nullability and both `0..2` reservation constraints were inspected. A
  rollback-only live smoke proved `2→1→released`, stable `409 messages_limit` and
  no residual data. Maintenance removed 10 already-expired sessions and the next
  dry-run was empty.
- Root-owned frontend release
  `/var/www/aichat-releases/release-20261013T160109_983111340` is active;
  `/var/www/aichat-releases/release-20261013T104046_858573441` is retained for
  atomic rollback. Its manifest, origin/public 200/403/404 boundaries, security
  headers, nginx syntax, three timers and manual security monitor all passed. The
  backend has three workers, zero automatic restarts and no warning/error rollout
  journal entries after readiness. Rollback is the retained dump and frontend
  release plus code rollback and reverse migration to `0021`; none was required.

### Indexed and bounded session rollout — 2026-10-13

- Deployed repository state `ae55cb5` with migration
  `0023_authenticatedsession`. Each Django session now has an owner-indexed
  registry row and a secret-keyed 64-character non-bearer handle. A fixed 30-day
  deadline survives session-key rotation, registry mismatches fail closed, and a
  user-row lock enforces a 20-session cap while preserving the current session
  and evicting the oldest alternatives.
- Session inventory, selected revocation and revoke-others use owner-scoped
  indexed queries instead of decoding the global active-session table. Legacy
  sessions are indexed lazily, malformed deadlines are repaired conservatively,
  and daily maintenance removes cookie-expired or absolute-expired session rows.
  All 433 backend, 33 Playwright and 10 monitor tests passed with lint, build,
  compile, Django/migration checks, `pip check` and zero npm advisories.
- The gzip-validated pre-migration rollback dump is
  `/home/micu/backups/nvidia_db/nvidia_db_20261013_234013_377863644.sql.gz`
  (`SHA-256 8faef5b53feef3ea80fa84f79061813c11e0449b4b91867f9fb494a878d324fc`,
  mode `0600`). Production had no active database sessions, so the migration
  backfilled zero rows. Foreign keys, the handle uniqueness constraint, the
  absolute-deadline check and owner/expiry indexes were inspected in PostgreSQL.
  A rollback-only live smoke proved indexed inventory, absolute-expiry logout and
  registry/session cascade with no residual rows.
- Root-owned frontend release
  `/var/www/aichat-releases/release-20261013T204054_055053842` is active;
  `/var/www/aichat-releases/release-20261013T160109_983111340` is retained for
  atomic rollback. Its manifest, origin/public 200/403/404 boundaries, security
  headers, nginx syntax, three timers, maintenance dry-run and manual security
  monitor passed. The backend has three workers, zero automatic restarts and no
  error-level journal entries after rollout readiness.
- A pre-migration origin health probe briefly returned 500 because already
  running workers retained the old `chat.models` module and later imported the
  newly written session module from the mutable checkout. This was a coherent-
  release failure, not database corruption or a migration failure; migration and
  a full service restart restored readiness in roughly 24 seconds. The event is
  now an explicit finding: production Python must move to root-owned,
  manifest-verified atomic releases. Until then, the backend must be stopped
  before deployed Python files change. Rollback is the retained dump, previous
  frontend release, code rollback and reverse migration to `0022`; it was not
  required.

### Immutable backend application rollout — 2026-10-13

- Deployed repository state `ea8812a` without a schema migration. The deployment
  script archives only tracked backend files from the clean commit, rejects
  symlinks, special files, secrets and mutable runtime directories, enforces
  root ownership and exact `0755`/`0644` modes, writes and verifies a SHA-256
  manifest, and preflights Django, migrations and the import origin as `aichat`.
- `/opt/aichat-backend-current` atomically selects root-owned release
  `/opt/aichat-backend-releases/release-20261013T205103_973321227`, whose embedded
  full commit is `ea8812aa40c059fafcd724ade5e9695cb2dca0fa`. Gunicorn's master and
  all three workers resolve that directory as their working directory. The
  service mount namespace cannot see checkout application source; it receives
  only read-only `.env`/venv binds and writable media/cache binds.
- Backend, maintenance and model-probe units now share the same release target.
  Their committed and installed service files match. The backend retained its
  `2.9 OK` systemd exposure score and zero automatic restarts. Running maintenance
  through the new sandbox succeeded and deleted zero objects; the 13-test monitor
  suite passed, the updated root-owned monitor returned no findings, and all four
  application timers are active.
- Origin/public root, health and `security.txt` returned 200; anonymous session
  inventory and direct config/git probes returned 403; direct media returned 404.
  The release manifest passed strict verification and the backend journal had no
  error-level entries after readiness. Future failed deploy probes restore both
  the prior release symlink and the previous installed unit files. The initial
  bootstrap required no rollback. Residual hardening is a root-owned, versioned
  dependency environment plus bounded release retention and a scheduled rollback
  exercise; the existing validated 23:40 database backup remains the data rollback
  point for this no-migration stage.

### Immutable Python environment rollout — 2026-10-14

- Repository states `493cf1b`, `f9292ad`, `2e75392` and `69fcd98` introduced a
  separate dependency-release builder and hardened its active-application/path
  validation. It reads only the committed `requirements.txt`, requires binary
  wheels, installs as secret-blind `nobody`, rejects missing/wrong/extra packages,
  symlinks, special files and unsafe paths, then converts the complete tree to
  exact root ownership/modes with both requirements and full-tree SHA-256
  manifests. There was no schema or data change.
- Two bootstrap candidates failed closed before activation and were removed: the
  first exposed a Bash-regex mismatch on `.release-commit`; the second exposed a
  host-specific non-ASCII interpreter alias copied by `venv`. Neither created the
  live symlink, restarted the service or changed its PID. The validators were
  corrected to deterministic Python path validation and explicit non-ASCII alias
  removal before the successful third build.
- `/opt/aichat-python-current` now selects root-owned release
  `/opt/aichat-python-envs/release-20261013T210131_257827390`, built from full
  commit `69fcd9878befe54cfc207a4d7fa083f3fbdc8b27`. It contains exactly the 24
  pinned runtime packages plus `pip`, no test tooling and no internal symlinks.
  Strict checks passed for both manifests and all installed requirements.
- Backend application release
  `/opt/aichat-backend-releases/release-20261013T210204_778720955` embeds the same
  commit; prior application release
  `/opt/aichat-backend-releases/release-20261013T205103_973321227` is retained.
  Gunicorn's executable resolves to the immutable Python release and its working
  directory to the immutable application release. Checkout source and its old
  builder venv are absent from the service mount namespace; only `.env` is bound
  read-only and media/cache are bound writable.
- All 433 backend and 16 monitor tests passed with Django/migration checks,
  `pip check`, ShellCheck and binary-wheel availability. Installed unit templates
  match the repository, maintenance through the final environment deleted zero
  objects, systemd remains `2.9 OK`, all timers are active, and the expanded
  monitor returned no findings. Origin/public 200, private 403 and media 404
  probes passed; the backend has zero automatic restarts and no post-readiness
  error-level journal entries. Residual supply-chain work is hash-locked wheels,
  provenance/SBOM, bounded release retention and a planned rollback exercise.

### Hash-locked Python supply-chain rollout — 2026-10-14

- Repository state `30b44d7fe7b766c073f906f721a816b97393de1f` added a
  committed lockfile for all 24 runtime packages. Each exact version mirrors
  `requirements.txt` and identifies the selected Python 3.14 Linux x86-64 wheel
  by SHA-256. A dedicated structural checker runs in CI, while the production
  builder installs binary wheels with pip `--require-hashes`; no schema or data
  change was involved.
- `/opt/aichat-python-current` atomically selects root-owned release
  `/opt/aichat-python-envs/release-20261014T122746_324335164`. The prior validated
  environment `/opt/aichat-python-envs/release-20261013T210131_257827390` remains
  intact as the automatic rollback target. The active requirements copy exactly
  matches the repository lockfile, both requirements hashes and all 7,263 entries
  in the full-tree manifest passed strict verification, and the tree contains no
  symlinks, non-root-owned entries or group/world-writable entries.
- The active environment contains exactly the expected 24 packages plus pip and
  passes `pip check`. Gunicorn's executable resolves inside the new release and
  its working directory remains the immutable backend release. The service is
  active with zero automatic restarts; all application timers are active,
  maintenance completed successfully and deleted zero objects, the security
  monitor returned no findings, and there are no warning-or-higher backend
  journal entries after activation.
- Origin and public root, health and `security.txt` probes returned 200; direct
  media returned 404; `.env`, `.git`, session inventory and conversation probes
  returned 403. Residual dependency-delivery work is retained SBOM/provenance
  evidence, controlled dependency updates, bounded release retention and a
  planned rollback exercise.

### Immutable CI Action rollout — 2026-10-14

- Repository state `a79a19d65a7cf1c3ee99cdd18e519d2a0234b5ad` replaced every
  moving remote Action reference with the full commit behind its reviewed
  official release: `actions/checkout` v4.4.0, `actions/setup-python` v5.6.0 and
  `actions/setup-node` v4.4.0. Human-readable release labels remain comments;
  GitHub executes only the immutable 40-character commit identifiers.
- A repository checker rejects tags, branches, missing refs and short SHAs while
  allowing local and explicit container actions. Its five regression tests and
  the checker itself run in CI, so a future moving reference fails the pipeline.
  Local tests, the current workflow scan and the independent production-lock
  check passed. This stage changed no production process, dependency or data.
- Residual CI/dependency provenance work is a controlled update/review process
  plus retained SBOM and provenance attestations. Pinning prevents a tag from
  silently moving; it does not establish that a newly reviewed commit or wheel
  was built through a trustworthy upstream chain.

### Bounded immutable-release retention rollout — 2026-10-14

- Repository state `08979f928242b955b8b0254630a211fea02b8b23` added one
  fail-closed retention path shared by frontend, backend application and Python
  environment deploys. Each executable root keeps its active release plus the
  two newest inactive rollback targets. Active selection is resolved and checked
  beneath the expected root; symlinks, special files, unknown entries, unsafe
  ownership/modes and family-specific file/byte overruns abort processing.
- Retirement is recoverable: a candidate is first removed from the executable
  namespace, frozen to root ownership, archived in a private `0700` hierarchy,
  validated for safe member paths/types and family bounds, written as `0600`,
  SHA-256-verified and fsynced before its source tree is removed. The tool is
  dry-run by default, requires root for `--apply`, never allows fewer than one
  rollback, and deploys explicitly preserve two.
- Production retained the active frontend
  `/var/www/aichat-releases/release-20261013T204054_055053842` plus releases
  `release-20261013T160109_983111340` and
  `release-20261013T104046_858573441`. Six older frontend releases and the
  group-writable legacy webroot were converted into seven root-only archives
  below `/home/micu/backups/nvidia_release_archive/frontend`; every gzip stream
  and SHA-256 sidecar passed independent verification. Backend and Python each
  already had only the active and one rollback, so nothing there was retired.
- All 433 backend, 19 monitor and six retention tests passed with ShellCheck,
  Bash syntax, Action-pin and requirement-lock gates. The installed monitor now
  rejects more than three executable entries or an unknown/stale staging entry
  and returned no findings after rollout. Active symlink targets did not change;
  the backend stayed active with zero automatic restarts and no warning-or-higher
  rollout journal entries. Origin/public 200, private/config 403 and media 404
  probes passed. Supplemental archives still need an encrypted off-site and
  expiry/storage lifecycle; they are not claimed as durable backups.

### Runtime SBOM rollout — 2026-10-14

- Repository state `7039490dddaccab423eb86471c17a6741edba254` added a
  deterministic CycloneDX 1.7 SBOM generator and exact verifier. For every one of
  the 24 runtime packages it records the normalized package URL, exact version
  and SHA-256 of the selected binary wheel. The document also binds the complete
  lockfile digest and repository commit; changing a component, hash or metadata
  makes exact verification fail. Six generator tests run in CI.
- The generated document was independently accepted by the official CycloneDX
  1.7 JSON Schema. It is intentionally an inventory, not a signed provenance
  claim: it establishes what the committed build selected and hash-bound, but
  does not independently attest which upstream builder produced each wheel.
- `/opt/aichat-python-current` now selects root-owned release
  `/opt/aichat-python-envs/release-20261014T124433_949187437`, built from the full
  repository commit above. Its `15174`-byte `.release-sbom.cdx.json` matches the
  active lock exactly, passes the official schema, is included in the requirements
  checksum set and the 7,264-entry full-tree manifest, and is required by the
  installed monitor. The two prior Python releases remain inactive rollback
  targets, so retention stayed within the three-entry policy.
- All 433 backend, 20 monitor, six SBOM, six retention and five Action-pin tests
  passed with ShellCheck, Bash syntax and lock validation. `pip check`, maintenance
  (zero deletions), the manual monitor, three timers, origin/public 200, private/
  config 403 and media 404 probes passed. Gunicorn resolves the new environment,
  remained active with zero automatic restarts, and emitted no warning-or-higher
  rollout journal entries. Residual work is signed builder provenance and its
  independently retained verification material.

### Controlled release rollback drill — 2026-10-14

- Repository state `6abef1a18c0cb92f12acb465974ef0efac6f860a` added a
  fail-closed drill for the immutable backend and Python release families. It
  validates trusted roots, direct symlinks, root ownership/non-writability,
  complete manifests and commit markers before any switch. Python candidates
  also require their lock/checksum/CycloneDX artifacts, exact SBOM validation,
  `pip check`, the same dependency lock as the active runtime, Django/import
  compatibility and no pending migration. Backend/Python deploys and the drill
  now share one exclusive operation lock; CI runs Bash syntax and ShellCheck on
  all operational shell scripts.
- The backend exercise switched from
  `release-20261013T210204_778720955` to
  `release-20261013T205103_973321227` and restored the exact original target.
  Rollback and restoration each reached verified health in three seconds, using
  distinct process IDs `2965821` and `2966151`. The Python preflight first
  rejected the newest old candidate because it correctly lacked the newly
  mandatory SBOM rather than weakening policy for the test.
- A fresh policy-compliant Python environment
  `release-20261014T130816_816588011` was built from the unchanged 24-package
  hash lock and repository state above. The retention policy archived the oldest
  environment privately and preserved SBOM-valid
  `release-20261014T124433_949187437` as the immediate candidate. The live Python
  drill switched to it and restored the exact original runtime; rollback and
  restoration each took three seconds with distinct process IDs `2971693` and
  `2971841`.
- Every activation required the PID's resolved working directory/executable plus
  seven origin probes: root, health and `security.txt` 200; arbitrary media 404;
  `.env`, `.git` and anonymous conversations 403. The signal/exit path always
  restores and re-probes the original target within 60 seconds and the drill runs
  no migrations, provider requests or application-data writes. Independent final
  checks found the intended backend and Python targets active, both full manifests
  and the 24-component SBOM valid, `NRestarts=0`, the monitor empty, all three
  timers active, matching public/origin 200/403/404 boundaries, and no
  warning-or-higher backend journal entries. Residual operational work is a
  scheduled drill cadence plus off-host evidence retention.

### Recent strong-authentication rollout — 2026-10-14

- Repository state `71c7932ed750c254063fa2075eea2da55e55f74a` introduced one
  five-minute policy for sensitive account actions. Its server-side session
  marker contains only user ID, timestamp and an HMAC-SHA256 fingerprint bound to
  the current password hash; it rejects malformed, expired, future-dated,
  cross-user or stale-credential state. The configurable lifetime is constrained
  to 60–3,600 seconds and reauthentication does not move the fixed absolute
  session deadline.
- Successful full login and password-reset login establish the marker. The
  dedicated, rate-limited reauthentication route requires the current password
  and, for 2FA accounts, a replay-protected TOTP or single-use recovery code.
  Password change now also requires that second factor. Enrollment, disable,
  recovery-code rotation and deletion use the same credential verifier, while
  session revocation fails closed with a machine-readable step-up response.
  Failed step-up attempts join the monitor's existing authentication-burst
  signal without logging passwords, codes, email addresses or session secrets.
- The responsive Settings flow retains the requested revocation, requests only
  the required factors, and automatically resumes after success. Backend coverage
  includes missing/expired/future markers, failed passwords, 2FA recovery-code
  consumption, absolute-deadline preservation and password changes on 2FA
  accounts. The browser regression exercises stale-session step-up and resumed
  revocation at 390 px.
- All 442 backend, 34 Playwright, 20 monitor, six SBOM, six retention and five
  Action-pin tests passed, alongside Django checks, frontend lint/build,
  ShellCheck and Bash syntax. `npm audit` reported zero vulnerabilities; Python
  dependency audit remains an enforced CI job and the runtime lock was unchanged.
  Production activated backend release
  `/opt/aichat-backend-releases/release-20261014T180355_832109969` and frontend
  release `/var/www/aichat-releases/release-20261014T180406_502593434`; the new
  anonymous reauthentication boundary returned 403. Active manifests and
  migration checks passed, the process resolves to the intended backend/Python
  releases with `NRestarts=0`, all timers are active, the monitor returned no
  findings, public/origin 200/403/404 boundaries passed, and no warning-or-higher
  backend journal entries appeared after rollout.

### Model-availability transparency rollout — 2026-10-14

- Repository state `3ec256d15be7ad1583a42617d685e7f0dd195d71` added
  catalog, available and unavailable counts to the authenticated model contract.
  The responsive UI now states when verified models are hidden instead of making
  a smaller picker look like the complete catalog. Failure details remain private;
  only aggregate state and bounded successful latency samples reach the browser.
- The availability timer now runs every Monday and Thursday with a randomized
  ten-minute delay. Its oneshot service has an effective six-minute start timeout,
  and the backend release mechanism atomically installs and rolls back both the
  service and timer definitions. This leaves several opportunities inside the
  existing eight-day trust window without turning the probe into continuous
  provider traffic.
- All 442 backend and 35 Playwright tests passed, including the 320/390/768/1440
  responsive suite and new verified/degraded availability cases. Frontend lint,
  production build, ShellCheck, Bash syntax and systemd unit/calendar validation
  passed; `npm audit` reported zero vulnerabilities.
- Production activated backend release
  `/opt/aichat-backend-releases/release-20261014T183355_484686667` and frontend
  release `/var/www/aichat-releases/release-20261014T183406_765208838`, retaining
  the previous releases as rollback targets. Both manifests match. The timer's
  persistent catch-up probe completed successfully in 3m02s with a 70.3 MB peak,
  refreshed the status timestamp, exposed 13 of 20 catalog models and retained
  prior trusted decisions through ten transient provider results; seven models
  remain hidden. The next run is scheduled for Thursday at 04:04 EEST.
- The backend is active with `NRestarts=0`; migrations, the manual security
  monitor and nginx validation passed. Origin/public health returned 200,
  anonymous models returned 403 and arbitrary media returned 404. The existing
  HSTS-preload warning remains intentionally unresolved pending an explicit
  whole-domain preload decision.

### Bounded transient-availability trust rollout — 2026-10-14

- Repository state `fab6ad0e7f6db2bae803c8ecf768793051dc0072` closed a
  liveness gap where a once-available endpoint could remain trusted forever while
  every later probe timed out or returned an invalid stream. A private bounded
  streak now preserves a verified model through two consecutive inconclusive runs,
  hides it on the third, and immediately restores it after a complete successful
  stream. New and previously unavailable models still fail closed on their first
  inconclusive result.
- The private runtime schema accepts pre-rollout files by inferring streak one for
  an existing transient result and zero for a conclusive result. It rejects boolean,
  out-of-range and outcome-inconsistent streaks; an omitted or invalid catalog
  result becomes unverified and therefore unavailable. Logs expose only aggregate
  inconclusive/persistent counts, while the authenticated API continues to omit
  per-model provider failure details.
- A production diagnostic repeated the three newly inconclusive probes sequentially
  rather than at the normal concurrency: GPT-OSS 20B and GLM 5.3 Flash each timed
  out after 60 seconds, while Laguna XS 2.1 returned a provider error in 182 ms.
  This ruled out local probe concurrency as the sole cause and avoided an unsupported
  reduction in coverage. No diagnostic result rewrote runtime availability.
- All 444 backend tests passed before commit; the final focused suite passed 37
  model-status cases, Python compilation, migration-drift and Django checks. No
  schema migration or frontend release was required. Backend release
  `/opt/aichat-backend-releases/release-20261014T184304_584274130` is active with
  the previous release retained for rollback and a valid manifest.
- The live pre-rollout status loaded compatibly: all three affected previously
  verified models remain available at inferred streak one, while the seven already
  unavailable endpoints remain hidden. The backend has `NRestarts=0`, the next
  timer run remains Thursday, migrations and the monitor passed, public/origin
  health returned 200, anonymous models returned 403, arbitrary media returned
  404, and no warning-or-higher backend journal entries appeared after activation.

### Provider data-flow disclosure rollout — 2026-10-15

- Repository state `33240aae4b2dedfba4c95147694215c146ce1509` added a
  versioned, owner-bound acknowledgement before chat, regeneration or image
  content can leave the application for NVIDIA. The record contains only the user
  relationship, disclosure version and timestamp. A stale, absent or malformed
  version fails with `428` before generation leases, budget reservations, message
  writes or provider calls; anonymous and CSRF-less acceptance attempts return
  `403`.
- Repository state `3cf1de7b0602f80226ad21ee0b785c954ca0dbf0` binds the
  keyboard-accessible responsive dialog's
  version to its compiled text. The dialog names prompts, relevant history,
  selected files and image settings, links NVIDIA's official privacy policy and
  service terms, and retains an equal cancel path. Its version is compiled with
  that exact text; a tab carrying a stale bundle preserves its draft or branch but
  cannot accept a newer server version and must reload the current UI. This control
  is transparency evidence only; it does not establish the
  operator's GDPR legal basis, NVIDIA retention/training terms, DPA/region, or
  production entitlement.
- All 451 backend and 37 Playwright tests passed, including 320 px first-use and
  stale-tab retries. Django checks and migration drift, frontend lint/build and
  `npm audit` passed with zero reported npm vulnerabilities. Pre-migration backup
  `/home/micu/backups/nvidia_db/nvidia_db_20261015_033647_394304357.sql.gz`
  is mode `0600`, gzip-valid and SHA-256
  `7f6da4d7872a1f0da308f1cf687ed532898488a44ca3d56b1f6c1f06e8ff6c5f`.
- Migration `chat.0024_providerdisclosureacceptance` applied successfully.
  Production activated backend release
  `/opt/aichat-backend-releases/release-20261015T003658_515283587` and frontend
  release `/var/www/aichat-releases/release-20261015T004138_786733853`, retaining
  their immediate predecessors. Public and origin root/health returned `200`,
  anonymous private and disclosure routes returned `403`, arbitrary media
  returned `404`, the backend remained at `NRestarts=0`, and no warning-or-higher
  backend journal entries appeared after activation.
- Rollout observation found the monitor state readable as JSON but owned by root
  after an earlier manual root execution, so the `micu` service had failed closed.
  Ownership was restored to `0600 micu:micu` and the service recovered. Repository
  state `326c7e2a5f85dba41baff2d420349d911ffdbfd1` now rejects
  non-regular, non-`0600`, or different-UID state before replacement; all 21
  monitor tests pass and the installed root-owned executable matches the committed
  SHA-256 exactly. The next timer-initiated run at 03:43 EEST completed with exit
  status zero and scheduled the following five-minute run.

### Attachment malware-scanning rollout — 2026-10-15

- Repository state `75e0d6b0968bf6fb22b1abde1abc1d68b523c259` streams
  upload bytes to local ClamAV before MIME/signature inspection, archive or
  document parsing, owner-scoped deduplication and storage. Generated NVIDIA PNG
  bytes are scanned before storage, with a scanner readiness gate before provider
  egress. The protocol sends neither filenames nor owner/prompt metadata, accepts
  only exact clean/infected replies, rewinds every input and fails closed on
  timeout, socket or protocol ambiguity. Malware responses and logs are generic.
- Ubuntu ClamAV `1.5.4` is installed from the distribution repository with
  official database version `28154` and `3,642,872` signatures at rollout.
  `aichat-clamd` runs as the non-login `clamav` identity, over a `0660
  clamav:clamav` Unix socket, in a private network namespace with only Unix
  sockets permitted and without devices, capabilities or home access. Scan time,
  stream/file/expanded size,
  recursion, archive-file count, threads, queue, tasks and memory are bounded;
  encrypted and limit-exceeding containers alert as detections. Its systemd
  exposure score is `2.1 OK`; the separately sandboxed signature updater scores
  `2.8 OK`.
- The deployment preflight and manual production readiness command required exact
  PING, benign CLEAN and EICAR FOUND outcomes. All 465 backend tests and 42
  operations tests passed, along with ShellCheck, Python compilation, Django
  checks, migration-drift checks and systemd unit validation. No schema migration
  was required.
- Production activated
  `/opt/aichat-backend-releases/release-20261015T081727_217819455`; its immediate
  rollback `/opt/aichat-backend-releases/release-20261015T081658_904867316` uses
  the same scanner-enforcing commit, and both SHA-256 manifests verify. Backend,
  scanner and updater are active with `NRestarts=0`; public/origin health returned
  `200`, anonymous upload returned `403`, arbitrary media returned `404`, and the
  backend had no new warning-or-higher journal entry after activation.
- The five-minute monitor now checks the scanner socket, daily-signature age and
  permissions plus any malware rejection or fail-closed request. Its installed
  executable matches the repository at SHA-256
  `c34be19f34356b6256dadfb3b07d76c11ce520f421d9d5393fa03b400a1e01ab`;
  the first post-rollout run exited successfully with no active issue. Signature
  scanning still cannot prove that novel malicious documents are harmless.

### Isolated document-parser rollout — 2026-10-15

- Repository state `36b193f79cea7719c681f658b089b419fc641cd3` removes
  PDF/DOCX library execution from the web identity and its 24 request threads.
  The web process sends only protocol version, document type, byte length,
  character cap and bounded bytes over a permissioned Unix socket; filenames,
  owners, prompts and credentials are not sent. Exact framed replies are required
  and timeout, truncation, invalid UTF-8, unknown status or trailing data fails
  closed with a generic retryable `503` before storage.
- Parsing is sequential under the non-login `aichat-parser` identity. The
  `aichat-document-parser` systemd sandbox has `PrivateNetwork=yes`, only
  `AF_UNIX`, an empty capability set, `ProtectHome=tmpfs`, read-only system paths,
  private devices/tmp, one-core quota, eight-task ceiling, 640/768 MiB memory
  high/max bounds and no core dumps. The child additionally has 512 MiB address
  space, six-second CPU, eight-second wall, 256 KiB output-file and 32-descriptor
  limits. The identity was verified unable to read the runtime `.env`; the unit
  scored `2.1 OK` and remained at `NRestarts=0`.
- All 482 backend and 43 operations tests passed. Focused protocol/upload tests,
  Python compilation, Django checks, migration-drift checks, ShellCheck and
  systemd unit/security validation passed. The deploy preflight and manual
  readiness command extracted a marker from a real DOCX through the production
  socket. No schema or frontend change was required.
- Production activated
  `/opt/aichat-backend-releases/release-20261015T125858_317189238`; immediate
  rollback `/opt/aichat-backend-releases/release-20261015T125838_969924808` uses
  the same parser-enforcing commit and both manifests verify. Backend, parser,
  scanner and signature updater are active with `NRestarts=0`. Public/origin
  health returned `200`, anonymous upload returned `403`, and arbitrary media
  returned `404`.
- The monitor now probes the exact parser health frame and correlates parser
  worker failures plus fail-closed upload events without forwarding content,
  extracted text or filenames. Follow-up state `75d3932f8febb27c49f6a468232a02fabb2e5647`
  also compares the installed service and worker's content, ownership and exact
  modes with their copies inside the active manifest-verified backend release;
  46 operations tests pass. The installed monitor matches repository SHA-256
  `861a4892c3c819a94b0e70fc390a6ab5ac72e7d75b0d017ec5119f0e17c4c2b0`, and
  its post-update run succeeded with no active issue. Large asynchronous documents
  and evidence quarantine remain future work before any limit increase.

### NVIDIA provider-egress bounds rollout — 2026-10-15

- Repository state `d15cdef3939b41a687dbcd01dcd4c08fa3b78102` closes
  unbounded upstream response and redirect behavior. Production startup now
  accepts only the exact approved NVIDIA HTTPS host/path pairs for chat, image
  generation and image status. Alternate schemes, hosts, suffix tricks, userinfo,
  ports, paths, query strings, fragments and malformed ports fail closed before
  the service starts.
- Chat and model-probe SSE is consumed incrementally with a 4 MiB aggregate and
  1 MiB line ceiling, strict UTF-8, validated object/list/delta/content/usage
  shapes, bounded read time and a 480-second chat wall limit. Image generation
  and polling stream JSON under a 16 MiB decoded response ceiling, validate
  declared and actual size, reject every non-`200` terminal response, close each
  polling response and continue to validate/decode the PNG under the existing
  10 MiB storage boundary. No provider request follows redirects.
- All 502 backend and 46 operations tests passed, including chunked responses
  without `Content-Length`, oversized line/body, invalid UTF-8, malformed event
  shapes, redirect flags and endpoint-confusion cases. Python compilation,
  Django/migration checks, ShellCheck and both scanner/parser deploy preflights
  passed; no schema or frontend change was required.
- Production activated
  `/opt/aichat-backend-releases/release-20261015T131046_140672450`; immediate
  rollback `/opt/aichat-backend-releases/release-20261015T131029_920737700` uses
  the same provider-bounded commit and both manifests verify. Backend and parser
  are active with `NRestarts=0`; the integrity monitor completed with no active
  issue. Public/origin health returned `200`, anonymous models returned `403`,
  and arbitrary media returned `404`.
- Follow-up state `a373c869d010413ac123809f22f19bf12692818c` emits only
  fixed `kind` and `reason` values when chat/image responses violate redirect,
  content-type, framing, size, UTF-8, shape, poll-ID, terminal-status or completion
  rules. No model, user, prompt, URL, response content or request identifier enters
  the event. The five-minute monitor alerts on any occurrence; 503 backend and 46
  operations tests pass. Production active
  `/opt/aichat-backend-releases/release-20261015T131413_413201885` and rollback
  `/opt/aichat-backend-releases/release-20261015T131359_064408972` both use this
  commit and have valid manifests. The installed monitor SHA-256 is
  `e44b33315fe0ad64bf54cae38c05da9c5ad436f0bc72396b998baaddcd699e34`;
  its post-rollout state had no active issue.

### Versioned two-factor key rollout — 2026-10-15

- Repository state `84cd788a55f4a8e22877714912ad2fbd61761abd` removes
  TOTP, recovery-code and enrollment-fingerprint dependence on Django's signing
  key. A separately generated 32-byte root key is purpose-separated for Fernet
  encryption and HMAC use; every stored artifact records an allowlisted version
  and key ID. The keyring is bounded to eight canonical base64url keys and
  malformed JSON, duplicate/invalid identifiers, unknown keys, invalid base32,
  bad recovery digests and corrupt ciphertext all fail closed.
- Production contained zero `TwoFactor` rows and zero recovery artifacts before
  rollout, so the independently generated `prod-2026-10` key was activated with
  legacy `SECRET_KEY` compatibility disabled and no account migration or forced
  re-enrollment. The read-only production audit passes with zero invalid or
  inactive artifacts. Future TOTP secrets can be rewrapped transactionally by
  management command or lazily after a successful use; old recovery hashes keep
  their recorded key dependency until consumed or regenerated, preventing unsafe
  early key removal.
- The atomic keyring configurator preserves unrelated dotenv values and never
  prints key material. Its first pre-deploy execution exposed that an
  unprivileged atomic replacement could preserve mode but not the service group;
  the verification gate caught this before restart while the live backend stayed
  healthy at zero restarts. Ownership was restored to `0640 micu:aichat`, and the
  helper now preserves UID/GID exactly or aborts, which requires `sudo` on this
  host and is regression-tested.
- All 512 backend tests and 50 focused operations tests passed, together with
  Django checks, ShellCheck, immutable Actions validation and the exact runtime
  requirements check. Production activated
  `/opt/aichat-backend-releases/release-20261015T183607_732311747`; immediate
  rollback `/opt/aichat-backend-releases/release-20261015T131413_413201885` was
  retained and both manifests verify. Backend and isolated parser are active at
  `NRestarts=0`, and the live gunicorn process uses the active release.
- The five-minute monitor now alerts on any privacy-minimized
  `two_factor_key_error`. Its installed root-owned executable matches repository
  SHA-256 `0e25b77aab25c66bc41f04c5ee37db2056bdc14b4328745143b7155a6731024a`;
  the post-rollout run exited successfully with no active issue. Public and
  origin health returned `200`, anonymous models and `/.env` returned `403`,
  arbitrary media returned `404`, and no warning-or-higher service event appeared
  after activation.

### Private backend-origin rollout — 2026-10-15

- Transitional repository state `985f691cd44a6dbd9dcfd1f8eaa8ec2a28dece83`
  created a dedicated `aichat-origin` group, a systemd-managed `0750
  aichat:aichat-origin` runtime directory and a Gunicorn Unix socket whose startup
  helper accepts only the expected real socket/UID/GID and enforces mode `0660`.
  Nginx was granted only that one-purpose group; `micu` and an unrelated
  `nobody` identity were confirmed absent/denied. A dual TCP/socket bind kept the
  service recoverable only while nginx moved to the committed socket vhost.
- Nginx configuration was retained privately at
  `/home/micu/backups/nvidia_config/aichat.nginx.before-origin-socket.20261015T184345Z.conf`,
  validated as root, reloaded and proven healthy before final state
  `e66697f841cd5754b8fa0dfbe1c1c949be351c42` removed TCP. Nothing now listens on
  `127.0.0.1:8501`; nginx and `www-data` receive health `200` through the socket,
  while an unrelated identity cannot traverse/connect.
- All 516 backend tests and 31 monitor tests passed, including unsafe directory,
  regular-file/symlink substitution, exact socket mode and TCP-regression cases.
  ShellCheck and systemd unit verification passed. The active backend release is
  `/opt/aichat-backend-releases/release-20261015T184456_343664785`; the process
  working directory and commit marker match, its manifest verifies, backend and
  parser have `NRestarts=0`, and the backend sandbox remains `2.9 OK`.
- The installed monitor matches repository SHA-256
  `66f710b5e235902ac0d48bb31f4c34c12b440a0aa075857d33c05989ba315745`
  and completed with no active issue. Root-run nginx validation passed. Public
  and origin health returned `200`, anonymous models and `/.env` returned `403`,
  arbitrary media returned `404`, and no warning-or-higher service journal event
  appeared after final activation. The cloudflared-to-nginx trust path remains a
  separate residual control.

### Versioned privileged-audit key rollout — 2026-10-15

- Repository state `b8bb1478c7b2a643a82e6d055706da02e1149140` removes
  privileged-audit dependence on `DJANGO_SECRET_KEY`. Nonnumeric object
  references and integrity tags use separate purpose-derived HMAC keys from an
  independently generated, eight-entry-bounded keyring. New tags carry their
  allowlisted version and key ID; malformed envelopes, unknown/corrupt roots and
  invalid rows fail closed.
- Production contained zero `AdminAuditEvent` and zero Django `LogEntry` rows
  before migration, so `prod-2026-10` was activated with legacy Django-key
  compatibility disabled and no historical evidence required re-tagging. The
  full inventory passes with zero invalid or inactive dependencies. Future
  rotation is transactional and first validates every locked row, preventing a
  tampered event from being blessed by a new key.
- The gzip-validated rollback dump is
  `/home/micu/backups/nvidia_db/nvidia_db_20261015_222737_034803086.sql.gz`
  (`0600 micu:micu`, SHA-256
  `04d902fb8b31e0bd09e52d3ab389e0e73cf6df41c15175f52de986b622f683cc`).
  Migration `0025` only widened `integrity_tag` from 64 to 104 characters and is
  applied. All 520 backend, 31 monitor and 5 atomic-keyring tests passed;
  Django/migration checks, Bash syntax, ShellCheck and diff validation passed.
- Production active release
  `/opt/aichat-backend-releases/release-20261015T192813_865090023` and immediate
  rollback `/opt/aichat-backend-releases/release-20261015T192754_224613062`
  contain the same compatible commit and have valid manifests. A live rollback
  drill switched in two seconds and restored the exact active release in one
  second. The restored process imports from that release; backend and parser are
  active at `NRestarts=0`, and no warning-or-higher backend event appeared.
- Public and origin health returned `200`, anonymous models and `/.env` returned
  `403`, and arbitrary media returned `404`. Port 8501 remains closed; the live
  Gunicorn socket remains a real `0660 aichat:aichat-origin` socket. The installed
  five-minute monitor matches repository SHA-256
  `66f710b5e235902ac0d48bb31f4c34c12b440a0aa075857d33c05989ba315745`
  and completed successfully with no active issue; the backend sandbox remains
  `2.9 OK`.
- The scoped CISO exercise ranks tampering and repudiation of the retained
  365-day privileged metadata above availability loss; prompts, attachments and
  provider data are not added to this flow. Invalid evidence is detected within
  the monitor's under-six-minute target and the runbook preserves the row/root,
  disables affected staff and revokes sessions before recovery. User-linked
  audit evidence still requires privacy/legal assessment and the GDPR 72-hour
  notification analysis when a breach qualifies. No new vendor was introduced.
  There is no separate incident-loss history, so the program's illustrative
  EUR 2,500/year baseline ALE remains the planning estimate rather than a new
  accounting claim. External immutable retention and the full timed incident
  tabletop remain open.

### Dedicated security-monitor identity rollout — 2026-10-16

- Repository states `f7465c24c6834b9d249b0951ee8f04d1340bc5a4`,
  `55e3caf58eab8104af748d07ac09f508d8b55e84`,
  `e2b7c497d052841abd2b86e9f72259179a7b74f0` and
  `2be47fe6e18ab76f308d418af00965332602f9cc` moved the five-minute
  security monitor off the interactive `micu` identity. Systemd-sysusers now
  provisions dedicated UID/GID `aichat-monitor` with `nologin`; the service has
  only its journal/scanner/parser/origin supplementary groups and keeps its
  `0700` state with a `0600` state file under that identity.
- Telegram configuration is copied into the service's private credential mount
  through `LoadCredential`; every invocation requires the exact systemd root
  ownership, mode and named ACL before evaluating conditions. The dedicated UID
  cannot open the source credential in `/home/micu/scripts/.env`. `journalctl`
  is invoked by absolute path, removing privileged `PATH` resolution.
- Exact named ACLs grant traverse-only access to the shared backup parent,
  list/stat access to only the NVIDIA backup directory and read access to the
  privacy-minimized restore result. A real one-byte open probe proves the newest
  mode-`0600` database dump remains unreadable while the restore result is
  readable. The monitor validates directory/file owners, modes and complete ACL
  entry sets on every run, so replacing a named ACL with generic group access
  fails closed.
- The installer snapshots the executable, unit/timer, ACLs and state content and
  restores them on failure. Three rollout gates deliberately exercised that
  path: a missing `/etc/sysusers.d`, systemd's root-owned `0440` credential ACL
  geometry, and unreliable `test -r` behavior under identity switching. Each
  attempt restored the prior `micu` unit, original ACLs, state ownership/content
  and active timer before the focused fix was committed. The final installation
  completed all gates.
- All 36 monitor tests, Python compilation, Bash syntax, ShellCheck and systemd
  unit verification passed. The installed executable matches repository SHA-256
  `ca12e231b14cdaa86759900cd62c8128e91be17a8e93daf803aa45214c6caafa`;
  installed service, timer and sysusers files exactly match the repository. Two
  consecutive dedicated-identity executions returned status zero with no active
  issue or warning-level event, the timer remains enabled/active, the service
  sandbox is `2.9 OK`, and public health remains `200`.
- The scoped CISO review ranks elevation of privilege and information disclosure
  through monitor compromise above alert-path availability. Its remaining data
  scope is privacy-minimized journal/restore metadata and the pre-existing
  Telegram notification credential, not database dumps, prompts, attachments,
  application dotenv or provider credentials. No new vendor was introduced;
  Telegram was already in scope. A qualifying personal-data incident still
  triggers GDPR 72-hour assessment. The program's illustrative EUR 2,500/year
  baseline ALE is unchanged; off-host immutable evidence and independent
  monitoring of monitor failure remain residual controls.

### Protected-configuration change detection — 2026-10-16

- Repository state `24a0303bc3d7a7453da475c768d604ad7873ea13`
  adds a root-managed `aichat-config-watch.path` boundary around 12 exact NVIDIA
  targets: application and Telegram dotenv files, the nginx vhost, backend/job/
  monitor systemd units, the monitor sysusers definition and installed monitor
  executable. The path unit is enabled, active and waiting in production.
- A change starts a network-denied `aichat-monitor` oneshot that writes only the
  fixed `event=protected_config_changed` journal message. It does not read or
  forward the changed path or content. The five-minute monitor now reads that
  unit's journal and raises a fixed alert within its six-minute correlation
  window; the incident runbook requires preserving the timestamp and comparing
  installed files to committed sources without copying secret contents.
- The atomic monitor installer now stops the watcher before planned monitor
  upgrades, snapshots both watcher units and restores their prior enabled/active
  state on failure. This avoids self-generated deployment alerts while retaining
  the already exercised executable/unit/ACL/state rollback path.
- All 36 monitor tests, Python compilation, Bash syntax, ShellCheck and systemd
  verification passed. Installed watcher service/path and monitor executable
  exactly match the repository. Bootstrap produced zero protected-config events;
  a subsequent monitor run under `aichat-monitor` returned status zero with no
  active issue or warning-level event. The watcher emitter scores `2.2 OK`, the
  monitor remains `2.9 OK`, and public application health remains `200`.
- The scoped CISO review ranks tampering and repudiation above availability.
  The emitted data is one fixed event plus journal time—no credential, path,
  prompt, attachment or user identifier. Blast radius is local evidence and the
  time needed to investigate a changed control. No vendor or new personal-data
  flow was added; GDPR 72-hour assessment still applies if investigation finds a
  qualifying breach. Root can disable or erase this local signal, so off-host
  immutable retention and independent monitor-failure detection remain open.

### Durable generation-idempotency rollout — 2026-10-16

- Repository state `3d2f69616110eb415261bf1c2a5590a95bc3067d` adds an
  owner-scoped durable `GenerationRequest` for every send/regenerate operation.
  A per-user UUID uniqueness constraint, operation/target and lifecycle checks,
  lease-to-job linkage, and HMAC-bound normalized request shape prevent replay
  across users, conversations, operations or changed payloads. The fingerprint
  does not duplicate prompt text and remains comparable through configured
  Django signing-key fallbacks.
- The browser creates one UUID per logical action. A completed or
  partial-canceled job replays its stored messages through the normal SSE shape
  without provider work, even after attachments were claimed or a regeneration
  target was replaced. Active duplicates return a bounded request-specific
  conflict. Failed/interrupted jobs stay closed; expired workers are fenced,
  uncommitted user-message/attachment state is reconciled and old workers cannot
  commit after a replacement lease.
- State transitions are explicit (`queued`, `streaming`, `completed`, `canceled`,
  `failed`, `interrupted`) and database-constrained. Daily maintenance marks
  stale work interrupted and deletes terminal metadata after the bounded
  seven-day default. New privacy-minimized events alert within the existing
  six-minute window on any interrupted job or three mismatched key reuses.
- Backup hardening commits `6fdc1e348a9ec711377c09da5de72ece1a598011`
  and `62e3a13e702b8ff5c925f2c72dc8c10ab3343334` stop the scheduled
  backup from rewriting the dedicated monitor's directory ACL mask. Existing
  directories are now validated, not chmodded. The real pre-migration backup
  `/home/micu/backups/nvidia_db/nvidia_db_20261016_044823_264688165.sql.gz`
  is `0600 micu:micu`, gzip-valid and has SHA-256
  `6cffaecae8faf7d95cd146806128f2b4e896734c872ff44d159f977ef702bc58`;
  the directory ACL hash was identical before and after creation and the monitor
  identity remains unable to open the dump.
- Migration `0026_generationrequest_and_lease_link` was applied with zero active
  leases and preserved the six conversations and 16 messages. PostgreSQL exposes
  the expected owner/key uniqueness, state, completion-shape and operation/target
  constraints. A production transactional smoke against the deployed release
  produced one mocked provider call, replayed the second same-key request, created
  one job/two messages inside the test transaction and then proved zero residue.
- All 533 backend tests and 36 monitor tests passed. Django checks and migration
  drift, frontend lint/build, ShellCheck, diff validation and `npm audit` (zero
  advisories) passed. Backend release
  `/opt/aichat-backend-releases/release-20261016T014903_023125386` and frontend
  release `/var/www/aichat-releases/release-20261016T014916_079743130` have valid
  manifests and derive from committed state `62e3a13`. A live backend rollback
  reached the prior release in two seconds and restored the exact active release
  in two seconds.
- Public and origin health return `200`; anonymous models and `/.env` return
  `403`, arbitrary media returns `404`, TCP 8501 is closed, and the origin socket
  remains `0660 aichat:aichat-origin`. Backend/parser have `NRestarts=0` and score
  `2.9/2.1 OK`. The watcher and monitor score `2.2/2.9 OK`; the installed monitor
  matches repository SHA-256
  `de24105ded8190736bb96341896574d22f4724a0b2dad809828843c6bcc83cfc`
  and reports no active issue.
- The scoped CISO review ranks cost/availability replay, request tampering and
  repudiation highest. Compromise is owner-scoped for history, while repeated
  provider work can consume the shared budget; no additional prompt copy or new
  vendor/data flow was introduced. Detection targets six minutes and the runbook
  now forbids automatic retries of indeterminate jobs. A qualifying personal-data
  breach still triggers the GDPR 72-hour assessment. NVIDIA remains the existing
  processor and its DPA/retention/production-entitlement evidence remains open.
  The illustrative EUR 2,500/year program ALE is unchanged; this rollout was a
  functional recovery exercise, not the still-required full incident tabletop.

### Saved-message byte-quota rollout — 2026-10-16

- Commit `b2e96ab099140a8f51cc14a74e18320139e13740` closes an expiry-
  fencing gap found while designing byte reservations: heartbeat and every final
  send/regenerate commit now require the same unexpired token/job lease. An old
  worker cannot resurrect after expiry, including a branch replacement that
  reserves zero new message rows. Commit
  `60ebb7bb61edb262d19ff3196adfa7322707086b` then adds the quota.
- PostgreSQL derives `Message.content_bytes` as the stored expression
  `octet_length(content)`, preventing application or bulk-write drift and exact
  UTF-8 undercount. A database-constrained singleton gate serializes service-wide
  accounting. Active leases reserve the exact user text plus four bytes per
  possible assistant character; persistence atomically exchanges reservation for
  stored bytes. Regeneration subtracts the branch it will replace and reserves
  only maximum net growth.
- Validated defaults are 16 MiB/conversation, 64 MiB/user and 1 GiB/service.
  Conversation and account conflicts expose only the owner's usage; the global
  `503` exposes neither tenant usage nor the service limit. Growth edits use the
  same transaction gate, shrink/deletion remain available for recovery, message
  admin is read-only, quota blocks use the existing six-minute alert, and the
  responsive account panel shows owner-scoped message-text consumption.
- All 543 backend tests and 36 monitor tests passed. Django checks and migration
  drift, frontend lint/build, ShellCheck, diff validation and `npm audit` (zero
  advisories) passed. Tests cover multibyte UTF-8, reservation transitions,
  conversation/user/global conflicts, cross-user non-disclosure, edit growth and
  shrink, net-growth regeneration, database singleton enforcement and admin
  bypass prevention.
- The gzip-validated pre-migration backup is
  `/home/micu/backups/nvidia_db/nvidia_db_20261016_143022_218854877.sql.gz`,
  mode `0600 micu:micu`, SHA-256
  `95fdc8c6a31c6808c55c4814c08c42763db79881350d6766395a3ae8078bcd29`.
  Its parent ACL hash was identical before/after backup and both `aichat` and
  `aichat-monitor` remain unable to read the dump.
- Migration `0027_conversationgenerationlease_reserved_bytes_and_more` preserved
  six conversations and 16 messages and reported 11,422 saved-message bytes,
  zero active leases/jobs and singleton key `1`. PostgreSQL reports stored
  generation (`attgenerated = s`), `octet_length(content)` and both positive-ID
  and singleton gate checks. A rollback-only production transaction proved six
  bytes for `é😀`, a 69-byte live reservation, a stable owner-byte conflict at
  75 bytes and zero residual account data without provider work.
- Backend release
  `/opt/aichat-backend-releases/release-20261016T113049_962337211` and frontend
  release `/var/www/aichat-releases/release-20261016T113101_720866007` are active
  with valid manifests; the immediately preceding releases remain rollback
  targets. A live backend rollback reached the prior release in two seconds and
  restored the exact new release in two seconds. Public/origin health is `200`,
  anonymous models and `/.env` are `403`, arbitrary media is `404`, TCP 8501 is
  closed, and the origin socket is `0660 aichat:aichat-origin`. Backend/parser
  remain at `NRestarts=0`; their systemd exposure is `2.9/2.1 OK`, while the
  watcher/monitor remain `2.2/2.9 OK`. The path watcher recorded the planned
  protected-file installation/drill changes; exact comparisons proved the vhost,
  units and monitor executable match committed sources, no later event appeared,
  and the alert cleared naturally after its six-minute window (`active=[]`).
- The scoped CISO review ranks shared-database availability exhaustion, quota
  tampering/bypass and insufficient attribution highest. Blast radius is bounded
  per conversation/account before the 1 GiB shared circuit breaker; owner IDs and
  scope are logged without content. No prompt copy, external transfer, new vendor
  or new special-category processing is introduced; byte length is derived from
  already retained text. The runbook now contains privacy-minimized containment,
  GDPR's qualifying-breach assessment remains 72 hours, NVIDIA processing is
  unchanged, and the operator-wide legal/default schedule plus off-host evidence
  remain open.

### Archived-chat retention rollout — 2026-10-16

- Commit `7c9924ee2d27f1e40e28d59fd3b34c867b4da9d4` adds an owner-scoped
  retention preference with a deletion-safe default of zero (keep until manual
  deletion) and explicit 30/90/180/365-day choices. Only inactive archived
  conversations whose archive and last-update timestamps both exceed the chosen
  period qualify. Active chats, missing/zero preferences and every conversation
  with a generation lease are excluded.
- The responsive Storage panel exposes the policy and confirms destructive
  changes. `GET/PATCH /api/account/chat-retention/` is authenticated, owner-
  scoped and separately throttled; accepted changes log only owner ID and day
  count. The daily job caps each run at 100 conversations by default, locks the
  global storage gate, owner and conversation in generation-compatible order,
  rechecks policy/age/lease state, and cascade-deletes messages plus linked files.
  Dry-run and completion output is aggregate-only. A failed maintenance unit now
  raises the immediate `maintenance_failed` monitor issue.
- The first production transaction exposed a PostgreSQL-specific safety defect:
  `SELECT FOR UPDATE` cannot lock the nullable side introduced by the optional
  reverse-lease outer join. The transaction failed and rolled back with zero test
  users, preferences or conversations retained. Commit
  `4f61cb09afb68e649de5277a2c6461923bca4e0a` moves the lease test to a separate
  query while the global gate and owner/conversation locks prevent a new lease.
  A query-shape regression now forbids a join in the locked conversation query.
- All 561 backend tests pass after the PostgreSQL repair; the targeted retention
  suite has 17 tests. Django checks, bytecode compilation, migration drift and
  diff validation pass. The feature rollout also passed 36 monitor tests,
  frontend lint/build and `npm audit` with zero advisories. Coverage includes
  authentication, strict policy values, owner isolation, database constraints,
  keep-forever and lease exclusions, bounded batches, dry-run preservation,
  linked physical-file deletion and the production lock regression.
- The gzip-validated pre-migration backup is
  `/home/micu/backups/nvidia_db/nvidia_db_20261016_144506_660395176.sql.gz`, mode
  `0600 micu:micu`, SHA-256
  `d324b30cbbda111e17096d1991554845ac890ceffcb24945f5acbc291d955c46`.
  Its parent ACL hash remained
  `712a434db0b0a18538c66d541396e876f35326e10e1bf442d9c5aeda2c87f615`,
  and neither `aichat` nor `aichat-monitor` can read the dump.
- Migration `0028_chathistoryretention` preserved six conversations and 16
  messages, with zero active leases/jobs and no retention preference created for
  existing users. Production dry-run found zero eligible conversations and clean
  audit integrity. Rollback-only PostgreSQL transactions proved the API default
  and 30-day update, deletion of one old archived conversation/message, exact
  13-byte aggregate accounting, and zero residual test data. The same cleanup
  smoke then passed from the immutable deployed release.
- Backend release
  `/opt/aichat-backend-releases/release-20261016T115029_582695479` at the repair
  commit and frontend release
  `/var/www/aichat-releases/release-20261016T114534_350011778` are active with
  valid manifests. A live backend drill reached the immediately preceding release
  in two seconds and restored the exact repaired release in three. Public and
  trusted-origin health return `200`; anonymous retention and `/.env` return
  `403`, arbitrary media returns `404`, TCP 8501 is closed, and the origin socket
  remains `0660 aichat:aichat-origin`. Backend/parser/scanner report zero restarts
  and no warning-or-higher rollout journal entries. The installed monitor is
  byte-identical to the repository, completed successfully, and reports
  `active=[]`.
- The scoped CISO review treats unintended deletion, policy tampering and a failed
  maintenance path as the highest new risks. Default-no-delete, owner isolation,
  two independent age checks, lease exclusion, a 100-row batch and rollback-
  tested backups bound blast radius; aggregate logs and immediate job-failure
  detection target sub-six-minute awareness without recording content. The
  runbook now requires dry-run scope validation and integrity-checked recovery,
  and forbids ad-hoc row reconstruction. No new vendor, provider transfer or data
  category is introduced. NVIDIA processing is unchanged, and any qualifying
  personal-data incident still enters the GDPR 72-hour assessment.

### AI-usage metadata retention rollout — 2026-10-16

- Commit `debbf66250c868d96cb9ff477fcf6a31d1317dfd` gives the numeric daily
  provider-budget records an explicit lifecycle. Rows tied to an account are kept
  for 90 days; service-wide rows, which have no user or object relationship, are
  kept for 400 days to retain annual capacity/cost evidence. Cutoffs use complete
  UTC dates and delete only rows strictly older than the configured period, so
  the boundary day remains available.
- `AI_USER_USAGE_RETENTION_DAYS` is validated from 30 through 3,650 days;
  `AI_GLOBAL_USAGE_RETENTION_DAYS` must be at least as long and no more than 3,650
  days. Each table independently deletes at most
  `AI_USAGE_RETENTION_DELETE_BATCH_SIZE` rows per daily run (default 1,000,
  validated 1 through 10,000), oldest first. Dry-run reports eligible totals and
  the batch limit; successful cleanup logs only deleted user/global row counts.
  Existing `maintenance_failed` detection covers any cleanup failure.
- The targeted cleanup suite passes 13 tests and the full backend suite passes
  563. Django checks, migration-drift detection, bytecode compilation, shell
  syntax and diff validation pass. Boundary, separate lifecycle, dry-run and
  independent-batch behavior are regression-tested. No database migration or
  frontend change was required.
- The gzip-validated pre-deploy backup is
  `/home/micu/backups/nvidia_db/nvidia_db_20261016_145542_013368149.sql.gz`, mode
  `0600 micu:micu`, 14,637 bytes, SHA-256
  `fb2618c872c96a7c0abc6dae72d694865e09051c9cc471426b5260c44041507e`.
  Its parent ACL hash remained
  `712a434db0b0a18538c66d541396e876f35326e10e1bf442d9c5aeda2c87f615`,
  and neither application nor monitor identity can read the dump. Production had
  zero per-user and zero aggregate usage rows before activation, and the deployed
  dry-run reports zero eligible rows.
- A rollback-only production transaction created rows one day beyond and exactly
  on each configured boundary. The deployed release deleted only 2026-07-17 and
  2025-09-10, preserved 2026-07-18 and 2025-09-11, emitted the expected one/one
  aggregate event and left no user or usage residue after rollback.
- Backend release
  `/opt/aichat-backend-releases/release-20261016T115546_439571979` is active at
  the exact feature commit with a valid manifest. The live drill reached the
  preceding PostgreSQL-compatible retention release in one second and restored
  this release in two. Public/trusted-origin health returns `200`, `/.env` returns
  `403`, arbitrary media returns `404`, backend/parser/scanner have zero restarts,
  and no warning-or-higher backend rollout event was recorded. The installed
  monitor remains byte-identical to the repository and reports `active=[]`.
- The scoped CISO review ranks over-deletion and premature loss of investigation
  evidence above storage pressure for this change. Independent minimum/ordering
  validation, strict boundary semantics, bounded batches, dry-run evidence,
  immediate job-failure detection and a rollback-tested private backup bound that
  risk. The 400-day aggregate preserves trend/cost evidence without user linkage;
  neither table stores prompts, files, filenames, emails or IP addresses. No new
  processor or egress path is introduced, NVIDIA processing is unchanged, and a
  qualifying breach remains subject to the GDPR 72-hour assessment.

### Full account export and Unix-socket client-IP repair — 2026-10-18

- Commit `cbfc6a1ba99b70ae430b96821716730c77845367` adds a responsive full-
  account JSON export in Settings. `GET /api/account/export/` is owner-scoped,
  requires the five-minute password-bound recent-auth marker (and 2FA when
  enabled), and is limited to two attempts per owner/day. It streams profile,
  preferences/security status, conversations/messages, an attachment manifest,
  durable generation outcomes, retained personal usage and safe session metadata.
  It never emits password hashes/plaintext, OTP/reset state, TOTP secrets,
  recovery hashes, raw session keys/handles, attachment paths/bodies, extracted
  text, content HMACs or request fingerprints. Abnormal cross-owner attachment
  links expose no foreign relationship IDs, and generation metadata requires
  both request and conversation ownership.
- A preflight rejects more than 25,000 records or a conservative estimate above
  128 MiB before response streaming; an independent hard byte counter aborts and
  emits an error event if stored data violates the estimate. Responses are
  `private, no-store, no-transform`, `nosniff`, unbuffered and attachment-only.
  Commit `615781ee33b7ab08660037de4e2ce2d704026c88` adds a privacy-minimized
  alert for every completed export and any hard-bound breach. The monitor relays
  only fixed issue names/counts, never owner/IP/filename/content values.
- The main new STRIDE risk is information disclosure after account takeover.
  Requiring current credentials and the configured second factor stops a stolen
  session cookie alone; owner filtering prevents horizontal disclosure; omitted
  file bodies/authentication material reduce impact. Worst-case application
  egress is one owner's retained JSON, at most 128 MiB twice/day. Spoofing,
  repudiation and denial-of-service are covered respectively by strong step-up,
  aggregate completion evidence and record/byte/rate bounds. There is no new
  NVIDIA/vendor egress. The feature supports access/portability operations but
  does not by itself establish GDPR identity-verification procedure, legal basis,
  response deadline, or the still-missing complete operator privacy notice.
- The first public alert-path smoke exposed a pre-existing production availability
  defect: Gunicorn's Unix socket leaves `REMOTE_ADDR` empty, while the real-IP
  middleware trusted `X-Real-IP` only for loopback TCP. `django-ratelimit` then
  raised `ImproperlyConfigured` on public login and returned `500`. The temporary
  account was removed with zero session residue. Commit
  `1d566b365fd35d81982c28afc61b35b34a408f0d` accepts nginx's overwritten
  `X-Real-IP` only when the peer is loopback or the protected Unix socket, keeps
  `X-Forwarded-For` ignored, ignores spoofed headers from nonlocal TCP peers, and
  fails a socket request with missing/malformed client IP as monitored `400`.
  A repeated public TLS login, recent-auth and export then passed with a 1,023-
  byte response and zero user/session residue; the monitor entered
  `account_export_completed` from the real Gunicorn journal, delivered the
  controlled alert, and returned to `active=[]` with a successful resolution run
  after the six-minute window expired. The installed monitor is byte-identical
  to the repository and its timer/config watcher are active.
- The full suites pass: 571 backend tests, 38 Playwright tests at widths down to
  320 px, and 36 monitor tests. Django checks, migration drift, compilation,
  frontend lint/build, diff validation and production dependency audit also pass;
  `npm audit --omit=dev` reports zero advisories. Coverage includes owner
  isolation, explicit secret/file exclusions, conservative/hard bounds, 2/day
  enforcement, safe browser initiation, mobile overflow, Unix/loopback/untrusted
  IP resolution, malformed socket identity, and privacy-minimized detection.
- The gzip-valid pre-deploy backup
  `/home/micu/backups/nvidia_db/nvidia_db_20261018_023746_120917256.sql.gz` is
  14,633 bytes, mode `0600 micu:micu`, SHA-256
  `bb8f86aabcdd088b222e5181f3a1215ef73409057f74b7268299ca00fa74db6c`.
  Neither `aichat` nor `aichat-monitor` can read it; the protected dotenv ACL
  hash remained `e957040aa926e7592861c49de6d536cb72c7c2c12ac78679d945d6e2abd39653`.
  No migration was required. A rollback-only production transaction exported
  six owner records in 2,213 bytes, excluded a second owner's data and all marked
  secrets, and left zero rows/files. The public TLS smoke also left zero residue.
- Final backend release
  `/opt/aichat-backend-releases/release-20261017T234407_285204479` and its newest
  rollback `/opt/aichat-backend-releases/release-20261017T234324_157417673` both
  derive from the repaired commit `1d566b3`; their controlled rollback/restore
  took two seconds each way. Frontend release
  `/var/www/aichat-releases/release-20261017T233805_774231936` rolled back to
  `/var/www/aichat-releases/release-20261016T114534_350011778` in one second and
  restored in under one second. All manifests validate. Public and origin root/
  health return `200`, anonymous export/models and `/.env` return `403`, arbitrary
  media returns `404`, TCP 8501 is closed, the origin socket remains
  `0660 aichat:aichat-origin`, and backend/parser/scanner have `NRestarts=0`.
- CISO response priority for an unexpected export is immediate session revocation,
  password/2FA recovery, authentication-window preservation and determination of
  whether the stream completed. Because chat/email/IP metadata are personal data,
  a plausible unauthorized export starts legal/privacy assessment from the
  recorded awareness time and may invoke the GDPR 72-hour notification duty.
  The runbook now includes containment and a quarterly export-alert exercise.
  External immutable log retention remains required so a host compromise cannot
  erase this evidence.

### Account-deletion session purge rollout — 2026-10-18

- The public export-alert smoke revealed one harness-created authenticated Django
  session remaining after its user row was deleted directly. The indexed
  `AuthenticatedSession` row had cascaded, but its parent `django_session` row
  cannot cascade in that direction. The orphan was identified without exposing
  its payload, deleted, and a complete inventory then returned zero authenticated
  sessions whose owner no longer existed. The application endpoint already
  logged out its current session, but other device sessions had the same parent-
  row lifecycle gap.
- Commit `e7ae2e4df1061b2b43401a1527d91f07a76a04d0` now locks the owner and
  deletes every indexed Django session inside the account-deletion transaction
  before the user/data cascade. The response reports only `sessions_revoked`;
  the security journal records former owner ID plus that count, and the monitor
  emits only the aggregate `account_deleted` issue. Password, 2FA when enabled,
  five-per-hour throttling and the existing confirmation UI remain mandatory.
- Tests create two independently authenticated clients and prove both parent
  session rows, both registry rows, the user and owned data disappear while the
  second client becomes anonymous. The full backend suite passes 572 tests;
  account/session-focused coverage passes 24 tests and all 36 monitor tests pass.
  Django checks, migration drift, compilation and diff validation remain clean;
  no schema or frontend bundle change was required.
- A real public TLS smoke created two sessions, deleted through the first and
  received `sessions_revoked=2`; both session tables and the temporary owner were
  empty afterward, and the second client received `403`. The real Gunicorn event
  activated and delivered the controlled `account_deleted` alert; after the
  six-minute journal window, the successful resolution run returned the installed
  byte-identical monitor to `active=[]`. Backend release
  `/opt/aichat-backend-releases/release-20261017T235214_114371420` carries the
  exact commit and has a valid manifest; rollback to repaired release
  `/opt/aichat-backend-releases/release-20261017T234407_285204479` and restoration
  each took two seconds.
- The STRIDE focus is destructive tampering and repudiation after credential
  theft. Strong step-up, rate limiting, all-session revocation and immediate
  privacy-minimized detection reduce likelihood and MTTD, but deletion remains
  intentionally irreversible in the live database. Scheduled/cancelable deletion
  and visible status were the next open control and are closed by the rollout
  below. Backup and mandated audit retention also mean
  the endpoint is not a promise of instant erasure from every retained copy; the
  operator still needs a published erasure/backup schedule and verified legal
  process. Suspected unauthorized deletion enters incident/privacy assessment
  from the awareness timestamp and uses only integrity-checked recovery.

### Cancelable scheduled account deletion rollout — 2026-10-18

- Commit `7e246983d27a99e85f24b55aeb83a66dfb254e25` adds owner-visible
  `GET/POST/DELETE /api/account/deletion/` state and a responsive Danger Zone
  flow down to 320 px. Mutations require the current password plus enabled 2FA,
  are independently limited to five/hour and serialize on the owner. The default
  grace period is seven days (startup-bounded 1–30); repeated scheduling returns
  the original deadline instead of extending it, and cancellation fails with
  `409 deletion_due` at the deadline. The account remains usable during grace so
  its verified owner can cancel.
- Migration `0029_accountdeletionrequest` creates one request per owner, an
  indexed execution deadline and a database constraint forbidding a deadline
  before its request timestamp. Daily maintenance reports the total in dry-run,
  excludes owners with a surviving generation lease before applying the default
  25-account batch (startup-bounded 1–100), then rechecks deadline and lease under
  the global storage-gate/owner/request lock order. Execution revokes all indexed
  parent Django sessions before the owner cascade. Immediate deletion now uses
  the same global-gate/owner fence, so neither path can race a new generation.
  Login holds the owner lock through session creation, closing the inverse
  login-versus-delete orphan race.
- Attachment storage deletion now runs only after database commit. A rollback
  therefore cannot restore a row whose physical file has already disappeared;
  regression coverage proves both rollback preservation and committed cascading
  deletion. At this rollout point, a post-commit storage failure still lacked a
  durable retry outbox and could leave an unreferenced private file until verified
  operator cleanup. The immediately following rollout closes that residual.
- Schedule, cancellation and committed execution write fixed structured events.
  The six-minute monitor sends only event names/counts, never username, email,
  IP, prompt, filename, session identifier or authentication factor. The local
  execution event contains only former numeric owner ID and revoked-session
  count. The runbook treats an unexpected schedule as urgent recoverable account
  takeover, an unexplained cancellation as possible persistence, and execution
  like immediate destructive deletion.
- The complete local CI contract passes: 584 backend tests, 39 Playwright tests,
  36 monitor tests, Django deploy checks, migration drift, compilation,
  ShellCheck/Bash syntax, immutable-Action and wheel-lock validation, deterministic
  SBOM generation/check, frontend lint/build, `npm audit --audit-level=low` and
  `pip-audit 2.10.1`; both dependency audits report zero known vulnerabilities.
  GitHub itself contains no failed Actions/check-run for this repository, but its
  remote `main` was 18 commits behind before this feature and therefore had not
  tested the recent local commits. Replaying the exact workflow locally found and
  fixed one stale Playwright text assertion; no push was made.
- Before migration, a gzip-validated database backup was written to
  `/home/micu/backups/nvidia_db/nvidia_db_20261018_162157_624392381.sql.gz`,
  14,644 bytes, mode `0600 micu:micu`, SHA-256
  `2823be77aafaf2a77caf177011ad57fa8d08fd19dfc0af8fdb2e488e0e6d2314`.
  Its ACL evidence hashes to
  `18e54a257a3289e280aa86fe4b2df9784c2dee1c6ed0ec64bab251796aa055c1`;
  neither `aichat` nor `aichat-monitor` can read the dump. Migration took one
  second and preserved three users, six conversations and 16 messages while
  creating zero deletion requests. PostgreSQL introspection confirmed the
  deadline check and `execute_after` index.
- Public TLS smoke created two sessions for a content-free temporary account and
  observed schedule `201`, identical-deadline repeat `200`, cancel `200`, and
  overdue cancel `409`. The deployed dry-run found exactly one due request; the
  real systemd maintenance job deleted it, revoked both sessions and left zero
  temporary users, requests or indexed sessions. Both old cookies then received
  `403`. A rollback-only PostgreSQL smoke proved active-lease exclusion, the
  immediate-delete fence, successful execution after lease release and zero
  residue. Its first harness attempt used Django's disallowed `testserver` host,
  failed before the feature path and rolled back with zero residue; the corrected
  real-host HTTPS run passed.
- Backend release
  `/opt/aichat-backend-releases/release-20261018T132221_973720049` and frontend
  release `/var/www/aichat-releases/release-20261018T132232_018494110` have valid
  manifests. Backend rollback to
  `/opt/aichat-backend-releases/release-20261017T235214_114371420` and restore
  each took two seconds; frontend rollback to
  `/var/www/aichat-releases/release-20261017T233805_774231936` took 72 ms and
  restore 68 ms. Backend, maintenance and monitor report successful results and
  zero automatic restarts; the installed monitor is byte-identical to the repo,
  timers are active and database dumps remain unreadable to it. The real journal
  activated exactly the three deletion-lifecycle issues plus the expected
  deployment config-change issue; successful resolution runs cleared config
  change first and returned all state to `active=[]` at 16:31:36 EEST. The final
  state hash is
  `6d5812e751fbfc00495a7293ecbb71e5248b09e31d1dbc2150086ebeab6ff2b6`.
- Scoped CISO review ranks credential-driven destructive tampering, accidental
  over-deletion and cleanup failure above availability. Strong proof, a deadline
  that cannot be attacker-extended, cancellation before due, active-generation
  fencing, owner/session locks, a 25-account daily cap, preflight dry-run, private
  rollback-tested backup and immediate execution/maintenance alerts bound the
  likely blast radius and target sub-six-minute detection. A compromised database
  or service identity can bypass application batching, and a worker outage delays
  execution, so timer health and least privilege remain mandatory. No new NVIDIA
  transfer, processor or data class is introduced. Live deletion does not erase
  restricted backups immediately; the local seven-dump lifecycle and any legally
  mandated evidence must be stated in the complete privacy/erasure schedule. A
  plausible unauthorized execution starts incident/privacy assessment at
  awareness and may trigger the GDPR 72-hour notification analysis.

### Durable attachment-file deletion outbox rollout — 2026-10-18

- Commit `6522259589aee8e69ff9627b43e7cb551c2f3fcc` couples every
  `Attachment` deletion to a `PendingFileDeletion` row in the same database
  transaction. Rollback removes the intent and preserves the file; commit invokes
  storage deletion and clears the intent only after success. A process crash
  between commit and callback, storage outage, or post-delete database failure
  therefore leaves durable retry state instead of silently abandoning a private
  object. Storage delete is idempotent, so repeating an operation whose object is
  already absent is safe.
- Failures increment only an attempt counter and timestamp and emit exactly
  `attachment_file_delete_failed`; exception text, file name and storage path are
  excluded from logs and Telegram. The read-only admin exposes only identifiers,
  counters and timestamps. Daily maintenance reports queue size in dry-run and
  retries at most `ATTACHMENT_FILE_DELETION_BATCH_SIZE` entries (default 1,000,
  startup-bounded 1–10,000). Never-attempted entries sort ahead of failures and
  failed entries rotate by last attempt, preventing a permanently failing full
  batch from starving newer work.
- Migration `0030_pendingfiledeletion` adds unique storage-name intent plus an
  indexed creation time. The full stage-local contract passed 586 backend tests,
  36 monitor tests, Django checks and migration drift, compilation, Bash syntax,
  ShellCheck, immutable-Action pins, requirements/wheel-lock and deterministic
  SBOM validation, and `pip-audit 2.10.1` with zero known vulnerabilities. The
  unchanged frontend retained the immediately preceding green lint/build/audit
  and 39-test Playwright run.
- The pre-migration dump is
  `/home/micu/backups/nvidia_db/nvidia_db_20261018_163930_004442870.sql.gz`,
  14,878 bytes, mode `0600 micu:micu`, SHA-256
  `91c8ba0d31d4a8e228f0dedd73063ea00ecdb7f051a0f82fddf963b10e9d292f`.
  Gzip validation passed, its ACL evidence hashes to
  `417d903900e8f3ff4970410a75b0ed10102131856ba461b510ce48ca01cbbcb6`,
  and neither `aichat` nor `aichat-monitor` can read it. Migration took one
  second, preserved three users, six conversations, 16 messages and zero
  attachments, and created an empty queue; live PostgreSQL introspection
  confirmed storage-name uniqueness and the creation-time index.
- Backend release
  `/opt/aichat-backend-releases/release-20261018T133955_444721552` deployed in
  12 seconds with a valid manifest and exact commit marker. Its scanner/parser
  preflights passed. A rollback drill activated
  `/opt/aichat-backend-releases/release-20261018T132221_973720049` in two seconds
  and restored the new release in two seconds with all public/private probes
  green. There was no frontend change or frontend deployment in this stage.
- A real production-filesystem smoke used a content-free temporary owner and
  forced storage deletion to fail after the attachment database deletion
  committed. The queue retained one attempt while the private file remained;
  the deployed retry then removed both, and cleanup left zero temporary users,
  attachment rows, files or outbox rows. Final inventory returned exactly to
  three users, six conversations and 16 messages. Maintenance dry-run reports
  zero due accounts, zero pending files and valid audit integrity.
- Final public/origin health is `200`; anonymous models/export and `/.env` are
  `403`, direct media is `404`, TCP 8501 is closed, and the origin socket is
  `0660 aichat:aichat-origin`. Backend, maintenance, model-probe, monitor and
  config-watch timers/paths are active; backend and isolated parser have zero
  automatic restarts; `aichat-clamd` is active. The installed monitor is
  byte-identical to the repository, reports `active=[]`, and its state SHA-256 is
  `6d5812e751fbfc00495a7293ecbb71e5248b09e31d1dbc2150086ebeab6ff2b6`.
- Scoped CISO review treats silent residual personal-data retention as the main
  threat, followed by queue starvation and sensitive path leakage. Transactional
  intent, bounded fair retry and count-only sub-six-minute alerting reduce those
  risks and cap each maintenance run. A compromised database/service identity can
  still delete queue evidence, and a persistent storage outage delays physical
  erasure; timer health, private media permissions, protected backups and incident
  escalation remain mandatory. The outbox stores the private storage name because
  deletion requires it, but it is absent from APIs/admin lists/logs and remains
  under the existing database access boundary. No new NVIDIA transfer, processor
  or data class is introduced.

### Strict style CSP and responsive rollout — 2026-10-18

- Commit `d246b8bfa165ce94a9e8925f61dd4ed32c776e37` removes every
  application-owned JSX inline style and replaces it with named responsive CSS
  classes. The ESLint AST gate now rejects both `style` and
  `dangerouslySetInnerHTML` JSX attributes, preventing a routine UI change from
  silently requiring CSP relaxation. Email-only HTML retains inline formatting
  because it is never served into the web origin.
- The nginx policy changed from `style-src 'self' 'unsafe-inline'` to
  `style-src 'self'` without adding a nonce, hash, remote host or data scheme.
  `script-src` remains `self` only. Frontend lint/build, source and entry-HTML
  checks, `npm audit --audit-level=low` and all 39 Playwright flows passed; the
  audit reported zero known vulnerabilities and responsive coverage spans
  320/390/768/1440 px.
- Frontend release
  `/var/www/aichat-releases/release-20261018T134632_591255484` activated in one
  second. Its manifest SHA-256 is
  `6a0beafd66b1fbc2645fec025f865e24b2eff3ecdcfaa54f59e1f85e098cc184`.
  The installed root-owned vhost is byte-identical to the committed template;
  both SHA-256 values are
  `51d02afcf410558ca9f39f339245fe38bf727f8583c7fa5d44e8483829cef67e`.
  Two early rollout probes restored the prior vhost automatically: the first
  sampled a draining nginx worker immediately after reload, while the second
  used a `pipefail`/early-exit pipeline that falsely rejected a matching parsed
  config. The corrected probe validates committed bytes, parsed config and two
  consecutive strict-CSP responses before accepting activation.
- Coordinated rollback relaxed CSP before activating frontend release
  `/var/www/aichat-releases/release-20261018T132232_018494110`, then restored the
  new frontend before reapplying strict CSP. Rollback and restore each took one
  second; root/health returned `200`, anonymous private API `403`, and media
  `404` throughout. This ordering is mandatory while an older rollback release
  still contains React inline styles.
- Real Chromium smoke against the direct nginx origin at 320 and 1440 px found
  CSS applied, no horizontal overflow, no inline style attributes and zero CSP
  violations. The Cloudflare edge also applied CSS with no style violations, but
  injected a 456-character inline Browser Insights loader and a
  `static.cloudflareinsights.com` module for browser traffic. Both are blocked by
  the unchanged `script-src 'self'`, producing two expected script violations;
  no external script was added to the release. The correct remediation is to
  disable Browser Insights injection in Cloudflare, not weaken CSP.
- Final public root/health are `200`; anonymous conversations and `/.env` are
  `403`, media is `404`, nginx/backend have zero automatic restarts, and all
  application/monitor timers and the config-watch path are active. The planned
  vhost transition raised `protected_config_changed`, giving the expected
  sub-six-minute detection evidence; it must clear naturally after the journal
  window rather than by deleting operational evidence.
- Scoped CISO review ranks CSP bypass and remotely mutable edge code above minor
  visual rollback differences. The strict policy materially limits injected
  markup, while class-only styling and a CI lint invariant keep the control
  durable. Cloudflare can still mutate bytes delivered at the edge and a
  compromised same-origin release remains in policy, so manifest verification,
  origin-versus-edge browser probes and removal of Browser Insights remain
  necessary. No user data model or NVIDIA processing flow changed.

### Memory-hard password rollout — 2026-10-19

- Commit `907db5448f4ce31d42b2143e03d1e0e0c42f3f91` makes Django's
  standard scrypt hasher the production preference while retaining the legacy
  Django hasher order for stored-format and rollback compatibility.
  The deployed scrypt parameters are Django 6.0.8 defaults: work factor 16,384,
  block size 8 and parallelism 5. No new package, schema migration, secret or
  external processor was introduced.
- Password verification and hash mutation are now distinct operations. Login
  verifies without a setter, locks and rechecks the exact user hash, completes
  required TOTP/recovery verification, and only then writes the upgraded hash.
  Reauthentication follows the same order, rotates and reindexes the current
  session after an upgrade, and removes older indexed sessions that the changed
  password-derived session signature invalidates. Unknown users still pay one
  preferred-hasher operation to retain the existing enumeration resistance.
  Wrong passwords, missing 2FA and invalid 2FA cannot rewrite the credential.
- Six dedicated regressions cover the production hasher order, new-password
  creation, legacy login upgrade, wrong-password immutability, incomplete-2FA
  session preservation, complete-2FA upgrade and current-session preservation.
  The full backend suite passed 593 tests. Django checks and migration-drift,
  Python compile and package consistency, immutable Action pins, Bash/ShellCheck,
  36 monitor tests, key/retention/SBOM operation tests and the Python dependency
  audit all passed; the audit reported zero known runtime vulnerabilities.
- Pre-rollout dump
  `/home/micu/backups/nvidia_db/nvidia_db_20261019_001656_570109556.sql.gz`
  is owner-only mode `0600`, passed gzip validation and has SHA-256
  `bb7f4462689b60b58b8b119c1fc4e76018346e37b2cdeb86b0dc053cff8cb480`.
  The production inventory contained three users and three PBKDF2-SHA256 hashes;
  deployment deliberately did not bulk-rewrite them.
- Root-owned backend release
  `/opt/aichat-backend-releases/release-20261018T211701_986466991` carries the
  exact commit marker and manifest SHA-256
  `aae4aae1ac47c3e4364657e48bf4712f34ab30e193a2c9d072e9f98e9ab82c0d`.
  Django/scanner/parser preflights passed. The sole deploy warning remains the
  intentional absence of HSTS preload enrollment; the one-year HSTS policy is
  unchanged.
- A public HTTPS/Cloudflare smoke created one content-free temporary active user
  with a PBKDF2 hash, established CSRF state, completed login, reached an
  authenticated private route and proved that the stored hash became scrypt.
  Its indexed session and user were then deleted; database verification found
  zero smoke residue and the real aggregate returned to three PBKDF2-SHA256
  users. The application security event contained only numeric user/session
  counts, never the credential or hash.
- The active pre-rollout release independently generated and verified a scrypt
  hash before deployment. The formal rollback drill then activated
  `/opt/aichat-backend-releases/release-20261018T133955_444721552` in three
  seconds and restored the new release in two seconds. Final root/health are
  `200`, anonymous private API and `/.env` are `403`, media is `404`, the backend
  reports zero automatic restarts, and every persistent application service,
  timer and watch path is active. The monitor succeeded and raised the expected
  `protected_config_changed` issue for the planned unit/release installation;
  it must clear naturally after its six-minute journal window.
- Scoped CISO review ranks offline cracking after database theft first and
  authentication resource exhaustion second. Memory hardness materially raises
  attacker cost, while the existing IP limiter, 128-character input ceiling,
  24-thread bound and 1/1.5 GiB service memory thresholds bound online pressure.
  Deferred mutation closes the pre-2FA session-invalidation path. It does not
  mitigate phishing, credential stuffing, a live application compromise or a
  weak chosen password; incident containment, session revocation, 2FA and
  private/off-site backup controls remain required. No new personal-data class or
  NVIDIA data flow was created, so processor scope and GDPR breach escalation
  remain unchanged.

### Failed-login detection follow-up — 2026-10-19

- Review immediately after the password rollout found that directly invoking
  the deferred verifier bypassed Django's `authenticate()` dispatcher and its
  `user_login_failed` signal. Invalid credentials still failed closed, but the
  six-minute brute-force monitor would not have counted those failures. Commit
  `e059b2ea7ec786159c4bfd8096ab5babb1bfca78` replaces that direct call with a
  configured `DeferredPasswordUpgradeBackend`: Django again sets backend
  attribution and emits its standard failure signal, while hash mutation remains
  deferred until the view completes required 2FA.
- A dedicated regression proves that one failed legacy-password login emits
  exactly one pseudonymous `auth_failed` event and that neither submitted nor
  valid password material enters the event. The complete backend suite now
  passes 594 tests; Django/migration/compile, immutable Action pins, Bash,
  ShellCheck, 36 monitor tests, key/retention/SBOM tests and the production lock
  check also pass.
- Root-owned release
  `/opt/aichat-backend-releases/release-20261018T212153_465094940` deployed with
  the exact commit marker. A public Cloudflare/CSRF probe for a nonexistent user
  returned the generic `401` body and produced exactly one
  `event=auth_failed actor=network:<pseudonym>` record without username or
  password. No account or session was created. Rollback activated the preceding
  scrypt-capable release in two seconds and restored the corrected release in two
  seconds with all release/health/private-route gates green.
- This follow-up narrows detection MTTD back below six minutes for online
  password attacks; local or root-level journal deletion and distributed attacks
  below thresholds remain residual risks. It also demonstrates why security
  telemetry must be tested through the real endpoint rather than only by directly
  firing its signal in unit tests.

### Privacy-minimized request logging rollout — 2026-10-19

- Commit `11bfe93023571db156567799a14f436234d81c34` disables inherited
  combined access logging in both HTTPS and redirect servers for this vhost and
  replaces Gunicorn's combined record with timestamp, method, `PATH_INFO`, HTTP
  version, status, response bytes and latency. Commit
  `feae7d00e7da07a41f263fe059880739bb03484c` removes redundant timestamp
  brackets. Client IP, authenticated-user atom, query, raw request URI,
  User-Agent, Referer, forwarded-IP and cookie metadata are absent. Application
  security events continue to correlate unauthenticated actors through a
  secret-keyed 16-hex pseudonym.
- `scripts/test_privacy_logging.py` enforces both nginx and systemd invariants in
  CI. Its two tests, all 594 backend tests, 36 monitor tests, immutable Action
  pins, Python lock/SBOM/key/retention tests, Bash syntax and ShellCheck passed.
  Systemd 259 parsed the doubled-percent unit template successfully; inspection
  of installed Gunicorn 25.3.0 confirmed `%U` maps to `PATH_INFO`, while `%q` and
  `%r` are the excluded query/raw-URI atoms.
- Root-owned backend release
  `/opt/aichat-backend-releases/release-20261018T212637_063270843` is active at
  exact commit `feae7d00e7da07a41f263fe059880739bb03484c`; its manifest file
  SHA-256 is
  `4fed9be5de881eb2c2e9650096c5c0baeff967b2f1451f98a87db2d23fc2db46`.
  The installed unit is byte-identical to the repository at SHA-256
  `e274fd85cadfbd4e9dde755b8b19842fed074c676010bed2bb4de1847721c3a2`.
  The installed vhost is likewise exact at SHA-256
  `c6f0a51a3900c7f0b4ef2e2b6b0a28c55510a5e5f9b47dd75c67a7f8744a7581`;
  `nginx -t` passed.
- A public request carried unique query, User-Agent and Referer canaries. It
  returned the expected `403`; none of the three canaries appeared in the
  post-rollout backend journal or shared nginx access log. The resulting
  Gunicorn record contained only `GET /api/conversations/ HTTP/1.1`, status,
  bytes and latency. Historical raw logs were deliberately retained as incident
  evidence and expire through the existing daily/14-rotation host policy.
- Backend rollback activated the immediately preceding privacy-safe release in
  two seconds and restored the normalized release in two seconds. An independent
  vhost drill installed the exact pre-control config, passed root/health/private/
  media probes, and restored the minimized vhost in one second/under one second.
  Final public root/health are `200`, anonymous private API and `/.env` are
  `403`, media is `404`, nginx/backend are active with zero automatic restarts,
  and the expected protected-configuration alert remains within its six-minute
  journal window.
- Scoped CISO review treats quiet aggregation of IP/device/query metadata as the
  primary threat and loss of edge forensic detail as the control's tradeoff.
  API/admin operational shape, latency and HMAC-pseudonymous security events
  remain locally available; static/edge attribution requires separately governed
  external evidence. A compromised root can still change logging or erase local
  journals, so off-host integrity and retention remain open. The change reduces
  breach-notification data scope but does not alter the GDPR 72-hour assessment
  clock, NVIDIA processing, authentication, authorization or supply chain.

### Recent-auth conversation export and alert rollout — 2026-10-19

- Commit `eab06f2b54d11e74c71ff743311480485c2add38` applies the existing
  five-minute, session/user/password-bound recent-auth gate to owner-scoped
  Markdown exports. The UI replaces the direct link with an accessible focus-
  trapped dialog that verifies the current password and, when enabled, TOTP or
  an alphanumeric recovery code before starting the download. The response is
  still owner-filtered, rate/size bounded, streamed with `private, no-store`, and
  now explicitly returns `X-Content-Type-Options: nosniff`.
- Commit `513053ac80e77ffaefe15457fb08044c7a37b039` retains rare account and
  conversation export events at `WARNING`, containing only numeric internal
  references/counts/bytes and never credentials, cookies, IPs, titles,
  filenames or content. Commit `b0e4ca49dceabe14b0c6f5cde2b43ad11da6d5bc`
  converts every `conversation_export_authorized` occurrence in the six-minute
  journal window into a count-only monitor alert and adds specific containment,
  privacy-scoping and GDPR-awareness-clock guidance to the incident runbook.
- The complete 595-test backend suite and 40 responsive Chromium checks passed,
  including the 320 px password-to-2FA/recovery challenge, focus restoration and
  no-overflow download path. ESLint/build, 36 monitor tests, Django checks and
  migration drift, Python/Node advisory scans, lock/SBOM/Action-pin tests, Bash
  syntax and ShellCheck also passed. Visual inspection at 320 by 844 pixels
  confirmed readable errors, fields and actions without horizontal overflow.
- The pre-rollout database backup
  `/home/micu/backups/nvidia_db/nvidia_db_20261019_050113_035789301.sql.gz` is
  mode `0600`, gzip-valid and has SHA-256
  `a3bdb56e0a406010dc91547e9687cbde0020bb61e7d1b0bd6c32f839cd0ce938`.
  Backend release `/opt/aichat-backend-releases/release-20261019T020445_854666292`
  is active at exact commit `513053ac80e77ffaefe15457fb08044c7a37b039`;
  its manifest file SHA-256 is
  `25978b40f1434ffc40821b3125dbd8b8e63f004e9cd45b613c941a62f290bd59`.
  Frontend release `/var/www/aichat-releases/release-20261019T020119_916731323`
  is active from `eab06f2`; its manifest file SHA-256 is
  `67fad5a68600c92ba75b1850872953978e2ebec2a379fc8a7ec9dbaf30504c13`.
  The installed monitor matches `b0e4ca4` at SHA-256
  `d5fb00d78b204e4fdf8426d70873065f17279944b66e19a057e82dd063a4dade`.
- A public Cloudflare/CSRF canary created one temporary owner and conversation,
  logged in, deliberately aged its recent-auth marker, and proved conversation
  export failed with `403` plus `reauthentication_required`. Password
  reauthentication returned `200`; the bounded Markdown export then returned
  `200` with the exact private canary text and private/no-store/no-sniff headers.
  A complete account export also returned `200`. Privileged journal inspection
  found both content-free export events, and monitor evaluation raised the new
  count-only conversation alert. The temporary owner and cascaded rows were
  deleted; three independent residue checks returned zero. The alert resolved
  naturally after its six-minute window, the recovery notification succeeded,
  and the final owner-only monitor state reports `active=[]` at SHA-256
  `6cadfe3ee81076b07520cc6f699849611befb2baac6e6ec1bb34ca398e082d9e`.
- The backend drill activated the immediately preceding compatible release and
  restored the final release in three seconds/three seconds. The frontend drill
  activated its preceding manifest-verified release and restored the final
  release in under one second/one second. Final public root/health are `200`,
  anonymous private API and `/.env` are `403`, media is `404`; nginx syntax is
  valid and nginx, backend, parser and scanner are active with zero automatic
  backend restarts.
- Scoped CISO review treats stolen-session data exfiltration as the primary
  threat. Step-up materially shortens useful cookie-only compromise, but a cookie
  stolen inside the five-minute window or stolen credentials plus factor can
  still export; session revocation, alert response and the separate admin edge
  gate remain necessary. Local root can erase journals, so off-host integrity is
  still open. The change adds no new processor or supply-chain dependency. Any
  plausible unauthorized export still starts privacy/legal triage and the GDPR
  72-hour assessment clock; the alert deliberately omits the data needed for
  substantive scoping, which responders obtain under the runbook from database
  metadata rather than Telegram.

### Scheduled isolated restore verification rollout — 2026-10-19

- A real `restore_stale` alert exposed that the legacy weekly cron had not
  recorded a successful result since 11 October. Host journal evidence shows its
  18 October invocation created and removed a scratch database but produced no
  success record or failure notification. An immediate manual drill restored the
  newest private dump and validated `48|3|6|16` migrations/users/conversations/
  messages with zero scratch databases left behind.
- Commit `9f3491e` adds a persistent Sunday 05:15 systemd timer with ten minutes
  of jitter, a root-owned fixed runner and a resource/filesystem/network sandbox.
  It runs as the interactive owner only because the existing explicit
  passwordless-sudo risk exception is required for fixed local PostgreSQL
  `createdb`/`dropdb` operations; that grant was neither added nor broadened.
  The service can reach only loopback/Unix sockets, sees the runtime dotenv
  read-only, writes only the NVIDIA backup directory and uses the active
  root-owned application/Python releases. Its production exposure score is
  `4.7 OK`.
- Follow-ups `63b9107`, `f987d56`, `b790750` and `d16f456` make the installed
  runner independent of its source location, keep migration verification from
  initializing the runtime cache, clear rolled-back unit failure state, and
  atomically migrate only the exact NVIDIA restore cron entry. The daily NVIDIA
  backup cron and every unrelated crontab entry remain installed. On any rollout
  error, the timer, files, ACL/state and legacy cron state are restored.
- Commit `97ab924` adds the restore unit to the monitor's actual journal query;
  a failed unit raises the count-free `restore_drill_failed` condition
  immediately, while missing, malformed and older-than-eight-day success
  evidence remains covered. The incident runbook explicitly forbids recovery
  tests over production. The protected-change watcher now covers all three new
  installed artifacts and has 15 exact targets.
- Two initial production starts failed safely: first because the installed copy
  tried to derive a checkout-relative runtime, then because Django attempted to
  initialize its cache on a read-only mount. Both attempts automatically removed
  the new timer/files, restored the monitor and watcher active states plus
  `active=[]`, dropped their scratch databases, and left the application healthy.
  After the fixes, an independent transient unit with the same sandbox passed in
  3.129 seconds at 39.5 MiB peak before the installer was rerun.
- The final installed job completed at `2026-10-19T14:02:32+03:00`, restored
  `nvidia_db_20261019_050113_035789301.sql.gz`, validated `48|3|6|16`, returned
  `Result=success`/status `0`, and left zero scratch databases. The next trigger
  is 25 October at 05:17:31 EET. Installed runner/service/timer SHA-256 values are
  `9b508c13410ff3047b50e9c64a62e64aae07984aa3fe3a1fe4f0c7e2adfc32a0`,
  `76ec7f87e924b0cd2a5e6aeb3ae24f021757f75d8418250a45831615744cb9c8`, and
  `09294642988a3a1d2c7d2beb269f4a115f7d078b60c74589317b55cec0a917c5`.
  Every installed artifact byte-matches the repository and is root-owned.
- The restore log remains `0640 micu:micu` with only a read ACL for the dedicated
  monitor; the newest dump remains `0600 micu:micu` and a real one-byte monitor
  probe is denied. The final monitor state is empty. Backend `595/595`, frontend
  `40/40`, twenty repeated protected-export checks, 65 operational tests,
  ShellCheck, builds, Django/migration/package checks and both advisory scans are
  clean. Final public root/health are `200`, anonymous private API and `/.env`
  are `403`, media is `404`; nginx syntax is valid and the application services
  are active with zero backend restarts.
- Scoped CISO review treats same-host destruction and privileged tampering as the
  remaining recovery threats: this control proves local restorability but cannot
  survive VPS loss, ransomware or root deletion of both dumps and evidence. No
  new processor, network destination or supply-chain dependency was introduced.
  Encrypted immutable off-site recovery with a separately held key and documented
  RPO/RTO remains P0. Any indication that backup loss followed unauthorized data
  access still starts incident scoping and the GDPR 72-hour assessment clock.

### Unsafe legacy NVIDIA webhook containment — 2026-10-19

- Read-only host inspection found `webhook-deploy@nvidia.service` failed on every
  observed attempt since 12 October. Its shared legacy worker performed only a
  fast-forward pull and `sudo systemctl restart nvidia-chat.service`; the target
  no longer exists, the sandbox prevents the privilege transition, and the flow
  has no immutable application/Python release, migration, backup, health or
  rollback contract. The repository's latest remote CI run `39187411931` for
  `9de6b72` is green; this was a separate deployment failure, not a failed GitHub
  check.
- The GitHub hook was subscribed directly to `push`, so merely relaxing
  `RestrictSUIDSGID`/capability bounds would let remote changes reach a broad
  passwordless-sudo identity before CI completed. The NVIDIA hook is now inactive
  at GitHub, its local queue is empty, and its stale failed unit state is reset.
  The receiver and every non-NVIDIA hook/configuration remain untouched. Manual
  deployments continue through the committed atomic scripts and their existing
  preflight/rollback gates.
- During configuration inspection the NVIDIA hook credential entered command
  output and was therefore treated as compromised. A new 256-bit value was
  generated without printing it, updated through GitHub's hook-config API and
  installed locally as `0640 root:webhook-cicd`; the receiver restarted healthy
  and a GitHub ping delivery returned `200`. The invalidated root-only rollback
  copy is
  `/home/micu/backups/nvidia_config/hooks.json.before-nvidia-secret-20261019T110716Z`.
- Re-enablement requires a NVIDIA-only design triggered by successful completion
  of the named `CI` workflow, bound to its exact reviewed SHA, with clean/divergent
  worktree rejection and the current database backup, migration compatibility,
  immutable release, public/private health and rollback gates. It must not execute
  npm, repository scripts or newly pulled code with root merely because a signed
  push event arrived. Until that exists, fail-closed manual delivery has less
  availability than automation but materially smaller host-wide elevation and
  supply-chain blast radius.

### Five-minute Django-admin elevation rollout — 2026-10-19

- Commit `8e1ea3f` extends the existing user/session/password-bound recent-auth
  marker to every Django-admin request. Staff still need application-enrolled 2FA
  in the current session; after five minutes a safe GET returns to the SPA's
  password-plus-TOTP/recovery dialog, while POST and other mutations fail `403`
  instead of being redirected or silently converted to GET. Admin logout remains
  available after expiry. Successful step-up clears the per-window access marker
  so the next admin entry emits the existing privacy-minimized alert again.
- The dedicated rate-limited endpoint verifies staff, enabled 2FA, current
  password and a replay-protected authenticator/recovery code without exposing
  `is_staff` through the normal profile API or enabling Django's stock login.
  Redirect state is generated server-side from the bounded request path; both
  backend and browser independently reject cross-origin/non-admin destinations
  and discard query/fragment content.
- Backend `600/600`, frontend `42/42`, 65 operational tests, lint/build,
  ShellCheck, migration drift, Django deployment checks, `pip check`, `pip-audit`
  and npm audit passed. Ten repeated 320 px step-up/cancel runs passed; visual
  inspection at 320 by 844 pixels confirmed readable fields, visible focus,
  balanced actions and no horizontal overflow. The only deploy-check warning is
  the deliberate domain-wide HSTS-preload decision.
- The gzip-valid pre-deploy backup is
  `/home/micu/backups/nvidia_db/nvidia_db_20261019_141542_353691133.sql.gz`, mode
  `0600 micu:micu`, 16,300 bytes, SHA-256
  `5643ea28c4d0bdfdcea487e6adb3b224e5f18d7888a1ca0edfd23961cf65b14a`.
  Backend release `/opt/aichat-backend-releases/release-20261019T111548_065830480`
  is active at the exact implementation commit; its manifest file SHA-256 is
  `d2c4c79e4ec28f383707105e619cccbecf28f3b46693251ab9675efdaf098d0b`.
  Frontend release `/var/www/aichat-releases/release-20261019T111601_121301894`
  is active with manifest file SHA-256
  `dc4b61304f0604c795fb0a3792e9ad3afcbcc48a33571f66017f4505217943a9`.
- A public same-origin canary created an isolated temporary superuser, logged in,
  enrolled and verified 2FA, and received `200` from fresh admin. After directly
  aging only its recent-auth timestamp, admin GET returned the exact safe `302`
  step-up location and an admin POST returned `403` without mutation. Password
  plus a single-use recovery code returned `200`, after which admin returned
  `200` again. Two preliminary clients also proved HTTPS Origin/Referer and
  post-login CSRF-token rotation fail closed. All canary users, factors and
  sessions were deleted; database residue and journal username searches are zero.
- The backend rollback drill activated the immediately preceding compatible
  release and restored the exact new release in two seconds/two seconds. The
  frontend symlink drill activated the preceding manifest-verified release and
  restored the new release in under one second/one second. Final public root and
  health are `200`, anonymous private API and `/.env` are `403`, media is `404`;
  nginx syntax is valid, the backend runs from the recorded release with zero
  automatic restarts, and the NVIDIA push webhook remains disabled. The planned
  unit/release change and public admin canary raised `protected_config_changed`
  and `admin_access`; after the six-minute journal window, the successful
  `14:23:24+03` resolution run delivered both recovery notices and persisted
  `active=[]` without deleting or editing monitor evidence.
- Scoped CISO review treats a stolen staff cookie as the primary threat. The
  change bounds cookie-only elevation to five minutes and prevents stale
  mutations, but cannot defeat theft inside that window or an attacker holding
  password plus factor. Cloudflare Access/VPN, minimal superusers, session
  revocation and externally retained security evidence remain necessary. No new
  processor or supply-chain dependency was introduced. A plausible unauthorized
  admin access or change still starts containment, privacy scoping and the GDPR
  72-hour assessment clock.

### Signed isolated model-availability rollout — 2026-10-19

- Commits `3fd5b9b` and `038ca5f` move the twice-weekly NVIDIA probe from the
  web identity to non-login `aichat-model-probe`. Its minimal settings have no
  installed Django applications, database, SMTP, session, 2FA or audit secrets.
  systemd exposes only the NVIDIA API key and an Ed25519 private key through the
  unit's ephemeral credential mount; `ProtectHome=tmpfs`, an empty capability
  set, `NoNewPrivileges`, strict filesystem protection and a socket-bind deny
  constrain the process to provider egress and its private state directory.
- The probe owns `/var/lib/aichat-model-probe/model_status.json` with mode `0640`
  and owner/group `aichat-model-probe:aichat`; the backend can read but cannot
  write it or read either root-owned credential source. It verifies a canonical Ed25519
  signature using only `/etc/aichat/model-status-public.pem`, plus regular-file,
  exact owner/group/mode, size, schema, catalog, range, time and freshness
  constraints. Missing/unsigned state, symlinks, permission drift, content
  changes and public-key rotation fail closed. Explicit signing-key rotation is
  available for incident response and never enables an unsigned compatibility
  window.
- Commit `acccc4a` adds immediate `model_probe_failed` detection in addition to
  existing degraded, authorization and invalid-status alerts. The initial
  rollout monitor SHA-256 was
  `c3f924ccde77f66f63706962b69e5ecdc6864c229d307efef835ada7964513bc`;
  its config watcher SHA-256 is
  `08e2dfdd87ab4f40a2f1047897e6dfee677933d71e4e4738c5051ef70f2d0888`
  and covers exactly 20 paths, including the probe credential, signing keys,
  sysusers definition, service and timer.
- Backend `608/608` and 70 operational tests passed, including missing and
  modified signatures, changed results, unsigned extra fields, public-key
  replacement, symlink state, permission drift, minimal-settings startup,
  credential scope and unit hardening. Bash syntax, ShellCheck, Python compile,
  migration drift, Django checks, immutable Action pins and `pip check` passed;
  `pip-audit` and npm audit found no known vulnerabilities. The only production
  check warning remains the deliberate domain-wide HSTS-preload decision. No new
  package or processor was introduced; Ed25519 uses the already locked
  `cryptography` runtime.
- The gzip-valid pre-deploy database backup is
  `/home/micu/backups/nvidia_db/nvidia_db_20261019_185440_032232347.sql.gz`, mode
  `0600 micu:micu`, 16,307 bytes, SHA-256
  `bc9d9ae16aec345cf3794d6b5c79ea5a3ad45e46ee3b4020c5874035507511c0`.
  Initial signed-probe backend release
  `/opt/aichat-backend-releases/release-20261019T155531_510720445` records exact
  commit `038ca5f62afbaa440f6b0aaa507ae40367a855d9`; its manifest file SHA-256 is
  `9319378f1c78289475f8438bb70b7eb6a776a8437021e130ca18e6b85a0dfba1`.
  A controlled backend drill activated the immediately preceding compatible
  release and restored the exact active release in two seconds/two seconds with
  a new verified PID and `NRestarts=0`.
- The real isolated full-stream probe completed in 2m26s with a 51 MB peak and
  signed all 20 catalog outcomes. Independent public-key verification passed.
  The signed state SHA-256 is
  `3514c6632c8635259100b4346e72d1dc3eaefbcc739dc44f3557df077752ab37`.
  The fresh-trust baseline conservatively exposes 7 models and hides 13: one
  definitive retirement and 12 inconclusive timeout/network/protocol outcomes.
  An HTTPS canary logged in through the real CSRF/session boundary, received
  `200` from `/api/models/`, saw the same `degraded` 20/7/13 aggregate and no
  signature or private outcome; its user/session residue is zero. The next
  persistent probe is scheduled for Thursday 2026-10-22 near 04:00 EEST.
- The first service activation failed before writing state because a default
  expression eagerly referenced `BASE_DIR`, which the deliberately minimal
  settings omit. Models remained fail-closed and public health stayed `200`;
  commit `038ca5f` made the fallback lazy, and the second activation succeeded.
  The first monitor-install attempt then refused an expected live rollout alert
  and transactionally restored its previous files/state. A scheduled alert send
  also failed closed during a transient Telegram outage without advancing state;
  the post-window monitor rerun succeeded with `active=[]`, the second installer
  completed, and a credential-isolated notification test subsequently sent.
  Restore validation passed twice against the retained backup with counts
  `48|3|6|16`; database dumps remain unreadable to the monitor identity.
- Final root/health return `200`, anonymous private API and `/.env` return `403`,
  arbitrary media returns `404`, nginx syntax is valid, all model/monitor/
  config-watch/restore timers or paths are enabled and active, and every related
  oneshot reports success. The NVIDIA GitHub push hook remains disabled.
- Scoped CISO review treats web-worker takeover, probe takeover and signing-key
  theft as distinct threats. The change prevents `aichat` alone from forging the
  picker, but a compromised probe can still sign arbitrary availability and use
  the shared provider credential; rotate both credentials after compromise and
  move signing to an external/hardware trust boundary before multi-host scale.
  Status contains no user content or identifier, but journals and alert delivery
  remain local/vendor-dependent. Preserve evidence, assess prompt/provider data
  scope, and start the GDPR 72-hour assessment clock if an incident plausibly
  reaches personal data rather than only public model metadata.

### Independent signed-model-state monitoring rollout — 2026-10-19

- Commit `7c151f1` adds a credential-free checker to the root-owned backend
  release. Every monitor run invokes it only after the active backend and Python
  manifests pass, with a fixed minimal environment that excludes the Telegram
  credential directory and NVIDIA key. It accepts only `verified` or `degraded`
  signed state; missing, stale, unreadable, forged or permission-drifted state
  becomes the fixed `model_status_health` issue even if no user opens the picker.
- The monitor receives supplementary group `aichat` only inside its systemd
  sandbox. `ProtectHome=tmpfs` hides the application dotenv/cache/media, while
  `/var/lib/aichat-model-probe/model_status.json` and the public key remain
  read-only; the private signing and NVIDIA credential sources remain unreadable.
  A transient unit with the installed geometry proved all six boundaries. The
  checker returned only `model_status=degraded`, with no model outcome or secret.
- Commits `87aab9a` and `e4571c0` make backend deployment validate the dedicated
  nologin identity/sysusers definition, config and state directories, exact
  owners/modes/sizes, matching Ed25519 pair, backend read/deny geometry and any
  existing signed-state file before staging or switching a release. The read-only
  `--check-model-probe-boundary` mode passes in production and allows the same
  gate to be exercised without a deploy.
- Backend `608/608` and 74 operational tests pass. New regressions cover clean,
  failed, malformed-output and timeout checker executions, credential-free env,
  partial monitor configuration, supplementary-group/home isolation and deploy
  boundary structure. Bash syntax, ShellCheck, Django deployment/migration checks
  and `pip check` pass; the only deployment warning remains the explicit HSTS
  preload decision.
- Backend release
  `/opt/aichat-backend-releases/release-20261019T160957_489332229` is active at
  exact commit `7c151f1f0018d138d133349bc9d6c3191b8721c5`; manifest file SHA-256 is
  `10119ef1ddcabaf73c70e16343fee901327d1ab48806ba6dc3e5390ec47303e2`.
  The rollback drill activated the preceding signed-probe release and restored
  the exact checker release in two seconds/two seconds with a new healthy PID.
- The installed monitor SHA-256 is
  `2d91bd78a666ef405a34b93c025eedcd84d0066b644b9f4b1fb52682b482cad2`;
  its unit SHA-256 is
  `3fdc7fe16ec2b932799b99dd088ab438f78f7ee448f53512b659ed4584cdeb33`
  and its systemd exposure is `2.9 OK`. The planned backend/unit change raised
  `protected_config_changed`; after the six-minute window the monitor delivered
  recovery, persisted `active=[]`, and the transactional installer plus a second
  real checker run completed successfully. Restore validation again returned
  `48|3|6|16`, and private dumps remain inaccessible to the monitor.
- Scoped CISO review: the new group grant gives a compromised monitor read access
  only to public model metadata/key. Its pre-existing boundary includes its own
  Telegram credential and bounded journal/health evidence; it cannot write model
  state or read app/provider/signing secrets. Executing the checker after both
  manifests pass prevents a writable-path substitution, while root compromise
  remains out of scope for this boundary and can replace monitor plus evidence.
  No new vendor, network
  egress or personal-data flow was introduced; external evidence retention and
  alert-channel redundancy remain open.

### Public Privacy Center and processing-register rollout — 2026-10-20

- Commit `f9d64e4` adds a public, versioned `/privacy/` route that renders without
  mounting the authenticated application or starting any API request. It
  consolidates account/security, chat/file and operations data; NVIDIA,
  mailcow, Cloudflare and local-inspection destinations; exact implemented
  retention; rotating-backup deletion lag; and current export, deletion,
  archived-retention, attachment-inclusion, session and 2FA controls. Login,
  Settings and the NVIDIA disclosure link to the notice.
- `docs/DATA_PROCESSING_REGISTER.md` records the code-backed inventory,
  technical safeguards, unresolved governance evidence and the notice/change
  rule. Both artifacts explicitly avoid claiming a legal basis, blanket consent,
  completed vendor review, controller identity/contact, DPA, NVIDIA region/
  retention/training terms or production entitlement that is not evidenced.
- All 608 backend, 98 operational and 45 responsive browser tests passed.
  ESLint, the bound production build, Bash syntax, ShellCheck and immutable-
  Action checks passed; npm and pip audits reported no known advisory. Browser
  regressions cover 320 and 1440 pixels, no horizontal overflow, safe links,
  notice access from all three entry points, and zero `/api/` requests on the
  public page.
- Signed frontend release
  `/var/www/aichat-releases/release-20261020T001039_571602493` was activated at exact
  commit `f9d64e4bd64dd9754d1893e87a7aa3fea6ff3014`, verified by key fingerprint
  `ced3b7c3d60778e7c0c95ad1dcfad7b44c57ad922c9e78f707eda2149596f1b1`.
  Origin and Cloudflare returned `200`; production Chromium at 320 and 1440
  pixels rendered notice version `2026-10-20.1`, made no API calls, had no
  overflow or inline styles, and loaded no remote script at origin. Cloudflare
  still injected its Browser Insights URL at the edge, where the unchanged CSP
  blocked it. A signed live frontend rollback completed in one second and
  restored the exact active release in zero seconds; the security monitor then
  returned `Result=success` and exit status zero.
- Residual governance remains account-side, contractual and legal: publish the
  responsible identity, jurisdiction and privacy contact; establish lawful
  bases and rights handling; retain NVIDIA/Cloudflare/mail DPA, retention,
  training, region, subprocessor, incident and entitlement decisions; remove
  Browser Insights in Cloudflare; and define external-log plus encrypted
  off-host-backup retention/deletion handling. The technical publication does
  not close those decisions.

### Attachment-aware model discovery rollout — 2026-10-20

- Commit `3b44568` centralizes browser-side model capability checks and makes the
  explorer evaluate every included pending file against every live model. It
  reports the number of compatible models, offers a responsive “Fits current
  files” filter, and exposes fit or incompatibility on cards and in comparisons.
  Files explicitly excluded by the owner do not constrain model discovery.
- The same contract closes a frontend preflight defect: switching from a model
  that accepts several images to one with a lower per-request maximum previously
  validated each image independently and allowed the backend to reject the total
  only at send time. Pending and historical image sets now enforce the cumulative
  model limit before provider work; incompatible pending files block send and
  historical overflow is omitted with an accurate explanation.
- All 608 backend, 108 operational and 48 responsive browser tests passed.
  ESLint, the bound production build, Bash syntax, ShellCheck and immutable-
  Action checks passed; npm and pip audits reported no known advisory. Browser
  regressions cover current-file filtering, the lower-count model transition and
  historical overflow, in addition to the existing mobile/desktop suite.
- Signed frontend release
  `/var/www/aichat-releases/release-20261020T050049_218001778` was activated at exact
  commit `3b44568767ce8e0a7d6aaffc88ee0773558e728a`, verified by key fingerprint
  `ced3b7c3d60778e7c0c95ad1dcfad7b44c57ad922c9e78f707eda2149596f1b1`.
  Origin and Cloudflare returned `200` for the app, Privacy Center and health;
  authenticated/private and fabricated-media probes returned the expected
  `403`/`404`. A signed rollback activated the preceding Privacy Center release
  in zero seconds and restored this exact release in one second. The security
  monitor then returned `Result=success` and exit status zero.

### Attachment compatibility recovery rollout — 2026-10-20

- Commit `633083b` adds a direct recovery action to an incompatible-attachment
  warning. It opens Model Explorer with stale search, purpose and favorite
  filters cleared and the complete-current-file compatibility filter enabled,
  so only models that can accept the included set remain. The destructive
  removal action remains available as a separate choice.
- Dialog focus returns to the initiating recovery button on close, or to the
  permanent explorer trigger when selecting a compatible model removes that
  warning from the document. The focus trap, Escape and backdrop-close behavior
  share this fallback. A 390-pixel regression exercises the full upload,
  incompatible-model switch, filtered recovery, compatible selection, warning
  removal and focus-return path; all 49 responsive browser tests, ESLint and the
  production build passed.
- Signed frontend release
  `/var/www/aichat-releases/release-20261020T050512_423596019` is active at exact
  commit `633083be72f963c10ac6bb070adcf0f0aeeced69`, verified by key fingerprint
  `ced3b7c3d60778e7c0c95ad1dcfad7b44c57ad922c9e78f707eda2149596f1b1`.
  Origin and Cloudflare returned `200` for the app, Privacy Center, health and
  security contact; the private conversation route and fabricated media path
  returned `403` and `404`. A signed rollback activated the preceding release in
  one second and restored this exact release in zero seconds. Repeated probes
  remained correct and the security monitor returned `Result=success` with exit
  status zero.

The verdict remains yellow: deployment closed A-01/A-03 configuration rollout and
A-04 local-mode actions. The isolated restore drill, durable request budgets,
generation idempotency, saved-message byte ceilings, archived-chat retention,
bounded usage-metadata retention, strongly authenticated full-account export,
privacy-minimized alerting, and verified-staff-2FA admin gate were completed
immediately afterward; actual-token budgets and invite-only registration are now
implemented, and privileged changes are now privacy-minimized and integrity
checked. Contract/GPU monetary enforcement and entitlement evidence, external
security-log retention, an admin perimeter control, and encrypted off-site backup
remain open.

## References

- [Django deployment checklist](https://docs.djangoproject.com/en/6.0/howto/deployment/checklist/)
- [django-ratelimit security considerations](https://django-ratelimit.readthedocs.io/en/stable/security.html)
- [GDPR consolidated text](https://eur-lex.europa.eu/eli/reg/2016/679/oj)
- [ICO personal data breach guidance](https://ico.org.uk/for-organisations/report-a-breach/personal-data-breach/personal-data-breaches-a-guide/)
- [NVIDIA NIM product and licensing FAQ](https://docs.api.nvidia.com/nim/docs/product)
- [NVIDIA privacy policy](https://www.nvidia.com/en-us/about-nvidia/privacy-policy/)
- [NVIDIA developer terms](https://developer.nvidia.com/legal/terms)
- [NVIDIA vision-language model support](https://docs.nvidia.com/nim/vision-language-models/2.0.10-variant/introduction.html)
- [NVIDIA hosted LLM API catalog](https://docs.api.nvidia.com/nim/reference/llm-apis)
- [NVIDIA Nemotron 3.5 Lightning model card](https://build.nvidia.com/nvidia/nemotron-3.5-lightning-30b-a3b/modelcard)
- [NVIDIA GLM 5.3 Flash model card](https://build.nvidia.com/z-ai/glm-5.3-flash/modelcard)
- [CycloneDX specification overview](https://cyclonedx.org/specification/overview/)
- [NVIDIA DiffusionGemma endpoint](https://build.nvidia.com/google/diffusiongemma-26b-a4b-it)
- [NVIDIA Ising Calibration 1.5 endpoint](https://build.nvidia.com/nvidia/ising-calibration-1.5-31b)
- [NVIDIA Riva Translate v2 API contract](https://docs.api.nvidia.com/nim/re/reference/nvidia-riva-translate-4b-instruct-v2-infer)
