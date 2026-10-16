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
upstream errors. `X-Real-IP` is accepted only from the local tunnel/nginx path and
upstream responses are now logged server-side while clients receive generic text.

## Findings register

| ID | Severity | Finding | Repository control | Residual action |
|---|---|---|---|---|
| A-01 | Critical | `/media/` could bypass object ownership | Authenticated download endpoint and deployed nginx denial | Keep the external `/media/*` 404 regression probe in every rollout |
| A-02 | High | PDF/DOCX handled in the request process | Deployed sequential Unix-socket parser under dedicated `aichat-parser`; no app secrets/network/capabilities; strict protocol plus child/cgroup time, CPU, memory, file, descriptor and task limits; outage fails closed | Keep limits low; move large asynchronous jobs to a durable queue before raising the 10 MB boundary |
| A-03 | High | Shared service user had broad host reach | Dedicated non-login `aichat` web/timer identity, separate root-owned application/dependency releases, narrowly bound runtime paths, unprivileged app database role and restrictive systemd sandbox | Move file-based secrets to systemd credentials during a controlled rotation |
| A-04 | High | Existing backups were mode `0664` in a `0755` directory | Private modes, `umask 077`, atomic output, locks, gzip verification, and scheduled restore drills are deployed | Add encryption and a tested off-site copy |
| A-05 | High | Anonymous session auth did not uniformly enforce CSRF | Strict session authentication and object-only JSON parser | Keep regression tests in CI |
| A-06 | High | Raw session keys were returned to the browser and long-lived stolen sessions could invoke session controls without fresh proof | HMAC-derived opaque non-bearer handles backed by an indexed owner/session registry; fixed absolute expiry/account caps; five-minute user/session/password-bound recent authentication with required 2FA and responsive step-up before revocation | Rotate sessions after any suspected historic disclosure; retain recent-auth and expiry regressions |
| A-07 | High | Dependency advisories in runtime/tooling packages | Pinned upgrades, SHA-256-locked production wheels with a release-embedded CycloneDX SBOM, full-commit-SHA CI Actions, plus weekly `pip-audit` and `npm audit` | Review failed scheduled jobs; use an update bot with controlled merges and retain signed provenance evidence |
| A-08 | Medium | File-cache increments were not safe under concurrency | `flock`-serialized cache add/increment with multiprocess test | Replace with Redis/PostgreSQL counters before horizontal scaling |
| A-09 | Medium | Declared MIME/extension or model capability could be misleading | Local fail-closed ClamAV scanning before parsing/dedup/storage, isolated document parsing, file signatures, safe stored names, PNG validation, download headers, and server-side per-model MIME/size/count enforcement | Keep official signatures current; signature scanning cannot establish that novel content is benign |
| A-10 | Medium | Model history, repeated calls or malformed provider responses could multiply payload, memory and cost | Per-message/history caps; model-specific image-count caps and incompatible-history filtering; PostgreSQL daily request and actual-token budgets per-user/globally; pre-call token reservations reconciled from terminal provider usage; exact NVIDIA endpoint validation; no redirects; bounded/shape-validated SSE and image JSON; kill-switch | Map the actual contract/GPU cost into a hard monetary limit and add administrative override audit |
| A-11 | Medium | Registration and recovery can be automated or used for account enumeration | Invite/open/closed modes; 100-bit one-time codes stored only as HMAC; atomic consumption/mail rollback; expiry and 90-day audit retention; IP throttles; uniform duplicate/recovery responses; case-insensitive database uniqueness | Keep production invite-only; add Turnstile only before reopening public signup; assess timing side channels under load |
| A-12 | Medium | Security event detection was incomplete | Structured events and five-minute alerts cover auth/rate/admin-denial bursts, valid admin access, privileged changes and audit-integrity failures, 2FA disable/key failures, invite rejection/consumption and verified signup, incompatible attachment/model bursts, malware detections, scanner outage/health/signature freshness, parser outage/health/failure correlation, chat-object quota blocks, generation interruptions/mismatched idempotency reuse, session registry mismatches/cap pressure, global budget, missing/malformed provider usage, token reservation overruns, errors, protected dotenv/vhost/unit/monitor changes, all three active release manifests, executable-release retention, backup and restore freshness | Add external retention and contract-spend correlation; tabletop the alert path |
| A-13 | Medium | TOTP secrets and recovery hashes depended directly on `DJANGO_SECRET_KEY`, and invalid ciphertext could fall through as plaintext | Independent bounded keyring; purpose-separated derivation; versioned TOTP/recovery envelopes; strict base32/digest validation; fail-closed unknown/corrupt artifacts; transactional and lazy secret rewrap; inventory/audit gate; five-minute key-error alert | Move root keys from dotenv to systemd credentials or KMS/HSM; retain an old key until every recovery hash dependency is consumed or regenerated |
| A-14 | Low | No public coordinated disclosure path | `SECURITY.md` and `/.well-known/security.txt` added | Test after every frontend deploy |
| A-15 | High | Django admin's stock login accepted only a password even when application 2FA was enabled | Direct/password-only admin access is denied; current staff session must verify application 2FA; access and privacy-minimized add/change/delete events are alerted and HMAC-audited for 365 days with an independent versioned keyring and fail-closed inventory/rotation controls | Add Cloudflare Access/VPN, minimize superusers, move audit roots to systemd credentials or KMS/HSM, and retain security events externally |
| A-16 | High | Production entitlement for the NVIDIA-hosted API is not evidenced; NVIDIA describes Developer Program endpoints as prototyping access | Durable request/token ceilings, fail-closed metering and global kill-switch bound technical consumption | Confirm and record an appropriate production license/contract, or restrict the deployment to private evaluation use; implement its real monetary/GPU budget |
| A-17 | Medium | Content hashes or extracted-text previews could correlate files across users, disclose private text, or race under parallel uploads | HMAC-SHA256 fingerprints are secret-keyed and owner-scoped, never serialized/logged, and unique only for unlinked files per owner; preview lookup is owner-scoped, truncated to 4,000 characters, rate-limited and `private, no-store`; the browser renders it as text; a user-row lock plus a partial PostgreSQL unique constraint closes concurrent duplicate creation | Treat fingerprint-key rotation as a deduplication reset; retain malware/ownership/cache/XSS regressions |
| A-18 | Medium | A missing/stale/tampered runtime model-status file could reactivate retired endpoints, while transient NVIDIA failures could hide working models for a week or leave permanently broken models trusted forever, leak provider failure details, or present volatile latency as model quality | The private `0600` file is bounded, schema/catalog/range/time validated, required in production, expires after eight days and is atomically replaced; invalid state hides all models and raises a monitored event. Definitive failures change availability. Transient outcomes retain the last trusted decision for two consecutive runs, fail closed on the third and recover on success; the bounded private streak is backward compatible and monitored. The authenticated API exposes only aggregate state and rounded successful samples labeled as a synthetic 1-token check | A compromised `aichat` identity can still rewrite its runtime status; isolate/sign the probe output before multi-host scaling and never treat a single sample as an SLA or quality score |
| A-19 | High | Production workers imported application code and dependencies from mutable checkout paths, allowing old/new mixtures or local tampering | Deploys use separate root-owned, manifest-verified application and SHA-256-locked minimal dependency releases with an embedded CycloneDX SBOM, atomically switch trusted symlinks, hide checkout source/venv from the service, restore prior targets on failed probes, bound executable roots to the active plus two rollbacks, and have passed a controlled production rollback/restore drill for both release families | Add signed builder provenance and define the supplemental-archive lifecycle plus off-host evidence retention |
| A-20 | Medium | Users could send prompts, history and selected files to NVIDIA without a durable, current disclosure acknowledgement | A versioned, owner-bound timestamp is stored without prompt/file/IP data; chat, regeneration and image generation return `428` before leases, budget reservations, message writes or provider egress until the current disclosure is accepted. The keyboard-accessible mobile UI names each data class, links official NVIDIA privacy/terms pages and offers an equal cancel path | Obtain legal review of the actual processing basis, publish the complete operator privacy notice, confirm NVIDIA retention/training/DPA/region and production-entitlement terms, and bump the version when the data flow materially changes |
| A-21 | Medium | Retried or concurrent chat generation could duplicate provider cost or mutate history ambiguously | Owner-scoped UUID idempotency, HMAC-bound request shape, durable job outcomes, lease/job fencing, stored-result SSE replay, attachment/message reconciliation, bounded retention and interruption/conflict alerts are deployed | NVIDIA cannot join the local database transaction; keep automatic retries disabled for failed/interrupted jobs and reconcile provider evidence before an explicit new-key attempt |
| A-22 | Medium | Authenticated accounts could grow saved message text until database/egress pressure affected every tenant | PostgreSQL-generated UTF-8 byte counts; transactionally serialized 16 MiB/conversation, 64 MiB/user and 1 GiB/service ceilings; worst-case in-flight reservations; net-growth regeneration; owner-only usage UI; generic global response; monitored quota events; read-only message admin | Define and enforce linked-history retention/deletion before materially raising account or quota volume |

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
  unchanged, and linked-history retention plus off-host evidence remain open.

The verdict remains yellow: deployment closed A-01/A-03 configuration rollout and
A-04 local-mode actions. The isolated restore drill, durable request budgets,
generation idempotency, saved-message byte ceilings, privacy-minimized alerting,
and verified-staff-2FA admin gate were completed
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
