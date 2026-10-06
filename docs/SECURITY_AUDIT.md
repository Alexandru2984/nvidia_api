# Security audit

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
archive validation, resource-bounded document parsing in a child process, atomic
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
| A-02 | High | PDF/DOCX handled in the request process | Magic-byte checks, ZIP limits, subprocess timeout and OS resource limits | Move parsing to a dedicated worker/container before higher-volume use |
| A-03 | High | Shared service user had broad host reach | Dedicated non-login `aichat` web/timer identity, app-owned runtime paths, unprivileged app database role and restrictive systemd sandbox | Move file-based secrets to systemd credentials during a controlled rotation |
| A-04 | High | Existing backups were mode `0664` in a `0755` directory | Private modes, `umask 077`, atomic output, locks, gzip verification, and scheduled restore drills are deployed | Add encryption and a tested off-site copy |
| A-05 | High | Anonymous session auth did not uniformly enforce CSRF | Strict session authentication and object-only JSON parser | Keep regression tests in CI |
| A-06 | High | Raw session keys were returned to the browser | HMAC-derived opaque session handles | Rotate sessions after any suspected historic disclosure |
| A-07 | High | Dependency advisories in runtime/tooling packages | Pinned upgrades plus weekly `pip-audit` and `npm audit` | Review failed scheduled jobs; use an update bot with controlled merges |
| A-08 | Medium | File-cache increments were not safe under concurrency | `flock`-serialized cache add/increment with multiprocess test | Replace with Redis/PostgreSQL counters before horizontal scaling |
| A-09 | Medium | Declared MIME/extension or model capability could be misleading | File signatures, safe stored names, PNG validation, download headers, and server-side per-model MIME/size/count enforcement | Add malware scanning/quarantine if uploads become public-facing |
| A-10 | Medium | Model history or repeated calls could multiply payload and cost | Per-message/history caps; model-specific image-count caps and incompatible-history filtering; PostgreSQL daily request and actual-token budgets per-user/globally; pre-call token reservations reconciled from terminal provider usage; kill-switch | Map the actual contract/GPU cost into a hard monetary limit and add administrative override audit |
| A-11 | Medium | Registration and recovery can be automated or used for account enumeration | Invite/open/closed modes; 100-bit one-time codes stored only as HMAC; atomic consumption/mail rollback; expiry and 90-day audit retention; IP throttles; uniform duplicate/recovery responses; case-insensitive database uniqueness | Keep production invite-only; add Turnstile only before reopening public signup; assess timing side channels under load |
| A-12 | Medium | Security event detection was incomplete | Structured events and five-minute alerts cover auth/rate/admin-denial bursts, valid admin access, privileged changes and audit-integrity failures, 2FA disable, invite rejection/consumption and verified signup, incompatible attachment/model bursts, global budget, missing/malformed provider usage, token reservation overruns, errors, backup and restore freshness | Add external retention and malware/contract-spend correlation; tabletop the alert path |
| A-13 | Medium | TOTP secrets depend on `SECRET_KEY`-derived protection | Access and file permissions restrict the key | Use key versioning/KMS-backed encryption before routine key rotation |
| A-14 | Low | No public coordinated disclosure path | `SECURITY.md` and `/.well-known/security.txt` added | Test after every frontend deploy |
| A-15 | High | Django admin's stock login accepted only a password even when application 2FA was enabled | Direct/password-only admin access is denied; current staff session must verify application 2FA; access and privacy-minimized add/change/delete events are alerted and HMAC-audited for 365 days | Add Cloudflare Access/VPN, minimize superusers, and retain security events externally |
| A-16 | High | Production entitlement for the NVIDIA-hosted API is not evidenced; NVIDIA describes Developer Program endpoints as prototyping access | Durable request/token ceilings, fail-closed metering and global kill-switch bound technical consumption | Confirm and record an appropriate production license/contract, or restrict the deployment to private evaluation use; implement its real monetary/GPU budget |
| A-17 | Medium | Content hashes or extracted-text previews could correlate files across users, disclose private text, or race under parallel uploads | HMAC-SHA256 fingerprints are secret-keyed and owner-scoped, never serialized/logged, and unique only for unlinked files per owner; preview lookup is owner-scoped, truncated to 4,000 characters, rate-limited and `private, no-store`; the browser renders it as text; a user-row lock plus a partial PostgreSQL unique constraint closes concurrent duplicate creation | Treat fingerprint-key rotation as a deduplication reset; add malware quarantine before public uploads and retain ownership/cache/XSS regressions |
| A-18 | Medium | A malformed/tampered runtime model-status file could reactivate retired endpoints, leak provider failure details, or present volatile latency as model quality | The private `0600` file is bounded, schema/catalog/range validated and atomically replaced; an existing invalid file hides all models and raises a monitored event; the authenticated API exposes only rounded successful samples and labels them as a synthetic 1-token availability check | A compromised `aichat` identity can still rewrite its runtime status; isolate/sign the probe output before multi-host scaling and never treat a single sample as an SLA or quality score |

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
six minutes and any invalid runtime model-status file use the same alert path.
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
- Cloudflare carries public traffic through Tunnel and may process network and
  request metadata. Review account security, access logs, DPA, and breach terms.
- The self-hosted mail system handles addresses and OTP/reset messages. Restrict
  logs, monitor delivery abuse, and ensure credentials are unique to this app.
- GitHub hosts source and CI metadata. Keep production secrets out of repository
  variables unless required and use least-privilege workflow permissions.

No vendor review was evidenced in-repository during this audit; owner confirmation
is required before describing those controls as complete.

## Verification evidence

- 301 backend tests pass, including ownership, CSRF, concurrency, recovery,
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
  retention remains required. A `DJANGO_SECRET_KEY` rotation must re-tag retained
  audit rows in a controlled migration or their integrity checks will fail.

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

The verdict remains yellow: deployment closed A-01/A-03 configuration rollout and
A-04 local-mode actions. The isolated restore drill, durable request budgets,
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
- [NVIDIA vision-language model support](https://docs.nvidia.com/nim/vision-language-models/2.0.10-variant/introduction.html)
- [NVIDIA Nemotron Nano 12B V2 VL model contract](https://docs.api.nvidia.com/nim/re/reference/nvidia-nemotron-nano-12b-v2-vl)
