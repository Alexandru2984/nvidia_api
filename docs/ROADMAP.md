# Product and security roadmap

Priorities are ordered by risk reduction and dependency, not by implementation
novelty. A feature is complete only when it has ownership checks, limits,
responsive behavior, tests, observable failure modes, and rollback notes.

## P0 — production safety and control

- **Verified rollout:** apply the committed nginx/systemd templates, deny direct
  media access, correct existing backup modes, validate health and rollback, and
  capture evidence in the deployment log. Frontend release builds now refuse
  dirty/untracked or ignored environment input, bind output to the exact commit
  and frontend Git tree, and must pass a bounded root-side preflight. Frontend,
  backend, Python and rollback operations share one fail-closed exclusive lock.
- **Safe deployment trigger:** the broken legacy NVIDIA `push` webhook is
  disabled. It targeted a removed service, ran before CI completion and did not
  use immutable release or migration gates. Keep manual atomic deployments until
  a NVIDIA-only handler consumes an exact successful `CI` workflow-run commit,
  refuses dirty/divergent state, and preserves the existing backup, compatibility,
  health and rollback contract without making remote checkout tooling root.
- **Strict browser style boundary is shipped:** every React inline style was
  replaced with a responsive CSS class, ESLint rejects future inline-style and
  raw-HTML injection props, and production CSP now uses only `style-src 'self'`.
  Cloudflare currently injects a Browser Insights inline/remote script for real
  browser traffic; the unchanged `script-src 'self'` correctly blocks both
  elements. Disable that injection in the Cloudflare dashboard rather than
  expanding the application's script policy.
- **Memory-hard password storage is shipped:** new and changed credentials use
  scrypt, existing PBKDF2 hashes upgrade only after complete password-plus-2FA
  authentication, incomplete second-factor attempts cannot mutate credentials
  or invalidate sessions, and the previous release remains able to verify the
  new format. Re-benchmark authentication memory/latency before increasing
  worker concurrency or materially opening registration traffic.
- **Dedicated service identity:** the web process and application maintenance
  timers run as the non-login `aichat` Unix user, with an unprivileged app-only
  database role and app-owned media/cache. Keep this invariant in deployment
  checks and move secrets to systemd credentials during a future rotation. The
  HTTP origin is now a monitored permissioned Unix socket shared only with nginx;
  the former loopback TCP listener is closed and monitored against regression.
- **Durable abuse and budget controls:** PostgreSQL-backed daily request budgets
  per user and globally, actual provider token accounting, fail-closed concurrent
  token reservations, and a configuration kill-switch are shipped. Add a
  contract/GPU-based monetary spend budget and an admin override/audit trail;
  invite-only registration with one-time HMAC-stored codes is shipped. Add a
  human-verification challenge only if public registration returns, and move
  burst throttles to Redis/PostgreSQL before scaling.
- **Provider entitlement:** confirm and record the NVIDIA production license or
  restrict the service to private evaluation use. Map the contractual/GPU cost
  model into alerts and a hard monetary circuit breaker.
- **Protected administration:** password-only Django admin access is blocked;
  staff must verify 2FA through the main application and refresh a five-minute
  password-plus-2FA elevation window through the responsive step-up UI. Expired
  mutations fail closed, return targets stay on `/admin/`, and valid/denied
  access is monitored. Privacy-minimized add/change/delete records retain actor,
  object, model, action, and changed field names for 365 days with HMAC integrity
  validation. Also place `/admin/` behind Cloudflare Access or a VPN, minimize
  superusers, and retain the security journal externally.
- **Detection:** structured privacy-minimized events and five-minute alerts now
  cover auth bursts, throttles, successful admin access, 2FA disable, global AI
  budget exhaustion, missing/malformed provider usage, token reservation
  overruns, invalid-invite bursts, invitation consumption, verified
  registrations, privileged admin changes, admin-audit integrity failures,
  backend error bursts, backup/restore freshness, malware detections, local
  scanner outages and ClamAV-signature freshness, isolated-parser health and
  parser/upload failure correlation, including installed parser drift from the
  manifest-verified backend release, malformed/redirected provider responses,
  failed scheduled maintenance, completed or bound-breaking full-account exports,
  and every authorized conversation export without exporting owner, conversation
  or content metadata.
  The monitor runs under a dedicated non-login identity, receives its Telegram
  configuration through a systemd credential, can read restore status but not
  database dumps, and validates those exact ACL boundaries on every run. A
  systemd path unit now turns changes to protected dotenv, vhost, application
  units, restore units/executable, monitor units/identity or installed monitor code into a fixed
  privacy-safe event within the same alert window. Routine request logging is now
  minimized too: nginx does not duplicate this vhost into the host-wide combined
  log, and Gunicorn excludes IP, User-Agent, Referer, cookies and query strings
  while retaining bounded request shape/status/latency. Add contract-spend
  correlation and an external log sink that preserves this field boundary and
  never logs prompts, cookies, OTPs, filenames, raw IPs, queries or secrets.
- **Recoverability:** the isolated database restore drill is now installed as a
  persistent weekly systemd timer, runs against the active immutable releases,
  is sandboxed to local PostgreSQL plus the private backup directory, and alerts
  immediately on unit failure as well as missing/stale/malformed success evidence.
  Encrypt backups with a separately held key, keep a tested immutable off-site
  copy, restore from that copy on schedule, and document RPO/RTO.
- **Versioned 2FA key lifecycle is shipped:** purpose-separated TOTP encryption,
  recovery HMACs and enrollment fingerprints use an independent bounded keyring;
  stored envelopes record their key ID, corrupt/unknown artifacts fail closed and
  alert, TOTP secrets rotate transactionally or lazily, and an audit gate prevents
  premature retirement while recovery codes still reference an old key. Move the
  root keys to systemd credentials or a KMS/HSM during the next secret rotation.
- **Versioned privileged-audit key lifecycle is shipped:** pseudonymous
  nonnumeric object references and integrity tags use separate purpose-derived
  keys from an independent bounded keyring. Stored tags name their key, corrupt
  or unknown evidence fails closed, transactional rotation refuses to bless a
  tampered row, and the inventory gate prevents premature retirement. Move these
  root keys to systemd credentials or a KMS/HSM with the other application keys.
- **Incident readiness:** execute the runbook and close exercise findings before
  changing the audit verdict to green.

P0 acceptance: production probes pass, no service can directly serve private
media, existing backups are private, a provider budget can be stopped without a
deploy, staff access is strongly authenticated, and a restore/tabletop produces
timed evidence.

## P1 — high-value product work

- **Capability-aware model and attachment UX is shipped:** the live selector is
  grouped by purpose, exposes context/input badges, and only offers formats the
  chosen model can consume. Switching models makes incompatible pending/history
  media explicit, with backend enforcement independent of the browser.
- **Model discovery is shipped:** search spans name/vendor/ID/description,
  browser-local favorites and recent models are bounded to public IDs, comparison
  supports three models, and the live availability-check timestamp is visible.
  Conservative “best for” guidance, rounded successful-probe latency, explicit
  sample caveats, and recommendation/latency/context/name sorting are shipped.
  Availability now has verified/degraded/fail-closed states, expires after the
  eight-day trust window, refreshes every Monday and Thursday, preserves verified
  decisions across two transient provider runs, hides them on the third consecutive
  failure, restores them on success, blocks newly added IDs until their first successful
  probe, and alerts degraded, authorization-failed or crashed probes without
  leaking provider error details. The probe now runs under a dedicated non-login
  identity with only its NVIDIA and Ed25519 credentials; `aichat` can read but
  cannot forge the exact-owner/mode, signature-verified state. A credential-free
  five-minute check verifies it independently from user traffic, and backend
  deployment refuses an absent/stale identity, key or permission boundary before
  switching releases. Provider egress is pinned to approved NVIDIA HTTPS
  endpoints; redirects are disabled and streamed SSE/image responses have
  aggregate, line, shape and wall-clock bounds. The
  October 2026 catalog tracks 20 documented endpoints, while the authenticated
  contract reports the changing verified/degraded aggregate rather than promising
  a fixed live count. Model-specific temperature/output-token contracts are
  enforced by API, responsive controls and database constraints; incomplete or
  unmetered streams fail closed without exposing provider details.
  Expose reasoning, tool use, structured output, and output modality controls only
  when verified and declared by the selected model.
- **Resilient attachment intake is shipped:** picker, drag/drop, clipboard image
  paste, per-file progress/cancel/retry/dismiss, capability rejection, and
  session-bound state clearing share one bounded queue. Secret-keyed owner-scoped
  duplicate detection, no-store extracted-text preview, and per-file inclusion
  toggles are also shipped. Every browser file link and image source is constrained
  to the exact same-origin, owner-checked private-download route; malformed or
  fabricated API values render unavailable without creating a link or request.
  Model-authored Markdown has an explicit safe-protocol layer, never auto-loads
  remote images, and suppresses referrer data on user-initiated external links.
  Client-generated upload-attempt identifiers now make
  retries idempotent and reconcile cancellation before or after database commit
  across workers without deleting an older deduplicated file. Upload bytes and
  generated NVIDIA images are now scanned by a local, permissioned ClamAV
  `INSTREAM` service before parsing, deduplication or storage; ambiguous verdicts,
  stale signatures and daemon failures fail closed and alert. PDF/DOCX extraction
  is serialized behind a bounded Unix protocol in a secret-blind, network-denied
  `aichat-parser` systemd sandbox. Move large-document processing to the background
  before raising upload or parser limits.
- **Conversation generation integrity is shipped:** a token-owned PostgreSQL
  lease serializes send/regenerate across workers, returns a bounded retry hint,
  heartbeats long streams, safely reclaims crashes, and blocks branch edits or
  conversation mutation while active. Token reservations and pending messages
  are reconciled even when a response is never iterated; pending attachments are
  claimed under row lock; failed or unstarted regeneration preserves the old
  branch. Owner-scoped client UUIDs now drive an explicit durable job state
  machine; completed/partial results replay without provider work, mismatched
  reuse fails closed, expired work is fenced and reconciled, and terminal metadata
  has bounded retention. A future horizontal queue must preserve this protocol;
  do not automatically retry `failed`/`interrupted` jobs because NVIDIA does not
  share an atomic transaction with PostgreSQL.
- **Bounded chat storage and egress are shipped:** owner-row serialization makes
  conversation limits and cross-conversation message reservations durable across
  workers; regeneration reserves only projected growth. Assistant output and
  streamed Markdown exports have hard bounds, attachment/export/session routes
  are throttled, expired sessions are removed by daily maintenance, quota blocks
  alert, and the responsive Storage panel shows the limits. Authenticated sessions
  now have an indexed owner registry, fixed 30-day maximum lifetime, a 20-session
  per-account cap, deadline-preserving rotations and atomic oldest-session
  eviction. Sensitive account changes now share a five-minute recent-strong-auth
  policy bound to the user/session/current password; 2FA accounts require their
  second factor for password changes, and stale session-revocation actions resume
  only after responsive reauthentication. Database-derived UTF-8 byte accounting
  now enforces transactional per-conversation, per-user and service-wide saved-
  message ceilings, including live worst-case generation reservations and net-
  growth regeneration. Owner-selected archived-history retention is now shipped:
  inactive archived conversations can be kept indefinitely or deleted after 30,
  90, 180, or 365 days by bounded daily maintenance, while active generations
  and active chats remain excluded. Owner-linked AI usage metadata now expires
  after 90 days and anonymous service aggregates after 400 days, both in bounded
  batches. Full owner-scoped account export is also shipped: recent password and
  2FA proof unlock a rate-limited streaming JSON export of profile, preferences,
  chats, usage, safe session metadata and an attachment manifest. File bodies,
  extracted text, authentication material, raw session identifiers and internal
  fingerprints stay excluded; record/byte preflight plus a hard stream bound
  protect the service. Every completed or bound-breaking export enters the
  six-minute privacy-minimized alert path. Cancelable scheduled account deletion
  is also shipped: strong authentication opens a seven-day grace period, visible
  status can be canceled before its deadline, and lease-safe daily maintenance
  revokes every session before deleting at most 25 due accounts. Define and
  publish the operator-wide legal/default schedule before materially raising
  account volume.
- **Immutable backend application delivery is shipped:** production imports only
  a committed, root-owned, manifest-verified release selected through one atomic
  symlink. Staging excludes secrets, media, cache and dependencies; preflight runs
  as `aichat`; backend, maintenance and the isolated probe read the same
  immutable release;
  health/private-route failures restore both code and systemd configuration. The
  five-minute monitor verifies the active manifest. The production Python
  environment is also a separately versioned root-owned release, built without
  secret access from exact runtime pins and SHA-256-locked binary wheels, with
  package-set, lockfile and manifest enforcement. A deterministic CycloneDX 1.7
  SBOM for every selected wheel is embedded in and hash-bound to the Python
  release. Backend and Python rollback paths have now been exercised against
  production through a common exclusive operation lock, strict compatibility
  preflights, PID/path verification, bounded health/security probes and guaranteed
  restoration. Executable roots retain the active plus two rollback releases,
  archiving older trees privately only after SHA-256 verification. Next add
  signed builder provenance and define an encrypted off-site/expiry lifecycle
  for those supplemental archives.
  CI's remote Actions are pinned to reviewed full commit SHAs, with a regression
  gate rejecting moving refs; updates must preserve that review trail.
- **Private-history pagination and indexed search are shipped:** conversation
  cursors bind owner/folder/search, message cursors bind owner/conversation, and
  attachment cursors bind owner/type. All expire after 24 hours, have firm page
  and legacy bounds, use stable indexed ordering, and have race-safe responsive
  loading covered by backend/browser tests. PostgreSQL title/content search uses
  concurrent trigram indexes.
- **Pinned and archived conversations are shipped:** owner-scoped filters and
  counts, explicit restore, pin-first ordering, labeled mobile actions, and a
  legacy-compatible rollout contract are covered by backend and browser tests.
  Add user-defined folders plus owner-scoped bulk move/delete/export.
- Conversation branching and explicit alternative responses on regeneration.
- Saved prompt library with variables, favorites, tags, and safe import/export.
- Per-user preferences: default model, generation parameters, theme, language,
  compact mode, and reduced-motion mode.
- Token/request/storage dashboard with daily/monthly budgets and downloadable
  personal usage history.
- **Scheduled account deletion and visible status are shipped:** schedule/cancel
  requires password plus enabled 2FA, scheduling is idempotent and cannot extend
  a pending deadline, due cancellation fails closed, daily execution is bounded
  and excludes active generation owners before slicing, and all lifecycle events
  enter the privacy-minimized alert path. Physical attachment deletion now uses a
  durable transaction-coupled outbox: commit-time failures retain bounded retry
  state, alert without a filename/path, and rotate behind untried work so a full
  batch of permanent failures cannot starve the queue.
- Image job history/gallery with cancel/retry/delete and preserved generation
  parameters.
- **Versioned provider disclosure is shipped:** before the first chat,
  regeneration, or image request, an accessible mobile dialog identifies the
  prompt, selected context/files and settings sent to NVIDIA. Minimal server-side
  acceptance is versioned, and every provider path independently fails with `428`
  before writes, reservations or egress when it is absent. This is explicitly an
  acknowledgement, not a claim of legal consent or production entitlement.
- Romanian and English localization and timezone-aware timestamps.
- Keyboard command palette, draft persistence, message copy/edit, code-block
  actions, and accessible confirmations/toasts.

P1 acceptance: mobile widths from 320 px and keyboard-only flows pass automated
tests; large accounts do not issue unbounded queries; exports and deletions are
owner-scoped and auditable.

## P2 — reliability, scale, and platform

- Move long model/image/document work to background jobs with cancellation,
  idempotency keys, retry policy, dead-letter visibility, and reuse the shipped
  per-conversation lease as the execution fence.
- Adopt ASGI-native streaming with reconnect/resume semantics and clear partial
  response state.
- Add OpenTelemetry metrics/traces with redaction, SLOs for request success and
  first-token latency, and capacity dashboards.
- The separate-identity, no-network, aggregate-bounded document parser and local
  fail-closed malware scanning are shipped. Consider a microVM only if future
  volume/risk warrants it; add a recoverable evidence-quarantine workflow for
  confirmed incidents without retaining rejected content by default.
- PWA shell and offline drafts without caching authenticated API responses or
  attachment bodies.
- WCAG 2.2 AA audit with assistive-technology testing and performance budgets for
  low-end mobile devices.
- Optional provider abstraction/failover with explicit per-provider privacy text,
  pricing metadata, and tenant-level allowlists.
- Infrastructure as code for nginx, systemd, Cloudflare, monitoring and secrets
  references; drift detection must fail closed on private-media routing.

P2 acceptance: load/failure tests prove isolation and cancellation, telemetry does
not contain user content, and disaster recovery meets documented RPO/RTO.

## Deliberately deferred

Public share links, team workspaces, plugins/tools, retrieval over user documents,
and payment plans amplify authorization and data-retention risk. Design their
tenant model, revocation, audit logs, quotas, consent, and deletion semantics before
implementation rather than layering them onto single-user assumptions.
