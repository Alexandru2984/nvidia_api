# Product and security roadmap

Priorities are ordered by risk reduction and dependency, not by implementation
novelty. A feature is complete only when it has ownership checks, limits,
responsive behavior, tests, observable failure modes, and rollback notes.

## P0 — production safety and control

- **Verified rollout:** apply the committed nginx/systemd templates, deny direct
  media access, correct existing backup modes, validate health and rollback, and
  capture evidence in the deployment log.
- **Dedicated service identity:** the web process and application maintenance
  timers run as the non-login `aichat` Unix user, with an unprivileged app-only
  database role and app-owned media/cache. Keep this invariant in deployment
  checks and move secrets to systemd credentials during a future rotation.
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
  staff must verify 2FA through the main application, and valid/denied access is
  monitored. Privacy-minimized add/change/delete records now retain actor,
  object, model, action, and changed field names for 365 days with HMAC integrity
  validation. Also place `/admin/` behind Cloudflare Access or a VPN, minimize
  superusers, and retain the security journal externally.
- **Detection:** structured privacy-minimized events and five-minute alerts now
  cover auth bursts, throttles, successful admin access, 2FA disable, global AI
  budget exhaustion, missing/malformed provider usage, token reservation
  overruns, invalid-invite bursts, invitation consumption, verified
  registrations, privileged admin changes, admin-audit integrity failures,
  backend error bursts, and backup/restore freshness. Add upload/parser/
  contract-spend correlation and an external log sink without logging prompts,
  cookies, OTPs, filenames, raw IPs, or secrets.
- **Recoverability:** the repository includes an isolated database restore drill;
  schedule and monitor it. Encrypt backups with a separately held key, keep a
  tested off-site copy, alert on job failure, and document RPO/RTO.
- **Key lifecycle:** version encryption keys for TOTP/recovery artifacts so the
  Django signing key can rotate without silent loss; document forced re-enrollment.
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
  probe, and alerts degraded or authorization-failed probes without leaking provider
  error details.
  The October 2026 catalog tracks 20 current documented endpoints; its deployed
  full-stream probe currently exposes 13, including six verified image-capable
  models. Model-specific temperature/output-token contracts are enforced by API,
  responsive controls and database constraints; incomplete or unmetered streams
  fail closed without exposing provider details.
  Expose reasoning, tool use, structured output, and output modality controls only
  when verified and declared by the selected model.
- **Resilient attachment intake is shipped:** picker, drag/drop, clipboard image
  paste, per-file progress/cancel/retry/dismiss, capability rejection, and
  session-bound state clearing share one bounded queue. Secret-keyed owner-scoped
  duplicate detection, no-store extracted-text preview, and per-file inclusion
  toggles are also shipped. Client-generated upload-attempt identifiers now make
  retries idempotent and reconcile cancellation before or after database commit
  across workers without deleting an older deduplicated file. Move large-document
  processing to the background before raising upload or parser limits.
- **Conversation generation integrity is shipped:** a token-owned PostgreSQL
  lease serializes send/regenerate across workers, returns a bounded retry hint,
  heartbeats long streams, safely reclaims crashes, and blocks branch edits or
  conversation mutation while active. Token reservations and pending messages
  are reconciled even when a response is never iterated; pending attachments are
  claimed under row lock; failed or unstarted regeneration preserves the old
  branch. Add client idempotency keys and explicit durable generation jobs before
  automatic network retries or horizontal queue processing.
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
  only after responsive reauthentication. Add global chat-byte budgets and
  configurable linked-history retention before materially raising account volume.
- **Immutable backend application delivery is shipped:** production imports only
  a committed, root-owned, manifest-verified release selected through one atomic
  symlink. Staging excludes secrets, media, cache and dependencies; preflight runs
  as `aichat`; backend, maintenance and model-probe units share the same release;
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
- Full account export (JSON plus attachment manifest), configurable retention,
  scheduled deletion, and visible deletion status.
- Image job history/gallery with cancel/retry/delete and preserved generation
  parameters.
- Romanian and English localization, timezone-aware timestamps, and clearer data
  sharing consent immediately before a provider request.
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
- Quarantine and malware-scan uploads; isolate parsers in a container or microVM.
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
