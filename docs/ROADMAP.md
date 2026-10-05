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
  contract/GPU-based monetary spend budget, registration challenge or invite
  mode, and an admin override/audit trail; move burst throttles to
  Redis/PostgreSQL before scaling.
- **Provider entitlement:** confirm and record the NVIDIA production license or
  restrict the service to private evaluation use. Map the contractual/GPU cost
  model into alerts and a hard monetary circuit breaker.
- **Protected administration:** password-only Django admin access is blocked;
  staff must verify 2FA through the main application, and valid/denied access is
  monitored. Also place `/admin/` behind Cloudflare Access or a VPN, minimize
  superusers, and add change-level audit records.
- **Detection:** structured privacy-minimized events and five-minute alerts now
  cover auth bursts, throttles, successful admin access, 2FA disable, global AI
  budget exhaustion, missing/malformed provider usage, token reservation
  overruns, backend error bursts, and backup/restore freshness. Add
  upload/parser/contract-spend correlation and an external log sink without
  logging prompts, cookies, OTPs, filenames, raw IPs, or secrets.
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

- Cursor pagination for conversations/messages/attachments and indexed search.
- Pinned, archived, and foldered conversations with bulk move/delete/export.
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
  idempotency keys, retry policy, dead-letter visibility, and per-conversation
  generation locks.
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
