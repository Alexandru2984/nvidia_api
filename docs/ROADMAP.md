# Product and security roadmap

Priorities are ordered by risk reduction and dependency, not by implementation
novelty. A feature is complete only when it has ownership checks, limits,
responsive behavior, tests, observable failure modes, and rollback notes.

## P0 — production safety and control

- **Verified rollout:** apply the committed nginx/systemd templates, deny direct
  media access, correct existing backup modes, validate health and rollback, and
  capture evidence in the deployment log.
- **Dedicated service identity:** run as an `aichat` Unix user with an app-only
  database role, media/cache directories, mail credential, and NVIDIA key. Remove
  cross-project read access.
- **Durable abuse and budget controls:** move throttles to Redis/PostgreSQL; add
  daily per-user token/image/storage quotas, global provider-spend circuit breaker,
  registration challenge or invite mode, and admin override/audit trail.
- **Protected administration:** place `/admin/` behind Cloudflare Access or a VPN,
  require staff 2FA, minimize superusers, and alert on every admin login/change.
- **Detection:** structured security events for auth, recovery, session revocation,
  uploads, admin actions, throttles, provider failures and spend. Alert within 15
  minutes without logging prompts, cookies, OTPs, or secrets.
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
