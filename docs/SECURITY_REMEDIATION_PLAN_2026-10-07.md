# Security remediation program — 2026-10-07

Source assessment: [SECURITY_AUDIT_2026-10-07.md](SECURITY_AUDIT_2026-10-07.md)  
Starting verdict: **RED — security work precedes product features**  
Scope: AI Chat Hub repository and production path, plus only those shared-host
controls that directly form its trust boundary.

## CISO decision record

- Top STRIDE threats: elevation of privilege through shared service identity;
  browser tampering/information disclosure through mutable JavaScript; denial of
  service/cost abuse through parser and unbounded authenticated paths.
- Worst-case blast radius: all three AI Chat Hub users, every prompt/message/file,
  database and backup contents, provider/mail credentials, and every project on
  the shared VPS.
- Illustrative baseline ALE: EUR 2,500/year from the audit. This is not an
  accounting forecast and must be recalculated from real provider spend,
  recovery time and all shared-host workloads.
- Current MTTD: under six minutes for covered application events; unbounded for
  webroot/script tampering and shared-identity privilege escalation.
- Response: `INCIDENT_RESPONSE.md` exists; a timed tabletop remains required.
- Regulatory: preserve awareness time and obtain privacy/legal review for any
  qualifying breach; GDPR assessment may have a 72-hour notification window.
- Supply chain: NVIDIA, Cloudflare, SMTP/mailcow, GitHub and the self-hosted
  analytics service remain in scope. No new vendor is introduced by this plan.

## Owner constraint and compensating control

The owner has explicitly chosen to retain unrestricted passwordless sudo for the
interactive `micu` account. This is recorded as a risk exception, not treated as
a completed remediation.

The compensating invariant is: **no network-facing or content-processing service
may run as `micu`**. Such services must use dedicated non-login identities with
`NoNewPrivileges=yes`, an empty capability set, private writable paths, and
systemd filesystem/process/network restrictions appropriate to their function.
Interactive automation under `micu` remains fully trusted. The verdict cannot be
green while remotely reachable services still inherit that identity.

Changes to unrelated projects require their own inventory, backup, health probe
and rollback. This program will not silently rewrite them merely because they
share the host.

## Delivery rules

1. Every stage gets a focused commit with only the repository owner's configured
   author/committer identity and no trailers or attribution body.
2. A production stage starts with recoverable database/config/webroot copies
   proportional to the change.
3. Repository tests run before deployment; local service/config validation runs
   before restart/reload; public and origin probes run afterward.
4. A failed acceptance criterion triggers rollback before the next stage.
5. Secret values, cookies, OTPs, prompts, attachment names and raw private logs
   never enter commits or deployment transcripts.
6. Feature work resumes only after every P0 gate is either closed with evidence
   or explicitly accepted by the owner with compensating controls.

## Wave 0 — plan and evidence baseline

Deliverables:

- Preserve the dated audit and this ordered remediation plan.
- Keep the worktree clean between stages and retain exact commit/deployment IDs.
- Re-run dependency, test, header, ownership and service-health baselines before
  declaring the program complete.

Exit gate: plan committed; current production health and recovery evidence are
known; no production mutation in this wave.

## Wave 1 — browser integrity and immutable frontend (P0)

Repository work:

- Remove remote analytics JavaScript from the authenticated SPA.
- Remove analytics/Cloudflare browser-script origins from CSP; retain only the
  minimum same-origin browser capabilities the app uses.
- Replace the documented `www-data`-owned deployment with a root-owned,
  read-only, staged release procedure.
- Add deployment validation for expected files, symlink safety, modes/owners and
  post-switch health.

Production work:

- Build and test the SPA.
- Preserve the current webroot, deploy a root-owned release and switch the nginx
  root path recoverably.
- Verify no external script remains, CSP is narrowed, HTML/assets are 200,
  `/media/` is 404, private API is 403 anonymously and nginx cannot write the
  release.

Rollback: restore the prior webroot path and nginx template, reload nginx, and
repeat public probes.

Exit gate: the browser has no remotely mutable analytics code; release files are
not writable by `www-data`; frontend tests and public probes pass.

Status: **completed and deployed 2026-10-07** in commit `903996a`.

- Local acceptance: 327 backend tests and 30 Playwright tests passed; ESLint,
  Vite production build, ShellCheck, Bash syntax and whitespace validation
  passed.
- Production release:
  `/var/www/aichat-releases/release-20261007T011042_995353522`; the prior
  directory is retained as
  `/var/www/aichat-releases/legacy-20261007T011042_995353522`.
- nginx rollback copy:
  `/etc/nginx/sites-available/aichat.micutu.com.rollback-20261007T011042Z`.
- Origin and Cloudflare probes returned homepage/asset/health `200`, anonymous
  private API `403`, and `/.env` `403`; neither delivered HTML contained a
  cross-origin script. Both paths returned the narrowed CSP plus COOP, CORP and
  Origin-Agent-Cluster headers.
- The active release is `root:root` with directories `0755` and files `0644`;
  direct write probes as `www-data` failed. nginx and the backend remained
  active with no warning-or-higher journal events during rollout.
- Commit `cd37d0b` added the remaining S-03 detection control and was deployed
  as `/var/www/aichat-releases/release-20261007T054248_670497515`. Its
  root-created manifest verified all 10 release files; the installed root-owned
  monitor returned an empty issue set with exit `0`, and the systemd run ended
  with `Result=success`. Its rollback targets are the preceding release and
  `/usr/local/libexec/aichat-security-monitor.rollback-20261007T054248Z`.

## Wave 2 — 2FA enrollment and admin boundary (P0)

Repository work:

- Require the current password for beginning 2FA enrollment.
- Track a short-lived recent-auth marker and rotate the session identifier after
  enrollment completes.
- Rate-limit recovery-code regeneration and require recent 2FA/password evidence
  for sensitive factor lifecycle actions.
- Add regression tests for stolen-session enrollment, session rotation, staff
  admin access and replay/lockout behavior.
- Make the responsive settings UI collect the password ephemerally and clear it
  on every completion/error/navigation boundary.

Production work:

- Deploy backend/frontend and validate anonymous CSRF, login and admin denial.
- The owner enrolls the staff factor from a trusted device after deployment.
- Put `/admin/` behind an independent Cloudflare Access or VPN policy when the
  account-side control is available.

Rollback: restore code/web release; keep admin fail-closed. Never disable a
working staff factor merely to roll back UI code.

Exit gate: session possession alone cannot add a factor or obtain verified-admin
state; the staff account has an enabled factor; admin requires both app and edge
gates.

Status: **code complete and deployed 2026-10-07; operational gate open**.

- Commits `e3c6c20` and `fc7db21` require current-password reauthentication,
  bind enrollment to a five-minute recent-auth marker, serialize completion,
  rotate the bearer session, revoke other sessions, and protect recovery-code
  regeneration with password, factor and a `5/h` limit. The responsive UI
  clears password state after both success and error.
- Local acceptance: 332 backend tests and 31 Playwright tests passed; Django
  checks found no model drift, and frontend lint/build passed.
- Pre-deploy recovery: database dump
  `/home/micu/backups/nvidia_db/nvidia_db_20261007_085128_860483914.sql.gz`;
  backend files under
  `/home/micu/backups/aichat-rollbacks/2fa-20261007T055128Z`; previous frontend
  `/var/www/aichat-releases/release-20261007T054248_670497515`.
- The initial single-shot readiness probe caught a transient `502` before
  gunicorn bound its socket. Automatic rollback restored the old backend and
  left the frontend untouched; origin/public health returned to `200`. The
  corrected rollout used a bounded readiness loop and activated frontend
  `/var/www/aichat-releases/release-20261007T055240_859987432`.
- Post-deploy origin and Cloudflare home/health probes returned `200`; anonymous
  enroll, recovery regeneration, private API and admin probes returned `403`.
  The release manifest and security-monitor dry-run passed, all relevant
  services remained active, and no warning-or-higher backend/nginx journal
  entries appeared after the successful rollout.
- Manual gates: production still reports one active staff account and zero
  enabled factors. The owner must enroll it from a trusted device and configure
  an independent Cloudflare Access or VPN policy for `/admin/`; the application
  continues to fail closed with `403` until enrollment.

## Wave 3 — shared-host identity isolation (P0)

Repository/host work:

- Keep `micu` passwordless sudo per the owner decision.
- Remove AI Chat Hub's trust in the analytics service (Wave 1).
- Inventory every active `User=micu` network/content service and migrate it one at
  a time to a dedicated identity, starting with analytics and public parsers.
- Add `NoNewPrivileges`, capability removal, private temp/devices, strict
  filesystem paths, resource ceilings and explicit address families.
- Remove credentials from process arguments and rotate the exposed runtime token
  after its service boundary is corrected.

Rollback: per-service unit/config/release backup and a defined service-specific
health probe. Never batch-migrate unrelated services in one restart window.

Exit gate: no network-facing service runs as `micu`; each migrated service passes
functional and sandbox tests; retained sudo is reachable only through the
interactive trusted identity, not a service unit.

Status: **in progress — 4 of 38 baseline services migrated**.

- Commits `a1ddb3a` and `cbb8aee` moved Umami to a dedicated non-login identity,
  root-managed environment, masked dotenv copies, read-only release, hidden
  home, localhost-only networking, empty capability set and bounded resources.
- Effective systemd exposure fell from `9.2 UNSAFE` to `2.7 OK`. Namespace probes
  proved AI Chat Hub is hidden and the Umami source is not writable. Direct and
  public heartbeat/dashboard/tracker probes plus the dependent PCEP page and AI
  Chat health returned `200`; the clean restart produced no application warning.
- Rollback artifacts are recorded in
  [SHARED_HOST_SERVICE_INVENTORY_2026-10-07.md](SHARED_HOST_SERVICE_INVENTORY_2026-10-07.md),
  which also records all remaining units and the next risk-ordered passes.
- Commit `b352ecd` moved Pastebox to its own identity and state directory. Both
  SQLite copies passed integrity and count comparisons; a non-persisting write
  transaction, namespace boundaries, loopback/public routes and AI Chat health
  passed. Its effective exposure fell from `9.2 UNSAFE` to `2.7 OK`, leaving 36
  baseline `User=micu` services.
- Commits `e665302` and `162e0c3` moved Video to the dedicated `videoapp`
  identity without reusing the privileged system `video` group. Its checkout is
  read-only, unrelated home projects are hidden, secrets are root-managed and
  SQLite state is private. Database integrity/counts, a rolled-back write,
  Redis, loopback/public routes and a clean restart passed. Exposure fell from
  `9.2 UNSAFE` to `2.7 OK`, leaving 35 baseline `User=micu` services.
- Commits `2838b72`, `d38d320` and `3aa9761` separated the public webhook
  receiver from deployment authority. The receiver now runs as `webhook-cicd`
  at `2.7 OK`, sees no home directory, has no sudo or external egress, and can
  modify only fixed request files. A root-owned allowlist bridges requests to
  short-lived trusted deployment jobs without accepting a command, path or unit
  name from HTTP. HMAC/branch rules, negative unsigned-request behavior, the
  no-op dispatch probe and restart passed, leaving 34 baseline `User=micu`
  services.
- Commit `4b23529` restricted the webhook ingress to POST through the declared
  Cloudflare/tunnel origin boundary and added real-client rate, body and timeout
  limits. Public-method, direct-origin and bounded-burst probes passed without
  enqueueing a deployment.

## Wave 4 — credential separation and lifecycle (P0)

Repository work:

- Support root-managed systemd credential files or `*_FILE` settings without
  putting values in process arguments.
- Separate Django signing, TOTP encryption and audit-integrity key purposes with
  versioned derivation/rotation behavior.
- Add configuration validation that rejects missing, placeholder or unsafe
  production secrets without logging values.

Production work:

- After Wave 3, issue unique NVIDIA and SMTP credentials for this application.
- Install them through the protected credential path, remove duplicate values
  from dotenv files, restart, test mail/provider flows, then revoke old values.

Rollback: retain old credentials only for the shortest controlled overlap;
restore references, not plaintext into the repository.

Exit gate: no provider/mail credential is reused across projects; no application
secret is supplied in argv; rotation and revocation are tested and documented.

## Wave 5 — host patch and reboot closure (P0)

- Take fresh application/database/config backups and verify available disk space.
- Apply standard security, kernel and cloudflared updates; decide whether to
  enable the required Universe/ESM coverage or remove/replace uncovered packages.
- Reboot in an explicit whole-VPS maintenance window.
- Validate SSH, UFW, tunnel, nginx, PostgreSQL, AI Chat Hub, timers, backups and
  every other declared production service.
- Alert on pending security-update count and reboot-required age.

Rollback: provider snapshot or equivalent host-level recovery plus retained
package/config state. This wave requires an explicit maintenance window because
it affects projects beyond AI Chat Hub.

Exit gate: zero applicable standard security updates, no reboot-required marker,
expected kernel/tunnel versions active, complete service health matrix green.

## Wave 6 — encrypted off-site recovery (P0)

- Encrypt backups before off-host transfer with a separately held/versioned key.
- Keep an immutable off-site copy and defined retention without exposing data or
  keys to the application service.
- Define RPO/RTO and alert on backup, transfer, age and restore failures.
- Restore a selected off-site artifact into an isolated database and record
  schema/migration/count evidence.

Exit gate: same-host destruction does not destroy the recovery path; a timed
off-site restore meets documented RPO/RTO.

## Wave 7 — parser, origin and concurrency isolation (P1)

- Run PDF/DOCX parsing under a separate identity with no app credentials, no
  network, a minimal read-only runtime, per-job and aggregate resource ceilings,
  bounded concurrency and a strict request/response protocol.
- Quarantine and malware-scan uploads before provider/browser use when a suitable
  engine and update policy are selected.
- Move gunicorn to a permissioned Unix socket and remove direct local TCP access.
- Isolate/authenticate cloudflared-to-nginx client-IP trust so unrelated local
  processes cannot mint rate-limit identities.
- Add transactional per-conversation generation locks, attachment row locks,
  idempotency keys and durable cancel/retry state.

Exit gate: parser compromise cannot read app secrets or reach the network; local
untrusted processes cannot bypass the origin boundary; parallel requests cannot
duplicate attachment consumption or destructive regeneration.

## Wave 8 — abuse, retention, detection and supply chain (P1/P2)

- Add absolute session lifetime and uniform recent-auth policy.
- Add durable per-user/global quotas for conversations, messages, sessions,
  export/download egress and retained bytes; schedule `clearsessions` and usage
  retention.
- Stream bounded exports and rate-limit session inventory/download endpoints.
- Send security/audit evidence off-host; monitor release hashes, identity/sudo
  events, environment/config changes, provider/mail anomalies and database/disk
  growth without collecting prompts or filenames.
- Pin GitHub Actions to reviewed full SHAs, produce a hash-locked Python input,
  retain SBOM/provenance, and automate reviewed updates.
- Publish complete privacy/retention/provider disclosures and record vendor/DPA/
  production-entitlement decisions.
- Execute a timed incident tabletop and close every action item.

Exit gate: load/abuse tests prove quotas and cleanup; high-risk tampering alerts
off-host within target MTTD; supply-chain inputs are immutable/reviewed; privacy
and vendor evidence is current.

## Final program acceptance

- Re-run the complete dated audit and compare every finding to objective evidence.
- No Critical finding remains open. A High finding requires named acceptance,
  compensating control, review date and owner; silence is not acceptance.
- Backend/frontend/security/restore suites pass, production drift checks pass,
  and the worktree is clean.
- Change the verdict from RED only after the evidence above is committed without
  embedding operational secrets.
