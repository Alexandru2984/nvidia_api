# End-to-end security audit — 2026-10-07

Scope: the complete tracked Django/DRF and React/Vite codebase, migrations,
tests, CI, scripts, nginx and systemd templates, the effective production
service configuration, database privileges, public anonymous routes, local
network exposure, host patch state, backup/recovery controls, and the shared-VPS
trust boundary.

Decision: **RED — freeze feature releases until P0 is complete.** The review
found no SQL injection, unauthenticated IDOR, stored XSS, committed credential,
or known Python/Node dependency advisory. The red verdict instead comes from a
confirmed host privilege-collapse chain: many unrelated services run as the
interactive `micu` identity, and that identity has unrestricted passwordless
root. The authenticated application also executes an unpinned analytics script
served by one of those services. One compromise can therefore cross project,
host, browser, database, backup, and provider boundaries.

This was a read-only assessment. It did not rotate credentials, alter accounts,
run destructive fuzzing/load tests, or change production configuration. No
secret values are reproduced here.

## Remediation status

- 2026-10-07: S-02 was remediated in commit `903996a` and production. The
  authenticated SPA no longer loads cross-origin JavaScript, the associated CSP
  origins were removed, and both origin and Cloudflare delivery were verified.
- 2026-10-07: S-03 was remediated in commits `903996a` and `cd37d0b`, then
  deployed. The atomic release is root-owned/read-only, carries a SHA-256
  manifest, and the five-minute security monitor validates content, topology,
  ownership and exact modes. This closes the `www-data` persistence path; S-01
  separately remains capable of root-level tampering until service isolation is
  complete.
- 2026-10-07: S-05's stolen-session enrollment path was remediated and deployed
  in commits `e3c6c20` and `fc7db21`. Enrollment now requires the current
  password plus a five-minute, user-and-secret-bound marker; completion is
  transactional, rotates the session and revokes all other sessions. Recovery
  regeneration now requires password plus factor and is rate-limited. The P0
  operational gate remains open because the one production staff account still
  has no enrolled factor and `/admin/` has no independent Cloudflare Access/VPN
  policy.
- 2026-10-07: S-01 remediation began with Umami in commits `a1ddb3a` and
  `cbb8aee`. The analytics runtime moved from `micu` and `9.2 UNSAFE` to a
  dedicated non-login identity and `2.7 OK`; its mount namespace hides AI Chat
  Hub and makes its own release read-only. Thirty-seven active `User=micu`
  services remain, so S-01 stays Critical and the owner-approved sudo exception
  is not yet adequately compensated.
- 2026-10-07: Pastebox was migrated in commit `b352ecd` from `micu` and `9.2
  UNSAFE` to a dedicated identity and `2.7 OK`, with its SQLite state isolated
  and mode `0600`. Thirty-six baseline services remain under `micu`; S-01 stays
  Critical.
- 2026-10-07: Video was migrated in commits `e665302` and `162e0c3` from `micu`
  and `9.2 UNSAFE` to the dedicated `videoapp` identity and `2.7 OK`. Its source,
  secrets, mutable state, network access and resource usage are now bounded;
  thirty-five baseline services remain under `micu`, so S-01 stays Critical.
- 2026-10-07: The webhook listener was migrated in commits `2838b72`, `d38d320`
  and `3aa9761` from direct execution as `micu` at `7.2 MEDIUM` to a dedicated,
  non-privileged receiver at `2.7 OK`. Its only deployment bridge is now a
  root-owned fixed-file/fixed-target dispatcher; normal `micu` services can no
  longer read the webhook HMAC config. Commit `4b23529` also added method,
  Cloudflare-origin, request-size, timeout and real-client rate controls at
  nginx. Thirty-four baseline services remain under `micu`, so S-01 stays
  Critical.
- 2026-10-07: Finance moved in commit `220cb7f` from `micu` and `9.2 UNSAFE` to
  dedicated `financeapp` and `2.7 OK`. Its database, cookie-signing keys,
  configuration, writable state, release and home visibility are separated.
  Thirty-three baseline services remain under `micu`; S-01 stays Critical.
- 2026-10-07: Traffic Analyzer moved in commits `4db4f05` and `4964d14` from
  `micu` and `9.2 UNSAFE` to dedicated `crystaltraffic` and `2.7 OK`. Its release,
  environment, writable state, home visibility and host-log access are now
  bounded; historical plaintext backup files were quarantined root-only.
  Thirty-two baseline services remain under `micu`; S-01 stays Critical and the
  application password still requires owner-coordinated rotation.
- 2026-10-07: Ruby Bookmarks moved in commits `c495d73` and `aa1fd2d` from
  `micu`, inline credentials and `9.2 UNSAFE` to dedicated `bookmarksapp` and
  `2.9 OK`. Ruby commits `c0a5d11` and `59da158` fixed five vulnerable dependency
  families and a DNS-rebinding SSRF path. Its keys, four SQLite databases,
  environment, writable state, release and home visibility are now bounded.
  Thirty-one baseline services remain under `micu`; S-01 stays Critical. The
  previously exposed SMTP credential requires provider-side revocation and
  replacement.
- 2026-10-07: GT Shop moved in commit `a68916f` from `micu`, an exposed DB
  credential, an embedded fallback JWT key and `9.2 UNSAFE` to dedicated
  `gtshopapp`, rotated secrets and `2.7 OK`. Commit `11d1f8c` fails closed at
  nginx around a confirmed anonymous authorization bypass for user, cart and
  checkout APIs while source recovery and a dependency/authentication rebuild
  remain P0. Thirty baseline services remain under `micu`; S-01 stays Critical.
- 2026-10-08: R Traffic Intelligence moved in commit `8d4b276` from `micu`,
  plaintext active credentials and `9.2 UNSAFE` to dedicated `rtraffic`, hashed
  UI authentication, a rotated least-privilege DB credential and `2.9 OK`.
  R commits `71e5e6f` and `b58c110` close a confirmed anonymous log-import path,
  enforce login throttling and reject missing production configuration;
  `b72f4bd` removes remote browser fonts. Commits `2f5a2cc` and `a94252f`
  restore package-managed Shiny assets, and `1cfc038` adds the Cloudflare-origin,
  request/body/connection and CSP boundary at nginx. Tests, DB continuity,
  denied DDL/direct-origin/anonymous upload, every local asset, public and
  WebSocket probes passed. Twenty-nine baseline services remain under `micu`,
  so S-01 stays Critical.
- 2026-10-08: Unison Idea Evolution moved in commits `647aebf`, `5add7b8` and
  `f0c322b` from `micu`, a writable public release and `9.2 UNSAFE` to dedicated
  `unisonapp`, private state, a read-only checkout, atomic root-owned frontend
  releases and `2.7 OK`. Unison commits `3be9fa9`, `cc0303c` and `4fe7f72`
  remove vulnerable/unused dependency families, bound public request and
  subprocess work, disable production API documentation, sanitize errors and
  enforce WebSocket origins. Tests/audits, exact database continuity, mutation
  execution, namespace isolation, Cloudflare-origin enforcement, method/body/
  rate bounds, CSP, public routes and WebSockets passed. Twenty-eight baseline
  services remain under `micu`, so S-01 stays Critical.
- 2026-10-08: The Cloudflare analytics Telegram bot moved in commits `1875621`,
  `a3b04c3` and `c03e97d` from `micu`, a hardcoded token and `9.2 UNSAFE` to
  dedicated `cfbot`, root-managed configuration, a root-owned release, hidden
  homes, private state and `2.9 OK`. Three known `urllib3` advisories were fixed;
  message authorization, input/upstream/log bounds, HTTPS IP lookup, active
  alert/report schedules and secret-redacting logs were added. Tests, dependency
  scans, API and local artifact probes, namespace, no-listener, exact-secret and
  clean-restart checks passed. The initially deployed INFO logger exposed the
  Telegram token to journald before commit `a3b04c3`; retained tool history also
  contains the legacy hardcoded value. BotFather revocation/regeneration and
  replacement of the Cloudflare token remain mandatory provider-side incident
  gates. Twenty-seven baseline services remain under `micu`, so S-01 stays
  Critical.
- 2026-10-08: Dead Drop moved in repository commit `4498c99` from `micu`, a
  user-owned runtime executable and checkout-local mutable state to dedicated
  `deaddrop`, a root-owned executable, private state, hidden homes and `1.3 OK`.
  Its fail-closed atomic deploy now rolls back on either health or doctor
  failure, and its root backup worker is network-denied at `1.6 OK`. Go and
  browser protocol/cryptography suites, vulnerability/secret scans, exact state
  continuity, backup restore validation, namespace, clean restart, loopback,
  Cloudflare and Tor delivery checks passed. Twenty-six baseline services remain
  under `micu`, so S-01 stays Critical.
- 2026-10-08: NuiGraph Studio moved in repository commits `1181c73`, `164c575`
  and `298e8c2` from `micu`, a user-writable executable/release, visible homes,
  owner-level DB access and `8.5 EXPOSED` to dedicated `nuigraph`, root-owned
  atomic releases, systemd credentials, a DML-only runtime role and `1.3 OK`.
  Strict config validation, health rollback and protected-config test execution
  were added; two vulnerable frontend build dependencies and a reproduced
  libpqxx normal-exit double-free were fixed. Five test suites, ASan/UBSan,
  Cppcheck, gitleaks, npm audit, DML/denied-DDL, exact DB continuity, full
  scratch restore, namespace, direct-origin, public and clean-restart probes
  passed. Twenty-five baseline services remain under `micu`, so S-01 stays
  Critical.
- 2026-10-13: S-11 was substantially remediated in commit `f9db80a` and
  production. Token-owned PostgreSQL leases now serialize send/regenerate per
  conversation across workers, heartbeat long streams, reject conflicts with a
  bounded retry hint, and clean up expired crash residue. Pending attachment
  rows are revalidated under row lock before linking; unstarted responses release
  reservations and pending messages; regeneration retains the old branch until
  replacement content exists. Conversation mutation and message editing are
  fenced while generation is active. Explicit request idempotency keys and a
  durable generation-job state machine remain open for safe automatic retries.
- 2026-10-16: the remaining S-11 application controls shipped in commit
  `3d2f696`. Browser-generated UUIDs now identify owner-scoped durable send and
  regenerate jobs. Payload-changing reuse fails closed; active duplicates return
  a bounded conflict; completed and partial-canceled results replay from stored
  messages without another NVIDIA call. Expired jobs are fenced, reconciled and
  marked interrupted rather than automatically rerun. Five-minute monitoring
  alerts on interruptions and repeated mismatched keys; terminal metadata expires
  after seven days by default.
- 2026-10-15: S-06 was partially mitigated in commit `75e0d6b` and production.
  Every upload is scanned before type inspection, parsing, deduplication or
  storage, and generated NVIDIA images are scanned before storage. Only exact
  clean/infected verdicts are accepted; scanner errors and ambiguous replies fail
  closed. The local `aichat-clamd` service runs as `clamav`, has no internet
  address family or capabilities, scored `2.1 OK` under `systemd-analyze security`,
  and uses bounded official signatures. Parser identity/network isolation remains
  open, so the finding stays High.
- 2026-10-15: S-06 parser isolation was remediated in commit `36b193f` and
  production. PDF/DOCX extraction is serialized by a dedicated `aichat-parser`
  identity over a bounded Unix protocol. The service has no app secrets, home or
  network address family, has no capabilities, and enforces child plus aggregate
  CPU/memory/time/task bounds. Parser outage and protocol ambiguity fail closed
  before storage and are monitored. Novel parser defects remain possible, but
  their credential/network/aggregate-concurrency blast radius is now bounded.
- 2026-10-15: privileged-audit integrity was decoupled from Django signing state
  in commit `b8bb147` and production. Purpose-separated nonnumeric references and
  versioned event tags now use an independent bounded keyring; malformed,
  unknown, corrupt and retired-too-early artifacts fail closed. Inventory and
  transactional rotation commands verify every retained event, and rotation
  refuses to re-sign a tampered row. Production had zero legacy audit rows, so
  the independent `prod-2026-10` root was activated with legacy compatibility
  disabled. A database backup, schema migration, duplicate compatible releases
  and a live rollback/restore drill all passed.
- 2026-10-16: S-13 local protected-configuration detection was expanded in
  commit `24a0303` and production. A root-managed systemd path unit watches the
  NVIDIA dotenv, nginx vhost, application/monitor units, monitor identity and
  installed monitor executable. Any change emits only the fixed
  `protected_config_changed` event for the five-minute alert path. The watcher
  is enabled and waiting with 12 exact targets; no bootstrap event was emitted.
- 2026-10-19: S-16 was remediated in commits `11bfe93` and `feae7d0`, then
  deployed. nginx no longer copies this application's requests into the shared
  raw-IP access log. Gunicorn retains only timestamp, method, path without query,
  HTTP version, status, response bytes and latency; IP, User-Agent, Referer,
  cookies and query strings are excluded by a CI regression gate. Public canary
  metadata was absent from both retained destinations, and backend plus vhost
  rollback/restore drills passed.
- 2026-10-19: S-10's remaining export path was hardened in commits `eab06f2`,
  `513053a` and `b0e4ca4`, then deployed. Conversation Markdown export now
  requires the same five-minute password-and-enabled-2FA proof as full-account
  export. The responsive mobile flow performs step-up before download, both
  export classes emit content-free retained events, and the six-minute monitor
  now alerts on each authorized conversation export without forwarding owner or
  conversation identifiers.
- 2026-10-20: the browser resource boundary was hardened in commit `f1fa632`
  and deployed. Model-authored Markdown now has an explicit `http`, `https`,
  `mailto` and relative-URL policy layered over the renderer's safe transform;
  rejected links and images become inert text, external images are never fetched
  automatically, and external navigation suppresses referrer data. Attachment
  links and image sources now accept only the exact same-origin private-download
  route with a positive numeric object ID and no credentials, query or fragment.
  Fabricated cross-origin, active-scheme and query-bearing API values remain
  visible as unavailable files but cannot become links or subresource requests.
  ESLint, the production build, all 44 responsive browser checks and `npm audit`
  passed. Root-owned frontend release
  `/var/www/aichat-releases/release-20261019T223041_059029511` was activated with
  a complete valid manifest; origin/edge and anonymous-boundary probes passed.
  A live atomic rollback to
  `/var/www/aichat-releases/release-20261019T111601_121301894` and restoration of
  the new release both completed within one second, after which the independent
  monitor finished successfully with no active issue.
- 2026-10-20: frontend release delivery was hardened in commit `e771db0` and
  production. The unprivileged builder now refuses dirty/untracked source,
  ignored environment files outside bounded build/test directories and ambient
  `VITE_*` values, strips Node preload variables, and records exact repository
  commit plus frontend Git-tree identities. Root deployment requires both
  identities to match committed `HEAD`, rejects symlinks, special or oversized
  input/release trees, verifies the active manifest and direct release symlink,
  and shares the backend/Python/rollback exclusive lock. CI exercises the same
  builder and five negative/positive regressions. A stale build and a contending
  deployment both failed closed without a production mutation; 80 operational
  checks, ShellCheck, ESLint and zero-advisory npm audit passed. Commit-bound
  release `/var/www/aichat-releases/release-20261019T223629_840187089` records
  commit
  `e771db0638f00471068717b2752262da82022140` and frontend tree
  `0b92e12329af843412ee4c0856c739dfb1cbee68`; its complete manifest, exact
  ownership/modes and origin/edge boundaries passed. A lock-held live rollback
  and exact restoration both completed within one second, followed by a clean
  independent monitor run.
- 2026-10-20: commit `7c2f0a7` added frontend to the common production rollback
  drill. It verifies the active and candidate immutable manifests, exact static
  modes, direct trusted-root symlinks and commit/tree correspondence when those
  markers exist; the one transitional unmarked candidate remains eligible only
  after full manifest validation. The static switch never restarts the backend,
  asserts its PID/restart continuity, runs the same bounded public/private/media
  probes after rollback and restore, and guarantees restoration on errors or
  signals. Frontend plus unchanged backend/Python preflights passed. The first
  automated live frontend drill rolled back in under one second, restored the
  exact commit-bound release in one second, and the subsequent monitor run
  finished successfully with no active issue.
- 2026-10-20: commits `0d5df6d` and `6cac5e8` added root-authorized Ed25519
  provenance for every immutable frontend, backend and Python release. A
  root-only private key signs a canonical exact-file manifest that contains the
  release's commit plus frontend-tree or requirement-lock/SBOM evidence; a
  retained public-key keyring preserves verification across rotation. Neither
  `aichat` nor the dedicated monitor can read the private key. Deploy, rollback
  and the independent five-minute monitor fail closed on missing, malformed,
  unlisted, altered or wrongly signed active artifacts. Two signed releases per
  family were built from `0d5df6d` so both the active and immediate rollback
  targets have valid provenance. The first monitor installation safely refused
  stale alerts exposed by an old monitor observing an in-progress Python build;
  `6cac5e8` then made monitoring take the shared release-operation lock and defer
  without clearing state while a deploy holds it exclusively. A live contention
  check proved that behavior. Signed rollback/restore drills completed in 0/1
  seconds for frontend, 2/1 for backend and 2/1 for Python, followed by clean
  origin/edge probes and a successful monitor state with no active issue.
- The overall verdict remains RED until all P0 gates are satisfied or carry a
  documented owner acceptance and compensating controls.

## Executive risk statement

The application-specific controls are materially stronger than the host it runs
on. The Django service is non-root and well sandboxed, but the protection is
one-directional: compromise of `aichat` is constrained, while compromise of one
of the numerous `micu` services reaches passwordless root and can then read or
replace everything belonging to AI Chat Hub. Root-owned source is not enough
while the deployed frontend is writable by nginx's worker identity and a remote
analytics script runs inside every authenticated browser.

Worst credible case: an RCE in any internet-reachable `micu` service obtains
root, replaces the analytics or AI Chat Hub JavaScript, steals active user data
and actions in-browser, copies the PostgreSQL data and local backups, and abuses
the reused NVIDIA/SMTP credentials. The blast radius is all three active AI Chat
Hub users plus every project and credential on this VPS, not just this database.

The five-minute monitor gives an expected MTTD below six minutes for the events
it knows about. It does not detect a modified webroot, malicious analytics
script, `micu`-to-root escalation, or deletion of local journals. MTTD for the
highest-risk chain is therefore currently unbounded. The existing illustrative
annualized-loss estimate of EUR 2,500/year is optimistic until the shared-host
boundary is fixed; actual loss depends primarily on all other VPS projects,
provider quotas, recovery time, and regulatory response rather than the current
three-user count.

## Confirmed findings

### S-01 — Critical — shared service identity has passwordless root

Evidence: `sudo -n -l` grants `(ALL) NOPASSWD: ALL` to `micu`; 106 live
processes and dozens of configured services run under that same identity,
including multiple web runtimes and the analytics service loaded by AI Chat
Hub.

Impact: code execution in any one of those services immediately becomes root and
compromises every project, secret, database, backup, tunnel and deployment
artifact on the VPS. The dedicated `aichat` identity does not protect against
this reverse-direction attack.

Remediation: migrate every network service away from the interactive operator
identity to a dedicated non-login identity; remove `NOPASSWD: ALL`; replace it
with root-owned, narrowly scoped deployment/maintenance units; make source,
environment files and release artifacts unreadable across service identities;
then rotate credentials. Do not rotate first into the still-compromisable
boundary.

### S-02 — High — privileged cross-origin analytics JavaScript

Evidence: `frontend/index.html` loads
`https://analytics.micutu.com/script.js` without Subresource Integrity. The CSP
explicitly allows this origin. The script is present in the deployed page.
`umami.service` runs as `micu` and scores 9.2 `UNSAFE` in
`systemd-analyze security`.

Impact: that script executes with the application's browser privileges. A
compromise or unauthorized change can read rendered conversations, make
same-origin authenticated API calls, and alter the UI for every visitor. In the
current host model, compromise of the service can also become root through
S-01.

Remediation: remove browser analytics from the authenticated application now.
Prefer server-side, content-free metrics. If it is retained later, isolate and
harden the service, use a reviewed immutable asset with SRI and change control,
minimize CSP origins, and ensure analytics never receives prompts, attachment
names, account identifiers, or DOM content.

### S-03 — High — production webroot is writable by the web worker

Evidence: `/var/www/aichat.micutu.com` and its asset directories are mode `0775`
and owned by `www-data:www-data`; deployed files are mode `0664` with the same
owner.

Impact: compromise of nginx or any other process sharing `www-data` can replace
the SPA with persistent credential/data-stealing JavaScript. The change is not
covered by the current monitor.

Remediation: deploy immutable releases owned by `root:root` (directories `0755`,
files `0644`) and give nginx read-only access. Use a root-owned staging directory
and atomic release switch, plus an externally checked manifest/hash alert.

### S-04 — High — credentials are shared across application boundaries

Evidence: safe equality checks confirmed that the repository-root environment and
`backend/.env` reuse the same NVIDIA key, SMTP identity and SMTP password. Values
were not printed. Every process running as `micu` can read the owner-only root
repository environment file, and `micu` owns the app environment file. One
unrelated `micu` service also exposes a credential-like distribution token in its
process arguments, making it readable through the same-user process boundary;
the value is intentionally not reproduced here.

Impact: a compromise in another `micu` service can incur provider cost, send mail
as the application, and support account-reset abuse even without touching the
AI Chat Hub process.

Remediation: after S-01, issue per-service credentials, rotate all reused values,
including the process-argument token, move them to root-managed systemd
credentials or an equivalent secret store, remove secrets from command lines,
and alert on provider/mail usage by credential identity.

### S-05 — High — a stolen session can enroll a new 2FA factor

Evidence: `/api/auth/2fa/enroll/` and `/verify-enroll/` require only an existing
session; they do not require the current password or a recent-authentication
marker. Production has one staff account and zero enabled 2FA factors. Direct
admin access is correctly denied while no factor is verified.

Impact: theft of the staff application session can be converted into durable
account takeover: the attacker enrolls their own TOTP, gains the verified staff
session marker, and reaches Django admin. Password reset intentionally preserves
2FA, so the legitimate mailbox owner can then be locked out.

Remediation: require password re-entry and a short-lived recent-auth marker for
2FA enrollment; rotate the session on completion; notify out of band; require
2FA before granting staff; place `/admin/` behind Cloudflare Access or a VPN; and
enroll the current staff account from a trusted device after deploying the fix.

### S-06 — Remediated — document-parser compromise reached app secrets/network

Evidence: PDF/DOCX parsing is correctly moved into a child with time, CPU, file,
descriptor and 512 MiB address-space limits, and its environment is scrubbed.
The child nevertheless shares the `aichat` identity, mount namespace, network
access and readable backend directory containing `.env`. Up to 24 request
threads can start parser children, so per-process memory limits can exceed the
1.5 GiB service cgroup limit in aggregate.

Impact: a parser-library exploit can read app credentials and call the network;
parallel malicious documents can kill/restart the entire backend.

Remediation: move parsing to a separate queue/identity/container with no app
secrets, no network, a read-only single input, a write-only bounded result, total
concurrency/memory limits, quarantine, malware scanning, and explicit parser
timeouts.

Initial status: partially mitigated on 2026-10-15. Uploads are streamed to a local,
permissioned ClamAV `INSTREAM` socket before signature inspection, parser entry,
deduplication or storage; generated provider images are scanned before storage.
Only exact clean/infected verdicts are accepted, scanner failure is fail-closed,
the upload rate is reduced, and health/signature age/detection/outage events are
monitored. `clamd` has no internet address family, uses official signatures and
bounded scan resources.

Final status: remediated on 2026-10-15 in `36b193f`. Complex PDF/DOCX parsing no
longer runs under `aichat`: a versioned bounded Unix-socket protocol sends only
type, length, character cap and bytes to a sequential `aichat-parser` service.
The identity cannot read the runtime `.env`, has no network address family or
capabilities, and runs with read-only system paths, hidden homes, private devices
and tmp, a 768 MiB cgroup ceiling, one-core quota and eight-task ceiling. Its
child retains 512 MiB address-space, CPU, output, descriptor and wall-time bounds.
  Service or protocol failure returns retryable `503` before storage; unreadable
  content returns `422`. The remaining risk is a parser defect contained inside
  this boundary, not direct credential/network access or 24-way parser fan-out.
- 2026-10-15: S-09's direct backend bypass was remediated in commits `985f691`
  and `e66697f`. Gunicorn no longer listens on TCP; nginx reaches a monitored
  `0660 aichat:aichat-origin` Unix socket below a `0750` runtime directory, and
  unrelated service identities are denied. Reintroduction of port 8501 alerts
  within five minutes. Authentication of the separate cloudflared-to-nginx
  client-IP trust path remains open, so S-09 is only partially closed.

### S-07 — High — host security updates and reboot are pending

Evidence: three standard Ubuntu security updates are pending; 24 installed
Universe packages have ESM fixes unavailable without the corresponding support;
`/var/run/reboot-required` lists prior kernel/libc work; the running kernel is
older than installed/available kernels; and `cloudflared` 2026.8.2 has a 2026.10.0
package available. Automatic upgrades are enabled but have not closed this gap.

Impact: known fixed vulnerabilities remain reachable through a large shared-host
attack surface. The exact exploitability of each package depends on which service
loads it, but S-01 turns any successful service compromise into total loss.

Remediation: take a backed-up maintenance window, apply supported security and
tunnel updates, reboot, validate every public service, and either enable the
appropriate security coverage or remove/replace unsupported Universe packages.
Alert on pending security updates and reboot age.

### S-08 — High — recovery copies are local and unencrypted

Evidence: database backups are mode `0600` in a `0700` directory. A persistent
weekly systemd timer now restores the newest artifact into a random local scratch
database, checks schema and migrations, always drops the scratch database, and
alerts immediately on job failure plus missing/stale/malformed success evidence.
No encrypted off-site copy or separately held recovery key is evidenced.

Impact: disk/VPS loss, root compromise or ransomware can remove production and
recovery data together; root compromise exposes the complete backup contents.

Remediation: encrypt before leaving the host with a separately held key, keep an
immutable/off-site copy, define RPO/RTO, and restore from that copy on schedule.

Status: local recoverability is monitored and repeatedly proven, including a
production systemd-sandbox run on 2026-10-19. Same-host destruction, root-level
tampering and backup confidentiality remain unmitigated until the off-site gate
above is completed.

### S-09 — Medium — loopback is treated as a trusted proxy boundary

Evidence: gunicorn listens on `127.0.0.1:8501`; a local request with an allowed
Host, `X-Forwarded-Proto: https`, and attacker-selected `X-Real-IP` reached health
with HTTP 200. nginx also trusts `CF-Connecting-IP` from loopback for the local
tunnel. The host runs many unrelated local services.

Impact: a compromised local service can bypass Cloudflare/nginx policy and spoof
per-IP identities to evade login/recovery throttles. This remains relevant after
removing passwordless sudo.

Remediation: put gunicorn behind a permissioned Unix socket; prevent untrusted
services from reaching the origin listener; authenticate/isolate the
cloudflared-to-nginx path; and accept client-IP headers only on that path.

Status: the direct gunicorn bypass is closed. The backend binds only a
permissioned, shape-checked Unix socket whose group contains nginx but neither
the interactive account nor unrelated service identities; the five-minute
monitor validates its owner/group/mode and asserts that port 8501 remains closed.
The local cloudflared-to-nginx trust and client-IP header boundary still requires
independent authentication/isolation.

### S-10 — Medium — sensitive actions lack absolute-session/recent-auth policy

Pre-fix evidence: sessions had a 14-day sliding expiry and no absolute lifetime.
Sensitive actions other than password/account deletion relied on possession of
the session and, in some flows, a TOTP code, without a uniform recent-password
boundary.

Impact: an actively used stolen session can survive indefinitely and can perform
high-impact actions until manually noticed and revoked.

Remediation: add an absolute lifetime, rotate sessions after privilege changes,
record `auth_time`, and require recent password/2FA confirmation for 2FA setup,
recovery-code regeneration, email changes, staff elevation and exports.

Status: substantially mitigated. Every authenticated session is now represented
in an indexed owner registry, expires at a fixed 30-day deadline that survives key
rotation, and is subject to an atomically enforced 20-session account cap.
Missing/mismatched registry state fails closed, legacy sessions are lazily
indexed, and cleanup removes both cookie-expired and absolute-expired rows.
Password/2FA changes, recovery-code regeneration, session revocation, account
deletion, full-account export and per-conversation export now share recent strong
authentication. Django admin now requires the same five-minute password-plus-2FA
window, safely redirects expired reads through a responsive step-up, rejects
expired mutations without method conversion, and re-alerts on every new elevation
window. Future email/identity changes must use the same policy; the separate
admin edge gate from S-05 is also still open.

### S-11 — Medium — concurrent generation/attachment integrity

Pre-fix evidence: pending attachments were selected before message creation
without row locks or a uniqueness constraint on attachment-to-request
consumption. Two concurrent sends could both resolve the same pending attachment
and race to reassign it; concurrent regenerations could truncate and recreate the
same branch.

Impact: authenticated users can create duplicate provider work, inconsistent
message history and unexpected cost/data loss inside their own account.

Remediation: introduce per-conversation generation locks and idempotency keys;
lock the conversation and pending attachment rows in one transaction; represent
generation jobs explicitly; make cancellation/retry state durable.

Status: the deployed per-conversation lease, mutation fences, attachment row
locks, stream lifecycle cleanup, non-destructive regeneration, owner-scoped
idempotency keys and durable job/cancellation outcomes close the confirmed
duplicate-generation and attachment/history races. A worker crash fences the job
as `interrupted`, reconciles its uncommitted send and rejects same-key execution.
Residual limitation: NVIDIA does not participate in the PostgreSQL transaction,
so an operator must reconcile provider evidence before authorizing a new-key
retry of indeterminate work; automatic retry of failed/interrupted jobs remains
intentionally disabled.

### S-12 — Medium — authenticated storage/egress paths lack complete quotas

Evidence: conversation creation has only a burst rate and no per-user count/data
quota; database sessions are not cleared by a scheduled `clearsessions`; linked
history and usage metadata have no retention; attachment downloads, exports and
session inventory have no explicit application/edge rate limit. Session listing
decodes all active sessions.

Impact: a valid or stolen account can grow the database indefinitely or consume
disk, DB CPU and egress without invoking the provider budget.

Remediation: add durable per-user/global object and byte quotas, scheduled session
cleanup, bounded export/download rates, streaming export, retention settings and
alerts on growth.

Status: substantially mitigated. Production now atomically enforces 500 saved
conversations/user, 10,000 messages/user and 2,000 messages/conversation across
workers, including projected send/regeneration rows. Assistant persistence is
bounded to 64,000 characters. Owner-scoped Markdown export streams only below a
conservative 25 MiB estimate and is limited to 10/hour; attachment downloads are
limited to 120/hour; session list/revocation routes have per-user limits. Daily
maintenance removes expired database sessions and the security monitor alerts on
quota blocks. Database-generated UTF-8 byte counts and a singleton transaction
gate now additionally enforce 16 MiB/conversation, 64 MiB/user and 1 GiB/service
message-text limits, including live generation reservations. The responsive
account panel exposes owner-scoped object and byte consumption without disclosing
global tenant usage. Owners can now keep archived chats indefinitely or select a
30/90/180/365-day lifecycle. Bounded daily cleanup rechecks the owner policy and
age under the same global/owner/conversation lock order, excludes every active
generation lease, and cascade-deletes linked messages and attachment files.
Maintenance failure is monitored. User-linked AI usage counters expire after 90
days and aggregate-only service counters after 400 days, using a separately
bounded batch. Residual work is a published operator-wide legal/default schedule.
The deployed owner-indexed session registry avoids decoding the global session
table and enforces both a fixed 30-day lifetime and a 20-session account cap.

### S-13 — Medium — highest-risk changes are not independently detectable

Pre-fix evidence: the five-minute monitor was healthy and intentionally privacy-
minimized, but journals and state were local. It had no release-manifest,
sudo/root-escalation, environment-file-change or external-log-retention signal.

Impact: S-01 through S-04 can persist without any current alert, and a root
attacker can erase local evidence.

Remediation: send append-only security events and host audit logs off-host; add
release-manifest verification, file-integrity alerts, sudo/process-identity
monitoring, provider/mail anomaly alerts, and exercise the response runbook.

Status: partially mitigated. The active frontend, backend application and Python
environment are now root-owned, atomically selected releases with bounded
SHA-256 manifests verified every five minutes. Local malware detections, scanner
outages, proactive socket health and signature freshness now use the same alert
path without filenames or content. The monitor itself now runs as a dedicated
non-login identity rather than the interactive administrator, receives the
Telegram configuration as an ephemeral systemd credential, cannot read database
dumps or its source credential, and has exact monitored ACL access only to backup
metadata and the privacy-minimized restore status. Model availability is now
produced by a second dedicated non-login identity with only its provider/signing
credentials; `aichat` has read-only/public-key access to exact-owner/mode Ed25519-
verified state, and a crashed probe alerts immediately rather than waiting for
the eight-day freshness deadline. A credential-free checker now re-verifies the
signed state independently every five minutes from manifest-checked code and
dependencies; deploys reject a missing or unsafe identity/key/state boundary
before switching releases. The remaining high-value
signals are off-host retention, sudo/process identity and provider/mail cost
anomalies. Scheduled restore failure is now ingested from its own unit and alerts
immediately; stale, missing or malformed success evidence remains latched through
the existing recovery checks.

### S-14 — Low — dependency provenance remains incomplete

Evidence: every remote GitHub Action is now pinned to a reviewed full commit SHA,
and a tested CI guard rejects moving tags, branches and short SHAs. Python
production requirements are exactly versioned and SHA-256 locked to selected
binary wheels, enforced by pip `--require-hashes` and a CI structural check. Each
Python release now embeds a deterministic CycloneDX 1.7 SBOM that records and
hash-binds those wheel artifacts, the lockfile and repository commit. Frontend
build output records and deploy-time validates its exact commit and Git tree,
while its immutable release manifest binds every served byte. This prevents
normal stale/dirty release activation. Commit `0d5df6d` now adds a purpose-
separated, root-only Ed25519 signer and retained public-key keyring. Every new
frontend, backend and Python release signs its canonical exact-file manifest,
thereby binding its commit plus frontend-tree or Python lock/SBOM evidence; the
deploy, rollback and independent monitor paths verify the signature. The active
and immediate rollback releases for all three families are signed, and neither
the application nor monitor identity can read the private key. Commit `6cac5e8`
prevents half-built trees from producing false integrity decisions by sharing
the exclusive deploy/shared monitor operation lock without clearing prior alert
state. This is strong local builder/deployer provenance and tamper evidence, but
does not independently attest that an upstream publisher built an uncompromised
wheel. Commit `76e3ab8` adds bounded weekly Dependabot proposals for the
frontend npm tree, Python runtime tree and GitHub Actions, plus a CI regression
gate and an explicit review policy. The policy prohibits auto-merge/deploy,
moving Action refs, credential or permission expansion and hash relaxation; it
requires upstream provenance review, green CI, exact Python hash-lock repair and
a manual commit-bound rollout. The workflow token remains restricted to
`contents: read`, and no production deployment secret is used. Because this
commit has not been pushed, GitHub has not yet ingested the updater configuration;
repository-side branch protection and required-review settings also remain
account-side evidence to verify. Independent upstream publisher provenance is
still incomplete.

Impact: a silently moved Action tag can no longer alter CI execution, a changed
wheel cannot satisfy the committed lock, and a post-build release/manifest
change cannot satisfy the retained local signer. An incorrectly reviewed new pin
or an already-compromised upstream build can still enter the signed trusted set;
local signing proves what was selected and deployed, not upstream publisher
integrity. Blast radius remains reduced by read-only permissions and lack of CI
deploy authority.

Remediation: after an authorized push, verify that all three updater entries are
active, security updates target the default branch, and branch protection
requires human review plus the `CI` workflow before considering the updater
control operational. Retain local signing public keys for the full executable
and archive lifecycles, protect/backup the active private key separately, and
record/verify upstream publisher attestations where the selected ecosystem and
artifact provide them.

### S-15 — Low/Medium — privacy/governance evidence is incomplete

Evidence: the UI explains that selected files go to NVIDIA, but no complete
privacy notice, retention choice, analytics disclosure/consent record, vendor
review, DPA evidence, or production NVIDIA entitlement is present in the repo.

Impact: users may not have a complete view of prompt/context processing and
retention. Incident notification and lawful-processing decisions cannot be
demonstrated from repository evidence alone.

Remediation: document all data flows and retention, present provider disclosure
before first generation, publish the privacy notice, record vendor/DPA and
production-entitlement decisions, and provide export/deletion status.

### S-16 — Remediated — routine request logs retained excess client metadata

Pre-fix evidence: nginx inherited the host-wide combined access log, retaining
raw client IP, Referer and User-Agent under 14 rotations. Gunicorn duplicated
those fields in journald and included the raw request URI, so a conversation-list
search query could enter routine logs. Security events already used a secret-
keyed network pseudonym, making the duplicate raw fields unnecessary for their
correlation purpose.

Impact: read access to nginx logs or the backend journal exposed linkable network
and device metadata for every request and could include user-supplied query text.
That enlarged incident/privacy scope without improving application authorization.

Remediation and status: the application vhost explicitly disables inherited
nginx access logging. Gunicorn's systemd-escaped format retains only timestamp,
method, normalized path without query, HTTP version, status, byte count and
latency. A standalone CI test rejects client-IP, authenticated-user, User-Agent,
Referer, raw-request, query, forwarded-IP and cookie atoms and requires both
nginx server blocks to opt out. Existing rotated evidence was not deleted and
expires under the host's normal lifecycle.

Public HTTPS probes containing unique query, User-Agent and Referer canaries
returned the expected response but left none of those values in the backend
journal or nginx access log. Application security events retain HMAC-pseudonymous
actor correlation. Residual tradeoff: static/edge traffic no longer has a local
per-request record, while API/admin shape and latency remain available through
Gunicorn. Any future off-host retention must preserve this minimization rather
than exporting historical combined-log fields.

## Controls verified as effective

- Every private conversation, message and attachment object lookup reviewed is
  owner-scoped; anonymous private endpoints returned 403 and `/media/*` returned
  404 externally.
- Session authentication enforces CSRF even before login; hostile origins receive
  no CORS allow headers; login without a valid CSRF token returned 403.
- JSON input is object-only with shared text-field type checks. ORM usage is
  parameterized; no `eval`, shell invocation, unsafe deserialization, raw SQL
  construction, `dangerouslySetInnerHTML`, or TLS verification bypass was found.
- Markdown is rendered without raw-HTML execution, an explicit protocol policy
  is layered over the renderer's safe URL transform, rejected schemes become
  inert text, remote images are converted into explicit no-referrer links, and
  new-tab links use opener isolation. Browser attachment resources are restricted
  to the exact same-origin owner-checked download route.
- Uploads enforce size, extension/signature agreement, owner-scoped HMAC
  fingerprints, transactional storage quota, DOCX archive limits, private
  download authorization, `nosniff`, sandbox CSP and blocked direct media paths.
- Provider URLs are configuration-controlled, polling IDs are allow-listed, raw
  provider errors are not returned, and PostgreSQL-backed per-user/global request
  and token budgets include a kill switch and fail-closed reservations.
- PostgreSQL generation leases serialize conversation work across workers,
  heartbeat active streams, fence conflicting mutation, row-lock attachment
  claims, and preserve the prior regeneration branch until replacement exists.
- User-row serialized chat quotas account for persisted and in-flight messages;
  assistant output and streamed exports are bounded, private egress/session
  routes are throttled, expired sessions are scheduled for deletion, and quota
  blocks feed the security monitor.
- Authenticated sessions have owner-indexed non-bearer handles, a fixed 30-day
  deadline preserved across rotations, a 20-session cap with atomic eviction,
  fail-closed registry validation and monitored mismatch/cap events.
- Password reset/verification codes are keyed hashes with expiry, attempt limits,
  transactional consumption and anti-enumeration response bodies. Password resets
  revoke sessions and do not bypass enabled 2FA.
- Privileged audit events use an independent, purpose-separated, versioned root
  keyring. Full-row inventory fails closed on any invalid tag or inactive-key
  dependency, and transactional rotation validates every row before re-signing.
- The backend runs as non-login `aichat`, binds only to a permissioned Unix socket, has no Linux
  capabilities, and scores 2.9 `OK` in `systemd-analyze security`. Its PostgreSQL
  role is neither superuser nor role/database creator and lacks database CREATE.
- UFW denies unsolicited inbound traffic except SSH and TURN; direct web-origin
  ports are not allowed. SSH disables root/password/keyboard-interactive login,
  limits attempts, and has Fail2ban coverage.
- TLS 1.0/1.1 are rejected; TLS 1.2/1.3 are accepted. HSTS, CSP, clickjacking,
  MIME, referrer and permissions headers are deployed. HSTS preload remains an
  explicit domain-wide decision rather than an application defect.
- Backups are private, recent and gzip-tested; the latest recorded isolated
  restore drill succeeded. The monitor ran clean and the backend showed zero
  errors in the sampled 24-hour journal window.
- Backend, Python-runtime and frontend immutable releases have common lock-held,
  fail-safe rollback drills; the frontend path additionally proves a static
  switch does not restart the backend process. Their active and immediate
  rollback targets now have independently monitored Ed25519-signed manifests.

## Verification evidence

- `pip-audit`: 24 direct runtime dependencies, zero known advisories.
- `npm audit`: 267 total dependencies (112 production, 156 development, 27
  optional), zero advisories at every severity.
- Bandit: zero high findings; one medium and nine low signals. The medium
  `urlopen` signal is a false positive because the Telegram scheme/host are fixed;
  subprocess calls use fixed argument arrays and security-sensitive executables
  use absolute paths.
- ShellCheck: clean for all repository shell scripts.
- `detect-secrets`: 23 unique candidates in the current tree and across 68
  reachable commit snapshots, all reviewed test/config placeholders or
  non-secret entropy; zero candidates in four unreachable Git objects. `.env`
  files were never tracked.
- Backend: 608 tests passed; migration drift check and `pip check` passed.
- Frontend: ESLint, production build and 44 Playwright checks at mobile/desktop
  widths passed.
- Operational security: 98 tests passed; Bash syntax, ShellCheck and immutable
  GitHub Actions validation passed.
- Django `check --deploy`: only `SECURE_HSTS_PRELOAD=False`; one-year HSTS with
  subdomains is active.
- nginx syntax passed and installed app nginx/systemd files matched the repository
  templates. Public probes returned expected 200/403/404/405 behavior and no
  hostile CORS authorization.

## Remediation gates

### P0 — before more product features

1. Remove the authenticated-page analytics script and its CSP allow-list entries.
2. Make the production webroot immutable to `www-data` and monitor its manifest.
3. Require recent-password confirmation for 2FA enrollment; deploy it; enroll the
   staff account; put admin behind an independent edge gate.
4. Migrate internet-facing services off `micu` and establish per-service
   identities and root-owned deploy paths. The retained passwordless sudo grant
   is an explicit owner risk exception and must remain reachable only through
   the trusted interactive identity, never through a network/content service.
5. Rotate the shared NVIDIA/SMTP credentials into per-service credentials after
   isolation is effective.
6. Apply supported host/tunnel security updates, reboot, and perform a complete
   service and rollback validation.
7. Create and restore-test an encrypted off-site backup.

### P1 — next security wave

1. Replace loopback TCP/backend trust with permissioned/authenticated origin
   paths.
2. Owner-configurable linked-history retention is deployed for inactive archived
   chats, together with global/per-owner chat-byte quotas, recent-auth policy,
   request idempotency/durable job state, absolute session deadlines, the indexed
   owner/session registry, per-user object quotas, bounded/throttled egress,
   expired-session cleanup, the per-conversation generation lease and attachment
   claim lock. Full-account and per-conversation exports both require recent
   password plus enabled-2FA proof. User-linked AI usage now expires after 90
   days and anonymous service aggregates after 400 days. Define the operator-wide
   legal/default schedule.
4. Local Ed25519 release provenance is deployed for frontend, backend and Python;
   it binds the exact manifest to commit/tree/lock/SBOM evidence and both signed
   active/immediate rollback targets passed production drills. Continue retaining
   each named public key, protect/backup the active private key separately, add
   upstream publisher attestations where available, and define an encrypted
   off-site/expiry lifecycle for supplemental retired-release archives.
5. Add off-host logs, host/file integrity monitoring and provider/mail anomaly
   detection; run the tabletop in `INCIDENT_RESPONSE.md`. Routine local request
   logs are now content-minimized; preserve that field boundary in any external
   sink rather than exporting raw IP, User-Agent, Referer, cookie or query data.
6. CI Actions are pinned to reviewed full commit SHAs and Python production
   artifacts are locked by hash. A review-only, rate-bounded Dependabot policy is
   committed for npm, Python and Actions, with a regression test covering its
   trust boundary. Push it through the authorized repository path, verify the
   GitHub-side updater/branch-protection state, and retain upstream review
   evidence for every accepted update.

### P2 — after the verdict returns to yellow/green

Resume model, attachment and UI work only after P0 evidence is recorded. Keep the
existing product roadmap, but require every new feature to define ownership,
quota, retention, provider disclosure, responsive behavior, monitoring,
rollback, and abuse tests before release.

## Reference standards

- OWASP's
  [Third Party JavaScript Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Third_Party_Javascript_Management_Cheat_Sheet.html)
  treats externally served analytics code as an arbitrary-code and sensitive-DOM
  trust boundary, and recommends controls such as removal, mirroring, sandboxing
  and SRI.
- GitHub's
  [Actions security hardening guidance](https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions)
  identifies a full commit SHA as the immutable way to pin an Action.
- Django's
  [deployment checklist](https://docs.djangoproject.com/en/6.0/howto/deployment/checklist/)
  is the baseline behind the production settings review and `check --deploy`.
- Ubuntu's
  [security-update guidance](https://documentation.ubuntu.com/security/security-updates/)
  documents daily unattended updates, repository-coverage boundaries and the
  need to complete restart/reboot handling.

## Audit limits

The audit did not inspect Cloudflare account policy, tunnel dashboard settings,
SMTP server internals, NVIDIA tenant/license records, GitHub repository settings,
or the source code of every unrelated VPS service. It did not authenticate to the
live site, exploit parser libraries, test volumetric capacity, or conduct social
engineering. Those limits do not weaken the confirmed findings above; they mean
the report must not be read as proof that no additional vulnerability exists.
