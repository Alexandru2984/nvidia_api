# Security audit

Date: 2026-10-05  
Scope: Django/DRF backend, React/Vite frontend, PostgreSQL data path, attachment
processing, nginx, systemd, backup automation, Cloudflare Tunnel, and CI.  
Decision: **YELLOW — mitigate then ship**. The repository fixes are deployed and
the request budgets are durable across processes and the request-serving process
has a dedicated Unix identity. The production verdict remains yellow until
security-event alerting is retained externally, staff access is also restricted
at the edge and change-audited, and encrypted off-site recovery is proven.

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
does not secure a running server.

Point-in-time production inventory observed during the audit: 3 active users,
6 conversations, 16 messages, no attachments, no enabled 2FA records, and one
staff/superuser account. These counts are operational context, not permanent
limits.

## Highest risks (STRIDE)

| Priority | Threat | Likelihood | Impact | Blast radius | State |
|---|---|---:|---:|---|---|
| 1 | **Elevation/tampering:** a malicious document exploits the parser or web process | Low/Medium | High | The AI Chat Hub database, runtime files and provider/mail credentials; other projects are outside the service sandbox | Resource-bounded parser plus dedicated non-login identity and systemd sandbox deployed |
| 2 | **Information disclosure:** direct media URLs or permissive backup modes expose private content | Medium | High | Attachment owners or the complete database, depending on path reached | Private API fixed; nginx block staged; existing backup modes require rollout |
| 3 | **Denial of service/cost abuse:** registrations and model generation consume mail, CPU, storage, or NVIDIA quota | High | Medium/High | Availability and provider budget for all users | Per-route limits and payload caps exist; durable quotas and signup challenge remain P0 |

STRIDE coverage also identified spoofing risk at the reverse-proxy boundary,
repudiation from limited security audit events, and disclosure through raw
upstream errors. `X-Real-IP` is accepted only from the local tunnel/nginx path and
upstream responses are now logged server-side while clients receive generic text.

## Findings register

| ID | Severity | Finding | Repository control | Residual action |
|---|---|---|---|---|
| A-01 | Critical | `/media/` could bypass object ownership | Authenticated download endpoint and nginx deny template | Apply vhost; assert `/media/*` is 404 externally |
| A-02 | High | PDF/DOCX handled in the request process | Magic-byte checks, ZIP limits, subprocess timeout and OS resource limits | Move parsing to a dedicated worker/container before higher-volume use |
| A-03 | High | Shared service user had broad host reach | Dedicated non-login `aichat` web/timer identity, app-owned runtime paths, unprivileged app database role and restrictive systemd sandbox | Move file-based secrets to systemd credentials during a controlled rotation |
| A-04 | High | Existing backups were mode `0664` in a `0755` directory | Backup script now uses `umask 077`, atomic output, locks, and gzip verification | Correct existing modes; add encryption, off-site copy, and restore drill |
| A-05 | High | Anonymous session auth did not uniformly enforce CSRF | Strict session authentication and object-only JSON parser | Keep regression tests in CI |
| A-06 | High | Raw session keys were returned to the browser | HMAC-derived opaque session handles | Rotate sessions after any suspected historic disclosure |
| A-07 | High | Dependency advisories in runtime/tooling packages | Pinned upgrades plus weekly `pip-audit` and `npm audit` | Review failed scheduled jobs; use an update bot with controlled merges |
| A-08 | Medium | File-cache increments were not safe under concurrency | `flock`-serialized cache add/increment with multiprocess test | Replace with Redis/PostgreSQL counters before horizontal scaling |
| A-09 | Medium | Declared MIME/extension could be misleading | File signatures, safe stored names, PNG validation, download headers | Add malware scanning/quarantine if uploads become public-facing |
| A-10 | Medium | Model history or repeated calls could multiply payload and cost | Per-message/history caps, PostgreSQL daily request budgets per-user/globally, and a kill-switch | Add token/monetary provider-spend budgets and administrative override audit |
| A-11 | Medium | Registration and recovery can be automated or used for account enumeration | IP/user throttles; uniform register/resend/verify/reset responses; silent cooldown/mail-failure handling; transactional code rollback; case-insensitive database uniqueness for usernames/emails | Add Turnstile or invite/approval mode; enforce mail and provider budgets; assess timing side channels under load |
| A-12 | Medium | Security event detection was incomplete | Structured events and five-minute alerts cover auth/rate/admin-denial bursts, valid admin access, 2FA disable, global budget, errors, backup and restore freshness; the sandboxed monitor alone receives journal-reader access after service separation | Add external retention and upload/provider-spend correlation; tabletop the alert path |
| A-13 | Medium | TOTP secrets depend on `SECRET_KEY`-derived protection | Access and file permissions restrict the key | Use key versioning/KMS-backed encryption before routine key rotation |
| A-14 | Low | No public coordinated disclosure path | `SECURITY.md` and `/.well-known/security.txt` added | Test after every frontend deploy |
| A-15 | High | Django admin's stock login accepted only a password even when application 2FA was enabled | Direct/password-only admin access is denied; current staff session must verify application 2FA, with access alerts | Add Cloudflare Access/VPN and admin change-level audit records |

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
failures, 2FA disable, backend error bursts, and global NVIDIA budget exhaustion.
External log retention and finer provider-spend signals remain open. Target
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
  regional processing, DPA availability, and incident notification obligations.
- Cloudflare carries public traffic through Tunnel and may process network and
  request metadata. Review account security, access logs, DPA, and breach terms.
- The self-hosted mail system handles addresses and OTP/reset messages. Restrict
  logs, monitor delivery abuse, and ensure credentials are unique to this app.
- GitHub hosts source and CI metadata. Keep production secrets out of repository
  variables unless required and use least-privilege workflow permissions.

No vendor review was evidenced in-repository during this audit; owner confirmation
is required before describing those controls as complete.

## Verification evidence

- 238 backend tests pass, including ownership, CSRF, concurrency, recovery,
  anti-enumeration, transactional mail-failure, payload, and generated-image
  boundary tests.
- Frontend lint/build, nine responsive Playwright checks (320–1440 px), and
  Python/Node dependency audits passed during remediation.
- Django deploy checks, nginx syntax, systemd isolation, backup restoration, and
  external route/header probes must be repeated during each production rollout.

### Production rollout — 2026-10-05

- Deployed repository state through `240e2a3`; database migrations reported no
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

The verdict remains yellow: deployment closed A-01/A-03 configuration rollout and
A-04 local-mode actions. The isolated restore drill, durable request budgets,
privacy-minimized alerting, and verified-staff-2FA admin gate were completed
immediately afterward; token/monetary budgets, external security-log retention,
an admin perimeter control, and encrypted off-site backup remain open.

## References

- [Django deployment checklist](https://docs.djangoproject.com/en/6.0/howto/deployment/checklist/)
- [django-ratelimit security considerations](https://django-ratelimit.readthedocs.io/en/stable/security.html)
- [GDPR consolidated text](https://eur-lex.europa.eu/eli/reg/2016/679/oj)
- [ICO personal data breach guidance](https://ico.org.uk/for-organisations/report-a-breach/personal-data-breach/personal-data-breaches-a-guide/)
