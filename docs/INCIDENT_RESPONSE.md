# Incident response runbook

Use this for suspected account takeover, data disclosure, malicious upload,
provider-key abuse, host compromise, or unexplained availability/cost spikes.
Keep commands and evidence out of tickets or chat systems that are not approved
for sensitive data.

## 1. Declare and preserve

1. Record the time of awareness, reporter, affected domain/account, observed
   indicators, and incident lead. Use UTC in the incident log.
2. Preserve relevant nginx, systemd journal, Django, Cloudflare, PostgreSQL, mail,
   authentication, and provider-usage records. Capture hashes for exported files.
3. Do not modify original evidence. Work from copies and restrict access to the
   smallest response group.
4. Classify severity: SEV-1 for confirmed sensitive-data or host/credential
   compromise; SEV-2 for contained account compromise or sustained abuse; SEV-3
   for suspicious but unconfirmed events.

The `aichat-security-monitor` Telegram message contains only an event name and
count. Confirm it against root-owned timer/service status and the system journal;
do not paste raw journal lines into Telegram. High-signal rules include a
successful admin login, any privileged admin change, any admin-audit integrity
failure, 2FA disable, global AI-budget exhaustion, 10 failed logins/6 minutes,
10 denied admin requests/6 minutes, 20 rate limits/6 minutes, 5 rejected
invitations/6 minutes, any invitation consumption or verified new account,
5 incompatible attachment/model rejections/6 minutes, 3 backend errors/6 minutes,
any attachment malware detection, any request blocked because the scanner was
unavailable, any failed scanner health check or ClamAV database older than 30 hours,
any request blocked because the isolated parser was unavailable, any parser
failure, failed parser-socket health check or installed-parser integrity mismatch,
any rejected redirect or malformed/bounds-violating provider response,
any invalid runtime model-status file, any degraded scheduled model probe, any
provider authorization/entitlement probe failure, a database backup older than
30 hours, a restore drill older than eight days, or any frontend/backend/Python-
environment release manifest, ownership or permission failure. Any lost
generation lease raises `generation_interrupted`; three mismatched reuses of an
`Idempotency-Key` within six minutes raise `generation_idempotency_conflict`.
Every completed full-account export raises `account_export_completed`; any
unexpected hard streaming-bound breach raises `account_export_bound_exceeded`.
Neither alert includes the owner, IP, exported fields, filenames, or content.
Any Unix-socket request missing a valid nginx-provided client address raises
`proxy_client_ip_invalid`; investigate the proxy/socket trust boundary before
restoring affected authentication paths.
Every permanent account deletion raises `account_deleted` with only an aggregate
count in the alert. Treat an unexpected event as destructive account takeover,
even when no active session remains to inspect.
Scheduling, cancellation and committed execution of delayed account deletion
raise `account_deletion_scheduled`, `account_deletion_canceled` and
`account_deletion_executed`. Telegram receives only event names/counts; the local
journal retains a numeric owner identifier and, for execution, the revoked-
session count. An unexpected schedule is still recoverable only until its stated
deadline, so treat it as urgent account takeover rather than a low-severity
preference change.
Any saved-chat object or byte quota block raises `chat_object_quota`. A failed
`aichat-maintenance.service` run raises `maintenance_failed`; this includes a
failed archived-history or scheduled-account cleanup and must not be dismissed
as routine expiry.

Any `protected_config_changed` alert means a watched dotenv, nginx vhost,
application/monitor systemd unit, sysusers definition, or installed monitor
executable changed. Treat an unplanned event as possible credential or host
tampering: preserve the journal timestamp, compare the root-owned installed file
to its committed source without copying secret contents, and contain before
acknowledging the alert.

## 2. Contain

- Disable the affected route/account or put the application into maintenance
  mode if continued exposure is plausible.
- Revoke suspicious Django sessions and Cloudflare/GitHub/provider tokens.
- Block confirmed hostile indicators at the closest trusted edge, but preserve
  the evidence that justified the block.
- For upload/parser compromise, stop the backend, quarantine the file without
  opening it on a workstation, stop `aichat-document-parser`, preserve its
  privacy-minimized journal and inspect the `aichat-parser` sandbox boundaries.
  Treat access to application secrets or network activity as evidence that the
  isolation boundary failed and escalate to host compromise.
- For a malware-rejection alert, remember that the rejected bytes were not stored:
  preserve the privacy-minimized event/time, verify scanner readiness and current
  signatures, correlate only within approved local logs, and ask the owner for the
  source file only through an approved evidence channel if investigation requires it.
  For scanner outage or stale signatures, keep uploads and generated-image storage
  fail-closed while repairing `aichat-clamd`/`clamav-freshclam`; do not bypass the
  scanner to restore availability.
- For NVIDIA cost abuse, disable generation or revoke the API key before tuning
  throttles. A spending incident can continue while the UI appears healthy.
- For an unexpected `account_export_completed`, treat the account as potentially
  compromised: preserve the event and nginx/authentication window, revoke all
  sessions, require a password reset and verify or re-enroll 2FA from a known-
  clean device. Determine whether the export response completed and which owner
  records existed at that time without copying message/file contents into the
  incident channel. The export never contains attachment bodies, authentication
  secrets or raw session credentials, but it can contain the owner's complete
  saved chat text, email, usage and session IP metadata; start legal/privacy
  assessment and the GDPR 72-hour awareness clock when unauthorized disclosure
  is plausible.
- For an unexpected `account_deleted`, immediately preserve the authentication,
  nginx and deletion-event window plus the newest pre-event backup identity and
  hash. Confirm that every session was revoked and contain any credential/control-
  plane compromise before considering recovery. The live deletion is immediate;
  do not recreate the user, messages, ownership links or files manually. Restore
  only through the documented integrity-checked recovery process with explicit
  owner/legal authorization, and account for retained backup/audit copies under
  the published retention policy.
- For an unexpected `account_deletion_scheduled`, preserve the schedule and
  authentication window, revoke suspicious sessions and contain the credential
  compromise immediately. Have the verified owner cancel through the normal
  strongly authenticated flow before the deadline; do not extend the deadline or
  rewrite timestamps with ad-hoc SQL. An unexplained cancellation may indicate an
  attacker preserving access, so investigate `account_deletion_canceled` against
  the same evidence window. Treat `account_deletion_executed` exactly as an
  immediate `account_deleted` event and verify the logged aggregate session count.
- For repeated saved-chat quota blocks, identify only the privacy-minimized owner
  and scope (`conversation`, `user` or `global`), preserve the event count and
  check database/disk growth. Do not export message content for triage. Keep the
  global gate fail-closed; deleting confirmed owner data requires the normal
  owner/account workflow, not direct counter or generated-column edits.
- For failed or disputed lifecycle cleanup, stop the maintenance timer, preserve
  its journal and any affected owner's retention preference, and run `manage.py
  cleanup_attachments --dry-run` before any retry. Validate both archived-chat
  scope, scheduled-account deadlines and the configured per-user/global AI-usage
  cutoffs. A database commit followed by physical-file deletion failure can leave
  an unreferenced private media file; preserve the failure event, restrict the
  path and escalate for verified cleanup rather than guessing ownership from a
  filename. Do not rewrite timestamps, policy rows, usage counters, or generated
  byte columns to force a result. Restore data believed to be deleted incorrectly
  only through the
  documented, integrity-checked database recovery path; never reconstruct linked
  messages, attachment ownership, or usage evidence with ad-hoc production SQL.
- For `generation_interrupted`, disable automatic/client retries, preserve the
  privacy-minimized request ID/state and provider-usage evidence, and reconcile
  the affected conversation before issuing a new key. Never change an
  `interrupted` job back to `queued`: the provider may have accepted work before
  the local worker failed. Repeated idempotency conflicts may be a broken client
  or deliberate replay/tampering; scope them by owner and key without logging or
  exporting the prompt fingerprint.
- For registration abuse, set `REGISTRATION_MODE=closed`, restart the backend,
  delete unused invitation rows through the verified-2FA admin, and preserve the
  relevant privacy-minimized events before reopening invite mode.
- For an unexpected admin change or integrity failure, disable the affected staff
  account, revoke its sessions, preserve `AdminAuditEvent`, Django `LogEntry`, and
  journal evidence, and verify all retained HMACs before allowing further admin
  mutations. Do not delete the suspected audit rows during containment.

## 3. Assess scope

- Establish the first and last known malicious activity and how access occurred.
- Query by user/object ownership; never assume one exposed ID means only one
  affected row.
- Determine whether prompts, messages, attachments, email addresses, password
  hashes, TOTP material, session cookies, backups, or provider keys were exposed.
- Verify the `aichat` service sandbox and dedicated database role still exclude
  other projects; treat any observed cross-project access as host compromise.
- Record which processors received affected data (NVIDIA, Cloudflare, mail
  infrastructure, GitHub) and consult their incident channels if relevant.

## 4. Eradicate and rotate

Patch the root cause before restoring normal traffic. Rotate affected credentials
from a known-clean device in dependency order: host/Cloudflare/GitHub control
plane, database and mail credentials, NVIDIA key, Django sessions, then application
secrets. `DJANGO_SECRET_KEY` rotation invalidates signed sessions, invitations and
other Django signing artifacts, but versioned TOTP/recovery protection uses the
independent `TWO_FACTOR_KEYS` keyring and privileged-audit evidence uses the
separate `ADMIN_AUDIT_KEYS` keyring. Rotating the Django key therefore does not
invalidate retained admin-audit HMACs or change pseudonymous nonnumeric object
references.

Rotate a suspected 2FA root key by adding a new key with
`configure_two_factor_keys.py --rotate`, selecting it as active, restarting the
backend, and running `manage.py rotate_two_factor_keys`. Do not remove an old key
until `manage.py audit_two_factor_keys --require-active` passes; recovery hashes
cannot be transformed and must first be consumed or regenerated. Any
`two_factor_key_error` is a high-signal integrity/availability incident. Preserve
the database and configuration evidence, revoke sessions, and require re-enrollment
only when the affected TOTP material cannot be decrypted with a trusted retained
key. Never enable legacy `SECRET_KEY` compatibility as an unreviewed workaround.

Rotate a suspected privileged-audit root key by preserving a database/config
copy, adding a new root with `configure_two_factor_keys.py --scope admin-audit
--rotate`, deploying it as active, and running `manage.py
rotate_admin_audit_keys`. The command locks and verifies every retained event
before replacing any tag; a single invalid row aborts and rolls back the complete
re-tag. Preserve that row and the old root as incident evidence, investigate the
integrity failure, and never make it valid by editing or deleting it. Remove an
old audit root only after `manage.py audit_admin_audit_keys --require-active`
passes. Never enable legacy Django-key compatibility merely to silence a failed
inventory.

## 5. Notify

- Notify affected users promptly when doing so reduces harm; provide concrete
  actions such as session revocation, password change, or 2FA re-enrollment.
- Escalate legal/privacy assessment immediately for personal data. Preserve the
  awareness timestamp; GDPR Article 33 may require supervisory-authority notice
  within 72 hours where the breach is likely to risk individuals' rights and
  freedoms.
- Follow contractual notification terms for processors and infrastructure
  providers. Do not speculate publicly before scope is supportable.

## 6. Recover and validate

1. Restore only from a backup whose timestamp and integrity are understood.
2. Apply migrations/configuration, start the backend, validate nginx/systemd, and
   probe health, authentication, private downloads, CSRF, rate limits, and denial
   of `/media/` before reopening traffic.
   Confirm `/run/aichat-backend` is `0750 aichat:aichat-origin`, its
   `gunicorn.sock` is a real `0660` socket with the same ownership, nginx can
   reach it, an unrelated service identity cannot, and nothing listens on the
   retired TCP port `127.0.0.1:8501`.
   Run `manage.py check_attachment_scanner` as `aichat` and require PING, benign
   CLEAN and EICAR FOUND verdicts before reopening attachment or image paths.
   Run `manage.py check_document_parser` as `aichat` and require the real DOCX
   marker to be extracted through the production Unix socket before reopening
   PDF/DOCX uploads. Confirm the parser service and backend both have zero
   unexpected restarts and that the socket remains `0660 aichat-parser` below a
   `0750 aichat-parser` runtime directory.
   Restore application code through the retained `/opt/aichat-backend-releases`
   target or rerun the committed deploy script; never copy repaired Python files
   into the active release. Restore dependencies only through a retained
   `/opt/aichat-python-envs` target or the committed environment deploy script.
   The two newest inactive targets are kept in each executable release root.
   Older supplemental copies may exist as root-only, SHA-256-sidecar archives in
   `/home/micu/backups/nvidia_release_archive`; verify both the sidecar and tar
   member paths/types in isolated staging before considering one for recovery.
   Before re-enabling maintenance after a retention incident, run
   `manage.py cleanup_attachments --dry-run`; confirm that only inactive archived
   conversations older than each owner's nonzero policy qualify and that active
   generation leases remain excluded. Confirm user-linked and aggregate-only AI
   usage rows use their independently configured cutoffs and batch bound.
3. Watch authentication, request/token reservations, unmetered provider calls,
   contractual/GPU spend, error rates, and database changes at elevated
   sensitivity for at least 24 hours.
4. Write a blameless timeline, root cause, affected records, control failures,
   costs, and owners/dates for corrective actions.

## Exercise schedule

- Quarterly: tabletop for credential theft plus private-attachment disclosure.
- Quarterly: alert-path test for availability, authentication abuse, and NVIDIA
  spend.
- Quarterly: controlled account-export alert followed by session containment,
  privacy scoping, and confirmation that the temporary account leaves no residue.
- Quarterly: exercise a failed-maintenance/retention scenario, including dry-run
  scope validation and recovery decision authority.
- At least twice yearly: restore a selected encrypted backup into an isolated
  database and validate row counts and application startup.
- After material architecture changes: repeat the threat model and runbook drill.
