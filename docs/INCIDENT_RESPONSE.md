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
a database backup older than 30 hours, or a restore drill older than eight days.

## 2. Contain

- Disable the affected route/account or put the application into maintenance
  mode if continued exposure is plausible.
- Revoke suspicious Django sessions and Cloudflare/GitHub/provider tokens.
- Block confirmed hostile indicators at the closest trusted edge, but preserve
  the evidence that justified the block.
- For upload/parser compromise, stop the backend, quarantine the file without
  opening it on a workstation, and inspect the service account's reachable files.
- For NVIDIA cost abuse, disable generation or revoke the API key before tuning
  throttles. A spending incident can continue while the UI appears healthy.
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
secrets. Treat `DJANGO_SECRET_KEY` rotation as a planned migration: it invalidates
signed sessions and currently affects protection/derivation of authentication
artifacts including TOTP material. Verify consequences before rotation and require
2FA re-enrollment when decryption or integrity cannot be assured. Existing admin
audit HMACs and pseudonymous nonnumeric object references also depend on this key;
re-tag them through a reviewed migration before rotation or preserve the old key
for evidence validation.

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
3. Watch authentication, request/token reservations, unmetered provider calls,
   contractual/GPU spend, error rates, and database changes at elevated
   sensitivity for at least 24 hours.
4. Write a blameless timeline, root cause, affected records, control failures,
   costs, and owners/dates for corrective actions.

## Exercise schedule

- Quarterly: tabletop for credential theft plus private-attachment disclosure.
- Quarterly: alert-path test for availability, authentication abuse, and NVIDIA
  spend.
- At least twice yearly: restore a selected encrypted backup into an isolated
  database and validate row counts and application startup.
- After material architecture changes: repeat the threat model and runbook drill.
