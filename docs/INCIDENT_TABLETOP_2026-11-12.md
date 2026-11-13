# Incident tabletop — signed-release compromise and NVIDIA abuse

Date: 2026-11-12  
Exercise window: 21:48:50–21:49:27 UTC  
Successful technical validation: 21:49:13–21:49:27 UTC (14 seconds)  
Scope: AI Chat Hub only; no unrelated service, Cloudflare route, credential,
account, provider request, user record or production release was changed.

## Scenario and decisions

The simulated trigger was a `frontend_provenance` alert accompanied by an
unexpected NVIDIA cost signal and a possible unauthorized account export. The
incident lead would declare SEV-1, preserve the awareness timestamp and the
active release/signature/public-key evidence, stop release operations, disable
new provider work, revoke suspicious sessions and the NVIDIA credential, and
start legal/privacy assessment before attempting repair. A plausible personal-
data disclosure starts the GDPR 72-hour assessment clock; it is not deferred
until perfect scope is known.

The team must not repair or re-sign a suspect release. Recovery selects a known-
good signed target or builds a fresh commit-bound release after evidence capture.
Signer rotation follows preservation and never replaces the retained public key
needed to verify historical evidence. Provider reconciliation is required before
retrying indeterminate work because NVIDIA is outside the local transaction.

## Evidence exercised

- Active frontend, backend and Python releases all passed Ed25519 verification
  with the retained production public-key fingerprint. No private signing key was
  read.
- The root-managed six-file application-credential boundary passed its exact
  manifest, ownership, mode, ACL and real-open checks without printing paths or
  values.
- Ten provenance regressions and 46 monitor regressions passed, including
  altered-file/signature, unsafe topology/mode and notification-state cases.
- Production settings expose the `AI_GENERATION_ENABLED` containment switch;
  it was intentionally left enabled because this was an exercise. Registration
  was observed as `open` and was not changed.
- The production isolated-restore unit restored the newest private dump into a
  random scratch database, verified schema/migrations and removed the scratch
  database. systemd reported `Result=success` and exit status zero.
- Origin and Cloudflare returned the expected status for root/health (`200`),
  arbitrary media (`404`), and dotenv/private conversations (`403`).
- The independent monitor completed with `Result=success`, exit status zero and
  no artificial Telegram notification.

The first operator command stopped safely after release verification because it
used `/usr/bin/python3` for the credential checker and that interpreter does not
contain `python-dotenv`. No production mutation occurred. The corrected command
used `/opt/aichat-python-current/bin/python`; future exercises must use the exact
active runtime rather than an ambient interpreter.

## Open actions

| Priority | Action | Owner / dependency | Review gate |
| --- | --- | --- | --- |
| P0 | Enroll the sole staff account in 2FA from a trusted device and place `/admin/` behind Cloudflare Access or VPN | Owner plus Cloudflare identity policy | Before the P0 admin gate can close |
| P0 | Issue unique NVIDIA and SMTP credentials, revoke the reused values and prove per-credential usage alerts | Owner/provider control planes | Before S-04 can close |
| P0 | Apply host/tunnel security updates and reboot with a shared-service maintenance window | Owner; affects other VPS applications | Coordinated window plus complete public-service validation |
| P1 | Isolate the shared cloudflared-to-nginx client-IP path, preferably with the documented HTTP-over-Unix-socket route | Shared tunnel maintenance; must not silently affect other applications | Direct-loopback spoof probe denied while edge identity remains correct |
| P1 | Replicate privacy-minimized security evidence and encrypted backups off-host with separately held recovery material | External destination/key decision | Restore and evidence-retention exercise from the off-host copy |
| P1 | Disable Cloudflare Browser Insights and retain the strict same-origin CSP | Cloudflare zone setting | Edge browser shows no injected remote/inline script |

## Completed follow-up — 2026-11-13

The guarded provider/registration action is closed by commit `5b51237`. The
root-owned installed command validates fixed dependencies and credential
boundaries, uses both the shared release lock and its own operation lock, writes
only through an exclusive staged file, and keeps its sole exact rollback snapshot
under `/run`. Failure after mutation restores that snapshot, restarts the backend
and re-runs bounded health, private-API and media probes. Planned changes pause
and restore the protected-config watcher so they do not create an artificial
Telegram alert; the five-minute monitor and its 24-hour per-issue cooldown were
not weakened.

Ten focused regressions, 136 operational tests, ShellCheck and all 647 backend
tests passed. The installed command and renderer are byte-identical root-owned
`0755` files and joined the now 30-target protected-config watcher. Production
dry-run confirmed `enabled/open` to `disabled/closed` without mutation. The live
exercise found zero active generation requests, contained in 5 seconds, restored
in 4 seconds, and produced the identical dotenv SHA-256 before and after. The
backend returned with a distinct healthy PID and `NRestarts=0`; seven origin and
seven Cloudflare-edge probes passed, the protected-config path and monitor/restore
timers remained active, and the independent monitor reported no active issue. No
provider request, account/data mutation, release switch or Telegram test
notification occurred.

The post-rollout failure-path drill ran separately in a private mount namespace.
It bind-mounted a non-secret runtime fixture and root-owned checker stubs, replaced
`systemctl`, `curl`, `runuser` and `logger` only through the namespace test path,
and injected failure into the first backend restart after the configuration
switch. The error trap restored the fixture byte-for-byte, performed the second
successful restart and bounded probes, restarted the watcher, returned failure to
the operator and left no `/run` snapshot. The real backend PID, `NRestarts=0`,
watcher/timer state and production dotenv hash were unchanged.

## Verdict

The runbook is executable for local detection, atomic provider/registration
containment, signed recovery and isolated database validation. Verdict remains
**yellow / mitigate then ship**: local controls work, but provider revocation,
independent admin perimeter, shared tunnel isolation, off-host evidence/backup
and coordinated host maintenance require owner or external control-plane action.
