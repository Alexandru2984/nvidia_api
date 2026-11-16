# Security program acceptance matrix — 2026-11-16

Scope: NVIDIA / AI Chat Hub only. This indexes the requirements in
[the dated audit](SECURITY_AUDIT_2026-10-07.md#remediation-gates) and
[remediation plan](SECURITY_REMEDIATION_PLAN_2026-10-07.md).
The detailed rollout log remains [SECURITY_AUDIT.md](SECURITY_AUDIT.md).
Historical evidence is identified as such; this is not a claim that every
historical check was independently rerun today. **Overall verdict remains RED.**

## P0 acceptance

| Gate | Recorded control/evidence | What still prevents closure |
| --- | --- | --- |
| P0.1 / S-02: remove browser analytics | Original control met: authenticated SPA source/CSP were narrowed; signed frontend and origin/edge browser evidence are recorded | Cloudflare Browser Insights removal remains an S-15 residual; its blocked injection does not reopen the removed analytics allow-list |
| P0.2 / S-03: immutable monitored webroot | Original control met: root-owned signed releases, manifests, guarded deployment and rollback; independent monitor returned healthy on 2026-11-16 | Off-host evidence and root-level tampering remain P1/S-01 dependencies, not a claim that nginx can still write the release |
| P0.3 / S-05: secure factor enrollment/admin | Password-bound recent proof, atomic factor/session changes, app admin step-up, committed-change operator alerts and regression tests | Fresh read-only inventory: one active staff account, zero enabled staff factors. Owner enrollment from a trusted device and independent Access/VPN admin perimeter remain required |
| P0.4 / S-01: isolate network identities | NVIDIA backend/parser/scanner use dedicated identities and monitored sandboxes | Unrelated services and the shared ingress are outside this authorized change scope. Host-wide compensation is unproven. Preserve the owner's `micu NOPASSWD: ALL` exception; do not migrate other projects silently |
| P0.5 / S-04: unique rotated credentials | Protected file references, exact credential manifest/ACLs, validation and tested local containment are deployed | Provider/mail uniqueness, issuance, revocation and per-credential anomaly evidence require external control planes; moving a value into a protected file is not rotation |
| P0.6 / S-07: host patch/reboot | Current read-only check confirms `/var/run/reboot-required`; running kernel is `7.0.0-42-generic` | Coordinated whole-VPS maintenance, current package/support inventory, reboot and complete shared-service validation; no host update or reboot was performed |
| P0.7 / S-08: encrypted off-site restore | Private local backups and isolated scheduled restores repeatedly pass, including the current guarded monitor installation | No accepted off-site destination, separately held key or off-site restoration proof is recorded. Same-host restore does not close this gate |

## Remaining findings and P1/P2 acceptance

| Finding / gate | Recorded control/evidence | Remaining acceptance evidence |
| --- | --- | --- |
| S-06: document processing | Dedicated credential-free/network-denied parser, bounded protocol/concurrency/resources and local fail-closed malware scanning | Retain parser/scanner regression and update evidence; novel parser defects remain a residual risk |
| S-09 / P1.1: origin trust | Backend Unix socket, exact permissions, direct TCP denial and identity checks are monitored | Shared cloudflared-to-nginx authentication/isolation requires a separate authorized ingress window |
| S-10: session/strong authentication | Absolute session lifetime, indexed registry/cap, recent-auth and account/factor/session serialization are deployed | Preserve the policy for future identity changes; staff-device and edge gates remain P0.3 |
| S-11: concurrency | Durable leases/idempotency/cancellation, attachment claims and native PostgreSQL concurrency tests pass | NVIDIA cannot share the local transaction; indeterminate provider work requires operator reconciliation before a new-key retry |
| S-12 / P1.2: storage/egress/retention | Object/message/file/metadata quotas, physical admission reserves, deletion outbox, bounded exports, archived-history options, usage retention and durable SMTP/recipient attempt budgets are deployed | Owner explicitly selected public registration with limits on 2026-11-16; `open` is intentional, not an invitation-deployment claim. Preserve the limits and review additional human verification if abuse persists. Operator-wide legal/default retention remains undefined; shared-host writers and crash-orphan reconciliation remain separate |
| S-13 / P1.5: detection/response | Signed release/config/socket/identity/storage health, privacy-minimized security events, guarded containment and local tabletop evidence exist | Off-host append-only retention, host sudo signals and provider/mail monetary anomaly evidence remain open; local journals/callbacks are not a durable external audit sink |
| S-14 / P1.4, P1.6: supply chain | Local signed manifests/SBOMs, pinned Actions/hash locks and partial upstream attestations are recorded; full backend PostgreSQL CI gate is committed | The new PostgreSQL gate still needs authorized push. The older Dependabot file is already present at remote `d137c50`; updater/branch-protection settings remain unverified. Remaining upstream attestations and encrypted off-host archive/key lifecycle are open; no new push was made |
| S-15: governance | Public technical notice and processing register are published | Operator identity/privacy contact, legal/default schedules and vendor/DPA/entitlement/region/retention/training decisions require owner and professional review; do not invent them in code |
| S-16: access-log minimization | Minimized nginx/Gunicorn fields and static/browser policy checks are deployed | Preserve minimization and exact retention when an external sink is selected |
| P2: feature-release gate | Existing model/attachment/responsive UI remains covered by the product roadmap and prior browser evidence | Resume new feature releases only after P0 closure or explicit, named owner acceptance with compensating controls |

## Current bounded verification

- Backend: all 814 PostgreSQL tests passed; SQLite passed 805 with nine explicit
  PostgreSQL-only lock skips. All 182 operational and 60 browser checks passed,
  plus a focused final privacy-copy/date rerun. Django/schema, frontend lint/
  build, compilation and shell checks passed. No schema change was required.
- Production backend is the signed exact commit
  `91cc793f5dba3c7bbc4260e82b32860a64596d98`, PID `2808881`, zero automatic
  restarts after a 2/3-second rollback/restoration. Frontend at the same commit
  passed a 1/0-second drill and publishes notice `2026-11-16.1`. Public/origin
  boundary probes, 320/1440 px real privacy browsers and monitor/isolated restore
  passed; the private ledger stayed at zero reserved attempts/recipient hashes
  during checks.
- No production password/factor mutation or synthetic notification was used for
  validation. Active monitor issues are empty; the last notification timestamp
  remains the investigated Certbot event and recovery-notification history is
  empty. Commit identity remains the owner's, without attribution trailers.
- This evidence supports the named controls, not completion of the external,
  host-wide or owner-dependent gates above. A final program close still needs
  fresh complete dependency/drift/security verification and proof for every
  remaining gate; another passing local suite cannot substitute for that proof.
