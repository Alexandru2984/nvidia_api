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
| S-12 / P1.2: storage/egress/retention | Object/message/file/metadata quotas, physical admission reserves, deletion outbox, bounded exports, archived-history options and usage retention are deployed | Operator-wide legal/default retention schedule remains undefined. Fresh runtime inspection reports registration `open`; invite capability alone does not prove invite-only production policy. Shared-host writers and crash-orphan reconciliation remain separate from admission reserves |
| S-13 / P1.5: detection/response | Signed release/config/socket/identity/storage health, privacy-minimized security events, guarded containment and local tabletop evidence exist | Off-host append-only retention, host sudo signals and provider/mail monetary anomaly evidence remain open; local journals/callbacks are not a durable external audit sink |
| S-14 / P1.4, P1.6: supply chain | Local signed manifests/SBOMs, pinned Actions/hash locks and partial upstream attestations are recorded; full backend PostgreSQL CI gate is committed | The new PostgreSQL gate still needs authorized push. The older Dependabot file is already present at remote `d137c50`; updater/branch-protection settings remain unverified. Remaining upstream attestations and encrypted off-host archive/key lifecycle are open; no new push was made |
| S-15: governance | Public technical notice and processing register are published | Operator identity/privacy contact, legal/default schedules and vendor/DPA/entitlement/region/retention/training decisions require owner and professional review; do not invent them in code |
| S-16: access-log minimization | Minimized nginx/Gunicorn fields and static/browser policy checks are deployed | Preserve minimization and exact retention when an external sink is selected |
| P2: feature-release gate | Existing model/attachment/responsive UI remains covered by the product roadmap and prior browser evidence | Resume new feature releases only after P0 closure or explicit, named owner acceptance with compensating controls |

## Current bounded verification

- Backend: all 790 PostgreSQL tests passed; SQLite passed 781 with nine explicit
  PostgreSQL-only lock skips. All 181 operational checks passed. Django/schema,
  compilation and shell checks passed. No schema/frontend change was required
  by the current account-security stage; prior browser evidence is separate.
- Production backend is the signed exact commit
  `0d6eaa0d6bc65c44444d1bb09c940b828b69c63f`, PID `973556`, zero automatic
  restarts after a 2/2-second rollback/restoration. Public/origin boundary probes
  and monitor/isolated restore passed. The frontend retains its earlier signed
  `2a0f38b` release.
- No production password/factor mutation or synthetic notification was used for
  validation. Active monitor issues are empty; the last notification timestamp
  remains the investigated Certbot event and recovery-notification history is
  empty. Commit identity remains the owner's, without attribution trailers.
- This evidence supports the named controls, not completion of the external,
  host-wide or owner-dependent gates above. A final program close still needs
  fresh complete dependency/drift/security verification and proof for every
  remaining gate; another passing local suite cannot substitute for that proof.
