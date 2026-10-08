# Shared-host `micu` service inventory — 2026-10-07

Purpose: track the compensating control for the owner's explicit decision to
retain `NOPASSWD: ALL` on the interactive `micu` account. A service leaves this
list only after it runs under a dedicated non-login identity, passes its own
functional probes, and cannot see unrelated projects or write its release.

The baseline contained 38 running system services with `User=micu`. Umami,
Pastebox, Video, the webhook receiver, Finance, Traffic Analyzer, Bookmarks, GT
Shop, R Traffic Intelligence and Unison Idea Evolution have been migrated; 28
remain. Loopback
listeners are externally relevant whenever nginx or a Cloudflare tunnel
publishes them.

| Service | NNP | Listener(s) | Known public route / note |
|---|---:|---|---|
| `cf_bot.service` | no | none | outbound bot; handles untrusted messages |
| `asm-canary.service` | yes | `34624` | `asm.micutu.com` |
| `brainfuck-canary.service` | yes | `34623` | `brainfuck.micutu.com` |
| `clojure-eventpulse-canary.service` | yes | `8120` | `clojure.micutu.com` |
| `cobol-canary.service` | yes | `9001` | `cobol.micutu.com` |
| `code-forest-canary.service` | yes | `8089` | `forest.micutu.com` |
| `deaddrop.service` | yes | `8100`, `8101` | `dead.micutu.com` plus internal listener |
| `drogon-blog.service` | yes | `8092` | `blog.micutu.com` |
| `evolving-minds-canary.service` | yes | `4001`, `37049` | `elixir.micutu.com` plus runtime listener |
| `fortran-canary.service` | yes | `8080` | `fortran.micutu.com` |
| `haskell-canary.service` | yes | `3060` | `haskell.micutu.com` |
| `julia-benchmark-lab.service` | yes | `8095` | `julia.micutu.com` |
| `lisp-canary.service` | yes | `8093` | `lisp.micutu.com` |
| `lua-recon-canary.service` | yes | `8084` | `lua.micutu.com` |
| `micu_market.service` | yes | none | background/network behavior to inventory |
| `micupoker.service` | yes | `4100` | `poker.micutu.com` |
| `nimplayground.service` | yes | `8888` | `nim.micutu.com` |
| `nuigraph-studio.service` | yes | `18081` | `nuicpp.micutu.com` |
| `pixelart-canary.service` | yes | `3000` | `pixelart.micutu.com` |
| `prolog-security-canary.service` | yes | `3050` | `prolog.micutu.com` |
| `racket-canary.service` | yes | `8345` | `racket.micutu.com` |
| `scala-logrisk-canary.service` | yes | `8096` | `scala.micutu.com` |
| `simulation-canary.service` | yes | `8094` | `simulation.micutu.com` |
| `spectre-link-canary.service` | yes | `4000`, `9100` | `spectre.micutu.com` plus metrics |
| `testlab.service` | yes | `3011` | `test.micutu.com` |
| `vix-arena.service` | yes | `18080` | `vix.micutu.com` |
| `weather-canary.service` | yes | `8105` | `weather.micutu.com` |
| `webos.service` | yes | `47271` | `odin.micutu.com` |

## Completed migration: Umami

- Changed from `User=micu`, no sandbox and systemd exposure `9.2 UNSAFE` to
  dedicated UID/GID `umami`, `NoNewPrivileges=yes`, strict/read-only filesystem,
  hidden home, no capabilities, localhost-only IP policy and resource ceilings.
- Effective exposure is `2.7 OK`. The service sees only the Umami bind under
  `/home/micu`; AI Chat Hub is absent from its mount namespace and the Umami
  source is not writable.
- Secrets are loaded from root-managed `/etc/umami/umami.env`. The source and
  standalone dotenv paths are over-mounted with a root-owned empty file.
- Loopback/public heartbeat, dashboard, tracker script, `pcep.micutu.com`, and
  AI Chat Hub health all returned `200` after migration.
- Rollback copies:
  `/home/micu/backups/service-migrations/umami-20261007T055635Z` and
  `/home/micu/backups/service-migrations/umami-unit-before-mask-20261007T055747Z`.

## Completed migration: Pastebox

- Changed from `User=micu`, no sandbox and `9.2 UNSAFE` to dedicated UID/GID
  `pastebox`, `NoNewPrivileges=yes`, hidden home, read-only build, localhost-only
  IP policy, empty capabilities and bounded resources at `2.7 OK`.
- The mutable SQLite database moved to a mode `0600` systemd state directory;
  the legacy copy was reduced from world-readable to mode `0600` and is not
  readable inside the service namespace. Root-managed config is bound read-only.
- Pre-migration and active SQLite copies both passed `quick_check` and had the
  same safe row counts (`6` pastes, `1` tag). A write-lock/rollback probe passed
  without persisting data; loopback DB read, public health/home, and AI Chat
  health returned `200`.
- Rollback copy:
  `/home/micu/backups/service-migrations/pastebox-20261007T060501Z`.

## Completed migration: Video

- Changed from `User=micu`, no sandbox and `9.2 UNSAFE` to dedicated non-login
  UID/GID `videoapp`, `NoNewPrivileges=yes`, hidden home, read-only checkout,
  localhost-only IP policy, empty capabilities and bounded resources at `2.7 OK`.
- The standard system group named `video` was deliberately not reused because it
  grants device access. Secrets now live in root-managed
  `/etc/video/video.env`; SQLite state moved to `/var/lib/video/db.sqlite3` at
  mode `0600`, and the legacy database was reduced from world-readable to mode
  `0600` and is unreadable in the service namespace.
- Rollback and active databases passed `quick_check` with identical safe counts
  (`6` users, `2` rooms, `0` messages, `12` sessions). A non-persisting write
  transaction, Redis connection, loopback/public health, public homepage,
  namespace isolation and clean restart all passed without warning-or-higher
  journal entries.
- Rollback copy:
  `/home/micu/backups/service-migrations/video-20261007T113236Z`.

## Completed migration: webhook receiver

- The public listener moved from `User=micu`, direct command execution and
  `7.2 MEDIUM` to dedicated UID/GID `webhook-cicd`, `NoNewPrivileges=yes`, hidden
  home, strict filesystem, localhost-only IP policy, empty capabilities, bounded
  files/resources and `2.7 OK`.
- All 17 existing HMAC SHA-256 and main-branch rules were preserved byte-for-byte
  while command, working-directory and argument handling were replaced. The
  protected receiver can now write only to fixed, root-owned request files and
  has no sudo access. The HMAC-bearing active and legacy configs are no longer
  readable by normal `micu` processes.
- A root dispatcher consumes no payload or command. It starts only root-owned,
  allowlisted deployment instances; the short-lived, non-listening deployment
  worker retains the explicitly trusted `micu` automation identity. A receiver
  compromise can request approved deploys but cannot choose commands, paths or
  service names.
- An unsigned public request produced no queue entry or deployment. The fixed
  no-op `self-test` traversed receiver permissions, path activation, dispatcher
  and worker successfully. Namespace denial, unknown-file denial, sudo denial,
  loopback/public probes and a clean restart passed.
- nginx now accepts only POST on the proxied route, rejects traffic outside the
  Cloudflare/tunnel origin boundary, caps body/timeouts and rate-limits by the
  restored real client IP. Public GET and a direct-origin probe returned `403`;
  a bounded 15-request unsigned burst returned eleven `200` and four `429`
  responses without creating a deployment request.
- Existing delivery debt remains visible instead of being guessed around: five
  configured checkout paths are retired and several legacy target units no
  longer exist. Each mapping needs its own build/health/rollback repair.
- Rollback copy:
  `/home/micu/backups/service-migrations/webhook-cicd-20261007T114224Z`.
- nginx rollback copy:
  `/home/micu/backups/service-migrations/webhook-nginx-20261007T114808Z`.

## Completed migration: Finance anomaly detector

- Changed from `User=micu`, no sandbox and `9.2 UNSAFE` to dedicated non-login
  UID/GID `financeapp`, `NoNewPrivileges=yes`, hidden home, read-only published
  application/static assets, localhost-only IP policy, empty capabilities and
  bounded resources at `2.7 OK`.
- SQLite and ASP.NET Data Protection keys moved into a mode `0700` systemd state
  directory; files are mode `0600`. The root-managed environment points only to
  this state. The legacy database is mode `0600` and is absent from the service
  namespace together with all unrelated home projects.
- NuGet state was restored from the project's pinned references and all 77 tests
  passed. Rollback and active databases passed `quick_check` with identical safe
  counts (`2` users, `11` expenses, `4` anomalies, `0` budgets). The one Data
  Protection key hash was preserved and a database write transaction rolled
  back cleanly.
- Loopback/public roots returned `200`; anonymous private API and an invalid
  login returned `401`. Namespace, permissions, clean restart and journal probes
  passed.
- Rollback copy:
  `/home/micu/backups/service-migrations/finance-anomaly-20261007T115309Z`.

## Completed migration: Traffic Analyzer

- Changed from `User=micu`, no sandbox and `9.2 UNSAFE` to dedicated non-login
  UID/GID `crystaltraffic`, `NoNewPrivileges=yes`, hidden unrelated homes,
  read-only checkout, localhost-only IP policy, empty capabilities and bounded
  resources at `2.7 OK`.
- The service can read only the nginx access/error directory from the host log
  tree and can write only its private state-backed application log. Its
  root-managed environment is mode `0640`; the legacy checkout environment is
  root-only and unreadable from the service namespace.
- Three untracked historical backup files containing credential material were
  moved, without deletion, to the root-only rollback directory. The owner's two
  pre-existing source modifications remain untouched and are the only changes
  reported by the Crystal repository.
- The current source compiled successfully (with only the existing deprecated
  Kemal log-handler warning). Loopback/public login and assets, protected HTTP
  and WebSocket denial, invalid-login cookie denial, log-reader continuity,
  namespace boundaries, clean restart and warning-level journal probes passed.
- The application password still requires owner-coordinated rotation because
  an earlier plaintext value existed in historical source/backup material.
- Rollback copy:
  `/home/micu/backups/service-migrations/traffic-analyzer-20261007T163707Z`.

## Completed migration: Ruby Bookmarks

- Changed from `User=micu`, inline secrets, no sandbox and `9.2 UNSAFE` to the
  dedicated non-login `bookmarksapp` identity, a root-managed environment and
  key, read-only checkout, hidden unrelated homes, private state/runtime paths,
  empty capabilities and bounded resources at `2.9 OK`. Outbound networking is
  intentionally retained for metadata retrieval and password-reset mail.
- Five vulnerable dependency families were updated in Ruby commit `c0a5d11`:
  Rails/Active Storage, JSON, Mail, RubyZip and SQLite. Bundler Audit and
  Importmap report no vulnerable packages, Brakeman reports no warnings, RuboCop
  is clean, and 139 tests with 409 assertions pass.
- Ruby commit `59da158` closes DNS-rebinding SSRF in metadata and link checks by
  rejecting non-public or mixed DNS answers and pinning each socket to the
  validated address while retaining the original TLS hostname. Redirects are
  resolved and validated independently.
- All four production SQLite databases pass `quick_check`; schema migration
  counts match and the primary database preserved `1` user, `1` session and `1`
  bookmark. The legacy key and databases are root-only, while active SQLite
  state and sidecars are mode `0600` under `bookmarksapp`.
- Namespace, checkout/runtime permissions, required egress, loopback/public
  health/login/registration, anonymous private/API denial, missing-CSRF denial,
  invalid-login behavior and clean-restart journal probes passed. The first
  isolated start safely rolled back because Ruby FFI requires executable
  trampolines; commit `aa1fd2d` removed only the incompatible
  `MemoryDenyWriteExecute` control and the retry passed.
- The old unit exposed its SMTP credential through systemd environment metadata.
  It is no longer present in unit metadata and now resides in a mode `0640`
  root-managed file, but that credential must still be revoked and replaced at
  the provider before this incident is closed.
- Rollback copy:
  `/home/micu/backups/service-migrations/bookmarks-20261007T165140Z`.

## Completed migration: GT Shop

- Changed from `User=micu`, a home-readable database credential, a writable JAR,
  no sandbox and `9.2 UNSAFE` to dedicated non-login UID/GID `gtshopapp`, a
  root-owned release/config, no home visibility, loopback-only IP policy, empty
  capabilities and bounded resources at `2.7 OK`.
- The embedded fallback JWT signing secret was active because no override was
  configured. A new 128-character random secret now lives only in the protected
  environment and intentionally invalidated every old bearer token. The
  PostgreSQL role password was also rotated transactionally; the role remains
  non-superuser without create-role/database, replication or bypass-RLS powers,
  and production now uses `ddl-auto=validate`.
- The recovered bytecode confirmed an application authorization bypass:
  `SecurityConfig` applies `permitAll` to all user, cart and checkout paths, and
  anonymous/fake-bearer profile requests returned `200`. Commit `11d1f8c`
  therefore makes nginx fail closed for those namespaces and for Swagger/OpenAPI.
  Only POST login and read-only rewards remain proxied, with method, body, rate
  and timeout bounds. The static site and rewards return `200`; affected routes
  and documentation return `403` publicly.
- The legacy artifact embeds Spring Boot 3.4.1, Framework 6.2.1, Security 6.4.2
  and Tomcat 10.1.34. No source/build checkout exists on the host, and upstream
  security fixes published since that build cannot be safely grafted into the
  fat JAR. Source recovery, dependency upgrades, authorization tests and a
  rebuilt artifact remain a P0 gate; the unsafe product functions stay disabled
  until that gate closes.
- The verified custom-format database dump preserves `3` users, `12` rewards,
  `16` purchase records and `0` cart items. Database continuity, root-owned JAR
  hash, namespace, permissions, local-only listener, public boundary, clean
  restart and warning-level journal probes passed.
- Rollback copy:
  `/home/micu/backups/service-migrations/gtshop-20261007T170301Z`.

## Completed migration: R Traffic Intelligence

- The service moved from `User=micu`, plaintext active credentials, no sandbox
  and `9.2 UNSAFE` to dedicated non-login UID/GID `rtraffic`, a root-managed
  environment, read-only checkout, hidden unrelated homes, localhost-only
  network policy, empty capabilities, private upload/log state and bounded
  resources at `2.9 OK`.
- R commit `71e5e6f` closes a confirmed authorization bypass: hiding the import
  tab did not protect its server-side observer, so an anonymous WebSocket client
  could trigger production log ingestion. Upload processing now requires the
  session's authenticated state. The same commit stores only a sodium password
  hash and rate-limits failures per normalized client address; commit `b58c110`
  rejects missing production DB settings and prevents dotenv from overriding
  systemd configuration.
- The database password was rotated without disclosure and the old credential
  is rejected. The plaintext checkout dotenv and intermediate secret files were
  removed after a root-only rollback copy was verified. The DB role is still a
  non-superuser and now has `CONNECT`/schema `USAGE` without database or schema
  `CREATE`; read, rolled-back write and denied-DDL probes passed. All seven table
  counts match the backup (`190714` requests, `805` IP summaries, `3` imports,
  `5000` mock requests, `4816` mock summaries and zero parser/suspicious rows).
- The host had unregistered Shiny/Bslib package trees with broken JavaScript
  symlinks. Commits `09f6495`, `2f5a2cc` and `a94252f` declare fail-fast runtime
  asset conditions, while the production packages and their dependencies are
  now managed and verify cleanly through dpkg. The first request and every one
  of the 27 referenced local assets return `200` after a clean restart.
- R commit `b72f4bd` replaces remote Google fonts with native UI/code font
  stacks and adds a regression test. The full suite passes 46 assertions.
  Commit `1cfc038` adds Cloudflare-origin enforcement, anti-spoofed client
  identity, per-client request/connection limits, a 25 MiB upload ceiling,
  method restrictions and a Shiny-specific CSP. Direct-origin, oversized-body
  and disallowed-method probes are denied; local/public WebSockets return `101`.
- `RestrictSUIDSGID` is intentionally omitted because the R `fs`/libuv recursive
  directory helper receives `EPERM` while compiling runtime theme assets under
  that filter. Strace confirmed the incompatibility. The release remains
  read-only with no capabilities and `NoNewPrivileges=yes`; namespace, secret,
  public route, credential continuity, login lockout, anonymous-upload denial
  and warning-free restart probes passed.
- Rollback copy:
  `/home/micu/backups/service-migrations/r-traffic-intel-20261007T225125Z`.

## Completed migration: Unison Idea Evolution

- The public FastAPI service moved from `User=micu`, a writable checkout and
  frontend, world-readable SQLite/log files and `9.2 UNSAFE` to dedicated
  non-login UID/GID `unisonapp`, private state, a read-only checkout, hidden
  unrelated homes, localhost-only network policy, empty capabilities and
  bounded resources at `2.7 OK`.
- Unison commits `3be9fa9`, `cc0303c` and `4fe7f72` update all vulnerable Python
  and Node dependency families, constrain anonymous requests and subprocess
  work, sanitize validation errors, bound database results, disable production
  API documentation, enforce exact WebSocket origins and restore the missing
  WebSocket runtime. Seven backend tests, Python compile/check/audit, frontend
  lint/build and both npm audits pass with zero known dependency advisories.
- The SQLite state moved to `/var/lib/unison-backend/evolution.db` at mode
  `0600`. Pre-stop, final-backup and active copies pass `quick_check` with all
  `14` ideas and the same mutation distribution. A write transaction rolled
  back without persistence, and the deterministic mutation engine passed a
  bounded direct smoke test.
- Commits `647aebf`, `5add7b8` and `f0c322b` add the isolated unit, disable
  production dotenv loading, publish root-owned read-only frontend releases
  through an atomic symlink, and enforce Cloudflare-origin, method, body,
  connection, request-rate, write-rate, CSP and WebSocket-origin controls at
  nginx. Documentation/OpenAPI return `404`, oversized input returns `413`,
  unknown mutation input returns a sanitized `422`, and direct-origin access
  returns `403`. Same-origin WebSockets return `101`; cross-origin upgrades are
  rejected at nginx and the application.
- Namespace, read-only checkout, private state, exact deployed hashes, public
  route, rate-limit, clean-restart and warning-level journal checks passed. The
  277 MiB legacy log was moved without deletion into the root-only rollback
  directory, and the legacy database mode was reduced from `0644` to `0600`.
- Rollback copy:
  `/home/micu/backups/service-migrations/unison-20261008T105418Z`.

## Ordered next passes

1. Repair each stale webhook mapping only with that project's build, migration,
   health and rollback contract; do not reactivate retired targets by guessing.
2. Migrate the remaining `NoNewPrivileges=no` content services one at a time,
   prioritizing externally reachable services that parse or store user input.
3. Migrate the already-partially-sandboxed canaries by runtime family, but keep
   distinct UIDs and writable paths rather than replacing `micu` with one new
   shared account.
4. Re-inventory system units, user units, cron, containers and manually launched
   listeners after every batch. The exit condition is zero network/content
   processes under `micu`, not merely zero unit files containing `User=micu`.
