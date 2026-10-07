# Shared-host `micu` service inventory — 2026-10-07

Purpose: track the compensating control for the owner's explicit decision to
retain `NOPASSWD: ALL` on the interactive `micu` account. A service leaves this
list only after it runs under a dedicated non-login identity, passes its own
functional probes, and cannot see unrelated projects or write its release.

The baseline contained 38 running system services with `User=micu`. Umami,
Pastebox, Video and the webhook receiver have been migrated; 34 remain. Loopback
listeners are externally relevant whenever nginx or a Cloudflare tunnel
publishes them.

| Service | NNP | Listener(s) | Known public route / note |
|---|---:|---|---|
| `bookmarks.service` | no | `3001` | `ruby.micutu.com` |
| `cf_bot.service` | no | none | outbound bot; handles untrusted messages |
| `finance-anomaly-detector.service` | no | `5000` | `f.micutu.com` |
| `gtshop.service` | no | `8087` | verify tunnel route |
| `r-traffic-intel.service` | no | `3838` | `r.micutu.com` |
| `traffic-analyzer.service` | no | `8070` | `crystal.micutu.com` |
| `unison-backend.service` | no | `8097` | verify tunnel route |
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
- Existing delivery debt remains visible instead of being guessed around: five
  configured checkout paths are retired and several legacy target units no
  longer exist. Each mapping needs its own build/health/rollback repair.
- Rollback copy:
  `/home/micu/backups/service-migrations/webhook-cicd-20261007T114224Z`.

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
