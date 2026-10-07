# Shared-host `micu` service inventory — 2026-10-07

Purpose: track the compensating control for the owner's explicit decision to
retain `NOPASSWD: ALL` on the interactive `micu` account. A service leaves this
list only after it runs under a dedicated non-login identity, passes its own
functional probes, and cannot see unrelated projects or write its release.

The baseline contained 38 running system services with `User=micu`. Umami was
migrated first; 37 remain. Loopback listeners are externally relevant whenever
nginx or a Cloudflare tunnel publishes them.

| Service | NNP | Listener(s) | Known public route / note |
|---|---:|---|---|
| `bookmarks.service` | no | `3001` | `ruby.micutu.com` |
| `cf_bot.service` | no | none | outbound bot; handles untrusted messages |
| `finance-anomaly-detector.service` | no | `5000` | `f.micutu.com` |
| `gtshop.service` | no | `8087` | verify tunnel route |
| `pastebox.service` | no | `7777` | `pastebox.micutu.com`; user content |
| `r-traffic-intel.service` | no | `3838` | `r.micutu.com` |
| `traffic-analyzer.service` | no | `8070` | `crystal.micutu.com` |
| `unison-backend.service` | no | `8097` | verify tunnel route |
| `video.service` | no | `8121` | `video.micutu.com`; media input |
| `webhook-cicd.service` | no | `9500` | `hooks.micutu.com`; deployment boundary |
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

## Ordered next passes

1. Inspect `webhook-cicd.service` first because a public webhook with deployment
   authority can invalidate every other service boundary.
2. Migrate the remaining `NoNewPrivileges=no` content services one at a time,
   prioritizing Pastebox and Video because they process user-controlled data.
3. Migrate the already-partially-sandboxed canaries by runtime family, but keep
   distinct UIDs and writable paths rather than replacing `micu` with one new
   shared account.
4. Re-inventory system units, user units, cron, containers and manually launched
   listeners after every batch. The exit condition is zero network/content
   processes under `micu`, not merely zero unit files containing `User=micu`.
