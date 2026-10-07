# Shared-host service isolation

These units are compensating controls for the owner's explicit decision to keep
passwordless sudo on the interactive `micu` account. Install one service at a
time, with its own config backup, health probes and rollback. Never grant a
service membership in the `micu` group.

## Umami

The unit expects a non-login `umami` user/group and a root-managed environment
file readable only by that group:

```bash
sudo useradd --system --user-group --home-dir /nonexistent --shell /usr/sbin/nologin umami
sudo install -d -o root -g umami -m 0750 /etc/umami
sudo install -o root -g umami -m 0640 /home/micu/umami/.env /etc/umami/umami.env
sudo install -o root -g root -m 0444 /dev/null /etc/umami/empty.env
sudo install -o root -g root -m 0644 ops/systemd/shared-host/umami.service /etc/systemd/system/umami.service
sudo systemctl daemon-reload
sudo systemctl restart umami.service
```

Before restart, retain `/etc/systemd/system/umami.service` and its drop-ins in a
root-readable rollback directory. Acceptance requires all of the following:

```bash
systemctl is-active umami.service
curl -fsS http://127.0.0.1:3010/api/heartbeat
curl -fsS https://analytics.micutu.com/api/heartbeat
systemctl show umami.service -p User -p NoNewPrivileges -p ProtectHome -p ProtectSystem
systemd-analyze security umami.service --no-pager
```

On failure, restore the prior unit/drop-ins, run `systemctl daemon-reload`, and
restart. The dedicated user and protected environment file may remain unused;
do not delete either during an incident rollback.

## Pastebox

Pastebox keeps its mutable SQLite database in a systemd state directory while
the existing build and public assets are mounted read-only. Its hard-coded
`../config.json` lookup resolves from `runtime` to the protected config bind:

```bash
sudo useradd --system --user-group --home-dir /nonexistent --shell /usr/sbin/nologin pastebox
sudo install -d -o root -g pastebox -m 0750 /etc/pastebox
sudo install -o root -g pastebox -m 0440 /home/micu/pastebox/backend/config.json /etc/pastebox/config.json
sudo install -d -o pastebox -g pastebox -m 0700 /var/lib/pastebox/runtime
sudo install -d -o pastebox -g pastebox -m 0700 /var/lib/pastebox/runtime/public
sudo install -d -o pastebox -g pastebox -m 0700 /var/lib/pastebox/runtime/uploads
sudo systemctl stop pastebox.service
sudo sqlite3 /home/micu/pastebox/backend/build/pastebox.db \
  ".backup '/var/lib/pastebox/runtime/pastebox.db'"
sudo chown pastebox:pastebox /var/lib/pastebox/runtime/pastebox.db
sudo chmod 0600 /var/lib/pastebox/runtime/pastebox.db
sudo install -o root -g root -m 0644 ops/systemd/shared-host/pastebox.service /etc/systemd/system/pastebox.service
sudo systemctl daemon-reload
sudo systemctl start pastebox.service
```

Run `PRAGMA quick_check` against both the pre-migration backup and active state,
then probe `/api/health` on loopback and the public hostname. On rollback, stop
the isolated service and use SQLite `.backup` from the active state database
back to the legacy path before restoring the old unit; this preserves pastes
created after migration.

## Video

The Django/Channels service uses a dedicated identity, a root-managed secret
file and a systemd state directory. The application checkout and virtualenv are
visible read-only; the rest of `/home` is hidden from the process.

```bash
sudo useradd --system --user-group --home-dir /nonexistent --shell /usr/sbin/nologin videoapp
sudo install -d -o root -g videoapp -m 0750 /etc/video
sudo install -o root -g videoapp -m 0640 /etc/video.env /etc/video/video.env
sudo install -d -o videoapp -g videoapp -m 0700 /var/lib/video
sudo systemctl stop video.service
sudo sqlite3 /home/micu/Video/db.sqlite3 \
  ".backup '/var/lib/video/db.sqlite3'"
sudo chown videoapp:videoapp /var/lib/video/db.sqlite3
sudo chmod 0600 /var/lib/video/db.sqlite3
sudo install -o root -g root -m 0644 ops/systemd/shared-host/video.service /etc/systemd/system/video.service
sudo systemctl daemon-reload
sudo systemctl start video.service
```

Validate both databases with `PRAGMA quick_check`, compare non-sensitive table
counts, and probe `/healthz` through loopback and the public hostname. Verify
that `videoapp` can update its state database but cannot write the checkout or see
other projects below `/home/micu`. On rollback, stop the isolated unit, copy
new writes back with SQLite `.backup`, restore the saved unit and restart.

## Webhook CI/CD

The public receiver must never execute deploy commands directly. It runs as the
dedicated `webhook-cicd` user, validates GitHub's existing HMAC and branch rules,
and writes only to 17 pre-created request files. It cannot create new queue
entries, see `/home`, access sudo, or reach a non-loopback address.

A root dispatcher reads no request body or command: it checks only the fixed
files and starts the matching `webhook-deploy@<id>.service`. The deploy unit is
a short-lived, non-listening automation task under the trusted interactive
`micu` identity. Its root-owned script contains the complete project/target
allowlist and its mount namespace exposes only those checkouts. A compromised
receiver can request approved deploys (availability risk), but cannot supply a
command, path, target or unit name.

Before installation, back up the effective unit, drop-ins, hook config and
scripts to a root-only rollback directory. Then create the identity, protected
config, fixed request files and root-owned executables:

```bash
sudo useradd --system --user-group --home-dir /nonexistent --shell /usr/sbin/nologin webhook-cicd
sudo install -d -o root -g webhook-cicd -m 0750 /etc/webhook-cicd
sudo install -d -o root -g root -m 0755 /var/lib/webhook-cicd
sudo install -d -o root -g webhook-cicd -m 0710 /var/lib/webhook-cicd/requests
for id in brainfuck cobol code-forest crystal deaddrop drogon-blog lisp lua nvidia pastebox taskmanager ruby pdf-editor pcep expense pixel-art micu-market; do
  sudo install -o root -g webhook-cicd -m 0620 /dev/null "/var/lib/webhook-cicd/requests/$id"
done
sudo install -o root -g webhook-cicd -m 0620 /dev/null /var/lib/webhook-cicd/requests/self-test
sudo install -o root -g root -m 0755 ops/systemd/shared-host/scripts/webhook-cicd-* /usr/local/libexec/
```

Generate `/etc/webhook-cicd/hooks.json` from the current config without printing
or changing its HMAC secret. For every hook, replace `execute-command` with
`/usr/local/libexec/webhook-cicd-enqueue`, replace the working directory with
`/var/lib/webhook-cicd`, and pass only its own hook ID as one fixed string
argument. Install the four tracked units, daemon-reload, enable/start the path
and receiver, then make the legacy config copies root-only.

Acceptance requires: all 17 HMAC and main-branch rules remain present; an
unsigned request causes no queue/deploy; a synthetic `self-test` request starts
only a no-op test instance; the receiver namespace cannot see `/home/micu`; the
request directory rejects new filenames; loopback and public hook endpoints
respond; and the receiver's systemd exposure is `OK`. Do not trigger a real
project deploy merely to test this boundary.

The old mapping has known operational debt: multiple checkout paths are not Git
worktrees and multiple legacy target unit names no longer exist. This migration
preserves those mappings rather than guessing replacements. Repair each hook
only with that project's build, migration, health and rollback contract.

Install `ops/nginx/shared-host/webhook-rate-limit.conf` in `/etc/nginx/conf.d/`
and the tracked webhook vhost in `/etc/nginx/sites-available/`, then run
`nginx -t` before reload. The vhost accepts only POST on the proxied route,
rejects peers outside the Cloudflare/tunnel origin boundary, limits each real
client to 30 requests/minute with a small burst, caps GitHub's payload at its
25 MiB delivery limit and bounds proxy/body timeouts. Keep ACME reachable on
plain HTTP. Acceptance includes a 405/403 for a public GET, 429 under a bounded
unsigned burst, no queued deployment, and a clean nginx error journal.

## Finance anomaly detector

The F#/.NET service keeps its published application and static assets read-only
and moves both SQLite and ASP.NET Data Protection keys into a private systemd
state directory. Runtime settings live in a root-managed environment file.

```bash
sudo useradd --system --user-group --home-dir /nonexistent --shell /usr/sbin/nologin financeapp
sudo install -d -o root -g financeapp -m 0750 /etc/finance-anomaly-detector
sudo install -o root -g financeapp -m 0640 /home/micu/f_sharp/.env /etc/finance-anomaly-detector/app.env
sudo install -d -o financeapp -g financeapp -m 0700 /var/lib/finance-anomaly-detector/keys
sudo systemctl stop finance-anomaly-detector.service
sudo sqlite3 /home/micu/f_sharp/data/finance.db \
  ".backup '/var/lib/finance-anomaly-detector/finance.db'"
sudo install -o financeapp -g financeapp -m 0600 /home/micu/f_sharp/data/keys/*.xml \
  /var/lib/finance-anomaly-detector/keys/
sudo chown financeapp:financeapp /var/lib/finance-anomaly-detector/finance.db
sudo chmod 0600 /var/lib/finance-anomaly-detector/finance.db
```

Before starting, replace `DB_PATH` and `KEYS_DIR` in the protected environment
with `/var/lib/finance-anomaly-detector/finance.db` and
`/var/lib/finance-anomaly-detector/keys`. Install the tracked unit, reload and
start. Acceptance requires matching safe row counts plus `quick_check`, a
rolled-back write transaction, preserved Data Protection key hashes, public and
loopback pages, login negative-path behavior, hidden unrelated homes, read-only
release/static assets and a clean restart. On rollback, stop the isolated unit,
SQLite-backup current state to the legacy path, restore any newly generated key
files, restore the old unit and start it as `micu`.

## Crystal traffic analyzer

This service legitimately reads nginx access/error logs, but it does not need
the rest of the host. The dedicated `crystaltraffic` identity receives `adm` as
a supplementary group inside a mount namespace where all of `/var/log` is
inaccessible except a read-only bind of `/var/log/nginx`. The checkout is
read-only and its `logs` subdirectory is over-mounted by private service state.

```bash
sudo useradd --system --user-group --home-dir /nonexistent --shell /usr/sbin/nologin crystaltraffic
sudo install -d -o root -g crystaltraffic -m 0750 /etc/traffic-analyzer
sudo install -o root -g crystaltraffic -m 0640 \
  /home/micu/crystal/traffic-analyzer/.env /etc/traffic-analyzer/app.env
sudo install -d -o crystaltraffic -g crystaltraffic -m 0700 \
  /var/lib/traffic-analyzer/logs
sudo install -o crystaltraffic -g crystaltraffic -m 0600 \
  /home/micu/crystal/traffic-analyzer/logs/app.log \
  /var/lib/traffic-analyzer/logs/app.log
sudo install -o root -g root -m 0644 \
  ops/systemd/shared-host/traffic-analyzer.service \
  /etc/systemd/system/traffic-analyzer.service
```

Before restart, move the untracked dotenv/source backup copies into the root-only
rollback directory: they contain superseded credential material and are not
runtime inputs. After acceptance, make the legacy active dotenv root-only. The
old password also exists in Git history, so owner password rotation remains a
mandatory manual gate even though the deployed code uses only a bcrypt hash.

Acceptance requires login/static/redirect/WebSocket-negative behavior, the
ability to follow current nginx logs across a clean restart, a writable private
application log, and namespace proof that other home projects and non-nginx logs
are absent. On rollback, restore the old unit, dotenv ownership, app log and
quarantined backup files, then restart as `micu`.

## Ruby Bookmarks

The Rails service processes public authentication/import input, fetches bookmark
metadata from the network, sends password-reset mail and stores application,
queue, cache and cable state in SQLite. It therefore keeps outbound IPv4/IPv6
access but moves every writable path and secret away from the checkout. The
checkout, including precompiled assets, is read-only; private state is mounted
over `storage` and an ephemeral runtime directory is mounted over `tmp`. The
Ruby image-processing stack uses FFI trampolines, so this unit cannot enable
`MemoryDenyWriteExecute`; the remaining privilege, filesystem and capability
controls still apply.

```bash
sudo useradd --system --user-group --home-dir /nonexistent --shell /usr/sbin/nologin bookmarksapp
sudo install -d -o root -g bookmarksapp -m 0750 /etc/bookmarks
sudo install -o root -g bookmarksapp -m 0640 \
  /home/micu/ruby_on_rails/config/master.key /etc/bookmarks/master.key
sudo install -d -o bookmarksapp -g bookmarksapp -m 0700 \
  /var/lib/bookmarks/storage
sudo install -o root -g root -m 0644 \
  ops/systemd/shared-host/bookmarks.service \
  /etc/systemd/system/bookmarks.service
```

Create `/etc/bookmarks/bookmarks.env` as `root:bookmarksapp` mode `0640` using a
root-controlled editor, with the non-secret runtime settings and SMTP settings
from the previous unit. Never place the SMTP credential on a command line or in
`Environment=`. Stop the old service before taking final SQLite `.backup`
copies of all four production databases into `/var/lib/bookmarks/storage`, then
make every copied database and sidecar private to `bookmarksapp`. Preserve the
old unit, key, environment metadata and consistent database backups in a mode
`0700` root-owned rollback directory.

Acceptance requires dependency/code scans and the full Rails suite, `quick_check`
plus matching safe row counts for every database, no pending migration, login and
CSRF negative paths, public/origin health, outbound metadata and SMTP contract
checks that disclose no secrets, a read-only checkout, hidden unrelated homes,
private state, a clean restart and bounded resource use. The credential exposed
by the previous inline systemd environment must be revoked and replaced at the
SMTP provider; moving it to the protected file only removes further local
disclosure. On rollback, stop the isolated service, back up its current SQLite
state, restore the old databases/unit/key ownership and restart as `micu`.

## GT Shop

GT Shop is deployed only as a legacy Spring Boot fat JAR. Copy the reviewed JAR
into root-owned `/opt/gtshop`; do not execute the `micu`-writable home copy. The
service needs only loopback PostgreSQL access, so the dedicated `gtshopapp`
identity has no home visibility or external network route. JVM JIT prevents use
of `MemoryDenyWriteExecute`; capabilities, namespaces, filesystem access,
resource use and address families remain bounded.

```bash
sudo useradd --system --user-group --home-dir /nonexistent --shell /usr/sbin/nologin gtshopapp
sudo install -d -o root -g root -m 0755 /opt/gtshop
sudo install -o root -g root -m 0444 \
  /home/micu/gt-shop-2.0.0.jar /opt/gtshop/gt-shop-2.0.0.jar
sudo install -d -o root -g gtshopapp -m 0750 /etc/gtshop
sudo install -o root -g root -m 0644 \
  ops/systemd/shared-host/gtshop.service /etc/systemd/system/gtshop.service
```

Create `/etc/gtshop/app.env` as `root:gtshopapp` mode `0640`. It must set the
loopback server address/port, local database URL and user, a newly rotated
database password, a newly generated high-entropy `JWT_SECRET`, and
`SPRING_JPA_HIBERNATE_DDL_AUTO=validate`. The embedded default JWT secret is
known material and must never be used. JWT rotation intentionally invalidates
all existing bearer tokens.

Before rotating anything, preserve the old unit/drop-in/environment, JAR hash,
role attributes, table counts and a verified custom-format `pg_dump` in a mode
`0700` root-owned rollback directory. Rotate the PostgreSQL role password and
activate the matching protected environment in the same stopped-service window.
Rollback must restore both the old role password and old unit/config before
starting the service.

The legacy artifact embeds Spring Boot 3.4.1, Spring Framework 6.2.1, Spring
Security 6.4.2 and Tomcat 10.1.34 and has no source/build checkout on this host.
Isolation does not remediate that dependency debt. A reviewed source recovery,
dependency upgrade, test suite and rebuilt signed artifact remain mandatory.
Until then, nginx must fail closed for the anonymously permitted user, cart and
checkout controllers and must not publish API documentation. Acceptance also
requires database continuity, invalid-token/anonymous denials at the public
boundary, public static/reward behavior, loopback-only listening, namespace and
network isolation, a clean restart and warning-level journal review.

Install `ops/nginx/shared-host/gtshop-rate-limit.conf` in nginx's `http` context
and `ops/nginx/shared-host/gtshop.conf` as the site. The boundary deliberately
allows only `POST /RewardHub/api/auth/login` and
`GET /RewardHub/api/rewards`; every other backend path is denied. This suspends
profile, cart and checkout behavior rather than exposing unauthenticated reads
and writes. Restore those routes only after a rebuilt backend enforces and tests
object-level authorization itself.

## R traffic intelligence

The Shiny dashboard needs loopback PostgreSQL access, a private upload area and
private application logs. It does not need a writable checkout, unrelated home
directories or an external network route. Keep the tracked sample data in the
read-only checkout and over-mount only `data/uploads` and `logs` with dedicated
service state. Ubuntu's `r-cran-bslib` package requires
`node-bootstrap-sass`; install it explicitly and retain the unit's path
condition so a missing theme dependency fails at startup instead of returning
HTTP 500 from new Shiny sessions. Do not add `RestrictSUIDSGID`: the `fs`/libuv
recursive directory helper used while compiling Shiny theme assets issues
`mkdir` calls whose mode bits are rejected by that systemd filter, including
for paths that already exist. The read-only checkout, empty capability sets and
`NoNewPrivileges` still prevent the service from creating privileged binaries.

```bash
sudo apt-get install --no-install-recommends node-bootstrap-sass
sudo useradd --system --user-group --home-dir /nonexistent --shell /usr/sbin/nologin rtraffic
sudo install -d -o root -g rtraffic -m 0750 /etc/r-traffic-intel
sudo install -d -o rtraffic -g rtraffic -m 0700 \
  /var/lib/r-traffic-intel/uploads /var/lib/r-traffic-intel/logs
sudo install -o root -g root -m 0644 \
  ops/systemd/shared-host/r-traffic-intel.service \
  /etc/systemd/system/r-traffic-intel.service
```

Create `/etc/r-traffic-intel/app.env` as `root:rtraffic` mode `0640`. Preserve
the non-secret runtime settings, replace the plaintext `APP_PASSWORD` with an
`APP_PASSWORD_HASH` produced by `sodium::password_store()`, and set a newly
rotated `DB_PASSWORD`. Do not retain a redundant `DATABASE_URL`, because it
duplicates the database credential. The application now rejects missing
database settings and ignores dotenv values when systemd already supplied a
setting.

Before rotation, stop the service and preserve its unit, dotenv file, role
attributes, safe table counts and a verified custom-format `pg_dump` in a
root-owned mode `0700` rollback directory. Rotate the PostgreSQL role password
in the same maintenance window as activating the protected environment. Revoke
`CREATE` on the application database and public schema from both the service
role and `PUBLIC`; grant only database `CONNECT`, schema `USAGE` and the
existing table/sequence privileges needed at runtime.

Acceptance requires all parser/config/auth tests, matching safe row counts,
successful read and rolled-back write transactions as `r_traffic_user`, a
working public page, login failure and rate-limit behavior, an authenticated
upload authorization check, loopback-only listening, hidden unrelated homes,
a read-only checkout, private writable upload/log mounts, a clean restart and a
warning-level journal review. On rollback, stop the isolated unit, restore the
old database password and unit/environment together, and restore any upload or
log files created during the isolated run before restarting as `micu`.
