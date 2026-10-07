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
