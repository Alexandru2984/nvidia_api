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
sudo install -o root -g root -m 0755 ops/systemd/shared-host/scripts/webhook-cicd-* /usr/local/libexec/
```

Generate `/etc/webhook-cicd/hooks.json` from the current config without printing
or changing its HMAC secret. For every hook, replace `execute-command` with
`/usr/local/libexec/webhook-cicd-enqueue`, replace the working directory with
`/var/lib/webhook-cicd`, and pass only its own hook ID as one fixed string
argument. Install the four tracked units, daemon-reload, enable/start the path
and receiver, then make the legacy config copies root-only.

Acceptance requires: all 17 HMAC and main-branch rules remain present; an
unsigned request causes no queue/deploy; a synthetic queue request starts only
a dry-run test instance; the receiver namespace cannot see `/home/micu`; the
request directory rejects new filenames; loopback and public hook endpoints
respond; and the receiver's systemd exposure is `OK`. Do not trigger a real
project deploy merely to test this boundary.

The old mapping has known operational debt: multiple checkout paths are not Git
worktrees and multiple legacy target unit names no longer exist. This migration
preserves those mappings rather than guessing replacements. Repair each hook
only with that project's build, migration, health and rollback contract.
