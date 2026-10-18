# AI Chat Hub

![CI](https://github.com/Alexandru2984/nvidia_api/actions/workflows/ci.yml/badge.svg)

A self-hosted chat UI for NVIDIA's NIM-hosted open models. Its conservative
catalog currently tracks 20 documented chat endpoints and exposes only those
verified by the private runtime probe. Pick a model, chat, and save private
conversations per user. Deployed at `https://aichat.micutu.com`.

## Stack

- **Backend** — Django 6 + Django REST Framework, PostgreSQL, gunicorn under systemd
- **Frontend** — React 19 + Vite (built static SPA, served by nginx)
- **Auth** — Django session cookies, CSRF-protected, invite-capable registration with 6-digit OTP via email
- **LLM** — Proxies to `https://integrate.api.nvidia.com/v1/chat/completions` (OpenAI-compatible)

## Repo layout

```
.
├── backend/
│   ├── nvidia_chat/        # Django project (settings, urls, wsgi)
│   ├── chat/               # the only app — models, views, serializers
│   │   ├── models_catalog.py   # validated list of working NVIDIA model IDs
│   │   └── migrations/
│   ├── manage.py
│   ├── requirements.txt
│   └── requirements.lock  # exact production wheels with SHA-256 hashes
├── frontend/
│   ├── src/                # React application and styles
│   ├── tests/              # responsive Playwright coverage
│   └── vite.config.js
├── ops/                     # reviewed nginx/systemd templates
├── scripts/                 # backup automation
└── docs/                    # audit, roadmap, incident runbook
```

## Local setup

```bash
# Backend
cd backend
python -m venv venv
. venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # see "Environment" below
python manage.py migrate
python manage.py createsuperuser
python manage.py runserver 8501

# Frontend
cd frontend
npm install
npm run dev   # vite dev server on :5173
```

The Vite development server proxies `/api` and `/admin` to
`http://127.0.0.1:8501`, keeping cookies and CSRF on one origin.

## Environment

`backend/.env` is the file Django loads (`load_dotenv(BASE_DIR / '.env')`). Required keys:

```
DJANGO_SECRET_KEY=...
DJANGO_DEBUG=False
DJANGO_ALLOWED_HOSTS=aichat.micutu.com,localhost,127.0.0.1
TWO_FACTOR_KEYS={"prod-2026-10":"<independently-generated-base64url-32-byte-key>"}
TWO_FACTOR_ACTIVE_KEY_ID=prod-2026-10
TWO_FACTOR_LEGACY_SECRET_KEY_ENABLED=False
ADMIN_AUDIT_KEYS={"prod-2026-10":"<different-independently-generated-base64url-32-byte-key>"}
ADMIN_AUDIT_ACTIVE_KEY_ID=prod-2026-10
ADMIN_AUDIT_LEGACY_SECRET_KEY_ENABLED=False

DB_NAME=nvidia_db
DB_USER=nvidia_user
DB_PASSWORD=...
DB_HOST=127.0.0.1
DB_PORT=5432

NVIDIA_API_KEY=nvapi-...
NVIDIA_API_URL=https://integrate.api.nvidia.com/v1/chat/completions
AI_GENERATION_ENABLED=True
AI_USER_DAILY_CHAT_LIMIT=100
AI_USER_DAILY_IMAGE_LIMIT=10
AI_GLOBAL_DAILY_CHAT_LIMIT=500
AI_GLOBAL_DAILY_IMAGE_LIMIT=50
CHAT_RETENTION_DELETE_BATCH_SIZE=100
ACCOUNT_DELETION_GRACE_DAYS=7
ACCOUNT_DELETION_BATCH_SIZE=25
ATTACHMENT_FILE_DELETION_BATCH_SIZE=1000
CHAT_MAX_CONVERSATIONS_PER_USER=500
CHAT_MAX_MESSAGES_PER_USER=10000
CHAT_MAX_MESSAGES_PER_CONVERSATION=2000
CHAT_MAX_ASSISTANT_CHARS=64000
CHAT_MAX_MESSAGE_BYTES_PER_CONVERSATION=16777216
CHAT_MAX_MESSAGE_BYTES_PER_USER=67108864
CHAT_MAX_MESSAGE_BYTES_GLOBAL=1073741824
CHAT_MAX_EXPORT_BYTES=26214400
ACCOUNT_EXPORT_MAX_BYTES=134217728
ACCOUNT_EXPORT_MAX_RECORDS=25000
SESSION_ABSOLUTE_MAX_AGE_SECONDS=2592000
SESSION_MAX_ACTIVE_PER_USER=20
RECENT_AUTH_MAX_AGE_SECONDS=300

# Email (used for OTP verification) — self-hosted mailcow
SMTP_HOST=mail.micutu.com
SMTP_PORT=587
SMTP_USER=noreply@micutu.com
SMTP_PASS=...
SMTP_FROM=noreply@micutu.com
FRONTEND_URL=https://aichat.micutu.com
```

Settings auto-pick `EMAIL_USE_SSL` when `SMTP_PORT=465`, otherwise STARTTLS (`EMAIL_USE_TLS`) is used — the mailcow server on `mail.micutu.com:587` takes the STARTTLS path.

## Registration policy

`REGISTRATION_MODE` accepts `open`, `invite`, or `closed`. The production systemd
profile selects `invite`; local development defaults to `open`. Create a one-time
code from the production application identity and transfer it only to the intended
recipient:

```bash
cd /home/micu/nvidia/backend
sudo -u aichat venv/bin/python manage.py create_registration_invite --expires-hours=72
```

The plaintext code is printed once and never stored. PostgreSQL keeps only an
HMAC, expiry, consumption time, and consuming account. Concurrent redemption is
serialized; mail failure rolls back both the inactive user and invitation use.
Expired unused records and used audit rows older than
`REGISTRATION_INVITE_AUDIT_DAYS` (default 90) are removed by daily maintenance.
Changing `DJANGO_SECRET_KEY` invalidates every outstanding invite.

## API

All endpoints are under `/api/`. Auth uses session cookies; mutations need `X-CSRFToken` from the `csrftoken` cookie.
JSON bodies must be objects and use exact field types: text stays text,
generation dimensions/counts/IDs are JSON integers (never booleans or coerced
strings/fractions), flags are booleans, and attachment IDs are positive signed
64-bit integers. Persistence IDs in URLs are bounded to the same database domain;
session-revocation handles are exactly 64 lowercase hexadecimal characters.

| Method | Path | Body | Auth | Notes |
|---|---|---|---|---|
| GET | `/auth/me/` | — | open | Sets `csrftoken` cookie. Returns `username`, `registration_mode`, and the current provider-disclosure state for authenticated users. |
| POST | `/auth/register/` | `{username, email, password, invite_code?}` | open | Creates an inactive user and emails an OTP. Invite mode requires an unused code; valid duplicate identifiers remain opaque and do not consume it. |
| POST | `/auth/verify/` | `{email, code}` | open | 6-digit code; failures do not disclose account/code state; logs the user in on success. |
| POST | `/auth/resend/` | `{email}` | open | Silent 60s cooldown with a generic response for unknown, throttled, or mail-failure cases. |
| POST | `/auth/forgot/` | `{email}` | open | Always returns generic success; emails a 6-digit reset code if eligible. |
| POST | `/auth/reset/` | `{email, code, password}` | open | Code-state failures are generic; applies Django's password validators after code verification. |
| POST | `/auth/login/` | `{username, password, code?}` | open | Rejects inactive users and requires TOTP/recovery code when 2FA is enabled. |
| POST | `/auth/logout/` | — | session | |
| POST | `/auth/reauthenticate/` | `{password, code?}` | session | Refreshes the five-minute sensitive-action window; 2FA accounts require both factors. |
| POST | `/auth/password/` | `{current_password, new_password, code?}` | session | Requires both factors when enabled, keeps this session, and revokes all others. |
| POST | `/auth/delete-account/` | `{password, code?}` | session | Permanent; needs 2FA code if enabled. Revokes every indexed Django session before cascading live user data and returns `sessions_revoked`. |
| GET/POST | `/auth/2fa/*` | varies | session | Status, enrollment, verification, disable, and recovery-code rotation. |
| GET/DELETE | `/auth/sessions/*` | — | session | Lists indexed, opaque non-bearer handles without decoding the global session table; revocation requires recent strong authentication. |
| GET | `/account/usage/` | — | session | Attachment bytes, saved conversation/message counts and limits, plus today's durable chat/image budgets and UTC reset. |
| GET/PATCH | `/account/chat-retention/` | `{archived_days}` | session | Owner-scoped opt-in lifecycle. Accepts 0 (keep until manually deleted), 30, 90, 180, or 365 days; only inactive archived conversations qualify. |
| GET/POST/DELETE | `/account/deletion/` | `{password, code?}` for mutations | session | Shows, schedules, or cancels owner-scoped account deletion. The default grace period is seven days; scheduling is idempotent and never extends an existing deadline. Cancellation closes at the deadline. |
| GET | `/account/export/` | — | recent strong session | Owner-only JSON stream containing account/chat/preferences/usage data and an attachment manifest, never file bodies or authentication secrets. Limited to 2/day and rejected before streaming above the validated record/byte ceilings. |
| POST | `/provider-disclosure/` | `{version}` | session | Records the current versioned NVIDIA data-flow acknowledgement; stale or non-integer versions fail closed. |
| GET | `/models/` | — | session | Returns only currently available NVIDIA models, grouped-purpose and conservative `best_for` guidance, per-model input/attachment capabilities, rounded successful-probe performance, the selected default, probe timestamp, and global attachment limits. Private failure outcomes are never returned. |
| GET | `/conversations/?q=` | — | session | Scoped to `request.user`; `q` searches titles and message text. |
| POST | `/conversations/` | `{model_id?, title?}` | session | Enforces the durable per-user conversation limit atomically. |
| GET/PATCH/DELETE | `/conversations/<id>/` | `{title?, model_id?, system_prompt?, temperature?, max_tokens?}` | session | 404 if not owned. Params: temp 0–1, tokens 64 through the selected model's advertised ceiling, prompt ≤4000 chars. |
| POST | `/conversations/<id>/messages/` | `{content, model_id?, attachment_ids?}` | session | Atomically reserves both saved-message slots before proxying to NVIDIA. The effective model is validated before any override is saved; incompatible type, MIME, byte size, image count, storage quota, or output bound fails closed. |
| GET | `/conversations/<id>/export/` | — | session | Owner-scoped Markdown stream; limited to 10/hour and rejected before streaming when its conservative estimate exceeds `CHAT_MAX_EXPORT_BYTES`. |
| GET | `/attachments/?kind=` | — | session | List user's attachments (optionally filter by `image`/`document`/`generated_image`). |
| POST | `/attachments/upload/` | `multipart` fields `file`, `model_id?` | session | Global whitelist: jpg/png/webp/gif, pdf, txt, md, docx; the selected model further restricts image types/count/size. 10 MB/file, 100 MB/user. Bytes are streamed to local ClamAV before type inspection, extraction, deduplication or storage. PDF/DOCX extraction then runs serially under the credential-free, network-denied `aichat-parser` identity; scanner/parser ambiguity or outage fails closed. Empty or image-only documents are rejected. An identical pending upload for the same owner is reused with `deduplicated: true`. |
| DELETE | `/attachments/<id>/` | — | session | Only unlinked attachments can be deleted. |
| GET | `/attachments/<id>/preview/` | — | session | Ownership-checked, 4,000-character extracted-text preview for documents; returned with private/no-store cache policy. |
| GET | `/attachments/<id>/download/` | — | session | Ownership-checked private download, limited to 120/hour; never expose `MEDIA_ROOT` directly. |
| GET | `/images/models/` | — | session | List image-generation catalog (FLUX schnell/dev; each entry includes `allowed_dims`). |
| POST | `/images/generate/` | `{prompt, model_id?, width?, height?, steps?, seed?}` | session | Returns `{attachment, …}`. Requires scanner readiness before provider egress and scans the returned PNG before local storage. |

The composer accepts picker, drag/drop, and clipboard image inputs through one
capability-aware queue. Each file has progress, cancel, retry, and dismiss state;
pending files can be included or excluded from the next request without deletion,
and extracted document text can be previewed as inert text. Identical unlinked
content is deduplicated with a secret-keyed, owner-scoped fingerprint that is never
serialized or logged. Failed files remain browser-local until retried or dismissed.
Logout/session loss aborts in-flight work and clears pending previews so attachment
state cannot cross accounts in a shared browser. An upload canceled after the
server has already committed can remain as an owner-scoped, unlinked attachment and
is covered by the normal attachment library/deletion flow and scheduled orphan
cleanup.

Before the first chat, regeneration, or image-generation request, the responsive
UI explains exactly which selected prompt, conversation context, files, and image
settings leave the self-hosted application for NVIDIA. Acceptance is versioned
server-side and records only the user relationship, version, and timestamp. The
backend returns `428 provider_disclosure_required` before acquiring generation
leases, reserving budget, writing messages, or contacting NVIDIA when the current
version has not been accepted. This is a transparency acknowledgement, not a
claim that it alone establishes a GDPR legal basis or NVIDIA production entitlement.

Chat, regeneration, and image calls reserve daily PostgreSQL-backed counters
before contacting NVIDIA. Limits apply per user and globally across all gunicorn
workers; exhausted user budgets return `429`, while a service-wide budget returns
`503`, both with a UTC reset time. Set `AI_GENERATION_ENABLED=False` and restart
the backend for an immediate provider circuit breaker. Streamed chat calls also
reserve a conservative token allowance atomically; the terminal NVIDIA `usage`
chunk replaces that reservation with actual prompt/completion tokens. Missing or
malformed usage fails closed until the UTC reset and is security-monitored. Tune
`AI_USER_DAILY_TOKEN_LIMIT`, `AI_GLOBAL_DAILY_TOKEN_LIMIT`, and
`AI_CHAT_TOKEN_RESERVATION` for the deployment's capacity. Daily maintenance
removes owner-linked usage rows older than `AI_USER_USAGE_RETENTION_DAYS`
(default 90) and aggregate-only rows older than
`AI_GLOBAL_USAGE_RETENTION_DAYS` (default 400), in independently bounded batches.

Only one send or regeneration may run per conversation across all workers.
PostgreSQL-backed leases return `409 generation_in_progress` with `Retry-After`,
are heartbeated during long streams, and expire fail-safe after
`CHAT_GENERATION_LEASE_SECONDS` (default 900; allowed 300–3600). Closing a stream
before provider dispatch removes its pending user message and releases its token
reservation. Pending attachment rows are revalidated under row lock before they
are linked, and regeneration keeps the previous branch until replacement text
exists.

Browser send/regenerate actions also carry a fresh canonical UUID in
`Idempotency-Key`. The durable owner-scoped request record and its lease are
created atomically; reusing the key with changed conversation, operation, target
or payload fails closed. Completed and partial-canceled results replay as SSE
from the stored messages without a second NVIDIA call, including after an
attachment has already been claimed or a regeneration target was replaced.
Active duplicates receive `409 generation_request_in_progress`; failed or
interrupted work remains closed instead of being dispatched ambiguously. The
request fingerprint is a purpose-derived HMAC and does not duplicate prompt text.
Legacy clients receive a server-generated key, but safe retry requires the client
to reuse the returned key. Maintenance reconciles expired leases and uncommitted
send rows, marks their jobs `interrupted`, and retains terminal metadata for
`GENERATION_REQUEST_RETENTION_DAYS` (default 7; allowed 1–90).

Saved chat growth is also bounded across workers. Conversation creation locks the
owner row before enforcing `CHAT_MAX_CONVERSATIONS_PER_USER`; send and trailing-
user regeneration reserve their projected message rows under the same lock before
provider work. Defaults are 500 conversations/user, 10,000 messages/user and
2,000 messages/conversation. Database-generated UTF-8 byte counts and a singleton
transaction gate additionally enforce 16 MiB/conversation, 64 MiB/user and 1
GiB/service message-text ceilings. Sends reserve the exact prompt plus the
worst-case assistant size before provider work; regeneration reserves only its
maximum net growth. Assistant output is capped at 64,000 characters, Markdown
exports are streamed under a conservative 25 MiB ceiling, and quota blocks are
security-monitored. The responsive Storage panel exposes current counts, text
bytes and owner-visible limits without disclosing global tenant usage. Its full
account export requires a fresh password plus 2FA when enabled, streams only the
owner's portable JSON under `ACCOUNT_EXPORT_MAX_BYTES` and
`ACCOUNT_EXPORT_MAX_RECORDS`, and omits file bodies, extracted text, hashes,
password/OTP/2FA material, raw session credentials and internal request
fingerprints. Daily
maintenance deletes expired database sessions and processes at most
`CHAT_RETENTION_DELETE_BATCH_SIZE` owner-opted-in archived conversations. It
revalidates policy, age and absence of a generation lease under the normal lock
order before cascading their messages and linked files. Active chats and accounts
without an explicit policy are kept until manual deletion. Session inventory/
revocation and attachment/export egress have explicit rate limits.

Owners can separately schedule complete live-account deletion with a default
seven-day grace period. `ACCOUNT_DELETION_GRACE_DAYS` is startup-validated from
1 through 30 days, and `ACCOUNT_DELETION_BATCH_SIZE` limits each daily run to
1–100 accounts (default 25). Schedule/cancel mutations require the current
password and enabled second factor, are limited to five attempts per hour, and
serialize on the owner row. Scheduling is idempotent, cannot push an existing
deadline forward, and cancellation fails closed once the deadline is due. The
maintenance job removes expired generation leases first, excludes every owner
with active generation work before applying the batch limit, then rechecks the
deadline and lease state under the global-gate/owner lock order. Execution
revokes every indexed session and cascades live account data; physical attachment
deletion is deferred until database commit so rollback cannot strand restored
rows without their files. The same transaction writes a durable deletion-outbox
row first. A successful post-commit storage delete clears it; failures emit only
`attachment_file_delete_failed` (never a path or filename) and daily maintenance
retries oldest entries under `ATTACHMENT_FILE_DELETION_BATCH_SIZE` (default
1,000, startup-bounded 1–10,000). Restricted operational backups expire
independently under the backup policy (the local default keeps the newest seven
dumps).

Authenticated sessions keep Django's 14-day sliding cookie but are also bounded
by a fixed 30-day lifetime from login. Rotations preserve that original deadline,
each account is limited to 20 active sessions, and the oldest non-current session
is removed atomically when the cap is reached. The owner-indexed session registry
stores only a secret-keyed non-bearer handle; registry mismatches fail closed and
feed the security monitor. Tune `SESSION_ABSOLUTE_MAX_AGE_SECONDS` and
`SESSION_MAX_ACTIVE_PER_USER` only within their validated ranges.

Sensitive account mutations share a recent-authentication policy. A complete
password/2FA login or explicit `/auth/reauthenticate/` confirmation creates a
five-minute marker bound to the user, session and current password hash through a
secret-keyed fingerprint. Missing, expired, future-dated, malformed or stale-
credential markers fail closed. Password changes, account deletion and 2FA
changes verify the required credentials inline; changing a 2FA account's password
now requires its second factor. Session revocation prompts responsively for a
fresh password and, when enabled, TOTP/recovery code before retrying the original
action. Reauthentication never extends the fixed absolute session deadline.
`RECENT_AUTH_MAX_AGE_SECONDS` defaults to 300 and is restricted to 60–3600.

The token limit is a consumption/capacity control, not a fabricated currency
estimate. NVIDIA documents production NIM pricing around licensing/GPU capacity,
so monetary enforcement must use the owner's actual contract or infrastructure
cost rather than an assumed per-token price.

Provider egress is pinned to the three documented NVIDIA HTTPS hosts/paths in
settings; userinfo, alternate ports/hosts/paths, query strings and fragments fail
startup validation. Chat/probe SSE and image JSON responses are streamed under
hard byte/line/time bounds, require validated shapes, never follow redirects, and
close every image polling response. Provider errors remain generic to clients.

## Model catalog

`chat/models_catalog.py` is the allowlisted set of documented NVIDIA NIM chat
endpoints. It was built by:

1. Calling `GET https://integrate.api.nvidia.com/v1/models` to get the live list.
2. Filtering out embeddings, retrievers, parsers, reward models and detectors;
   chat-compatible safety and translation models remain explicitly classified.
3. Checking the official model card for context, purpose and modalities, then
   probing each candidate with a one-token chat request. The source allowlist may
   retain a documented endpoint through a transient outage, but the runtime
   status exposes it only after a successful probe or trusted prior decision.

NVIDIA retires NIM models regularly and `/v1/models` is unreliable in both directions, so availability is re-checked automatically:

- `python manage.py probe_models` probes every catalog model with the production
  streaming envelope and a 1-token completion (with one retry for cold starts).
  A model passes only after a valid SSE event, terminal usage accounting and
  `[DONE]`; a 200 JSON response, provider error event, truncated stream or missing
  usage is an inconclusive protocol failure. The command writes the private `0600` runtime file
  `backend/.cache/model_status.json` atomically. Its schema, size, model IDs,
  outcome vocabulary, latency range, attempt count, timezone and freshness are
  validated when read. Production requires this file and accepts it for eight
  days; missing, stale, future-dated or malformed state fails closed and triggers
  the security monitor.
- Definitive endpoint failures (`404/410`) and payload-contract rejection
  (`400/422`) mark a model unavailable. Authentication/entitlement failures,
  throttling, timeouts, network/protocol errors, ambiguous 4xx and provider 5xx responses
  are inconclusive: an already verified model keeps its last decision through
  two consecutive probe runs, then fails closed on the third; the first success
  automatically restores it. A never-verified model remains blocked. Degraded,
  persistent and authorization failures are alerted and explicit in the
  authenticated UI without exposing provider bodies.
- `/api/models/` subtracts the resolved unavailable set at request time — dead models disappear from the picker without a deploy. If the default model is down, the response falls back to the first available one.
- Each catalog row exposes `purpose`, `recommended`, conservative `best_for`,
  input `capabilities`, and a model-specific `generation` contract. The UI groups assistant/coding/translation/safety/
  specialized models and derives its image/document picker from that contract;
  it also derives temperature/output-token controls from the selected model.
  The backend and database independently enforce the same attachment and
  generation rules. Riva Translate v2 is capped at its documented 4096 output
  tokens and uses the provider's documented 0/512 defaults for new conversations.
- The model explorer searches name/vendor/ID/capabilities/guidance, sorts by
  recommendation, last probe, context, or name, compares up to three available
  models, and shows the runtime availability timestamp. Successful latency is
  rounded to 100 ms and explicitly labeled as one synthetic availability sample,
  not a quality benchmark; provider failure details stay server-side. Favorites and
  six recent model IDs are browser-local, bounded preferences; no user identity,
  prompt, conversation title, or message content is written there.
- Documents are provided to models as bounded extracted text. Images are sent
  only to explicitly documented vision endpoints; incompatible pending files
  block sending, and incompatible historical images are omitted when switching
  to a text-only model.
- Conversation creation uses that same fallback, while explicit selection,
  sending, or regeneration with a retired model is rejected before consuming a
  request/token reservation.
- Existing conversations retain their history when a model retires. The UI marks
  the stale selection as unavailable, blocks generation, and offers a one-click
  switch to the current available default.
- `aichat-model-probe.timer` refreshes it every Monday and Thursday, with a
  randomized ten-minute delay. A six-minute service deadline bounds hung
  provider calls. Run the command manually after NVIDIA announces model changes.

Adding a brand-new model means editing `chat/models_catalog.py` and verifying its
ID, description, context window, purpose, recommendation status, input modalities,
accepted image MIME types, maximum image count/bytes, and live probe result.
Also declare any generation-limit/default override in `chat/generation.py` and
verify the maximum request shape against the official hosted endpoint.

## Production deploy

The VPS pattern matches every other `*.micutu.com` app on this host:

- **systemd unit** `/etc/systemd/system/aichat-backend.service` runs `gunicorn` as the dedicated, non-login `aichat` identity (gthread workers, `--timeout 600` for SSE streams), binds only the `0660 aichat:aichat-origin` Unix socket below a `0750` runtime directory, imports application code only from `/opt/aichat-backend-current`, and executes the root-owned runtime at `/opt/aichat-python-current`. Secrets, media and cache remain below the private runtime directory `/home/micu/nvidia/backend`; checkout source and its builder virtualenv are hidden from the service namespace. The reviewed unit and sandbox are under `ops/systemd/`.
- **nginx** vhost `/etc/nginx/sites-available/aichat.micutu.com` serves the built SPA from `/var/www/aichat.micutu.com/` and proxies API/admin traffic through the permissioned backend socket. Only `aichat` and nginx's `www-data` workers receive the one-purpose `aichat-origin` group; unrelated local service identities cannot bypass edge policy through a TCP origin. `/media/` must return `404`; private files are served only through `/api/attachments/<id>/download/`. The reviewed template is `ops/nginx/aichat.micutu.com.conf`.
- **SSL** via certbot: `sudo certbot --nginx -d aichat.micutu.com --non-interactive --agree-tos --email <you> --redirect`. `certbot.timer` handles renewal.
- **PostgreSQL** runs on `127.0.0.1:5432`. Per-app DB and user as documented in the VPS pattern.
- **Attachment malware scanning** — `clamd` accepts only a permissioned local
  Unix socket and receives raw bytes through `INSTREAM`; it receives no filename,
  owner, prompt or attachment metadata. Official signatures refresh locally,
  scanner limits are tighter than the application upload boundary, encrypted or
  limit-exceeding containers are rejected, and upload/image paths fail closed on
  timeout, malformed verdict or daemon failure. This reduces known-malware risk;
  it does not prove that a novel malicious document is harmless.
- **Isolated document parsing** — PDF/DOCX bytes cross a versioned, bounded local
  Unix-socket protocol with no filename, owner or prompt metadata. A sequential
  `aichat-document-parser` service starts a resource-limited child under the
  non-login `aichat-parser` identity. Its systemd sandbox hides home/secrets,
  denies network address families and capabilities, keeps the filesystem
  read-only except for private runtime/tmp paths, and caps aggregate memory,
  CPU and tasks. Invalid documents are never stored; service/protocol failure is
  a retryable fail-closed response.
- **Scheduled jobs**: application jobs run as `aichat` through the sandboxed
  `aichat-maintenance.timer` and `aichat-model-probe.timer`. Host-level backup
  jobs remain in the administrator's cron:
  ```cron
  # Postgres backup, gzip, keeps newest 7 (daily)
  30 2 * * * /home/micu/nvidia/scripts/backup_db.sh
  # Isolated restore/integrity drill (weekly)
  15 5 * * 0 /home/micu/nvidia/scripts/backup_restore_drill.sh
  ```
- **Monitoring** — the host-wide `check_sites.sh` cron pings `https://aichat.micutu.com` every minute and alerts on failures.
- **Security monitoring** — `aichat-security-monitor.timer` evaluates structured,
  privacy-minimized auth/admin/rate/budget events, privileged changes, audit
  integrity, all three active root-owned release manifests, executable-release
  retention, generation lease interruptions and repeated mismatched idempotency
  keys, protected dotenv/vhost/unit/monitor changes, backup/restore
  freshness, ClamAV health/signature freshness, scanner
  failures, malware rejections, parser socket health, parser failures and installed
  parser executable integrity against the manifest-verified backend release, plus
  redirected/malformed provider response rejections every five minutes. It uses the host's
  existing Telegram channel through a systemd credential, runs under the
  dedicated non-login `aichat-monitor` identity, keeps cooldown state under
  `/var/lib/aichat-security-monitor`, and never forwards raw log lines. A named
  read-only ACL permits listing/statting this app's backup directory and reading
  only the privacy-minimized restore status; mode-`0600` database dumps remain
  unreadable to the monitor.
  Account-deletion schedule, cancellation and committed execution each raise a
  count-only alert; journal evidence contains numeric owner identifiers but no
  username, email, IP, prompt, filename, session key or authentication factor.
  A committed attachment-storage deletion failure also alerts without its path
  or filename while the durable maintenance outbox retains retry state.

Deploy steps after a code change:

```bash
# One-time local scanner prerequisite (Ubuntu repository packages only)
sudo apt-get install --no-install-recommends clamav-daemon clamav-freshclam
sudo scripts/install_attachment_scanner.sh
sudo -u aichat env --chdir=/home/micu/nvidia/backend \
  /home/micu/nvidia/backend/venv/bin/python manage.py check_attachment_scanner

# One-time isolated PDF/DOCX parser prerequisite
sudo scripts/install_document_parser.sh

# Backend application code (deploys committed HEAD only)
cd /home/micu/nvidia
git status --short
sudo -u aichat env AICHAT_RUNTIME_DIR=/home/micu/nvidia/backend \
  /opt/aichat-python-current/bin/python backend/manage.py migrate
sudo scripts/deploy_backend.sh
sudo runuser --user aichat -- env --chdir=/opt/aichat-backend-current \
  AICHAT_RUNTIME_DIR=/home/micu/nvidia/backend PYTHONDONTWRITEBYTECODE=1 \
  /opt/aichat-python-current/bin/python manage.py check_document_parser

# Only when requirements.txt and its validated requirements.lock change;
# versions must remain compatible with the currently active application until
# the following backend switch completes.
python3 scripts/check_requirements_lock.py
sudo scripts/deploy_python_env.sh
sudo scripts/deploy_backend.sh

# Frontend
cd /home/micu/nvidia/frontend
npm run build
cd /home/micu/nvidia
sudo scripts/deploy_frontend.sh

# Validate the shared edge after deployment
sudo nginx -t
sudo systemctl reload nginx
curl -fsS https://aichat.micutu.com/api/health/
curl -o /dev/null -sS -w '%{http_code}\n' https://aichat.micutu.com/media/not-public

# Install/update the root-owned security monitor and timer
sudo scripts/install_security_monitor.sh
```

The frontend deploy script stages a root-owned release below
`/var/www/aichat-releases`, validates that it contains no remote script tag, and
atomically switches `/var/www/aichat.micutu.com`. nginx receives read-only
`0755`/`0644` content and each release includes a SHA-256 manifest checked by the
five-minute security monitor; never restore `www-data` ownership. The first
conversion from the legacy directory requires
`sudo scripts/deploy_frontend.sh --bootstrap`.
Every later deploy omits `--bootstrap`. Failed health/private-route probes switch
back to the prior target automatically while retaining both releases for review.

The backend deploy script archives only tracked files from committed `HEAD`,
rejects dirty tracked changes, symlinks, special files, secrets and mutable-state
directories, and stages a root-owned `0755`/`0644` release below
`/opt/aichat-backend-releases`. It verifies the manifest, runs Django and migration
preflights as `aichat` (including real scanner and isolated-parser readiness),
atomically switches `/opt/aichat-backend-current`, installs
the committed systemd templates, restarts, checks the process working directory
and public/private boundaries, and restores both code and unit files on failure.
Use `sudo scripts/deploy_backend.sh --bootstrap` only for the first conversion.
Later deploys omit the flag and retain the previous release. Database migrations
must be backed up, reviewed for backward compatibility and applied before the
switch.

The Python-environment deploy script builds the committed `requirements.lock`
using only binary wheels whose exact versions and SHA-256 hashes mirror
`requirements.txt`. Installation runs with pip's `--require-hashes` under an
unprivileged builder that cannot read application secrets or private state. The
script rejects extra packages, symlinks, special/unsafe paths and excessive size,
runs application/import preflights, normalizes the release to root ownership and
exact modes, embeds a deterministic CycloneDX 1.7 SBOM for the selected wheels,
writes requirement and full-tree manifests, and atomically switches
`/opt/aichat-python-current`. The SBOM records each package URL, version and wheel
SHA-256, is checked exactly against the committed lock in CI/build, and is covered
by both release hash chains. On later dependency changes the deploy restarts and
probes the backend, restoring the prior environment on failure. Use
`sudo scripts/deploy_python_env.sh --bootstrap` only for the first environment.
CI validates lockfile structure, and the five-minute monitor validates the active
release manifest and requires the SBOM artifacts.

Every successful deploy keeps the active release and the two newest inactive
rollback targets in its executable release root. Older releases and any converted
legacy frontend tree are frozen to root ownership, archived below the private
`/home/micu/backups/nvidia_release_archive`, gzip- and SHA-256-verified, and only
then removed from the executable root. The retention tool is dry-run by default:

```bash
python3 scripts/archive_release_retention.py --family all
sudo scripts/archive_release_retention.py --apply --family all
```

It fails closed on symlinks, special files, unknown root entries, unsafe ownership
or size/file-count limits, and never selects the active target or the newest two
rollback releases. Archived releases are supplemental recovery material; define
an encrypted off-site lifecycle before treating them as durable backups.

Backend and Python deploys share an exclusive release-operation lock with the
rollback drill, so their atomic symlink changes cannot overlap. Exercise each
rollback family independently, first read-only and then with two brief service
restarts:

```bash
sudo scripts/release_rollback_drill.sh --family backend --preflight-only
sudo scripts/release_rollback_drill.sh --family backend
sudo scripts/release_rollback_drill.sh --family python --preflight-only
sudo scripts/release_rollback_drill.sh --family python
```

The drill chooses the newest inactive release, verifies root ownership, safe
modes, the complete manifest, commit marker and compatibility before switching.
Python candidates must additionally have exact lock/checksum/SBOM evidence, pass
`pip check`, and use the same requirements lock as the active environment. Each
activation is tied to the service PID's real working directory or executable and
must pass root, health, `security.txt`, private API, source/config and media
boundary probes within 60 seconds. An exit/signal trap always switches back to
the exact original target and verifies it. The drill never runs migrations,
contacts the model provider or writes application data.

Conversation search uses PostgreSQL's trusted `pg_trgm` extension. Install it
once as the database administrator before migration `0017`; do not grant the
application role database-level `CREATE` solely for this operation:

```bash
sudo -u postgres psql --dbname=<app-database> --set=ON_ERROR_STOP=1 \
  --command='CREATE EXTENSION IF NOT EXISTS pg_trgm;'
```

The migration creates the title/content GIN indexes concurrently so normal chat
writes are not held behind an index build.

One-time immutable-release conversion for an existing healthy checkout-based
service (take configuration and database backups first):

```bash
# Prerequisite: the checkout-backed aichat service is already active and healthy.
sudo chgrp aichat backend/.env && sudo chmod 0640 backend/.env
sudo chown -R aichat:aichat backend/media backend/.cache
sudo chmod 0700 backend/media backend/.cache
sudo scripts/deploy_backend.sh --bootstrap
sudo scripts/deploy_python_env.sh --bootstrap
sudo scripts/deploy_backend.sh
sudo install -o root -g root -m 0644 ops/systemd/aichat-{maintenance,model-probe}.{timer} /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now aichat-maintenance.timer aichat-model-probe.timer
```

Run production management commands that touch runtime files as `aichat`. Source
updates remain owned by the deployment administrator; production dependency
installation runs as the secret-blind `nobody` builder and becomes root-owned
before activation.

Bootstrap the independent 2FA keyring before the first production deployment
that contains 2FA key versioning. The helper changes only the three managed
settings, replaces `.env` atomically, preserves its exact owner/group/mode, and
never prints key material:

```bash
sudo python3 scripts/configure_two_factor_keys.py \
  --env-file /home/micu/nvidia/backend/.env --key-id prod-2026-10
sudo -u aichat env AICHAT_RUNTIME_DIR=/home/micu/nvidia/backend \
  /opt/aichat-python-current/bin/python /opt/aichat-backend-current/manage.py \
  audit_two_factor_keys --require-active
```

For a planned 2FA-key rotation, use the same helper with a new identifier and
`--rotate`, restart/deploy the backend, then run `rotate_two_factor_keys`. TOTP
secrets are re-encrypted transactionally; recovery hashes retain their recorded
old key ID until each code is consumed or the user regenerates the set. Keep the
retired key configured until `audit_two_factor_keys --require-active` passes.
`TWO_FACTOR_LEGACY_SECRET_KEY_ENABLED` exists only for an explicitly supervised
legacy migration and stays `False` in production.

Bootstrap the independent privileged-audit keyring with a different generated
root key before deploying audit-key versioning, then prove that every retained
event validates with the active key:

```bash
sudo python3 scripts/configure_two_factor_keys.py \
  --scope admin-audit --env-file /home/micu/nvidia/backend/.env \
  --key-id prod-2026-10
sudo -u aichat env AICHAT_RUNTIME_DIR=/home/micu/nvidia/backend \
  /opt/aichat-python-current/bin/python /opt/aichat-backend-current/manage.py \
  audit_admin_audit_keys --require-active
```

For a planned audit-key rotation, add a new root with the same helper plus
`--scope admin-audit --rotate`, deploy/restart so it becomes active, run
`rotate_admin_audit_keys`, and rerun the inventory with `--require-active` before
removing the retired root. Rotation verifies every event before re-signing and
rolls the entire operation back if any retained row is corrupt or unverifiable.
`ADMIN_AUDIT_LEGACY_SECRET_KEY_ENABLED` is a supervised migration bridge only and
stays `False` in production.

Take a recoverable copy of each live configuration before replacing it. After
deployment, check service logs, authentication/CSRF, a private attachment download,
`/.well-known/security.txt`, and rollback. See the
[security audit](docs/SECURITY_AUDIT.md), [incident runbook](docs/INCIDENT_RESPONSE.md),
and [roadmap](docs/ROADMAP.md).

## Auth notes

- Conversations are FK'd to the user with `on_delete=CASCADE` — deleting a user deletes their chats.
- Cross-user access on `/api/conversations/<id>/` returns `404`, not `403`, to avoid leaking which IDs exist.
- OTP code is HMAC-SHA256 hashed (peppered with `SECRET_KEY`) before storage. TTL 30 min. Six wrong attempts invalidates the code.
- Resend and password recovery have a 60s server-side cooldown. Eligible,
  ineligible, cooling-down, and mail-failure requests deliberately return the
  same public response so account and code state cannot be enumerated.
- Registration returns the same success shape for available and existing valid
  identifiers. Verification/reset failures do not distinguish unknown accounts,
  missing codes, expired codes, exhausted attempts, or wrong codes.
- Email verification gates registration. New registrations are limited per IP and
  use a honeypot, but a durable cross-process limiter plus challenge/invite mode is
  still required before opening registration to higher-volume traffic.
- Django admin never accepts a password-only/direct admin session. Staff must
  enable 2FA and verify it through the main application in the current session;
  denied probes and the first valid admin access are security-monitor events.
- Every Django admin add/change/delete is written to the sanitized native log and
  a privacy-minimized `AdminAuditEvent` mirror. The mirror stores actor/object IDs,
  model/action, and changed field names, but no titles, emails, message content,
  filenames, or changed values. Its HMAC is checked by daily maintenance; any
  privileged change or integrity failure alerts within the five-minute monitor
  cycle. Both audit stores retain 365 days by default via
  `ADMIN_AUDIT_RETENTION_DAYS`.
- TOTP secrets and recovery-code hashes use purpose-separated keys inside
  versioned envelopes. Their root keyring is independent of
  `DJANGO_SECRET_KEY`; missing, retired-too-early, malformed, or corrupted
  artifacts fail closed and emit `two_factor_key_error` for the five-minute
  security monitor. Recovery codes remain usable during a TOTP lockout.
- Nonnumeric admin object references and integrity tags use separate,
  purpose-derived keys inside versioned envelopes. Their bounded root keyring is
  independent of both `DJANGO_SECRET_KEY` and the 2FA keyring; unknown, malformed,
  corrupt, or retired-too-early artifacts fail closed. Numeric database IDs
  remain unchanged for incident correlation.

## Things to know about the email provider

Email is sent through the self-hosted mailcow instance at `mail.micutu.com` (STARTTLS on 587), so `From: noreply@micutu.com` works as-is. SPF/DKIM/DMARC are managed at the mailcow/DNS level. If you ever switch back to Gmail SMTP, note that Gmail rewrites the `From:` header to the authenticated account.
