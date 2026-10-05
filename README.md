# AI Chat Hub

![CI](https://github.com/Alexandru2984/nvidia_api/actions/workflows/ci.yml/badge.svg)

A self-hosted chat UI for NVIDIA's NIM-hosted open-weight LLMs (Llama, Nemotron, Qwen, DeepSeek, GPT-OSS — ~40 validated models). Pick a model, chat, save conversations per-user. Deployed at `https://aichat.micutu.com`.

## Stack

- **Backend** — Django 6 + Django REST Framework, PostgreSQL, gunicorn under systemd
- **Frontend** — React 19 + Vite (built static SPA, served by nginx)
- **Auth** — Django session cookies, CSRF-protected, register flow with 6-digit OTP via email
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
│   └── requirements.txt
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

DB_NAME=nvidia_db
DB_USER=nvidia_user
DB_PASSWORD=...
DB_HOST=127.0.0.1
DB_PORT=5432

NVIDIA_API_KEY=nvapi-...
NVIDIA_API_URL=https://integrate.api.nvidia.com/v1/chat/completions

# Email (used for OTP verification) — self-hosted mailcow
SMTP_HOST=mail.micutu.com
SMTP_PORT=587
SMTP_USER=noreply@micutu.com
SMTP_PASS=...
SMTP_FROM=noreply@micutu.com
FRONTEND_URL=https://aichat.micutu.com
```

Settings auto-pick `EMAIL_USE_SSL` when `SMTP_PORT=465`, otherwise STARTTLS (`EMAIL_USE_TLS`) is used — the mailcow server on `mail.micutu.com:587` takes the STARTTLS path.

## API

All endpoints are under `/api/`. Auth uses session cookies; mutations need `X-CSRFToken` from the `csrftoken` cookie.

| Method | Path | Body | Auth | Notes |
|---|---|---|---|---|
| GET | `/auth/me/` | — | open | Sets `csrftoken` cookie. Returns `{username}` or `{username: null}`. |
| POST | `/auth/register/` | `{username, email, password}` | open | Creates inactive user, emails OTP. |
| POST | `/auth/verify/` | `{email, code}` | open | 6-digit code; logs user in on success. |
| POST | `/auth/resend/` | `{email}` | open | 60s cooldown; never leaks whether the email exists. |
| POST | `/auth/forgot/` | `{email}` | open | Always returns generic success; emails a 6-digit reset code if account exists. |
| POST | `/auth/reset/` | `{email, code, password}` | open | Validates the code, applies Django's password validators, logs the user in. |
| POST | `/auth/login/` | `{username, password}` | open | Rejects inactive users. |
| POST | `/auth/logout/` | — | session | |
| POST | `/auth/password/` | `{current_password, new_password}` | session | Keeps this session, revokes all others. |
| POST | `/auth/delete-account/` | `{password, code?}` | session | Permanent; needs 2FA code if enabled. Cascades all user data. |
| GET/POST | `/auth/2fa/*` | varies | session | Status, enrollment, verification, disable, and recovery-code rotation. |
| GET/DELETE | `/auth/sessions/*` | — | session | Lists opaque session handles and revokes selected/other sessions. |
| GET | `/account/usage/` | — | session | Storage totals by attachment kind. |
| GET | `/models/` | — | session | Returns validated NVIDIA models. |
| GET | `/conversations/?q=` | — | session | Scoped to `request.user`; `q` searches titles and message text. |
| POST | `/conversations/` | `{model_id?, title?}` | session | |
| GET/PATCH/DELETE | `/conversations/<id>/` | `{title?, model_id?, system_prompt?, temperature?, max_tokens?}` | session | 404 if not owned. Params: temp 0–2, tokens 64–8192, prompt ≤4000 chars. |
| POST | `/conversations/<id>/messages/` | `{content, model_id?, attachment_ids?}` | session | Proxies to NVIDIA, persists both messages. Vision images allowed only on vision-capable models. |
| GET | `/attachments/?kind=` | — | session | List user's attachments (optionally filter by `image`/`document`/`generated_image`). |
| POST | `/attachments/upload/` | `multipart` field `file` | session | Whitelist: jpg/png/webp/gif, pdf, txt, md, docx. 10 MB/file, 100 MB/user. Document text is extracted on upload. |
| DELETE | `/attachments/<id>/` | — | session | Only unlinked attachments can be deleted. |
| GET | `/attachments/<id>/download/` | — | session | Ownership-checked private download; never expose `MEDIA_ROOT` directly. |
| GET | `/images/models/` | — | session | List image-generation catalog (FLUX schnell/dev; each entry includes `allowed_dims`). |
| POST | `/images/generate/` | `{prompt, model_id?, width?, height?, steps?, seed?}` | session | Returns `{attachment, …}`. Saves the generated image to local media storage. |

## Model catalog

`chat/models_catalog.py` is the validated list of NVIDIA NIM models that respond to chat completions. It was built by:

1. Calling `GET https://integrate.api.nvidia.com/v1/models` to get the live list.
2. Filtering out non-chat models (embeddings, retrievers, parsers, classifiers, reward models).
3. Probing each candidate with a minimal `messages: [{role: "user", content: "hi"}]` request and keeping only those returning `200`.

NVIDIA retires NIM models regularly and `/v1/models` is unreliable in both directions, so availability is re-checked automatically:

- `python manage.py probe_models` probes every catalog model with a 1-token completion (with one retry for cold starts) and writes `backend/model_status.json`.
- `/api/models/` subtracts the unavailable set at request time — dead models disappear from the picker without a deploy. If the default model is down, the response falls back to the first available one.
- A weekly cron (Sunday 04:00) keeps the status fresh. Run the command manually after NVIDIA announces model changes.

Adding brand-new models still means editing `chat/models_catalog.py` (id, name, vendor, context, vision flag).

## Production deploy

The VPS pattern matches every other `*.micutu.com` app on this host:

- **systemd unit** `/etc/systemd/system/aichat-backend.service` runs `gunicorn` (gthread workers, `--timeout 600` for SSE streams), binds `127.0.0.1:8501`, and reads `/home/micu/nvidia/backend/.env`. Apply the reviewed drop-in at `ops/systemd/hardening.conf`; migrating from the shared `micu` identity to an app-only identity remains a P0 task.
- **nginx** vhost `/etc/nginx/sites-available/aichat.micutu.com` serves the built SPA from `/var/www/aichat.micutu.com/`, proxies authenticated API/admin traffic, and must return `404` for `/media/`. Private files are served only through `/api/attachments/<id>/download/`. The reviewed template is `ops/nginx/aichat.micutu.com.conf`.
- **SSL** via certbot: `sudo certbot --nginx -d aichat.micutu.com --non-interactive --agree-tos --email <you> --redirect`. `certbot.timer` handles renewal.
- **PostgreSQL** runs on `127.0.0.1:5432`. Per-app DB and user as documented in the VPS pattern.
- **Cron jobs**:
  ```cron
  # orphan attachments + expired OTP rows (daily)
  0 3 * * *  cd /home/micu/nvidia/backend && venv/bin/python manage.py cleanup_attachments
  # NVIDIA model availability probe (weekly)
  0 4 * * 0  cd /home/micu/nvidia/backend && venv/bin/python manage.py probe_models
  # Postgres backup, gzip, keeps newest 7 (daily)
  30 2 * * * /home/micu/nvidia/scripts/backup_db.sh
  # Isolated restore/integrity drill (weekly)
  15 5 * * 0 /home/micu/nvidia/scripts/backup_restore_drill.sh
  ```
- **Monitoring** — the host-wide `check_sites.sh` cron pings `https://aichat.micutu.com` every minute and alerts on failures.

Deploy steps after a code change:

```bash
# Backend
cd /home/micu/nvidia/backend
. venv/bin/activate
pip install -r requirements.txt
python manage.py migrate
sudo systemctl restart aichat-backend.service

# Frontend
cd /home/micu/nvidia/frontend
npm run build
sudo rsync -a --delete dist/ /var/www/aichat.micutu.com/
sudo chown -R www-data:www-data /var/www/aichat.micutu.com/

# Validate before/reload after installing reviewed ops templates
sudo nginx -t
sudo systemctl daemon-reload
sudo systemctl restart aichat-backend.service
sudo systemctl reload nginx
curl -fsS https://aichat.micutu.com/api/health/
curl -o /dev/null -sS -w '%{http_code}\n' https://aichat.micutu.com/media/not-public
```

Take a recoverable copy of each live configuration before replacing it. After
deployment, check service logs, authentication/CSRF, a private attachment download,
`/.well-known/security.txt`, and rollback. See the
[security audit](docs/SECURITY_AUDIT.md), [incident runbook](docs/INCIDENT_RESPONSE.md),
and [roadmap](docs/ROADMAP.md).

## Auth notes

- Conversations are FK'd to the user with `on_delete=CASCADE` — deleting a user deletes their chats.
- Cross-user access on `/api/conversations/<id>/` returns `404`, not `403`, to avoid leaking which IDs exist.
- OTP code is HMAC-SHA256 hashed (peppered with `SECRET_KEY`) before storage. TTL 30 min. Six wrong attempts invalidates the code.
- Resend has a 60s server-side cooldown, returning `429` with `resend_available_in` so the frontend can sync the timer.
- Email verification gates registration. New registrations are limited per IP and
  use a honeypot, but a durable cross-process limiter plus challenge/invite mode is
  still required before opening registration to higher-volume traffic.

## Things to know about the email provider

Email is sent through the self-hosted mailcow instance at `mail.micutu.com` (STARTTLS on 587), so `From: noreply@micutu.com` works as-is. SPF/DKIM/DMARC are managed at the mailcow/DNS level. If you ever switch back to Gmail SMTP, note that Gmail rewrites the `From:` header to the authenticated account.
