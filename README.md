# NVIDIA Chat Hub

A self-hosted chat UI for NVIDIA's NIM-hosted open-weight LLMs (Llama, Mixtral, Nemotron, Qwen, GLM, GPT-OSS, and ~50 more). Pick a model, chat, save conversations per-user. Deployed at `https://nvidia.micutu.com`.

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
└── frontend/
    ├── src/                # App.jsx, api.js, index.css
    ├── index.html
    └── vite.config.js
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
python manage.py runserver 8500

# Frontend
cd frontend
npm install
npm run dev   # vite dev server on :5173
```

The Vite dev server hits `http://127.0.0.1:8500/api` directly. CORS + cookies are pre-wired for `localhost:5173`.

## Environment

`backend/.env` is the file Django loads (`load_dotenv(BASE_DIR / '.env')`). Required keys:

```
DJANGO_SECRET_KEY=...
DJANGO_DEBUG=False
DJANGO_ALLOWED_HOSTS=nvidia.micutu.com,localhost,127.0.0.1

DB_NAME=nvidia_db
DB_USER=nvidia_user
DB_PASSWORD=...
DB_HOST=127.0.0.1
DB_PORT=5432

NVIDIA_API_KEY=nvapi-...
NVIDIA_API_URL=https://integrate.api.nvidia.com/v1/chat/completions

# Email (used for OTP verification)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=465
SMTP_USER=...@gmail.com
SMTP_PASS=...                 # Gmail app password, not the account password
SMTP_FROM=noreply@example.com # Gmail rewrites this to SMTP_USER on send
FRONTEND_URL=https://nvidia.micutu.com
```

Port `465` (SMTPS) is used instead of `587` (STARTTLS) because some hosts silently drop outbound 587. Settings auto-pick `EMAIL_USE_SSL` when `SMTP_PORT=465`.

## API

All endpoints are under `/api/`. Auth uses session cookies; mutations need `X-CSRFToken` from the `csrftoken` cookie.

| Method | Path | Body | Auth | Notes |
|---|---|---|---|---|
| GET | `/auth/me/` | — | open | Sets `csrftoken` cookie. Returns `{username}` or `{username: null}`. |
| POST | `/auth/register/` | `{username, email, password}` | open | Creates inactive user, emails OTP. |
| POST | `/auth/verify/` | `{email, code}` | open | 6-digit code; logs user in on success. |
| POST | `/auth/resend/` | `{email}` | open | 60s cooldown; never leaks whether the email exists. |
| POST | `/auth/login/` | `{username, password}` | open | Rejects inactive users. |
| POST | `/auth/logout/` | — | session | |
| GET | `/models/` | — | session | Returns validated NVIDIA models. |
| GET | `/conversations/` | — | session | Scoped to `request.user`. |
| POST | `/conversations/` | `{model_id?, title?}` | session | |
| GET/PATCH/DELETE | `/conversations/<id>/` | — | session | 404 if not owned. |
| POST | `/conversations/<id>/messages/` | `{content, model_id?, attachment_ids?}` | session | Proxies to NVIDIA, persists both messages. Vision images allowed only on vision-capable models. |
| GET | `/attachments/?kind=` | — | session | List user's attachments (optionally filter by `image`/`document`/`generated_image`). |
| POST | `/attachments/upload/` | `multipart` field `file` | session | Whitelist: jpg/png/webp/gif, pdf, txt, md, docx. 10 MB/file, 100 MB/user. Document text is extracted on upload. |
| DELETE | `/attachments/<id>/` | — | session | Only unlinked attachments can be deleted. |
| GET | `/images/models/` | — | session | List image-generation catalog (Flux schnell/dev, SDXL, SD3 medium). |
| POST | `/images/generate/` | `{prompt, model_id?, width?, height?, steps?, seed?}` | session | Returns `{attachment, …}`. Saves the generated image to local media storage. |

## Model catalog

`chat/models_catalog.py` is the validated list of NVIDIA NIM models that respond to chat completions. It was built by:

1. Calling `GET https://integrate.api.nvidia.com/v1/models` to get the live list.
2. Filtering out non-chat models (embeddings, retrievers, parsers, classifiers, reward models).
3. Probing each candidate with a minimal `messages: [{role: "user", content: "hi"}]` request and keeping only those returning `200`.

To resync after NVIDIA adds or removes models, rerun `/tmp/probe_models.py` (or recreate it from the snippet in `chat/views.py`-area history) and regenerate the catalog.

## Production deploy

The VPS pattern matches every other `*.micutu.com` app on this host:

- **systemd unit** `/etc/systemd/system/nvidia-chat.service` runs `gunicorn` as user `micu`, binds `127.0.0.1:8500`, reads `EnvironmentFile=/home/micu/nvidia/backend/.env`.
- **nginx** vhost `/etc/nginx/sites-available/nvidia.micutu.com` serves the built SPA from `/var/www/nvidia.micutu.com/` with `try_files $uri $uri/ /index.html;` for client-side routing, and proxies `/api/`, `/admin/`, `/static/` and `/media/` to gunicorn (or, for `/media/`, you can serve directly from `/home/micu/nvidia/backend/media/` for lower overhead).
- **SSL** via certbot: `sudo certbot --nginx -d nvidia.micutu.com --non-interactive --agree-tos --email <you> --redirect`. `certbot.timer` handles renewal.
- **PostgreSQL** runs on `127.0.0.1:5432`. Per-app DB and user as documented in the VPS pattern.
- **Cron** for orphan-attachment cleanup (daily at 03:00):
  ```cron
  0 3 * * *  cd /home/micu/nvidia/backend && /home/micu/nvidia/backend/venv/bin/python manage.py cleanup_attachments
  ```

Deploy steps after a code change:

```bash
# Backend
cd /home/micu/nvidia/backend
. venv/bin/activate
pip install -r requirements.txt
python manage.py migrate
sudo systemctl restart nvidia-chat.service

# Frontend
cd /home/micu/nvidia/frontend
npm run build
sudo rsync -a --delete dist/ /var/www/nvidia.micutu.com/
sudo chown -R www-data:www-data /var/www/nvidia.micutu.com/
```

## Auth notes

- Conversations are FK'd to the user with `on_delete=CASCADE` — deleting a user deletes their chats.
- Cross-user access on `/api/conversations/<id>/` returns `404`, not `403`, to avoid leaking which IDs exist.
- OTP code is HMAC-SHA256 hashed (peppered with `SECRET_KEY`) before storage. TTL 30 min. Six wrong attempts invalidates the code.
- Resend has a 60s server-side cooldown, returning `429` with `resend_available_in` so the frontend can sync the timer.
- Email verification gates registration but doesn't rate-limit *new* registrations; if abuse becomes a concern, add a per-IP throttle on `/auth/register/`.

## Things to know about the email provider

Gmail SMTP rewrites the `From:` header to the authenticated account. To actually send from `noreply@yourdomain` you need a transactional provider (Mailgun, Postmark, SES) plus SPF/DKIM/DMARC records on the domain.
