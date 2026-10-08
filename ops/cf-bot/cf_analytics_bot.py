import asyncio
import datetime
import ipaddress
import json
import logging
import os
import re
import stat
import tempfile
from dataclasses import dataclass
from functools import wraps
from pathlib import Path
from typing import Any, Callable, Coroutine
from zoneinfo import ZoneInfo

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
import psutil
import requests
from fpdf import FPDF
from matplotlib.dates import DateFormatter
from requests.adapters import HTTPAdapter
from telegram import ReplyKeyboardMarkup, Update
from telegram.ext import (
    Application,
    ApplicationBuilder,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)
from urllib3.util.retry import Retry


LOGGER = logging.getLogger("cf_bot")
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_LABEL_CHARACTERS = 80
MAX_LOG_BYTES = 32 * 1024
MAX_LOG_LINES = 10
CF_GRAPHQL_URL = "https://api.cloudflare.com/client/v4/graphql"
IP_LOOKUP_URL = "https://ipwho.is/{ip}"
TELEGRAM_TOKEN_PATTERN = re.compile(r"^[0-9]{8,12}:[A-Za-z0-9_-]{30,}$")
TELEGRAM_TOKEN_IN_TEXT = re.compile(r"[0-9]{8,12}:[A-Za-z0-9_-]{30,}")
BEARER_TOKEN_IN_TEXT = re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/-]{20,}")
ZONE_ID_PATTERN = re.compile(r"^[A-Fa-f0-9]{32}$")

MENU_BUTTONS = [
    ["📊 Trafic", "📡 DNS", "🍕 Status"],
    ["🌍 Țări", "🔗 Pagini", "🏠 Hosts"],
    ["📋 Sumar", "🛡️ Threats", "🖥️ Server"],
    ["🔍 Nginx Errors", "🕵️ IP Lookup"],
]
MAIN_MARKUP = ReplyKeyboardMarkup(MENU_BUTTONS, resize_keyboard=True)


class ConfigurationError(RuntimeError):
    pass


class UpstreamError(RuntimeError):
    pass


def redact_sensitive(value: str) -> str:
    value = TELEGRAM_TOKEN_IN_TEXT.sub("[REDACTED_TELEGRAM_TOKEN]", value)
    return BEARER_TOKEN_IN_TEXT.sub(r"\1[REDACTED_TOKEN]", value)


class RedactingFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        return redact_sensitive(super().format(record))


def configure_logging() -> None:
    logging.basicConfig(level=os.environ.get("CF_BOT_LOG_LEVEL", "INFO"))
    formatter = RedactingFormatter(
        "%(asctime)s %(levelname)s %(name)s: %(message)s"
    )
    for handler in logging.getLogger().handlers:
        handler.setFormatter(formatter)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)


@dataclass(frozen=True)
class Settings:
    bot_token: str
    allowed_chat_id: int
    cloudflare_api_token: str
    cloudflare_zone_id: str
    credentials_path: Path
    runtime_dir: Path
    nginx_error_log: Path

    @classmethod
    def load(
        cls,
        credentials_path: Path | None = None,
        *,
        require_root_owner: bool = True,
    ) -> "Settings":
        path = credentials_path or Path(
            os.environ.get("CF_BOT_CREDENTIALS", "/etc/cf-bot/credentials.json")
        )
        if path.is_symlink():
            raise ConfigurationError("Credentials must not be a symbolic link")
        path = path.resolve(strict=True)
        flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW

        descriptor = os.open(path, flags)
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise ConfigurationError("Credentials must be a regular file")
            if require_root_owner and metadata.st_uid != 0:
                raise ConfigurationError("Credentials must be owned by root")
            if stat.S_IMODE(metadata.st_mode) & 0o027:
                raise ConfigurationError("Credentials permissions are too broad")
            with os.fdopen(descriptor, encoding="utf-8") as stream:
                descriptor = -1
                payload = json.load(stream)
        except (OSError, json.JSONDecodeError) as exc:
            raise ConfigurationError("Credentials cannot be loaded") from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)

        required = {
            "bot_token",
            "allowed_chat_id",
            "cloudflare_api_token",
            "cloudflare_zone_id",
        }
        if not isinstance(payload, dict) or set(payload) != required:
            raise ConfigurationError("Credentials fields do not match the schema")

        bot_token = payload["bot_token"]
        api_token = payload["cloudflare_api_token"]
        zone_id = payload["cloudflare_zone_id"]
        chat_id = payload["allowed_chat_id"]
        if not isinstance(bot_token, str) or not TELEGRAM_TOKEN_PATTERN.fullmatch(bot_token):
            raise ConfigurationError("Telegram bot token has an invalid format")
        if not isinstance(api_token, str) or len(api_token) < 20 or any(ch.isspace() for ch in api_token):
            raise ConfigurationError("Cloudflare API token has an invalid format")
        if not isinstance(zone_id, str) or not ZONE_ID_PATTERN.fullmatch(zone_id):
            raise ConfigurationError("Cloudflare zone ID has an invalid format")
        if isinstance(chat_id, bool) or not isinstance(chat_id, int) or chat_id <= 0:
            raise ConfigurationError("Allowed chat ID must be a positive integer")

        runtime_dir = Path(os.environ.get("CF_BOT_RUNTIME_DIR", "/run/cf-bot")).resolve()
        nginx_error_log = Path(
            os.environ.get("CF_BOT_NGINX_ERROR_LOG", "/var/log/nginx/error.log")
        ).resolve()
        return cls(
            bot_token=bot_token,
            allowed_chat_id=chat_id,
            cloudflare_api_token=api_token,
            cloudflare_zone_id=zone_id,
            credentials_path=path,
            runtime_dir=runtime_dir,
            nginx_error_log=nginx_error_log,
        )


def build_http_session() -> requests.Session:
    retry = Retry(
        total=2,
        connect=2,
        read=1,
        backoff_factor=0.25,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset({"GET", "POST"}),
        respect_retry_after_header=True,
    )
    adapter = HTTPAdapter(max_retries=retry, pool_connections=4, pool_maxsize=8)
    session = requests.Session()
    session.mount("https://", adapter)
    return session


def bounded_json_response(response: requests.Response) -> Any:
    if response.status_code != 200:
        raise UpstreamError(f"Upstream returned HTTP {response.status_code}")
    chunks: list[bytes] = []
    size = 0
    for chunk in response.iter_content(chunk_size=64 * 1024):
        size += len(chunk)
        if size > MAX_RESPONSE_BYTES:
            raise UpstreamError("Upstream response exceeded the size limit")
        chunks.append(chunk)
    try:
        return json.loads(b"".join(chunks))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise UpstreamError("Upstream returned invalid JSON") from exc


def safe_label(value: Any, limit: int = MAX_LABEL_CHARACTERS) -> str:
    text = str(value)
    text = "".join(ch if ch.isprintable() else " " for ch in text)
    text = " ".join(text.split())
    return text[:limit]


class CloudflareClient:
    def __init__(self, settings: Settings, session: requests.Session | None = None):
        self.zone_id = settings.cloudflare_zone_id
        self.session = session or build_http_session()
        self.headers = {
            "Authorization": f"Bearer {settings.cloudflare_api_token}",
            "Content-Type": "application/json",
        }

    def query(self, query: str, variables: dict[str, Any]) -> dict[str, Any]:
        try:
            with self.session.post(
                CF_GRAPHQL_URL,
                headers=self.headers,
                json={"query": query, "variables": variables},
                timeout=(5, 20),
                stream=True,
            ) as response:
                payload = bounded_json_response(response)
        except requests.RequestException as exc:
            raise UpstreamError("Cloudflare request failed") from exc

        if not isinstance(payload, dict) or payload.get("errors"):
            raise UpstreamError("Cloudflare returned a GraphQL error")
        try:
            zones = payload["data"]["viewer"]["zones"]
        except (KeyError, TypeError) as exc:
            raise UpstreamError("Cloudflare response schema was invalid") from exc
        if not isinstance(zones, list) or len(zones) != 1 or not isinstance(zones[0], dict):
            raise UpstreamError("Cloudflare zone response was invalid")
        return zones[0]

    @staticmethod
    def window(hours: int) -> tuple[datetime.datetime, datetime.datetime]:
        if not 1 <= hours <= 48:
            raise ValueError("Hours must be between 1 and 48")
        until = datetime.datetime.now(datetime.UTC)
        return until - datetime.timedelta(hours=hours), until

    def traffic(self, hours: int = 24) -> tuple[list[datetime.datetime], list[int]]:
        since, until = self.window(hours)
        query = """
        query ($zoneTag: string, $since: Time, $until: Time) {
          viewer { zones(filter: {zoneTag: $zoneTag}) {
            httpRequests1hGroups(limit: 1000,
              filter: {datetime_geq: $since, datetime_lt: $until},
              orderBy: [datetime_ASC]) {
              dimensions { datetime }
              sum { requests }
            }
          }}
        }
        """
        groups = self.query(query, self._variables(since, until)).get("httpRequests1hGroups", [])
        groups = self._groups(groups)
        times = [datetime.datetime.strptime(item["dimensions"]["datetime"], "%Y-%m-%dT%H:%M:%SZ") for item in groups]
        counts = [max(0, int(item["sum"]["requests"])) for item in groups]
        return times, counts

    def dns(self, hours: int = 24) -> tuple[list[datetime.datetime], list[int]]:
        since, until = self.window(hours)
        query = """
        query ($zoneTag: string, $since: Time, $until: Time) {
          viewer { zones(filter: {zoneTag: $zoneTag}) {
            dnsAnalyticsAdaptiveGroups(limit: 1000,
              filter: {datetime_geq: $since, datetime_lt: $until},
              orderBy: [datetimeHour_ASC]) {
              dimensions { datetimeHour }
              count
            }
          }}
        }
        """
        groups = self.query(query, self._variables(since, until)).get("dnsAnalyticsAdaptiveGroups", [])
        groups = self._groups(groups)
        times = [datetime.datetime.strptime(item["dimensions"]["datetimeHour"], "%Y-%m-%dT%H:%M:%SZ") for item in groups]
        counts = [max(0, int(item["count"])) for item in groups]
        return times, counts

    def grouped_metric(
        self,
        dimension: str,
        hours: int = 24,
        *,
        limit: int = 10,
    ) -> tuple[list[str], list[int]]:
        allowed_dimensions = {
            "clientCountryName",
            "edgeResponseStatus",
            "clientRequestPath",
            "clientRequestHTTPHost",
        }
        if dimension not in allowed_dimensions:
            raise ValueError("Unsupported Cloudflare dimension")
        since, until = self.window(hours)
        query = f"""
        query ($zoneTag: string, $since: Time, $until: Time) {{
          viewer {{ zones(filter: {{zoneTag: $zoneTag}}) {{
            httpRequestsAdaptiveGroups(limit: 1000,
              filter: {{datetime_geq: $since, datetime_lt: $until}}) {{
              dimensions {{ {dimension} }}
              count
            }}
          }}}}
        }}
        """
        groups = self.query(query, self._variables(since, until)).get("httpRequestsAdaptiveGroups", [])
        totals: dict[str, int] = {}
        for item in self._groups(groups):
            label = safe_label(item["dimensions"].get(dimension, "unknown"))
            totals[label] = totals.get(label, 0) + max(0, int(item["count"]))
        items = sorted(totals.items(), key=lambda pair: pair[1], reverse=True)[:limit]
        return [item[0] for item in items], [item[1] for item in items]

    def threats(self, hours: int = 24) -> tuple[list[datetime.datetime], list[int]]:
        since, until = self.window(hours)
        query = """
        query ($zoneTag: string, $since: Time, $until: Time) {
          viewer { zones(filter: {zoneTag: $zoneTag}) {
            httpRequests1hGroups(limit: 1000,
              filter: {datetime_geq: $since, datetime_lt: $until},
              orderBy: [datetime_ASC]) {
              dimensions { datetime }
              sum { threats }
            }
          }}
        }
        """
        groups = self.query(query, self._variables(since, until)).get("httpRequests1hGroups", [])
        groups = self._groups(groups)
        times = [datetime.datetime.strptime(item["dimensions"]["datetime"], "%Y-%m-%dT%H:%M:%SZ") for item in groups]
        counts = [max(0, int(item["sum"]["threats"])) for item in groups]
        return times, counts

    def recent_server_errors(self) -> list[dict[str, Any]]:
        until = datetime.datetime.now(datetime.UTC)
        since = until - datetime.timedelta(minutes=10)
        query = """
        query ($zoneTag: string, $since: Time, $until: Time) {
          viewer { zones(filter: {zoneTag: $zoneTag}) {
            httpRequestsAdaptiveGroups(limit: 5,
              filter: {datetime_geq: $since, datetime_lt: $until,
                       edgeResponseStatus_geq: 500}) {
              dimensions { edgeResponseStatus clientRequestPath clientRequestHTTPHost }
              count
            }
          }}
        }
        """
        groups = self.query(query, self._variables(since, until)).get("httpRequestsAdaptiveGroups", [])
        return self._groups(groups)[:5]

    def _variables(self, since: datetime.datetime, until: datetime.datetime) -> dict[str, str]:
        return {
            "zoneTag": self.zone_id,
            "since": since.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "until": until.strftime("%Y-%m-%dT%H:%M:%SZ"),
        }

    @staticmethod
    def _groups(value: Any) -> list[dict[str, Any]]:
        if not isinstance(value, list) or len(value) > 1000:
            raise UpstreamError("Cloudflare group response was invalid")
        if not all(isinstance(item, dict) for item in value):
            raise UpstreamError("Cloudflare group item was invalid")
        return value


class IPLookupClient:
    def __init__(self, session: requests.Session | None = None):
        self.session = session or build_http_session()

    def lookup(self, value: str) -> dict[str, str]:
        try:
            address = ipaddress.ip_address(value.strip())
        except ValueError as exc:
            raise ValueError("Adresa IP nu este validă.") from exc
        if not address.is_global:
            raise ValueError("Sunt acceptate numai adrese IP publice.")
        try:
            with self.session.get(
                IP_LOOKUP_URL.format(ip=address.compressed),
                timeout=(5, 10),
                stream=True,
            ) as response:
                payload = bounded_json_response(response)
        except requests.RequestException as exc:
            raise UpstreamError("IP lookup request failed") from exc
        if not isinstance(payload, dict) or payload.get("success") is not True:
            raise UpstreamError("IP lookup returned no result")
        connection = payload.get("connection") if isinstance(payload.get("connection"), dict) else {}
        return {
            "ip": address.compressed,
            "country": safe_label(payload.get("country", "unknown")),
            "city": safe_label(payload.get("city", "unknown")),
            "isp": safe_label(connection.get("isp", "unknown")),
            "org": safe_label(connection.get("org", "unknown")),
            "latitude": safe_label(payload.get("latitude", "unknown"), 24),
            "longitude": safe_label(payload.get("longitude", "unknown"), 24),
        }


def create_plot(
    x: list[Any],
    y: list[int],
    title: str,
    ylabel: str,
    filename: Path,
    *,
    is_bar: bool = False,
    is_pie: bool = False,
    color: str = "#00FFFF",
) -> None:
    if not x or len(x) != len(y) or len(x) > 1000:
        raise ValueError("Plot data is empty or invalid")
    figure, axis = plt.subplots(figsize=(10, 6))
    try:
        if is_pie:
            axis.pie(y, labels=x, autopct="%1.1f%%", startangle=140)
        elif is_bar:
            bars = axis.bar(x, y, color=color, alpha=0.8)
            axis.tick_params(axis="x", rotation=45)
            for bar in bars:
                axis.text(
                    bar.get_x() + bar.get_width() / 2,
                    bar.get_height(),
                    str(int(bar.get_height())),
                    va="bottom",
                    ha="center",
                    fontsize=9,
                )
        else:
            axis.plot(x, y, marker="o", linestyle="-", color=color, linewidth=2)
            axis.fill_between(x, y, alpha=0.2, color=color)
            axis.xaxis.set_major_formatter(DateFormatter("%H:%M"))
        axis.set_title(title, fontsize=14, fontweight="bold", pad=20)
        if not is_pie:
            axis.set_ylabel(ylabel)
            axis.grid(True, linestyle="--", alpha=0.2)
        figure.tight_layout()
        figure.savefig(filename, dpi=120)
    finally:
        plt.close(figure)


def read_nginx_errors(path: Path) -> list[str]:
    with path.open("rb") as stream:
        stream.seek(0, os.SEEK_END)
        size = stream.tell()
        stream.seek(max(0, size - MAX_LOG_BYTES))
        data = stream.read(MAX_LOG_BYTES)
    lines = data.splitlines()[-MAX_LOG_LINES:]
    return [safe_label(line.decode("utf-8", errors="replace"), 180) for line in lines]


Handler = Callable[[Update, ContextTypes.DEFAULT_TYPE], Coroutine[Any, Any, None]]


def authorized(handler: Handler) -> Handler:
    @wraps(handler)
    async def wrapper(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        settings: Settings = context.application.bot_data["settings"]
        chat = update.effective_chat
        user = update.effective_user
        if (
            chat is None
            or user is None
            or chat.type != "private"
            or chat.id != settings.allowed_chat_id
            or user.id != settings.allowed_chat_id
        ):
            return
        await handler(update, context)

    return wrapper


async def reply_error(update: Update, operation: str) -> None:
    LOGGER.warning("Bot operation failed: %s", operation)
    if update.effective_message is not None:
        await update.effective_message.reply_text("Operația nu a putut fi finalizată. Încearcă din nou.")


@authorized
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.effective_message.reply_text(
        "Cloudflare Analytics Bot\n\nFolosește meniul pentru statistici și diagnostic.",
        reply_markup=MAIN_MARKUP,
    )


async def send_chart(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    *,
    operation: str,
    loading_text: str,
    fetch: Callable[[], tuple[list[Any], list[int]]],
    title: str,
    ylabel: str,
    caption: str,
    is_bar: bool = False,
    is_pie: bool = False,
    color: str = "#00FFFF",
) -> None:
    status_message = await update.effective_message.reply_text(loading_text)
    settings: Settings = context.application.bot_data["settings"]
    plot_lock: asyncio.Lock = context.application.bot_data["plot_lock"]
    try:
        x, y = await asyncio.to_thread(fetch)
        if not x:
            await status_message.edit_text("Nu există date pentru intervalul cerut.")
            return
        with tempfile.TemporaryDirectory(prefix="chart-", dir=settings.runtime_dir) as temp_dir:
            path = Path(temp_dir) / "chart.png"
            async with plot_lock:
                await asyncio.to_thread(
                    create_plot,
                    x,
                    y,
                    title,
                    ylabel,
                    path,
                    is_bar=is_bar,
                    is_pie=is_pie,
                    color=color,
                )
            with path.open("rb") as photo:
                await update.effective_message.reply_photo(photo=photo, caption=caption)
        await status_message.delete()
    except (OSError, ValueError, UpstreamError, requests.RequestException):
        await status_message.edit_text("Operația nu a putut fi finalizată. Încearcă din nou.")
        LOGGER.warning("Chart operation failed: %s", operation)


@authorized
async def traffic(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    client: CloudflareClient = context.application.bot_data["cloudflare"]
    await send_chart(
        update,
        context,
        operation="traffic",
        loading_text="Generez graficul de trafic...",
        fetch=client.traffic,
        title="Trafic HTTP - ultimele 24h",
        ylabel="Request-uri",
        caption="Trafic HTTP în ultimele 24h",
    )


@authorized
async def dns(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    client: CloudflareClient = context.application.bot_data["cloudflare"]
    await send_chart(
        update,
        context,
        operation="dns",
        loading_text="Generez graficul DNS...",
        fetch=client.dns,
        title="Query-uri DNS - ultimele 24h",
        ylabel="Query-uri",
        caption="Query-uri DNS în ultimele 24h",
        color="#32CD32",
    )


async def grouped_chart(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    dimension: str,
    operation: str,
    title: str,
    caption: str,
    *,
    is_pie: bool = False,
    color: str = "#FFD700",
) -> None:
    client: CloudflareClient = context.application.bot_data["cloudflare"]
    await send_chart(
        update,
        context,
        operation=operation,
        loading_text="Pregătesc datele...",
        fetch=lambda: client.grouped_metric(dimension),
        title=title,
        ylabel="Request-uri",
        caption=caption,
        is_bar=not is_pie,
        is_pie=is_pie,
        color=color,
    )


@authorized
async def countries(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await grouped_chart(update, context, "clientCountryName", "countries", "Top țări - 24h", "Top 10 țări")


@authorized
async def status(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await grouped_chart(update, context, "edgeResponseStatus", "status", "Coduri HTTP - 24h", "Distribuție coduri HTTP", is_pie=True)


@authorized
async def paths(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await grouped_chart(update, context, "clientRequestPath", "paths", "Top pagini - 24h", "Top 10 pagini", color="#FF69B4")


@authorized
async def hosts(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await grouped_chart(update, context, "clientRequestHTTPHost", "hosts", "Top hosts - 24h", "Top 10 hosts", color="#00FA9A")


@authorized
async def threats(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    client: CloudflareClient = context.application.bot_data["cloudflare"]
    await send_chart(
        update,
        context,
        operation="threats",
        loading_text="Verific amenințările...",
        fetch=client.threats,
        title="Amenințări blocate - 24h",
        ylabel="Amenințări",
        caption="Amenințări blocate în ultimele 24h",
        color="#FF4500",
    )


@authorized
async def summary(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    client: CloudflareClient = context.application.bot_data["cloudflare"]
    message = await update.effective_message.reply_text("Pregătesc sumarul...")
    try:
        _, current = await asyncio.to_thread(client.traffic, 24)
        _, previous_window = await asyncio.to_thread(client.traffic, 48)
        previous = previous_window[: max(0, len(previous_window) - len(current))]
        current_total = sum(current)
        previous_total = sum(previous)
        change = ((current_total - previous_total) / previous_total * 100) if previous_total else 0
        await message.edit_text(
            "Sumar Cloudflare\n\n"
            f"Trafic HTTP (24h): {current_total:,} request-uri\n"
            f"Evoluție față de intervalul precedent: {change:+.1f}%\n"
            "Status: online"
        )
    except (ValueError, UpstreamError, requests.RequestException):
        await message.edit_text("Operația nu a putut fi finalizată. Încearcă din nou.")
        LOGGER.warning("Summary operation failed")


@authorized
async def server_health(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    cpu = await asyncio.to_thread(psutil.cpu_percent, 0.2)
    ram = psutil.virtual_memory()
    disk = psutil.disk_usage("/")
    await update.effective_message.reply_text(
        "Server Health\n\n"
        f"CPU: {cpu}%\n"
        f"RAM: {ram.percent}% ({ram.used // 1024 // 1024} MiB / {ram.total // 1024 // 1024} MiB)\n"
        f"Disk: {disk.percent}% ({disk.used // 1024 // 1024 // 1024} GiB / {disk.total // 1024 // 1024 // 1024} GiB)"
    )


@authorized
async def nginx_errors(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    settings: Settings = context.application.bot_data["settings"]
    try:
        lines = await asyncio.to_thread(read_nginx_errors, settings.nginx_error_log)
        text = "Ultimele erori Nginx:\n\n" + "\n".join(lines) if lines else "Nu există erori recente."
        await update.effective_message.reply_text(text[:3500])
    except OSError:
        await reply_error(update, "nginx-errors")


@authorized
async def ip_lookup_prompt(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    context.user_data["awaiting_ip"] = True
    await update.effective_message.reply_text("Trimite o adresă IP publică pentru verificare.")


@authorized
async def handle_text(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    text = (update.effective_message.text or "").strip()
    routes: dict[str, Handler] = {
        "📊 Trafic": traffic,
        "📡 DNS": dns,
        "🍕 Status": status,
        "🌍 Țări": countries,
        "🔗 Pagini": paths,
        "🏠 Hosts": hosts,
        "📋 Sumar": summary,
        "🛡️ Threats": threats,
        "🖥️ Server": server_health,
        "🔍 Nginx Errors": nginx_errors,
        "🕵️ IP Lookup": ip_lookup_prompt,
    }
    if text in routes:
        await routes[text](update, context)
        return
    if not context.user_data.pop("awaiting_ip", False):
        return

    client: IPLookupClient = context.application.bot_data["ip_lookup"]
    try:
        result = await asyncio.to_thread(client.lookup, text)
        await update.effective_message.reply_text(
            f"IP Lookup: {result['ip']}\n\n"
            f"Țară: {result['country']}\n"
            f"Oraș: {result['city']}\n"
            f"ISP: {result['isp']}\n"
            f"Organizație: {result['org']}\n"
            f"Lat/Lon: {result['latitude']}, {result['longitude']}"
        )
    except ValueError as exc:
        await update.effective_message.reply_text(str(exc))
    except (UpstreamError, requests.RequestException):
        await reply_error(update, "ip-lookup")


async def check_alerts(context: ContextTypes.DEFAULT_TYPE) -> None:
    client: CloudflareClient = context.application.bot_data["cloudflare"]
    settings: Settings = context.application.bot_data["settings"]
    try:
        _, requests_per_hour = await asyncio.to_thread(client.traffic, 6)
        if len(requests_per_hour) >= 2:
            current = requests_per_hour[-1]
            average = sum(requests_per_hour[:-1]) / len(requests_per_hour[:-1])
            alert_key = (datetime.datetime.now(datetime.UTC).hour, current)
            if current > average * 3 and current > 50 and context.application.bot_data.get("last_spike") != alert_key:
                context.application.bot_data["last_spike"] = alert_key
                await context.bot.send_message(
                    chat_id=settings.allowed_chat_id,
                    text=f"Spike detectat: {current} request-uri/oră (medie {int(average)}).",
                )

        errors = await asyncio.to_thread(client.recent_server_errors)
        if errors:
            item = errors[0]
            dimensions = item.get("dimensions") if isinstance(item.get("dimensions"), dict) else {}
            status_code = safe_label(dimensions.get("edgeResponseStatus", "5xx"), 8)
            host = safe_label(dimensions.get("clientRequestHTTPHost", "unknown"))
            path = safe_label(dimensions.get("clientRequestPath", "unknown"))
            alert_key = (status_code, host, path)
            if context.application.bot_data.get("last_5xx") != alert_key:
                context.application.bot_data["last_5xx"] = alert_key
                await context.bot.send_message(
                    chat_id=settings.allowed_chat_id,
                    text=f"Eroare {status_code} detectată.\nHost: {host}\nPath: {path}",
                )
    except (ValueError, UpstreamError, requests.RequestException):
        LOGGER.warning("Scheduled alert check failed")


async def send_daily_report(context: ContextTypes.DEFAULT_TYPE) -> None:
    client: CloudflareClient = context.application.bot_data["cloudflare"]
    settings: Settings = context.application.bot_data["settings"]
    plot_lock: asyncio.Lock = context.application.bot_data["plot_lock"]
    try:
        datasets = [
            ("Trafic", await asyncio.to_thread(client.traffic), False, False),
            ("Status", await asyncio.to_thread(client.grouped_metric, "edgeResponseStatus"), False, True),
            ("Pagini", await asyncio.to_thread(client.grouped_metric, "clientRequestPath"), True, False),
            ("Hosts", await asyncio.to_thread(client.grouped_metric, "clientRequestHTTPHost"), True, False),
        ]
        with tempfile.TemporaryDirectory(prefix="report-", dir=settings.runtime_dir) as temp_dir:
            temp_path = Path(temp_dir)
            images: list[Path] = []
            async with plot_lock:
                for index, (name, data, is_bar, is_pie) in enumerate(datasets):
                    x, y = data
                    image = temp_path / f"chart-{index}.png"
                    await asyncio.to_thread(
                        create_plot,
                        x,
                        y,
                        f"{name} - ultimele 24h",
                        "Request-uri",
                        image,
                        is_bar=is_bar,
                        is_pie=is_pie,
                    )
                    images.append(image)

            pdf_path = temp_path / "cloudflare-report.pdf"
            pdf = FPDF()
            pdf.add_page()
            pdf.set_font("Helvetica", "B", 20)
            pdf.cell(190, 20, "Cloudflare Report", align="C")
            for image in images:
                pdf.add_page()
                pdf.image(str(image), x=10, y=20, w=190)
            await asyncio.to_thread(pdf.output, str(pdf_path))
            with pdf_path.open("rb") as report:
                await context.bot.send_document(
                    chat_id=settings.allowed_chat_id,
                    document=report,
                    caption="Raportul Cloudflare zilnic",
                )
    except (OSError, ValueError, UpstreamError, requests.RequestException):
        LOGGER.warning("Daily report generation failed")


async def error_handler(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    LOGGER.error("Telegram update failed with %s", type(context.error).__name__)


def build_application(settings: Settings) -> Application:
    application = (
        ApplicationBuilder()
        .token(settings.bot_token)
        .concurrent_updates(False)
        .connect_timeout(5)
        .read_timeout(20)
        .write_timeout(20)
        .pool_timeout(5)
        .build()
    )
    application.bot_data.update(
        {
            "settings": settings,
            "cloudflare": CloudflareClient(settings),
            "ip_lookup": IPLookupClient(),
            "plot_lock": asyncio.Lock(),
        }
    )
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("server", server_health))
    application.add_handler(CommandHandler("status", status))
    application.add_handler(CommandHandler("traffic", traffic))
    application.add_handler(CommandHandler("dns", dns))
    application.add_handler(CommandHandler("countries", countries))
    application.add_handler(CommandHandler("paths", paths))
    application.add_handler(CommandHandler("hosts", hosts))
    application.add_handler(CommandHandler("summary", summary))
    application.add_handler(CommandHandler("threats", threats))
    application.add_handler(CommandHandler("errors", nginx_errors))
    application.add_handler(CommandHandler("ip", ip_lookup_prompt))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text))
    application.add_error_handler(error_handler)

    if application.job_queue is None:
        raise ConfigurationError("Telegram job queue support is unavailable")
    application.job_queue.run_repeating(check_alerts, interval=300, first=60, name="alerts")
    application.job_queue.run_daily(
        send_daily_report,
        time=datetime.time(hour=7, minute=0, tzinfo=ZoneInfo("Europe/Bucharest")),
        name="daily-report",
    )
    return application


def main() -> None:
    configure_logging()
    settings = Settings.load()
    settings.runtime_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    application = build_application(settings)
    application.run_polling(drop_pending_updates=True, bootstrap_retries=3)


if __name__ == "__main__":
    main()
