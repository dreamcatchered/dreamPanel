"""
Админ‑бот для управления systemd сервисами через Telegram (pyTelegramBotAPI).
Авторизован только один пользователь (ADMIN_IDS). Бот ожидает токен в переменной
окружения TELEGRAM_BOT_TOKEN или BOT_TOKEN. Запускать от пользователя с правами
на systemctl/journalctl (обычно root).
"""

import datetime
import html
import io
import os
import re
import shlex
import subprocess
import textwrap
import time
import threading
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple
from zoneinfo import ZoneInfo

import telebot
from telebot import types
from telebot.apihelper import ApiTelegramException

def _parse_admin_ids() -> set[int]:
    raw = os.environ.get("ADMIN_IDS") or os.environ.get("ADMIN_TELEGRAM_ID") or "669994046"
    ids: set[int] = set()
    for part in str(raw).split(","):
        part = part.strip()
        if not part:
            continue
        try:
            ids.add(int(part))
        except ValueError:
            continue
    return ids or {669994046}


def _get_bot_token() -> str:
    token = os.environ.get("TELEGRAM_BOT_TOKEN") or os.environ.get("BOT_TOKEN") or ""
    return token.strip()


# Разрешенные админы (по умолчанию один).
ADMIN_IDS = _parse_admin_ids()

# Системные сервисы, которые нужно исключить из списка
SYSTEM_SERVICES = {
    "sshd.service", "sudo.service", "syslog.service", "rsyslog.service",
    "chronyd.service", "nginx.service", "postgresql.service", "docker.service",
    "snapd.service", "systemd-resolved.service", "NetworkManager.service",
    "ufw.service", "cron.service", "atd.service", "containerd.service",
    "openvpn.service", "certbot.service", "unattended-upgrades.service",
    "irqbalance.service", "mdmonitor.service", "iscsi.service",
    "console-setup.service", "dmesg.service", "e2scrub_reap.service",
    "growroot.service", "grub-common.service", "grub-initrd-fallback.service",
    "networkd-dispatcher.service", "networking.service", "remote-fs.target",
    "set-root-pw.service", "ua-reboot-cmds.service", "ubuntu-advantage.service",
    "snap-certbot-5214.mount", "snap-certbot-5234.mount", "snap-core-17247.mount",
    "snap-core24-1225.mount", "snap-core24-1237.mount", "snap-snapd-25202.mount",
    "snap-snapd-25577.mount", "snap-ufw-653.mount", "snap.ufw.srv.service",
    "snapd.apparmor.service", "snapd.autoimport.service", "snapd.core-fixup.service",
    "snapd.recovery-chooser-trigger.service", "snapd.seeded.service",
    "snap.certbot.renew.service", "snap.certbot.renew.timer",
    "crontab-randomizer.service", "ntp.service", "systemd-timesyncd.service",
}

# Кэш для списка сервисов
_SERVICES_CACHE: Optional[List[Dict[str, str]]] = None
_SERVICE_INDEX_CACHE: Optional[Dict[str, Dict[str, str]]] = None


TOKEN = _get_bot_token()
if not TOKEN:
    raise RuntimeError("TELEGRAM_BOT_TOKEN (или BOT_TOKEN) не задан")

bot = telebot.TeleBot(TOKEN, parse_mode="HTML")

# ----------- Alert / monitoring settings ------------
ALERT_ENABLED = os.environ.get("ALERT_ENABLED", "1").lower() in ("1", "true", "yes", "y", "on")
ALERT_INTERVAL_SEC = int(os.environ.get("ALERT_INTERVAL_SEC", "30"))
ALERT_COOLDOWN_SEC = int(os.environ.get("ALERT_COOLDOWN_SEC", "600"))
ALERT_MEMORY_PERCENT = float(os.environ.get("ALERT_MEMORY_PERCENT", "90"))
ALERT_SERVICE_RSS_MB = int(os.environ.get("ALERT_SERVICE_RSS_MB", "1024"))  # per-service threshold
ALERT_TOP_N = int(os.environ.get("ALERT_TOP_N", "5"))

# --------------------------- helpers --------------------------------- #


def is_admin(user_id: int) -> bool:
    return user_id in ADMIN_IDS


def safe_run(cmd: str, timeout: int = 15) -> Tuple[bool, str]:
    """Выполнить shell команду и вернуть (ok, stdout|stderr)."""
    try:
        completed = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except Exception as exc:  # pylint: disable=broad-except
        return False, f"Ошибка запуска: {exc}"

    output = (completed.stdout or "") + (completed.stderr or "")
    return completed.returncode == 0, output.strip()


def format_bytes(num: int) -> str:
    try:
        n = float(num)
    except Exception:
        return "0 B"
    if n <= 0:
        return "0 B"
    units = ["B", "KB", "MB", "GB", "TB"]
    i = 0
    while n >= 1024 and i < len(units) - 1:
        n /= 1024.0
        i += 1
    return f"{n:.1f} {units[i]}"


def get_pid_resources(pid: int) -> Tuple[int, float]:
    """(rss_bytes, cpu_percent) по PID через ps."""
    if not pid or pid <= 0:
        return 0, 0.0

    rss_bytes = 0
    cpu_percent = 0.0

    ok, out = safe_run(f"ps -o rss= -p {pid} 2>/dev/null", timeout=5)
    if ok and out.strip():
        try:
            rss_kb = int(out.strip().split()[0])
            rss_bytes = max(0, rss_kb) * 1024
        except Exception:
            rss_bytes = 0

    ok, out = safe_run(f"ps -o %cpu= -p {pid} 2>/dev/null", timeout=5)
    if ok and out.strip():
        try:
            cpu_percent = float(out.strip().split()[0].replace(",", "."))
        except Exception:
            cpu_percent = 0.0

    return rss_bytes, cpu_percent


def get_system_memory_metrics() -> Dict[str, float]:
    """Возвращает total/used/percent по RAM (bytes + percent)."""
    ok, out = safe_run("free -b", timeout=5)
    if not ok or not out:
        return {"total": 0.0, "used": 0.0, "percent": 0.0}

    for line in out.splitlines():
        if line.lower().startswith("mem:"):
            parts = line.split()
            if len(parts) >= 3:
                try:
                    total = float(parts[1])
                    used = float(parts[2])
                    percent = (used / total * 100.0) if total > 0 else 0.0
                    return {"total": total, "used": used, "percent": percent}
                except Exception:
                    break
    return {"total": 0.0, "used": 0.0, "percent": 0.0}


def top_services_by_rss(limit: int = 5) -> List[Dict[str, object]]:
    """Топ сервисов по RSS (по MainPID)."""
    items: List[Dict[str, object]] = []
    services = get_services()
    idx = get_service_index()

    for svc in services:
        unit = svc["unit"]
        state = get_service_state(unit)
        pid_str = state.get("MainPID", "0") or "0"
        try:
            pid = int(pid_str)
        except Exception:
            pid = 0
        rss, cpu = get_pid_resources(pid)
        title = idx.get(unit, {}).get("title", unit)
        items.append({
            "unit": unit,
            "title": title,
            "pid": pid,
            "rss": rss,
            "cpu": cpu,
            "state": state.get("ActiveState", "unknown"),
        })

    items.sort(key=lambda x: float(x.get("rss", 0) or 0), reverse=True)
    return items[: max(1, int(limit))]


def send_alert_to_admins(text: str) -> None:
    for admin_id in sorted(ADMIN_IDS):
        try:
            bot.send_message(admin_id, text)
        except Exception:
            continue


def chunked(text: str, size: int = 3500) -> Iterable[str]:
    for i in range(0, len(text), size):
        yield text[i : i + size]


def format_status_emoji(active_state: str) -> str:
    mapping = {
        "active": "🟢",
        "inactive": "🔴",
        "failed": "❌",
        "activating": "🟡",
        "deactivating": "🟠",
        "reloading": "🔄",
    }
    return mapping.get(active_state, "⚪")


def parse_systemctl_show(raw: str) -> Dict[str, str]:
    result: Dict[str, str] = {}
    for line in raw.splitlines():
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        result[key.strip()] = value.strip()
    return result


def parse_service_file(service_path: Path) -> Optional[Dict[str, str]]:
    """Парсит .service файл и извлекает описание."""
    try:
        content = service_path.read_text(encoding="utf-8")
        description = ""
        in_unit = False
        
        for line in content.splitlines():
            line = line.strip()
            if line == "[Unit]":
                in_unit = True
                continue
            if line.startswith("[") and line != "[Unit]":
                in_unit = False
                continue
            if in_unit and line.startswith("Description="):
                description = line.split("=", 1)[1].strip()
                break
        
        if not description:
            # Если нет Description, используем имя файла
            description = service_path.stem.replace("-", " ").replace("_", " ").title()
        
        return {"description": description}
    except Exception:
        return None


def discover_services() -> List[Dict[str, str]]:
    """Динамически обнаруживает все пользовательские сервисы из /etc/systemd/system/"""
    global _SERVICES_CACHE
    
    services = []
    systemd_dir = Path("/etc/systemd/system")
    
    if not systemd_dir.exists():
        return []
    
    # Ищем все .service файлы
    for service_file in systemd_dir.glob("*.service"):
        unit_name = service_file.name
        
        # Пропускаем системные сервисы
        if unit_name in SYSTEM_SERVICES:
            continue
        
        # Пропускаем snap сервисы (начинаются с snap. или содержат snap application)
        if unit_name.startswith("snap.") or "snap application" in unit_name.lower():
            continue
        
        # Пропускаем системные mount точки
        if unit_name.startswith("snap-") and unit_name.endswith(".mount"):
            continue
        
        # Пропускаем симлинки в подпапках (они дублируют основные файлы)
        if service_file.is_symlink():
            continue
        
        # Парсим файл для получения описания
        service_info = parse_service_file(service_file)
        if not service_info:
            continue
        
        # Пропускаем если описание содержит "snap application"
        if "snap application" in service_info.get("description", "").lower():
            continue
        
        # Проверяем, что сервис загружен в systemd (не обязательно активен)
        ok, _ = safe_run(f"systemctl show {shlex.quote(unit_name)} --no-page --property=LoadState 2>/dev/null", timeout=5)
        if not ok:
            continue
        
        # Создаем ключ из имени сервиса (убираем .service и заменяем дефисы)
        key = unit_name.replace(".service", "").replace("-", "")
        
        # Извлекаем короткое имя для поиска
        short_name = unit_name.replace(".service", "")
        
        services.append({
            "key": key,
            "unit": unit_name,
            "title": service_info["description"],
            "short_name": short_name,
        })
    
    # Сортируем по имени для удобства
    services.sort(key=lambda x: x["title"].lower())
    
    _SERVICES_CACHE = services
    return services


def get_services() -> List[Dict[str, str]]:
    """Возвращает список сервисов (с кэшированием)."""
    global _SERVICES_CACHE
    if _SERVICES_CACHE is None:
        discover_services()
    return _SERVICES_CACHE or []


def get_service_index() -> Dict[str, Dict[str, str]]:
    """Возвращает индекс сервисов по unit имени."""
    global _SERVICE_INDEX_CACHE
    if _SERVICE_INDEX_CACHE is None:
        services = get_services()
        _SERVICE_INDEX_CACHE = {svc["unit"]: svc for svc in services}
    return _SERVICE_INDEX_CACHE


def get_service_state(unit: str) -> Dict[str, str]:
    unit_q = shlex.quote(unit)
    ok, raw = safe_run(
        f"systemctl show {unit_q} --no-page "
        "--property=ActiveState,SubState,UnitFileState,MainPID,"
        "ExecMainStartTimestamp,FragmentPath,StatusErrno",
        timeout=10,
    )
    info = parse_systemctl_show(raw if ok else "")
    info.setdefault("ActiveState", "unknown")
    info.setdefault("SubState", "-")
    info.setdefault("UnitFileState", "unknown")
    info.setdefault("MainPID", "0")
    info.setdefault("ExecMainStartTimestamp", "")
    info["ok"] = ok
    info["raw"] = raw
    return info


def describe_service(unit: str) -> str:
    state = get_service_state(unit)
    emoji = format_status_emoji(state["ActiveState"])
    since = state.get("ExecMainStartTimestamp", "") or "—"
    enabled = state.get("UnitFileState", "unknown")
    pid = state.get("MainPID", "0")
    try:
        pid_i = int(pid)
    except Exception:
        pid_i = 0
    rss, cpu = get_pid_resources(pid_i)
    ram_line = f"<code>{format_bytes(rss)}</code>" if rss > 0 else "—"
    cpu_line = f"<code>{cpu:.1f}%</code>" if pid_i > 0 else "—"

    utc_now = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc)
    msk_now = datetime.datetime.now(ZoneInfo("Europe/Moscow"))

    service_index = get_service_index()
    title = service_index.get(unit, {}).get("title", unit)

    return textwrap.dedent(
        f"""
        {emoji} <b>{title}</b> ({unit})
        Статус: <b>{state['ActiveState']}</b> / {state['SubState']}
        Автозапуск: <b>{enabled}</b>
        PID: <code>{pid}</code>
        RAM: {ram_line} · CPU: {cpu_line}
        С момента старта: <i>{since}</i>
        Текущее время: <code>{utc_now:%Y-%m-%d %H:%M:%S %Z}</code> | <code>{msk_now:%Y-%m-%d %H:%M:%S %Z}</code>
        """
    ).strip()


def system_metrics() -> str:
    parts: List[str] = []

    ok, uptime = safe_run("uptime -p && uptime")
    if ok:
        parts.append(f"⏱ Uptime:\n<code>{uptime}</code>")

    ok, memory = safe_run("free -h")
    if ok:
        parts.append(f"💾 Память:\n<code>{memory}</code>")
    else:
        mem = get_system_memory_metrics()
        if mem.get("total", 0) > 0:
            parts.append(
                "💾 Память:\n"
                f"<code>{format_bytes(int(mem['used']))} / {format_bytes(int(mem['total']))} ({mem['percent']:.1f}%)</code>"
            )

    ok, disk = safe_run("df -h /")
    if ok:
        parts.append(f"💽 Диск /:\n<code>{disk}</code>")

    ok, loadavg = safe_run("cat /proc/loadavg")
    if ok:
        parts.append(f"📊 LoadAvg: <code>{loadavg}</code>")

    # Top RAM services
    try:
        top = top_services_by_rss(limit=ALERT_TOP_N)
        if top:
            lines = []
            for i, item in enumerate(top, 1):
                title = html.escape(str(item.get("title", "")))
                unit = html.escape(str(item.get("unit", "")))
                rss = format_bytes(int(item.get("rss", 0) or 0))
                cpu = float(item.get("cpu", 0.0) or 0.0)
                st = html.escape(str(item.get("state", "unknown")))
                lines.append(f"{i}. {title} ({unit}) — {rss} | CPU {cpu:.1f}% | {st}")
            parts.append("🔥 Top RAM сервисы:\n<code>" + "\n".join(lines) + "</code>")
    except Exception:
        pass

    return "\n\n".join(parts) if parts else "Нет данных по метрикам"


def tail_logs(unit: str, lines: int = 80, priority: Optional[str] = None) -> str:
    unit_q = shlex.quote(unit)
    prio = f"-p {priority} " if priority else ""
    cmd = (
        f"journalctl -u {unit_q} {prio}-n {lines} "
        "--no-pager --output=short-iso"
    )
    ok, out = safe_run(cmd, timeout=12)
    if not ok:
        return f"Не удалось получить логи: {out or 'ошибка'}"
    return out or "Логи пусты"


def service_keyboard(unit: str) -> types.InlineKeyboardMarkup:
    kb = types.InlineKeyboardMarkup(row_width=3)
    kb.add(
        types.InlineKeyboardButton("🔄 Обновить", callback_data=f"svc:{unit}:refresh"),
        types.InlineKeyboardButton("📑 Логи", callback_data=f"svc:{unit}:logs"),
        types.InlineKeyboardButton("⚠️ Ошибки", callback_data=f"svc:{unit}:errors"),
    )
    kb.add(
        types.InlineKeyboardButton("▶️ Старт", callback_data=f"act:{unit}:start"),
        types.InlineKeyboardButton("⏸ Стоп", callback_data=f"act:{unit}:stop"),
        types.InlineKeyboardButton("♻️ Рестарт", callback_data=f"act:{unit}:restart"),
    )
    kb.add(
        types.InlineKeyboardButton("✅ Enable", callback_data=f"act:{unit}:enable"),
        types.InlineKeyboardButton("🚫 Disable", callback_data=f"act:{unit}:disable"),
        types.InlineKeyboardButton("🧹 Daemon-reload", callback_data="system:daemon-reload"),
    )
    kb.add(types.InlineKeyboardButton("⬅️ Назад", callback_data="menu:root"))
    return kb


def get_all_states() -> Dict[str, Dict[str, str]]:
    services = get_services()
    return {svc["unit"]: get_service_state(svc["unit"]) for svc in services}


def main_menu_keyboard(states: Optional[Dict[str, Dict[str, str]]] = None) -> types.InlineKeyboardMarkup:
    states = states or get_all_states()
    kb = types.InlineKeyboardMarkup(row_width=2)
    services = get_services()
    for svc in services:
        state = states.get(svc["unit"], {"ActiveState": "unknown"})
        emoji = format_status_emoji(state.get("ActiveState", "unknown"))
        kb.add(
            types.InlineKeyboardButton(
                f"{emoji} {svc['title']}", callback_data=f"svc:{svc['unit']}:open"
            )
        )
    kb.add(
        types.InlineKeyboardButton("📊 Метрики", callback_data="system:metrics"),
        types.InlineKeyboardButton("🔁 Обновить все", callback_data="menu:refresh"),
    )
    # Кнопка для открытия веб-панели как WebApp
    kb.add(
        types.InlineKeyboardButton(
            "🌐 Открыть панель управления",
            web_app=types.WebAppInfo(url="https://manage.dreampartners.online")
        )
    )
    kb.add(
        types.InlineKeyboardButton("🔌 Reboot", callback_data="system:reboot"),
        types.InlineKeyboardButton("ℹ️ Help", callback_data="system:help"),
    )
    return kb


def send_long_message(chat_id: int, text: str) -> None:
    for chunk in chunked(text, 3800):
        bot.send_message(chat_id, chunk)


def safe_edit_message(chat_id: int, message_id: int, text: str, reply_markup: Optional[types.InlineKeyboardMarkup] = None):
    try:
        bot.edit_message_text(
            text,
            chat_id=chat_id,
            message_id=message_id,
            reply_markup=reply_markup,
        )
    except ApiTelegramException as exc:
        # Игнорируем "message is not modified"
        if "message is not modified" in str(exc):
            return
        raise


def send_logs_document(chat_id: int, title: str, content: str):
    """Отправить логи как текстовый файл, чтобы избежать проблем с parse_mode."""
    data = content or "Логи пусты"
    bio = io.BytesIO(data.encode("utf-8", errors="replace"))
    bio.name = f"{title}.txt"
    bot.send_document(chat_id, bio, caption=f"📑 {title}")


def render_services_overview(states: Optional[Dict[str, Dict[str, str]]] = None) -> str:
    states = states or get_all_states()
    lines: List[str] = ["Сервисы:"]
    services = get_services()
    for svc in services:
        state = states.get(svc["unit"], {"ActiveState": "unknown", "SubState": "-", "UnitFileState": "-"})
        emoji = format_status_emoji(state["ActiveState"])
        enabled = state.get("UnitFileState", "-")
        lines.append(
            f"{emoji} <b>{svc['title']}</b> "
            f"({svc['unit']}) — {state['ActiveState']}/{state['SubState']} | {enabled}"
        )
    return "\n".join(lines)


def normalize(text: str) -> str:
    return re.sub(r"[^a-zA-Z0-9а-яА-Я._-]+", " ", text.lower().replace("ё", "е")).strip()


def find_service(query: str) -> Optional[Dict[str, str]]:
    q = normalize(query)
    if not q:
        return None

    services = get_services()

    # 1) прямое попадание по подстроке в тексте
    for svc in services:
        tokens = [
            normalize(svc["key"]),
            normalize(svc["unit"]),
            normalize(svc["title"]),
            normalize(svc.get("short_name", "")),
        ]
        for t in tokens:
            if t and t in q:
                return svc

    # 2) поиск по словам
    words = q.split()
    for svc in services:
        tokens = [
            normalize(svc["key"]),
            normalize(svc["unit"]),
            normalize(svc["title"]),
            normalize(svc.get("short_name", "")),
        ]
        if any(w == t or w in t or t in w for w in words for t in tokens if t):
            return svc

    return None


def action_text(unit: str, action: str) -> str:
    return f"{action} {unit}"


def perform_action(unit: str, action: str) -> Tuple[bool, str]:
    unit_q = shlex.quote(unit)
    commands = {
        "start": f"systemctl start {unit_q}",
        "stop": f"systemctl stop {unit_q}",
        "restart": f"systemctl restart {unit_q}",
        "enable": f"systemctl enable {unit_q}",
        "disable": f"systemctl disable {unit_q}",
    }
    cmd = commands.get(action)
    if not cmd:
        return False, "Неизвестное действие"
    return safe_run(cmd, timeout=30)


def process_text_command(message_text: str) -> Tuple[str, Optional[Dict[str, str]], str]:
    """
    Парсим свободный текст, возвращаем (action, svc, original_text)
    Действия: status, start, stop, restart, enable, disable, logs, errors.
    """
    text_raw = message_text or ""
    text = normalize(text_raw)

    synonyms = {
        "restart": (
            "рестарт",
            "рест",
            "перезапусти",
            "перезапуск",
            "перезагрузи",
            "ребутни",
            "ребут",
            "reboot",
            "restart",
            "reload",
            "обнови",
        ),
        "start": ("старт", "запусти", "включи", "start", "run", "launch", "запуск"),
        "stop": ("стоп", "останови", "выключи", "off", "офни", "оффни", "offni", "offne", "stop"),
        "status": ("статус", "status", "состояние", "state", "покажи", "инфа"),
        "logs": ("логи", "лог", "logs", "journal", "журнал"),
        "errors": ("ошибки", "error", "errors", "warn", "warning", "warnings"),
        "enable": ("enable", "автозапуск", "включи автозапуск", "autoenable", "auto"),
        "disable": ("disable", "отключи автозапуск", "без автозапуска", "noauto"),
    }

    all_syn_values = {v for vals in synonyms.values() for v in vals}

    chosen_action = "status"
    for action, keys in synonyms.items():
        if any(k in text for k in keys):
            chosen_action = action
            break

    # Если пользователь просит help
    if text in ("help", "хелп", "помощь", "инфо", "info"):
        return "help", None, text_raw

    # Попробуем найти сервис прямым поиском
    svc = find_service(text)
    if svc:
        return chosen_action, svc, text_raw

    # Если нет — возьмём первое слово, не являющееся синонимом
    for w in text.split():
        if w in all_syn_values:
            continue
        if len(w) < 2:
            continue
        svc = find_service(w)
        if svc:
            return chosen_action, svc, text_raw

    return chosen_action, None, text_raw


# --------------------------- handlers -------------------------------- #


def ensure_admin(func):
    def wrapper(message):
        if not is_admin(message.from_user.id):
            bot.reply_to(message, "Доступ запрещён")
            return
        return func(message)

    return wrapper


@bot.message_handler(commands=["start", "help"])
@ensure_admin
def handle_start(message):
    # Обновляем кэш при старте
    discover_services()
    text = textwrap.dedent(
        """
        Привет! Это бот для управления сервисами.
        • /services — список сервисов
        • /metrics — системные метрики
        Можно писать: "статус vpads", "рестарт auth", "логи mp3".
        Все действия доступны через кнопки.
        
        🌐 Нажмите кнопку "Открыть панель управления" для доступа к веб-интерфейсу!
        """
    ).strip()
    states = get_all_states()
    bot.send_message(message.chat.id, text, reply_markup=main_menu_keyboard(states))


@bot.message_handler(commands=["services"])
@ensure_admin
def handle_services(message):
    # Обновляем кэш при запросе списка сервисов
    discover_services()
    bot.send_message(
        message.chat.id,
        render_services_overview(),
        reply_markup=main_menu_keyboard(),
    )


@bot.message_handler(commands=["metrics"])
@ensure_admin
def handle_metrics(message):
    bot.send_message(message.chat.id, system_metrics())


def help_text() -> str:
    return textwrap.dedent(
        """
        Текстовые команды (без /):
        • статус сервис — показать статус
        • рестарт / перезапуск / перезагрузи / ребутни сервис — рестарт
        • старт / запусти / включи сервис — запустить
        • стоп / останови / выключи / офни сервис — остановить
        • логи сервис — последние логи (txt)
        • ошибки сервис — ошибки (txt)
        • enable сервис — включить автозапуск
        • disable сервис — отключить автозапуск

        Сервис можно указывать как ключ (vpads), unit (vpads.service) или имя (VPADS Bot).
        Доступ только для админа 669994046.
        """
    ).strip()


def handle_service_view(chat_id: int, unit: str):
    bot.send_message(chat_id, describe_service(unit), reply_markup=service_keyboard(unit))


@bot.message_handler(func=lambda m: True)
def handle_free_text(message):
    # Жёсткая проверка админа на любые сообщения.
    if not is_admin(message.from_user.id):
        return

    action, svc, _ = process_text_command(message.text or "")

    if action == "help":
        bot.send_message(message.chat.id, help_text(), parse_mode=None)
        return

    if not svc:
        bot.reply_to(message, "Не понял сервис. Напиши, например: статус vpads")
        return

    unit = svc["unit"]

    if action == "status":
        bot.send_message(
            message.chat.id,
            describe_service(unit),
            reply_markup=service_keyboard(unit),
        )
        return

    if action == "logs":
        logs = tail_logs(unit, lines=200)
        send_logs_document(message.chat.id, f"logs-{unit}", logs)
        return

    if action == "errors":
        logs = tail_logs(unit, lines=120, priority="3")
        send_logs_document(message.chat.id, f"errors-{unit}", logs)
        return

    # Показываем статус выполнения
    action_names = {
        "start": "Запускаю",
        "stop": "Останавливаю",
        "restart": "Перезапускаю",
        "enable": "Включаю автозапуск",
        "disable": "Отключаю автозапуск",
    }
    action_text = action_names.get(action, action)

    # Сначала пишем, что делаем (важно, если перезапускаем сам бот)
    progress_msg = bot.send_message(
        message.chat.id,
        f"⏳ {action_text} <b>{unit}</b>…\n\nПодождите, выполняю команду.",
    )

    ok, out = perform_action(unit, action)

    # Если бот не умер (например, при рестарте своего сервиса) — обновим сообщение
    if ok:
        time.sleep(0.5)
        safe_edit_message(
            message.chat.id,
            progress_msg.message_id,
            describe_service(unit),
            reply_markup=service_keyboard(unit),
        )
    else:
        out_safe = html.escape(out)
        safe_edit_message(
            message.chat.id,
            progress_msg.message_id,
            f"❌ {action_text} <b>{unit}</b>: FAIL\n<code>{out_safe}</code>",
            reply_markup=service_keyboard(unit),
        )


@bot.callback_query_handler(func=lambda call: True)
def handle_callbacks(call):
    global _SERVICES_CACHE, _SERVICE_INDEX_CACHE
    
    user_id = call.from_user.id
    if not is_admin(user_id):
        bot.answer_callback_query(call.id, "Нет доступа", show_alert=True)
        return

    data = call.data or ""

    if data.startswith("menu:root"):
        # Обновляем кэш при возврате в главное меню
        if _SERVICES_CACHE is None:
            discover_services()
        states = get_all_states()
        safe_edit_message(
            call.message.chat.id,
            call.message.message_id,
            render_services_overview(states),
            reply_markup=main_menu_keyboard(states),
        )
        bot.answer_callback_query(call.id, "Главное меню")
        return

    if data.startswith("menu:refresh"):
        # Обновляем кэш сервисов
        _SERVICES_CACHE = None
        _SERVICE_INDEX_CACHE = None
        discover_services()
        states = get_all_states()
        safe_edit_message(
            call.message.chat.id,
            call.message.message_id,
            render_services_overview(states),
            reply_markup=main_menu_keyboard(states),
        )
        bot.answer_callback_query(call.id, "Обновлено")
        return

    if data.startswith("system:metrics"):
        bot.answer_callback_query(call.id, "Метрики")
        bot.send_message(call.message.chat.id, system_metrics())
        return

    if data.startswith("system:help"):
        bot.answer_callback_query(call.id, "Help")
        bot.send_message(call.message.chat.id, help_text(), parse_mode=None)
        return

    if data.startswith("system:reboot"):
        bot.answer_callback_query(call.id, "Перезагрузка…")
        bot.send_message(
            call.message.chat.id,
            "🔄 Перезагружаю систему...\n\n"
            "Система будет перезагружена через systemctl reboot.\n"
            "После перезагрузки бот автоматически восстановит работу."
        )
        time.sleep(1)
        safe_run("systemctl reboot", timeout=5)
        return

    if data.startswith("system:daemon-reload"):
        ok, out = safe_run("systemctl daemon-reload", timeout=20)
        bot.answer_callback_query(call.id, "Готово" if ok else "Ошибка", show_alert=not ok)
        bot.send_message(
            call.message.chat.id,
            f"daemon-reload: {'OK' if ok else 'FAIL'}\n<code>{out}</code>",
        )
        return

    if data.startswith("svc:"):
        _, unit, action = data.split(":", 2)
        if action in ("open", "refresh"):
            bot.answer_callback_query(call.id, "Обновляю…")
            safe_edit_message(
                call.message.chat.id,
                call.message.message_id,
                describe_service(unit),
                reply_markup=service_keyboard(unit),
            )
            return
        if action == "logs":
            bot.answer_callback_query(call.id, "Логи")
            logs = tail_logs(unit, lines=200)
            send_logs_document(call.message.chat.id, f"logs-{unit}", logs)
            return
        if action == "errors":
            bot.answer_callback_query(call.id, "Ошибки")
            logs = tail_logs(unit, lines=120, priority="3")
            send_logs_document(call.message.chat.id, f"errors-{unit}", logs)
            return

    if data.startswith("act:"):
        _, unit, action = data.split(":", 2)
        unit_q = shlex.quote(unit)
        commands = {
            "start": f"systemctl start {unit_q}",
            "stop": f"systemctl stop {unit_q}",
            "restart": f"systemctl restart {unit_q}",
            "enable": f"systemctl enable {unit_q}",
            "disable": f"systemctl disable {unit_q}",
        }
        cmd = commands.get(action)
        if cmd:
            action_names = {
                "start": "Запускаю",
                "stop": "Останавливаю",
                "restart": "Перезапускаю",
                "enable": "Включаю автозапуск",
                "disable": "Отключаю автозапуск",
            }
            action_text = action_names.get(action, action)

            # Сначала показываем, что делаем (важно для рестарта самого бота)
            try:
                bot.answer_callback_query(call.id, f"{action_text}…", show_alert=False)
            except Exception:
                pass

            progress_text = f"⏳ {action_text} <b>{unit}</b>…\n\nПодождите, выполняю команду."
            safe_edit_message(
                call.message.chat.id,
                call.message.message_id,
                progress_text,
                reply_markup=None,
            )

            ok, out = safe_run(cmd, timeout=25)
            try:
                bot.answer_callback_query(call.id, "Ок" if ok else "Ошибка", show_alert=not ok)
            except Exception:
                pass
            
            # Не отправляем промежуточное сообщение, сразу показываем статус
            if ok:
                # Небольшая задержка для обновления статуса
                time.sleep(0.5)
                status_text = describe_service(unit)
                safe_edit_message(
                    call.message.chat.id,
                    call.message.message_id,
                    status_text,
                    reply_markup=service_keyboard(unit),
                )
            else:
                out_safe = html.escape(out)
                safe_edit_message(
                    call.message.chat.id,
                    call.message.message_id,
                    f"❌ {action_text} <b>{unit}</b>: FAIL\n<code>{out_safe}</code>",
                    reply_markup=service_keyboard(unit),
                )
        else:
            bot.answer_callback_query(call.id, "Неизвестное действие", show_alert=True)


def monitor_loop() -> None:
    """Периодический мониторинг RAM и сервисов с алертами в Telegram."""
    # чуть ждём, чтобы бот полностью поднялся
    time.sleep(10)

    last_mem_alert = 0.0
    last_service_alert: Dict[str, float] = {}
    last_failed_alert: Dict[str, float] = {}

    while True:
        try:
            if not ALERT_ENABLED:
                time.sleep(max(5, ALERT_INTERVAL_SEC))
                continue

            now = time.time()
            mem = get_system_memory_metrics()
            total = int(mem.get("total", 0) or 0)
            used = int(mem.get("used", 0) or 0)
            percent = float(mem.get("percent", 0.0) or 0.0)

            services_count = len(get_services())
            items = top_services_by_rss(limit=max(1, services_count))
            top = items[: max(1, ALERT_TOP_N)]

            # 1) Global RAM alert
            if total > 0 and percent >= ALERT_MEMORY_PERCENT and (now - last_mem_alert) >= ALERT_COOLDOWN_SEC:
                lines = [
                    f"🚨 ТРЕВОГА: RAM {percent:.1f}% ({format_bytes(used)} / {format_bytes(total)})",
                    "",
                    "🔥 Топ по памяти:",
                ]
                for i, it in enumerate(top, 1):
                    title = html.escape(str(it.get("title", "")))
                    unit = html.escape(str(it.get("unit", "")))
                    rss = format_bytes(int(it.get("rss", 0) or 0))
                    cpu = float(it.get("cpu", 0.0) or 0.0)
                    st = html.escape(str(it.get("state", "unknown")))
                    lines.append(f"{i}. {title} ({unit}) — {rss} | CPU {cpu:.1f}% | {st}")
                lines.append("")
                lines.append("Панель: https://manage.dreampartners.online")
                send_alert_to_admins("\n".join(lines))
                last_mem_alert = now

            # 2) Per-service hog alert
            rss_threshold = max(1, ALERT_SERVICE_RSS_MB) * 1024 * 1024
            for it in items:
                unit = str(it.get("unit", ""))
                rss = int(it.get("rss", 0) or 0)
                if rss <= 0 or rss < rss_threshold:
                    continue
                last = last_service_alert.get(unit, 0.0)
                if (now - last) < ALERT_COOLDOWN_SEC:
                    continue
                title = html.escape(str(it.get("title", unit)))
                cpu = float(it.get("cpu", 0.0) or 0.0)
                st = html.escape(str(it.get("state", "unknown")))
                send_alert_to_admins(
                    "\n".join(
                        [
                            "🚨 ТРЕВОГА: сервис жрёт память",
                            f"Сервис: <b>{title}</b> ({html.escape(unit)})",
                            f"RAM: <code>{format_bytes(rss)}</code> · CPU: <code>{cpu:.1f}%</code> · State: <b>{st}</b>",
                            "Панель: https://manage.dreampartners.online",
                        ]
                    )
                )
                last_service_alert[unit] = now

            # 3) Failed service alert
            for it in items:
                unit = str(it.get("unit", ""))
                st = str(it.get("state", "unknown"))
                if st != "failed":
                    continue
                last = last_failed_alert.get(unit, 0.0)
                if (now - last) < ALERT_COOLDOWN_SEC:
                    continue
                title = html.escape(str(it.get("title", unit)))
                send_alert_to_admins(
                    "\n".join(
                        [
                            "❌ ТРЕВОГА: сервис упал (failed)",
                            f"Сервис: <b>{title}</b> ({html.escape(unit)})",
                            "Панель: https://manage.dreampartners.online",
                        ]
                    )
                )
                last_failed_alert[unit] = now

        except Exception:
            pass

        time.sleep(max(5, ALERT_INTERVAL_SEC))


def main():
    print("Admin bot is running…")
    # Инициализируем кэш сервисов при старте
    print("Обнаружение сервисов...")
    discover_services()
    services_count = len(get_services())
    print(f"Найдено сервисов: {services_count}")

    # Сообщаем админу, что бот поднялся, + краткая сводка о сервере
    try:
        utc_now = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc)
        msk_now = datetime.datetime.now(ZoneInfo("Europe/Moscow"))
        summary = system_metrics()
        text = (
            "✅ <b>Admin bot включился</b>\n"
            f"UTC: <code>{utc_now:%Y-%m-%d %H:%M:%S %Z}</code>\n"
            f"MSK: <code>{msk_now:%Y-%m-%d %H:%M:%S %Z}</code>\n"
            f"Сервисов найдено: <b>{services_count}</b>\n"
            "Панель: https://manage.dreampartners.online\n\n"
            f"{summary}"
        )
        # Инлайн кнопка для открытия веб-панели
        startup_kb = types.InlineKeyboardMarkup()
        startup_kb.add(
            types.InlineKeyboardButton(
                "🌐 Открыть панель управления",
                web_app=types.WebAppInfo(url="https://manage.dreampartners.online")
            )
        )
        for admin_id in sorted(ADMIN_IDS):
            try:
                bot.send_message(admin_id, text, reply_markup=startup_kb)
            except ApiTelegramException as e:
                print(f"Failed to send startup message to {admin_id}: {e}")
            except Exception as e:
                print(f"Failed to send startup message to {admin_id}: {e}")
    except Exception:
        pass

    if ALERT_ENABLED:
        print(
            "Monitoring enabled: "
            f"interval={ALERT_INTERVAL_SEC}s, cooldown={ALERT_COOLDOWN_SEC}s, "
            f"ram>={ALERT_MEMORY_PERCENT}%, svc_rss>={ALERT_SERVICE_RSS_MB}MB"
        )
        t = threading.Thread(target=monitor_loop, daemon=True)
        t.start()

    while True:
        try:
            bot.infinity_polling(skip_pending=True, timeout=20, long_polling_timeout=20)
        except Exception as exc:  # pylint: disable=broad-except
            print(f"Polling crashed: {exc}. Restarting in 5s...")
            time.sleep(5)


if __name__ == "__main__":
    main()

