import os
import datetime
import html
import io
import re
import shlex
import textwrap
import time
import threading
from pathlib import Path
from zoneinfo import ZoneInfo
from typing import Dict, Iterable, List, Optional, Tuple
from dotenv import load_dotenv

import telebot
import requests


os.environ["HTTP_PROXY"] = os.environ.get("HTTPS_PROXY", "")
os.environ["HTTPS_PROXY"] = os.environ.get("HTTPS_PROXY", "")
telebot.apihelper.proxy = {"https": os.environ.get("HTTPS_PROXY", "")}


from telebot import types
from telebot.apihelper import ApiTelegramException

from utils import (
    safe_run, format_bytes, get_pid_resources,
    parse_systemctl_show, get_system_metrics, discover_services,
    SYSTEM_SERVICES
)

# Адрес веб-панели для кнопки "Панель" (можно переопределить в .env)
PANEL_URL = os.environ.get("PANEL_URL", "https://manage.dreampartners.online")

# Load env
load_dotenv()
if Path("/etc/admin_bot.env").exists():
    load_dotenv("/etc/admin_bot.env")

def _parse_admin_ids() -> set[int]:
    raw = os.environ.get("ADMIN_IDS") or os.environ.get("ADMIN_TELEGRAM_ID")
    if not raw:
        return set()
    ids: set[int] = set()
    for part in str(raw).split(","):
        part = part.strip()
        if not part:
            continue
        try:
            ids.add(int(part))
        except ValueError:
            continue
    return ids

def _get_bot_token() -> str:
    token = os.environ.get("TELEGRAM_BOT_TOKEN") or os.environ.get("BOT_TOKEN") or ""
    return token.strip()

ADMIN_IDS = _parse_admin_ids()
_SERVICES_CACHE: Optional[List[Dict[str, str]]] = None
_SERVICE_INDEX_CACHE: Optional[Dict[str, Dict[str, str]]] = None

TOKEN = _get_bot_token()
if not TOKEN:
    raise RuntimeError("TELEGRAM_BOT_TOKEN (или BOT_TOKEN) не задан")

if not ADMIN_IDS:
    print("\n[SECURITY WARNING] No ADMIN_IDS set! Bot will ignore all users.\n")

bot = telebot.TeleBot(TOKEN, parse_mode="HTML")

ALERT_ENABLED = os.environ.get("ALERT_ENABLED", "1").lower() in ("1", "true", "yes", "y", "on")
ALERT_INTERVAL_SEC = int(os.environ.get("ALERT_INTERVAL_SEC", "30"))
ALERT_COOLDOWN_SEC = int(os.environ.get("ALERT_COOLDOWN_SEC", "600"))
ALERT_MEMORY_PERCENT = float(os.environ.get("ALERT_MEMORY_PERCENT", "90"))
ALERT_SERVICE_RSS_MB = int(os.environ.get("ALERT_SERVICE_RSS_MB", "1024"))
ALERT_TOP_N = int(os.environ.get("ALERT_TOP_N", "5"))

def is_admin(user_id: int) -> bool:
    return user_id in ADMIN_IDS

def get_services() -> List[Dict[str, str]]:
    global _SERVICES_CACHE
    if _SERVICES_CACHE is None:
        raw_services = discover_services()
        services = []
        for svc in raw_services:
            services.append({
                "key": svc["unit"].replace(".service", "").replace("-", ""),
                "unit": svc["unit"],
                "title": svc["description"],
                "short_name": svc["name"]
            })
        _SERVICES_CACHE = services
    return _SERVICES_CACHE or []

def get_service_index() -> Dict[str, Dict[str, str]]:
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
    return info

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

def describe_service(unit: str) -> str:
    state = get_service_state(unit)
    emoji = format_status_emoji(state["ActiveState"])
    since = state.get("ExecMainStartTimestamp", "") or "—"
    enabled = state.get("UnitFileState", "unknown")
    pid = state.get("MainPID", "0")
    try:
        pid_i = int(pid)
    except:
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

def system_metrics_text() -> str:
    metrics = get_system_metrics()
    parts = []
    
    parts.append(f"⏱ Uptime: <code>{metrics.get('uptime', 'N/A')}</code>")
    
    mem_total = metrics.get('memory_total', 0)
    if mem_total:
        mem_used = metrics.get('memory_used', 0)
        mem_pct = metrics.get('memory_percent', 0)
        parts.append(f"💾 Память: <code>{format_bytes(mem_used)} / {format_bytes(mem_total)} ({mem_pct}%)</code>")
        
    disk_total = metrics.get('disk_total', 0)
    if disk_total:
        disk_used = metrics.get('disk_used', 0)
        disk_pct = metrics.get('disk_percent', 0)
        parts.append(f"💒 Диск /: <code>{format_bytes(disk_used)} / {format_bytes(disk_total)} ({disk_pct}%)</code>")
        
    parts.append(f"📊 LoadAvg: <code>{metrics.get('load_1min', '0')} {metrics.get('load_5min', '0')} {metrics.get('load_15min', '0')}</code>")
    
    return "\n\n".join(parts)

def tail_logs(unit: str, lines: int = 80, priority: Optional[str] = None) -> str:
    unit_q = shlex.quote(unit)
    prio = f"-p {priority} " if priority else ""
    cmd = f"journalctl -u {unit_q} {prio}-n {lines} --no-pager --output=short-iso"
    ok, out = safe_run(cmd, timeout=12)
    return out if ok else f"Ошибка получения логов: {out}"

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

def main_menu_keyboard() -> types.InlineKeyboardMarkup:
    kb = types.InlineKeyboardMarkup(row_width=2)
    services = get_services()
    for svc in services:
        state = get_service_state(svc["unit"])
        emoji = format_status_emoji(state.get("ActiveState", "unknown"))
        kb.add(types.InlineKeyboardButton(f"{emoji} {svc['title']}", callback_data=f"svc:{svc['unit']}:open"))
    
    kb.add(
        types.InlineKeyboardButton("📊 Метрики", callback_data="system:metrics"),
        types.InlineKeyboardButton("🔁 Обновить", callback_data="menu:refresh"),
    )
    kb.add(types.InlineKeyboardButton("🌐 Панель", web_app=types.WebAppInfo(url=PANEL_URL)))
    kb.add(
        types.InlineKeyboardButton("🔌 Reboot", callback_data="system:reboot"),
        types.InlineKeyboardButton("ℹ️ Help", callback_data="system:help"),
    )
    return kb

def ensure_admin(func):
    def wrapper(message):
        if not is_admin(message.from_user.id):
            bot.reply_to(message, "Доступ запрещён")
            return
        return func(message)
    return wrapper

@bot.message_handler(commands=["start", "help", "services"])
@ensure_admin
def handle_commands(message):
    if message.text.startswith("/services") or message.text.startswith("/start"):
        get_services()
        bot.send_message(message.chat.id, "Выберите сервис:", reply_markup=main_menu_keyboard())
    elif message.text.startswith("/help"):
        bot.send_message(message.chat.id, "Бот для управления сервисами. Используйте меню или кнопки.")

@bot.message_handler(commands=["metrics"])
@ensure_admin
def handle_metrics(message):
    bot.send_message(message.chat.id, system_metrics_text())

@bot.message_handler(commands=["cleanup"])
@ensure_admin
def handle_cleanup(message):
    msg = bot.reply_to(message, "⏳ Выполняю агрессивную очистку...")
    commands = [
        "apt-get autoremove -y",
        "apt-get clean",
        "journalctl --vacuum-time=1d",
        "npm cache clean --force",
        "rm -rf /root/.npm/_cacache",
        "rm -rf /tmp/*",
        "sync; echo 3 > /proc/sys/vm/drop_caches"
    ]
    results = []
    for cmd in commands:
        ok, out = safe_run(cmd, shell=True)
        results.append(f"<code>{cmd}</code>: {'✅' if ok else '❌'}")
    
    bot.edit_message_text("\n".join(results), chat_id=msg.chat.id, message_id=msg.message_id)

@bot.message_handler(commands=["start", "stop", "restart"])
@ensure_admin
def handle_multi_action(message):
    # Команды вида: /restart vpads webapp
    parts = message.text.split()
    if len(parts) < 2:
        return handle_commands(message) # Fallback to standard menu

    action = parts[0][1:] # 'start', 'stop', 'restart'
    targets = parts[1:]
    
    all_svcs = get_services()
    results = []
    
    for t in targets:
        # Ищем совпадения (частичное имя)
        found = []
        for s in all_svcs:
            if t.lower() in s['unit'].lower() or t.lower() in s['title'].lower():
                found.append(s)
        
        if not found:
            results.append(f"❌ <b>{t}</b>: не найдено")
            continue
            
        for s in found:
            ok, _ = safe_run(f"systemctl {action} {shlex.quote(s['unit'])}", timeout=20)
            results.append(f"{'✅' if ok else '❌'} <b>{s['unit']}</b>: {action}")
            
    bot.reply_to(message, "\n".join(results))

@bot.message_handler(func=lambda message: True)
@ensure_admin
def handle_text(message):
    query = message.text.strip().lower()
    all_svcs = get_services()
    found = []
    for s in all_svcs:
        if query in s['unit'].lower() or query in s['title'].lower():
            found.append(s)
    
    if not found:
        bot.reply_to(message, f"❌ Сервис '<b>{query}</b>' не найден.")
        return
        
    for s in found:
        bot.send_message(
            message.chat.id, 
            describe_service(s['unit']), 
            reply_markup=service_keyboard(s['unit'])
        )

@bot.callback_query_handler(func=lambda call: True)
def handle_callbacks(call):
    user_id = call.from_user.id
    if not is_admin(user_id):
        bot.answer_callback_query(call.id, "Нет доступа", show_alert=True)
        return

    data = call.data
    if data == "menu:root" or data == "menu:refresh":
        global _SERVICES_CACHE
        if data == "menu:refresh": _SERVICES_CACHE = None
        bot.edit_message_text("Выберите сервис:", chat_id=call.message.chat.id, message_id=call.message.message_id, reply_markup=main_menu_keyboard())
    
    elif data == "system:metrics":
        bot.send_message(call.message.chat.id, system_metrics_text())
        bot.answer_callback_query(call.id)
        
    elif data.startswith("svc:"):
        _, unit, action = data.split(":")
        if action in ("open", "refresh"):
            bot.edit_message_text(describe_service(unit), chat_id=call.message.chat.id, message_id=call.message.message_id, reply_markup=service_keyboard(unit))
        elif action == "logs":
            logs = tail_logs(unit, lines=100)
            bio = io.BytesIO(logs.encode('utf-8'))
            bio.name = f"{unit}.log"
            bot.send_document(call.message.chat.id, bio)
            bot.answer_callback_query(call.id)
            
    elif data.startswith("act:"):
        _, unit, action = data.split(":")
        ok, out = safe_run(f"systemctl {action} {shlex.quote(unit)}", timeout=20)
        bot.answer_callback_query(call.id, "Ок" if ok else "Ошибка", show_alert=not ok)
        bot.edit_message_text(describe_service(unit), chat_id=call.message.chat.id, message_id=call.message.message_id, reply_markup=service_keyboard(unit))

def monitor_loop() -> None:
    """Периодический мониторинг RAM и сервисов."""
    time.sleep(10)
    last_mem_alert = 0.0
    while True:
        try:
            if not ALERT_ENABLED:
                time.sleep(ALERT_INTERVAL_SEC)
                continue
            
            now = time.time()
            metrics = get_system_metrics()
            percent = metrics.get('memory_percent', 0)
            
            if percent >= ALERT_MEMORY_PERCENT and (now - last_mem_alert) >= ALERT_COOLDOWN_SEC:
                text = f"🚨 ТРЕВОГА: Высокая загрузка RAM: {percent}%"
                for admin_id in ADMIN_IDS:
                    try: bot.send_message(admin_id, text)
                    except: pass
                last_mem_alert = now
        except:
            pass
        time.sleep(ALERT_INTERVAL_SEC)

def main():
    print("Bot started...")
    if ALERT_ENABLED:
        t = threading.Thread(target=monitor_loop, daemon=True)
        t.start()
    bot.infinity_polling()

if __name__ == "__main__":
    main()
