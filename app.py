"""

Flask веб-панель управления серверами и сервисами

Безопасный интерфейс для управления systemd сервисами, проектами и nginx конфигами

"""

import os

import subprocess

import shlex

import json

import hashlib

import hmac

import re

import secrets

import threading

import time

import urllib.parse

import urllib.request

import uuid

import shutil

import tarfile

import tempfile

import socket

import zipfile

import requests

from datetime import datetime

from pathlib import Path

from typing import Dict, List, Optional, Tuple

from functools import wraps

from flask import Flask, render_template, request, jsonify, session, redirect, url_for, send_file, send_from_directory
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
from utils import (
    safe_run, format_bytes, get_pid_resources, 
    parse_systemctl_show, get_system_metrics, discover_services,
    SYSTEM_SERVICES, SYSTEMD_DIR
)

# Загружаем переменные окружения
load_dotenv()
if Path("/etc/admin_bot.env").exists():
    load_dotenv("/etc/admin_bot.env")

# Telegram Bot Token для проверки WebApp данных
TELEGRAM_BOT_TOKEN = os.environ.get('TELEGRAM_BOT_TOKEN', '')

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

ADMIN_IDS = _parse_admin_ids()

app = Flask(__name__)
# За обратным прокси (nginx/xray терминируют TLS) сообщаем Flask о реальной
# схеме/хосте, чтобы url_for(..., _external=True) генерировал https-ссылки.
from werkzeug.middleware.proxy_fix import ProxyFix
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)
app.config['PREFERRED_URL_SCHEME'] = 'https'
# ВАЖНО: SECRET_KEY должен быть в .env! Fallback на случайный токен только для dev.
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
# Используем стандартные cookie-сессии Flask (вместо flask-session из-за бага в 0.8.0)
app.config['SESSION_COOKIE_NAME'] = 'session'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True  # Только HTTPS
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = 3600  # 1 час

# Инициализация Rate Limiter
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["2000 per day", "500 per hour"],
    storage_uri="memory://",
)

@app.after_request
def add_security_headers(response):
    """Добавление заголовков безопасности к каждому ответу."""
    if response.content_type and response.content_type.startswith("text/html"):
        response.headers["Content-Type"] = "text/html; charset=utf-8"

    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'no-referrer-when-downgrade'
    # Ограничиваем CSP (разрешаем telegram.org для работы WebApp)
    response.headers['Content-Security-Policy'] = "default-src 'self' https:; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://telegram.org; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; img-src 'self' data: https:; frame-src 'self' https://telegram.org;"
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'

    return response

@app.context_processor
def _inject_panel_paths():
    """Пути на сервере отдаются шаблонам динамически (не хардкодятся во фронтенде)."""
    try:
        return {'panel_paths': {
            'projects_dir': str(PROJECTS_DIR),
            'bots_dir': str(BOTS_DIR),
            'backups_dir': str(BACKUPS_DIR),
        }}
    except NameError:
        return {'panel_paths': {}}

# DreamID SSO Configuration
DREAMID_CLIENT_ID = os.environ.get('DREAMID_CLIENT_ID', 'admin_bot')
DREAMID_CLIENT_SECRET = os.environ.get('DREAMID_CLIENT_SECRET', '')
DREAMID_AUTH_URL = os.environ.get('DREAMID_AUTH_URL', 'https://auth.dreampartners.online')
ALLOWED_USERNAME = os.environ.get('ALLOWED_USERNAME', '') # Только этот пользователь имеет доступ
ALLOWED_TELEGRAM_ID = int(os.environ.get('ALLOWED_TELEGRAM_ID', '0')) # СТРОГАЯ ПРОВЕРКА

# Конфигурация
# ВАЖНО: Измените пароль по умолчанию через переменные окружения!
ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'admin')
# По умолчанию пароль НЕ ЗАДАН, если не указан в .env (безопасность!)
DEFAULT_PASSWORD = os.environ.get('ADMIN_PASSWORD')
if not DEFAULT_PASSWORD and not os.environ.get('ADMIN_PASSWORD_HASH'):
    # Если нет пароля в .env, генерируем случайный и выводим в консоль (один раз при старте)
    DEFAULT_PASSWORD = secrets.token_urlsafe(16)
    print(f"\n[SECURITY] No ADMIN_PASSWORD set! Temporary password generated: {DEFAULT_PASSWORD}\n")

ADMIN_PASSWORD_HASH = os.environ.get('ADMIN_PASSWORD_HASH', generate_password_hash(DEFAULT_PASSWORD if DEFAULT_PASSWORD else "disable_auth_if_no_password"))

PROJECTS_DIR = Path(os.environ.get('PROJECTS_DIR', str(Path.home() / 'projects')))

WWW_DIR = Path('/var/www')

NGINX_SITES_DIR = Path('/etc/nginx/sites-enabled')

NGINX_SITES_AVAILABLE_DIR = Path('/etc/nginx/sites-available')

SYSTEMD_DIR = Path('/etc/systemd/system')

PORT = int(os.environ.get('PORT', 5001))

# File manager roots:

# - WRITE roots: где разрешены изменения (create/save/delete/rename/upload)

# - READ roots: где разрешены просмотр/скачивание (list/content/download)

FILE_MANAGER_WRITE_ROOTS = [

    WWW_DIR,

    PROJECTS_DIR,

    NGINX_SITES_DIR,

    NGINX_SITES_AVAILABLE_DIR,

    SYSTEMD_DIR,

    Path('/etc/letsencrypt'),

]

FILE_MANAGER_READ_ROOTS = list(FILE_MANAGER_WRITE_ROOTS)

# ПО УМОЛЧАНИЮ НЕЛЬЗЯ просматривать весь сервер! Только по явному разрешению в .env.
if os.environ.get("FILE_MANAGER_ALLOW_READ_ALL", "0").lower() in ("1", "true", "yes", "y", "on"):
    FILE_MANAGER_READ_ROOTS.append(Path("/"))

# Safety limit for in-browser editor (bytes)

MAX_EDITOR_BYTES = int(os.environ.get('MAX_EDITOR_BYTES', str(2 * 1024 * 1024)))  # 2MB

# Backups

# Бэкапы хранятся прямо в папке приложения (рядом с самим проектом),
# а не в отдельной серверной директории.
BACKUPS_DIR = Path(os.environ.get('BACKUPS_DIR', str(Path(__file__).resolve().parent / 'backups')))

try:

    BACKUPS_DIR.mkdir(parents=True, exist_ok=True)

except Exception:

    pass

PROJECT_MARKER_FILE = ".panel_project.json"

# Icons API Configuration

ICONS_API_TOKEN = os.environ.get('ICONS_API_TOKEN', 'your-secret-token-change-this')

ICONS_API_URL = os.environ.get('ICONS_API_URL', 'http://127.0.0.1:8499')

# Allow browsing backups via file manager (read/write restricted by allowlist)

try:

    if BACKUPS_DIR not in FILE_MANAGER_WRITE_ROOTS:

        FILE_MANAGER_WRITE_ROOTS.append(BACKUPS_DIR)

    if BACKUPS_DIR not in FILE_MANAGER_READ_ROOTS:

        FILE_MANAGER_READ_ROOTS.append(BACKUPS_DIR)

except Exception:

    pass

def _is_relative_to(path: Path, base: Path) -> bool:

    try:

        path.relative_to(base)

        return True

    except ValueError:

        return False

def _is_allowed_path(path: Path, roots: List[Path]) -> bool:

    """Check if path is inside allowed file manager roots."""

    try:

        rp = path.resolve()

    except Exception:

        rp = path

    for root in roots:

        try:

            rr = root.resolve()

        except Exception:

            rr = root

        if _is_relative_to(rp, rr):

            return True

    return False

def _resolve_allowed_path(raw_path: str, roots: List[Path]) -> Path:

    """Resolve and validate an allowed path for the file manager API."""

    if not raw_path:

        raise ValueError('Path is required')

    p = Path(raw_path).expanduser()

    try:

        rp = p.resolve()

    except Exception:

        rp = p.absolute()

    if not _is_allowed_path(rp, roots):

        raise PermissionError('Доступ запрещен')

    return rp

def _resolve_read_path(raw_path: str) -> Path:

    return _resolve_allowed_path(raw_path, FILE_MANAGER_READ_ROOTS)

def _resolve_write_path(raw_path: str) -> Path:

    return _resolve_allowed_path(raw_path, FILE_MANAGER_WRITE_ROOTS)

def _is_read_allowed_path(path: Path) -> bool:

    return _is_allowed_path(path, FILE_MANAGER_READ_ROOTS)

def _is_write_allowed_path(path: Path) -> bool:

    return _is_allowed_path(path, FILE_MANAGER_WRITE_ROOTS)

def _validate_entry_name(name: str) -> str:

    """Validate a single file/folder name (no separators, no traversal)."""

    name = (name or '').strip()

    if not name:

        raise ValueError('Name is required')

    if '/' in name or '\\' in name:

        raise ValueError('Invalid name')

    if name in {'.', '..'}:

        raise ValueError('Invalid name')

    return name

# Системные сервисы для исключения (как в боте)

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


def _project_marker_path(project_dir: Path) -> Path:

    return project_dir / PROJECT_MARKER_FILE

def _read_project_marker(project_dir: Path) -> Dict[str, object]:

    try:

        marker = _project_marker_path(project_dir)

        if marker.exists() and marker.is_file():

            return json.loads(marker.read_text(encoding="utf-8", errors="replace") or "{}") or {}

    except Exception:

        pass

    return {}

def _write_project_marker(project_dir: Path, meta: Dict[str, object]) -> None:

    try:

        marker = _project_marker_path(project_dir)

        marker.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")

    except Exception:

        pass

def _coerce_bool(value: object, default: bool = False) -> bool:

    if value is None:

        return default

    if isinstance(value, bool):

        return value

    return str(value).strip().lower() in {"1", "true", "yes", "y", "on"}

def _resolve_python_candidates() -> List[str]:

    candidates: List[str] = []

    seen: set[str] = set()

    def _add(raw: Optional[str]) -> None:

        if not raw:

            return

        candidate = str(raw).strip()

        if not candidate or candidate in seen:

            return

        resolved = shutil.which(candidate) or candidate

        if os.path.exists(resolved):

            seen.add(candidate)

            seen.add(resolved)

            candidates.append(resolved)

    env_python = os.environ.get("ADMIN_BOT_DEFAULT_PYTHON", "").strip()

    _add(env_python)

    for raw in (

        shutil.which("python3"),

        shutil.which("python"),

        "/usr/bin/python3",

        "/usr/local/bin/python3",

        "/usr/bin/python3.13",

        "/usr/bin/python3.12",

        "/usr/bin/python3.11",

        "/usr/bin/python3.10",

        "/usr/bin/python3.9",

    ):

        _add(raw)

    for base_dir in ("/usr/bin", "/usr/local/bin"):

        base = Path(base_dir)

        if not base.exists():

            continue

        try:

            for p in sorted(base.glob("python3*"), reverse=True):

                if p.is_file():

                    _add(str(p))

        except Exception:

            continue

    return candidates

def _pick_python_bin(requested: str = "") -> Tuple[str, List[str]]:

    candidates = _resolve_python_candidates()

    requested = (requested or "").strip()

    warnings: List[str] = []

    if requested:

        resolved = shutil.which(requested) or requested

        if os.path.exists(resolved):

            return resolved, warnings

        warnings.append(f"Python not found: {requested}. Falling back to detected interpreter.")

    if candidates:

        return candidates[0], warnings

    fallback = "/usr/bin/python3"

    warnings.append("Could not detect a Python interpreter automatically. Using /usr/bin/python3.")

    return fallback, warnings

def _append_warning(warnings: List[str], message: str) -> None:

    msg = (message or "").strip()

    if msg:

        warnings.append(msg)

def check_dns_resolves(domain: str) -> Tuple[bool, Optional[str], Optional[str], Optional[str]]:

    """

    Проверяет, резолвится ли домен и указывает ли на IP сервера.

    Возвращает (ok, server_ip, domain_ip, error_msg).

    """

    try:

        # Получаем IP сервера (первый не-localhost интерфейс)

        server_ip = None

        try:

            # Пробуем через hostname -I

            ok, out = safe_run("hostname -I | awk '{print $1}'", timeout=5)

            if ok and out.strip():

                server_ip = out.strip().split()[0]

        except Exception:

            pass

        if not server_ip:

            # Fallback: через socket

            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

            try:

                s.connect(('8.8.8.8', 80))

                server_ip = s.getsockname()[0]

            except Exception:

                pass

            finally:

                s.close()

        if not server_ip:

            return False, None, None, "Не удалось определить IP сервера"

        # Резолвим домен (все A/AAAA)

        try:

            infos = socket.getaddrinfo(domain, None)

            ips = sorted({info[4][0] for info in infos if info and info[4] and info[4][0]})

        except socket.gaierror as e:

            return False, server_ip, None, f"Домен не резолвится: {e}"

        domain_ip = ips[0] if ips else None

        # Сравниваем

        if server_ip in ips:

            return True, server_ip, domain_ip, None

        else:

            shown = ", ".join(ips[:5]) if ips else "N/A"

            return False, server_ip, domain_ip, f"Домен указывает на {shown}, а сервер на {server_ip}"

    except Exception as e:

        return False, None, None, f"Ошибка проверки DNS: {e}"


def verify_telegram_webapp_data(init_data: str) -> Optional[Dict]:

    """Проверка и парсинг данных Telegram WebApp."""

    try:

        if not init_data:

            return None

        if not TELEGRAM_BOT_TOKEN:

            # Без токена нельзя безопасно проверить initData

            return None

        # Парсим данные используя parse_qsl (как в рабочем проекте)

        parsed_data = dict(urllib.parse.parse_qsl(init_data))

        # Извлекаем hash

        if 'hash' not in parsed_data:

            return None

        received_hash = parsed_data.pop('hash')  # Удаляем hash из данных

        # Создаем секретный ключ

        secret_key = hmac.new(

            key=b"WebAppData",

            msg=TELEGRAM_BOT_TOKEN.encode(),

            digestmod=hashlib.sha256

        ).digest()

        # Формируем data_check_string: сортируем все параметры кроме hash и соединяем через \n

        data_check_string = '\n'.join(f"{k}={v}" for k, v in sorted(parsed_data.items()))

        # Вычисляем hash

        calculated_hash = hmac.new(

            key=secret_key,

            msg=data_check_string.encode('utf-8'),

            digestmod=hashlib.sha256

        ).hexdigest()

        # Сравниваем

        if calculated_hash != received_hash:

            return None

        # Защита от replay: initData должен быть свежим (макс. 1 час)
        auth_date = parsed_data.get('auth_date')

        if auth_date:
            try:
                ts = int(auth_date)
                if time.time() - ts > 3600:
                    return None
            except (ValueError, TypeError):
                return None
        else:
            return None

        # Парсим данные пользователя

        user_data = {}

        if 'user' in parsed_data:

            user_json = parsed_data['user']

            user_data = json.loads(user_json)

        return user_data

    except Exception as e:

        print(f"Ошибка проверки Telegram данных: {e}")

        return None

def login_required(f):

    """Декоратор для проверки авторизации."""

    @wraps(f)

    def decorated_function(*args, **kwargs):

        # Проверяем авторизацию через Telegram WebApp

        init_data = request.headers.get('X-Telegram-Init-Data') or request.args.get('tgWebAppData')

        if init_data:

            user_data = verify_telegram_webapp_data(init_data)

            if user_data and user_data.get('id') == ADMIN_TELEGRAM_ID:

                # Автоматическая авторизация для админа через Telegram

                session['authenticated'] = True

                session['username'] = 'admin'

                session['telegram_id'] = user_data.get('id')

                return f(*args, **kwargs)

        # Обычная проверка сессии

        if 'authenticated' not in session or not session['authenticated']:

            # Если это API запрос, возвращаем JSON

            if request.path.startswith('/api/'):

                return jsonify({'error': 'Требуется авторизация'}), 401

            # Иначе редиректим на логин

            return redirect(url_for('login'))

        return f(*args, **kwargs)

    return decorated_function


# Публичные маршруты, которые не требуют авторизации
PUBLIC_API_PATHS = (
    '/api/auth_check',
    '/api/public/',
)


@app.before_request
def require_api_auth():
    """Глобальная защита всех /api/* маршрутов.

    Раньше API-маршруты были доступны анонимно (критическая уязвимость).
    Теперь любой /api/* запрос требует аутентифицированную сессию или
    валидный Telegram WebApp initData администратора.
    """
    path = request.path

    # Не трогаем не-API маршруты
    if not path.startswith('/api/'):
        return

    # Разрешаем только явно публичные маршруты
    for pub in PUBLIC_API_PATHS:
        if path == pub or path.startswith(pub):
            return

    # Проверяем Telegram WebApp initData (для SPA фронтенда)
    init_data = request.headers.get('X-Telegram-Init-Data') or request.args.get('tgWebAppData')
    if init_data:
        user_data = verify_telegram_webapp_data(init_data)
        if user_data and int(user_data.get('id', 0)) in ADMIN_IDS:
            session['authenticated'] = True
            session['username'] = 'admin'
            session['telegram_id'] = user_data.get('id')
            return

    if session.get('authenticated'):
        return

    return jsonify({'error': 'Требуется авторизация'}), 401


def get_service_state(unit: str) -> Dict[str, str]:

    """Получение состояния сервиса."""

    unit_q = shlex.quote(unit)

    ok, raw = safe_run(

        f"systemctl show {unit_q} --no-page "

        "--property=ActiveState,SubState,UnitFileState,MainPID,"

        "ExecMainStartTimestamp,FragmentPath",

        timeout=10,

    )

    info = parse_systemctl_show(raw if ok else "")

    info.setdefault("ActiveState", "unknown")

    info.setdefault("SubState", "-")

    info.setdefault("UnitFileState", "unknown")

    info.setdefault("MainPID", "0")

    info.setdefault("ExecMainStartTimestamp", "")

    return info


# ==================== Routes ====================

@app.route('/')
def index():
    """Главная страница - редирект на логин или dashboard."""
    # Проверяем авторизацию через Telegram WebApp
    init_data = request.headers.get('X-Telegram-Init-Data') or request.args.get('tgWebAppData')
    if init_data:
        user_data = verify_telegram_webapp_data(init_data)
        if user_data and int(user_data.get('id', 0)) in ADMIN_IDS:
            session['authenticated'] = True
            session['username'] = 'admin'
            session['telegram_id'] = user_data.get('id')
            return redirect(url_for('dashboard'))

    if 'authenticated' in session and session['authenticated']:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/api/auth_check')
def auth_check():
    """Endpoint for Nginx auth_request to check if user is authenticated."""
    if session.get('authenticated'):
        return '', 200

    # Поддерживаем вход по Telegram WebApp initData (используется фронтендом)
    init_data = request.headers.get('X-Telegram-Init-Data') or request.args.get('tgWebAppData')
    if init_data:
        user_data = verify_telegram_webapp_data(init_data)
        if user_data and int(user_data.get('id', 0)) in ADMIN_IDS:
            session['authenticated'] = True
            session['username'] = 'admin'
            session['telegram_id'] = user_data.get('id')
            return '', 200

    return '', 401

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
    """Страница входа - гибридный вход: логин/пароль ИЛИ DreamID SSO."""
    # Проверяем авторизацию через Telegram WebApp
    init_data = request.headers.get('X-Telegram-Init-Data') or request.args.get('tgWebAppData')
    if init_data:
        user_data = verify_telegram_webapp_data(init_data)
        if user_data and int(user_data.get('id', 0)) in ADMIN_IDS:
            session['authenticated'] = True
            session['username'] = 'admin'
            session['telegram_id'] = user_data.get('id')
            return redirect(url_for('dashboard'))

    if request.method == 'POST':
        settings_path = Path('settings.json')
        login_enabled = True
        if settings_path.exists():
            try:
                with open(settings_path, 'r', encoding='utf-8') as f:
                    login_enabled = json.load(f).get('login_enabled', True)
            except:
                pass
        
        if not login_enabled:
            return jsonify({'success': False, 'error': 'Вход по паролю отключен в настройках'}), 403

        username = request.form.get('username', '')

        password = request.form.get('password', '')

        # СТРОГАЯ ПРОВЕРКА: только dreamcatch_r может войти по логину/паролю

        if username == ADMIN_USERNAME and check_password_hash(ADMIN_PASSWORD_HASH, password):

            session['authenticated'] = True

            session['username'] = username

            return jsonify({'success': True, 'redirect': url_for('dashboard')})

        else:

            return jsonify({'success': False, 'error': 'Неверные учетные данные'}), 401

    return render_template('login.html')

@app.route('/login/dreamid')

def login_dreamid():

    """Вход через DreamID SSO."""

    # Генерируем state для защиты от CSRF

    state = secrets.token_urlsafe(32)

    session['oauth_state'] = state

    # Формируем redirect_uri

    redirect_uri = url_for('sso_callback', _external=True)

    # Перенаправляем на DreamID для авторизации

    auth_url = f"{DREAMID_AUTH_URL}/authorize?client_id={DREAMID_CLIENT_ID}&redirect_uri={urllib.parse.quote(redirect_uri)}&state={state}"

    return redirect(auth_url)

@app.route('/sso/callback')

def sso_callback():

    """Обработка callback от DreamID SSO."""

    code = request.args.get('code')

    state = request.args.get('state')

    error = request.args.get('error')

    # Проверяем state.
    # В обычном браузерном потоке oauth_state есть в сессии — сверяем строго (CSRF).
    # При быстром входе через Telegram кнопка открывается во встроенном WebView
    # без нашей cookie — oauth_state отсутствует. В этом случае полагаемся
    # на одноразовый серверный code + строгую проверку telegram_id ниже.

    saved_state = session.get('oauth_state')

    if saved_state and state != saved_state:

        return "Invalid state parameter", 400

    if error:

        return f"Authorization error: {error}", 400

    if not code:

        return "No authorization code received", 400

    # Обмениваем code на токен

    try:

        token_response = requests.post(

            f"{DREAMID_AUTH_URL}/token",

            json={

                "code": code,

                "client_id": DREAMID_CLIENT_ID,

                "client_secret": DREAMID_CLIENT_SECRET

            },

            timeout=10

        )

        if token_response.status_code != 200:

            return f"Token exchange failed: {token_response.text}", 400

        token_data = token_response.json()

        access_token = token_data.get('access_token')

        if not access_token:

            return "No access token received", 400

        # Получаем данные пользователя

        user_response = requests.get(

            f"{DREAMID_AUTH_URL}/api/user",

            headers={"Authorization": f"Bearer {access_token}"},

            timeout=10

        )

        if user_response.status_code != 200:

            return f"Failed to get user data: {user_response.text}", 400

        user_data = user_response.json()

        username = user_data.get('username')

        telegram_id = user_data.get('telegram_id')

        # СТРОГАЯ ПРОВЕРКА: только по Telegram ID (появляется при быстром входе через Telegram)
        if not telegram_id or telegram_id != ALLOWED_TELEGRAM_ID:
            return "Доступ запрещен. Только авторизованные пользователи могут войти.", 403

        # Авторизуем пользователя (только если прошли ОБЕ проверки)

        session['authenticated'] = True

        session['username'] = username

        session['user_id'] = user_data.get('id')

        session['telegram_id'] = telegram_id

        session['access_token'] = access_token

        session.pop('oauth_state', None)

        return redirect(url_for('dashboard'))

    except requests.RequestException as e:

        return f"SSO error: {str(e)}", 500

    except Exception as e:

        return f"Unexpected error: {str(e)}", 500

@app.route('/logout')

def logout():

    """Выход из системы."""

    session.clear()

    return redirect(url_for('login'))

@app.route('/static/<path:path>')

def send_static(path):

    """Отдача статических файлов."""

    return send_from_directory('static', path)

@app.route('/dashboard')



def dashboard():

    """Главная панель управления."""

    # Используем новый улучшенный шаблон на Bootstrap
    settings = _get_settings()
    return render_template(
        'dashboard_bootstrap.html',
        microservices_enabled=settings.get('microservices_enabled', True),
        console_enabled=settings.get('console_enabled', True),
    )

def _get_settings():
    settings_path = Path('settings.json')
    # Default settings
    settings = {
        'login_enabled': True,
        'alerts_enabled': str(os.getenv('ALERT_ENABLED', '1')) == '1',
        'bot_token': os.getenv('TELEGRAM_BOT_TOKEN', ''),
        'bot_enabled': os.getenv('BOT_ENABLED', '1').lower() in ('1', 'true', 'yes', 'y', 'on'),
        'microservices_enabled': True,
        'console_enabled': True,
        'maintenance_exclude': ["admin-bot.service", "nginx.service", "sshd.service", "xray.service", "zapret.service"],
        'status_page_enabled': True,
        'public_services': [
            'dreampartners-webapp.service',
            'dreampartners.service',
            'dreamgpt.service',
            'player.service',
            'swagplayer.service',
            'auth-sso.service',
            'downloader-bot.service',
            'sms-bot.service',
            'mp3-app.service',
            'tones.service',
            'icons-api.service',
            'vpn-bot.service',
            'share.service',
        ]
    }
    if settings_path.exists():
        try:
            with open(settings_path, 'r', encoding='utf-8') as f:
                saved_settings = json.load(f)
            settings.update(saved_settings)
        except:
            pass
    return settings

@app.route('/status')
def status_public():
    """Публичная страница статусов всех сервисов."""
    settings = _get_settings()
    if not settings.get('status_page_enabled', True):
        return "Not Found", 404
    return render_template('status_public.html')

# ==================== Demo Routes ====================

DEMO_DIR = Path(__file__).parent / 'admin_panel_demo'

@app.route('/demo')

def demo_index():

    """Демо-версия панели управления - страница входа."""

    demo_index_path = DEMO_DIR / 'index.html'

    if demo_index_path.exists():

        return send_file(str(demo_index_path))

    return "Demo not found", 404

@app.route('/demo/dashboard.html')

def demo_dashboard():

    """Демо-версия панели управления - dashboard."""

    demo_dashboard_path = DEMO_DIR / 'dashboard.html'

    if demo_dashboard_path.exists():

        return send_file(str(demo_dashboard_path))

    return "Demo dashboard not found", 404

@app.route('/demo/static/<path:path>')

def demo_static(path):

    """Отдача статических файлов демо."""

    return send_from_directory(str(DEMO_DIR / 'static'), path)

@app.route('/demo/<path:filename>')

def demo_files(filename):

    """Отдача других файлов демо (например, README.md)."""

    # Исключаем уже обработанные пути

    if filename == 'dashboard.html' or filename.startswith('static/'):

        return "File not found", 404

    file_path = DEMO_DIR / filename

    if file_path.exists() and file_path.is_file():

        # Проверяем, что файл находится внутри DEMO_DIR (безопасность)

        try:

            file_path.resolve().relative_to(DEMO_DIR.resolve())

            return send_file(str(file_path))

        except ValueError:

            return "Access denied", 403

    return "File not found", 404

# ==================== API Routes ====================


@app.route('/api/backups/targets')

def api_backups_targets():
    sites = []
    if os.path.exists('/var/www'):
        sites = [d for d in os.listdir('/var/www') if os.path.isdir(os.path.join('/var/www', d))]
    projects = []
    if PROJECTS_DIR.exists():
        projects = [d for d in os.listdir(PROJECTS_DIR) if os.path.isdir(os.path.join(PROJECTS_DIR, d))]
    return jsonify({'sites': sorted(sites), 'projects': sorted(projects)})

@app.route('/api/system/cleanup', methods=['POST'])

def api_system_cleanup():
    """Агрессивная очистка системы (кэши, логи, старые пакеты)."""
    commands = [
        "apt-get autoremove -y",
        "apt-get clean",
        "journalctl --vacuum-time=1d",
        "npm cache clean --force",
        "rm -rf /root/.npm/_cacache",
        "rm -rf /root/.cache",
        "rm -rf /tmp/*",
        "sync; echo 3 > /proc/sys/vm/drop_caches"
    ]
    results = []
    for cmd in commands:
        ok, out = safe_run(cmd, shell=True)
        results.append({"command": cmd, "ok": ok, "output": out})
    
    return jsonify({"success": True, "results": results})
# ===================== SETTINGS API =====================
@app.route('/api/settings', methods=['GET', 'POST'])

def api_settings():
    settings_path = Path('settings.json')
    if request.method == 'GET':
        return jsonify(_get_settings())

    if request.method == 'POST':
        data = request.json
        # Load current to preserve fields not in POST
        settings = _get_settings()

        # Update from request
        for key in ['login_enabled', 'alerts_enabled', 'maintenance_exclude', 'status_page_enabled', 'public_services',
                    'bot_enabled', 'microservices_enabled', 'console_enabled']:
            if key in data:
                settings[key] = data[key]

        with open(settings_path, 'w', encoding='utf-8') as f:
            json.dump(settings, f, ensure_ascii=False, indent=4)
        # update .env for ALERT_ENABLED / BOT_ENABLED if needed
        try:
            env_path = Path('.env')
            if env_path.exists():
                with open(env_path, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                for i, line in enumerate(lines):
                    if line.startswith('ALERT_ENABLED='):
                        lines[i] = "ALERT_ENABLED=" + ("1" if settings['alerts_enabled'] else "0") + "\n"
                    if line.startswith('BOT_ENABLED='):
                        lines[i] = "BOT_ENABLED=" + ("1" if settings.get('bot_enabled') else "0") + "\n"
                with open(env_path, 'w', encoding='utf-8') as f:
                    f.writelines(lines)
        except:
            pass

        return jsonify({'success': True})



MAINTENANCE_STATE_FILE = Path('maintenance_state.json')

@app.route('/api/maintenance/status')

def api_maintenance_status():
    if MAINTENANCE_STATE_FILE.exists():
        try:
            with open(MAINTENANCE_STATE_FILE, 'r', encoding='utf-8') as f:
                state = json.load(f)
            return jsonify(state)
        except:
            pass
    return jsonify({'active': False})

@app.route('/api/maintenance/toggle', methods=['POST'])

def api_maintenance_toggle():
    active = request.json.get('active', False)
    
    if active:
        # Enable maintenance
        services = discover_services()
        to_stop = []
        total_rss = 0
        total_cpu = 0.0
        stopped_info = [] # Store per-service stats
        
        # We don't want to stop the panel itself or system services
        EXCLUDE = {"admin-bot.service", "nginx.service", "sshd.service", "xray.service", "zapret.service"}
        settings_path = Path('settings.json')
        if settings_path.exists():
            try:
                with open(settings_path, 'r', encoding='utf-8') as f:
                    saved_settings = json.load(f)
                    if 'maintenance_exclude' in saved_settings:
                        EXCLUDE = set(saved_settings['maintenance_exclude'])
            except:
                pass
        
        for svc in services:
            unit = svc['unit']
            if unit in EXCLUDE or unit in SYSTEM_SERVICES:
                continue
            
            state = get_service_state(unit)
            if state.get("ActiveState") == "active":
                try:
                    pid = int(state.get("MainPID", "0") or "0")
                    rss = 0
                    cpu = 0.0
                    if pid > 0:
                        rss, cpu = get_pid_resources(pid)
                        total_rss += rss
                        total_cpu += cpu
                    
                    to_stop.append(unit)
                    stopped_info.append({
                        'unit': unit,
                        'rss': rss,
                        'cpu': cpu
                    })
                except:
                    pass
        
        # Stop services
        for unit in to_stop:
            safe_run(f"systemctl stop {shlex.quote(unit)}")
            
        state = {
            'active': True,
            'stopped_services_detailed': stopped_info,
            'stopped_services': to_stop, # for backwards compat
            'saved_ram_bytes': total_rss,
            'saved_cpu': total_cpu,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        with open(MAINTENANCE_STATE_FILE, 'w', encoding='utf-8') as f:
            json.dump(state, f, ensure_ascii=False, indent=4)
            
        return jsonify({'success': True, 'state': state})
    else:
        # Disable maintenance
        if not MAINTENANCE_STATE_FILE.exists():
            return jsonify({'success': True, 'active': False})
            
        try:
            with open(MAINTENANCE_STATE_FILE, 'r', encoding='utf-8') as f:
                state = json.load(f)
        except:
            return jsonify({'error': 'Could not read maintenance state'}), 500
            
        stopped_detailed = state.get('stopped_services_detailed', [])
        # If no detailed info, use basic list
        if not stopped_detailed:
            stopped_detailed = [{'unit': u, 'rss': 0} for u in state.get('stopped_services', [])]
        
        # Smart algorithm: Sort by RSS ascending (start lighter services first to not overload immediately)
        stopped_detailed.sort(key=lambda x: x.get('rss', 0))
        
        def start_gradually(items):
            for item in items:
                unit = item['unit']
                safe_run(f"systemctl start {shlex.quote(unit)}")
                # Wait based on "weight": minimum 2s, more if rss was large (e.g. +1s per 100MB)
                rss = item.get('rss', 0)
                delay = 2 + (rss // (100 * 1024 * 1024))
                time.sleep(min(delay, 10)) # Max 10s wait
                
        thread = threading.Thread(target=start_gradually, args=(stopped_detailed,))
        thread.start()
        
        if MAINTENANCE_STATE_FILE.exists():
            try:
                MAINTENANCE_STATE_FILE.unlink()
            except:
                pass
            
        return jsonify({'success': True, 'active': False, 'restarting_count': len(stopped_detailed)})

@app.route('/api/services')

def api_services():
    """API: Список всех сервисов с их состояниями."""
    services = discover_services()
    result = []
    pids_to_svc = {}
    
    for svc in services:
        state = get_service_state(svc["unit"])
        pid_str = state.get("MainPID", "0") or "0"
        try:
            pid_int = int(pid_str)
        except Exception:
            pid_int = 0
            
        svc_data = {
            "unit": svc["unit"],
            "name": svc["name"],
            "description": svc["description"],
            "state": state.get("ActiveState", "unknown"),
            "substate": state.get("SubState", "-"),
            "enabled": state.get("UnitFileState", "unknown"),
            "pid": str(pid_int),
            "started": state.get("ExecMainStartTimestamp", ""),
            "rss_bytes": 0,
            "cpu_percent": 0.0,
        }
        if pid_int > 0:
            pids_to_svc[pid_int] = svc_data
        result.append(svc_data)

    if pids_to_svc:
        pids_str = ",".join(map(str, pids_to_svc.keys()))
        ok, out = safe_run(f"ps -p {pids_str} -o pid,rss,%cpu --no-headers", timeout=5)
        if ok:
            for line in out.strip().split('\n'):
                parts = line.split()
                if len(parts) >= 3:
                    try:
                        pid = int(parts[0])
                        rss_kb = int(parts[1])
                        cpu = float(parts[2])
                        if pid in pids_to_svc:
                            pids_to_svc[pid]["rss_bytes"] = rss_kb * 1024
                            pids_to_svc[pid]["cpu_percent"] = cpu
                    except (ValueError, IndexError): continue
    return jsonify(result)

@app.route('/api/service/<unit>/action', methods=['POST'])



def api_service_action(unit):

    """API: Выполнение действия над сервисом."""

    action = request.json.get('action')

    unit_q = shlex.quote(unit)

    commands = {

        'start': f"systemctl start {unit_q}",

        'stop': f"systemctl stop {unit_q}",

        'restart': f"systemctl restart {unit_q}",

        'enable': f"systemctl enable {unit_q}",

        'disable': f"systemctl disable {unit_q}",

        'reload': f"systemctl daemon-reload",

        'kill': f"systemctl kill --signal=SIGKILL {unit_q}",

    }

    if action not in commands:

        return jsonify({'error': 'Неизвестное действие'}), 400

    ok, output = safe_run(commands[action], timeout=30)

    if ok:

        # Обновляем состояние после действия

        time.sleep(0.5)

        state = get_service_state(unit)

        return jsonify({

            'success': True,

            'state': state.get("ActiveState", "unknown"),

            'substate': state.get("SubState", "-"),

            'enabled': state.get("UnitFileState", "unknown"),

        })

    else:

        return jsonify({'success': False, 'error': output}), 500

@app.route('/api/service/<unit>/clear-journal', methods=['POST'])



def api_service_clear_journal(unit):

    """API: Очистка журнала сервиса."""

    unit_q = shlex.quote(unit)

    # Очищаем журнал для конкретного unit

    ok, output = safe_run(f"journalctl --rotate && journalctl --vacuum-time=1s -u {unit_q}", timeout=30)

    if ok:

        return jsonify({'success': True, 'message': 'Журнал очищен'})

    else:

        return jsonify({'success': False, 'error': output}), 500

@app.route('/api/service/<unit>/logs')



def api_service_logs(unit):

    """API: Получение логов сервиса."""

    lines = request.args.get('lines', 100, type=int)

    priority = request.args.get('priority')

    unit_q = shlex.quote(unit)

    prio = f"-p {priority} " if priority else ""

    cmd = f"journalctl -u {unit_q} {prio}-n {lines} --no-pager --output=short-iso"

    ok, logs = safe_run(cmd, timeout=12)

    if ok:

        # Возвращаем как текстовый файл для удобного просмотра

        from flask import Response

        return Response(

            logs,

            mimetype='text/plain',

            headers={'Content-Disposition': f'attachment; filename=logs-{unit}.txt'}

        )

    else:

        return jsonify({'error': logs}), 500

@app.route('/api/metrics')



def api_metrics():

    """API: Системные метрики."""

    return jsonify(get_system_metrics())

@app.route('/api/projects')



def api_projects():

    """API: Список проектов."""

    projects = []

    include_hidden = _coerce_bool(request.args.get("include_hidden"), default=False)

    if PROJECTS_DIR.exists():

        for item in PROJECTS_DIR.iterdir():

            if item.is_dir() and not item.name.startswith('.'):

                meta = _read_project_marker(item)

                hidden = _coerce_bool(meta.get("hidden"), default=False)

                if hidden and not include_hidden:

                    continue

                projects.append({

                    'name': item.name,

                    'path': str(item),

                    'size': sum(f.stat().st_size for f in item.rglob('*') if f.is_file()),

                    # best-effort metadata (wizard writes this marker)

                    'domain': meta.get('domain'),

                    'service': meta.get('service'),

                    'port': meta.get('port'),

                    'hidden': hidden,

                    'python_bin': meta.get('python_bin'),

                    'visible_in_catalogs': not hidden,

                })

    return jsonify(projects)


def api_projects_delete(name):

    """API: Удаление проекта."""

    name = (name or '').strip()

    if not name or '/' in name or '\\' in name or name in {'.', '..'}:

        return jsonify({'success': False, 'error': 'Недопустимое имя проекта'}), 400

    project_path = PROJECTS_DIR / name

    if not project_path.exists():

        return jsonify({'success': False, 'error': 'Проект не найден'}), 404

    if not project_path.is_dir():

        return jsonify({'success': False, 'error': 'Это не директория'}), 400

    try:

        # Проверяем, есть ли связанный сервис

        meta = _read_project_marker(project_path)

        service_name = meta.get('service')

        # Если есть связанный сервис, останавливаем и отключаем его

        if service_name:

            safe_run(f"systemctl stop {shlex.quote(str(service_name))}", timeout=10)

            safe_run(f"systemctl disable {shlex.quote(str(service_name))}", timeout=10)

        # Удаляем директорию проекта

        shutil.rmtree(project_path)

        return jsonify({'success': True, 'message': f'Проект {name} удалён'})

    except Exception as e:

        return jsonify({'success': False, 'error': str(e)}), 500

# ==================== Projects Wizard (upload + deploy) ====================

PROJECT_WIZARD_TMP_ROOT = Path(

    os.environ.get("PROJECT_WIZARD_TMP_ROOT") or (Path(tempfile.gettempdir()) / "admin_bot_project_wizard")

)

try:

    PROJECT_WIZARD_TMP_ROOT.mkdir(parents=True, exist_ok=True)

except Exception:

    pass

_PROJECT_WIZARD_LOCK = threading.Lock()

_PROJECT_WIZARD_JOBS: Dict[str, Dict[str, object]] = {}

def _validate_project_name(name: str) -> str:

    name = (name or "").strip()

    if not name:

        raise ValueError("Название проекта обязательно")

    # Avoid weird names for folders/systemd units

    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", name):

        raise ValueError("Недопустимое имя проекта (разрешены: буквы/цифры/._-)")

    if name in {".", ".."}:

        raise ValueError("Недопустимое имя проекта")

    return name

def _wizard_job_log(job_id: str, message: str) -> None:

    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

    line = f"[{ts}] {message}"

    with _PROJECT_WIZARD_LOCK:

        job = _PROJECT_WIZARD_JOBS.get(job_id)

        if not job:

            return

        logs = job.setdefault("logs", [])

        if isinstance(logs, list):

            logs.append(line)

            # cap memory

            if len(logs) > 2500:

                del logs[:-2500]

def _wizard_job_update(job_id: str, **kwargs) -> None:

    with _PROJECT_WIZARD_LOCK:

        job = _PROJECT_WIZARD_JOBS.get(job_id)

        if not job:

            return

        job.update(kwargs)

def _wizard_job_get(job_id: str) -> Optional[Dict[str, object]]:

    with _PROJECT_WIZARD_LOCK:

        job = _PROJECT_WIZARD_JOBS.get(job_id)

        return dict(job) if isinstance(job, dict) else None

def _wizard_create_job() -> Dict[str, object]:

    job_id = uuid.uuid4().hex

    job_dir = PROJECT_WIZARD_TMP_ROOT / job_id

    job_dir.mkdir(parents=True, exist_ok=False)

    job = {

        "id": job_id,

        "status": "created",

        "created_at": datetime.utcnow().isoformat(),

        "tmp_dir": str(job_dir),

        "logs": [],

        "analysis": {},

        "result": {},

        "error": None,

    }

    with _PROJECT_WIZARD_LOCK:

        _PROJECT_WIZARD_JOBS[job_id] = job

    _wizard_job_log(job_id, "Создан новый job")

    return job

def _safe_extract_zip(zip_path: Path, dest_dir: Path) -> None:

    dest_dir = dest_dir.resolve()

    with zipfile.ZipFile(zip_path, "r") as zf:

        infos = zf.infolist()

        for info in infos:

            name = info.filename

            # normalize and prevent absolute paths

            if name.startswith("/") or name.startswith("\\"):

                raise ValueError(f"Unsafe path in zip: {name}")

            target = (dest_dir / name).resolve()

            if not _is_relative_to(target, dest_dir):

                raise ValueError(f"Unsafe path in zip: {name}")

        zf.extractall(path=str(dest_dir))

def _safe_extract_tar(tar_path: Path, dest_dir: Path) -> None:

    dest_dir.mkdir(parents=True, exist_ok=True)

    with tarfile.open(tar_path, "r:*") as tar:

        members = []

        for m in tar.getmembers():

            # skip links/devs

            try:

                if m.issym() or m.islnk() or m.isdev():

                    continue

            except Exception:

                pass

            # allow only files/dirs

            if m.isdir() or m.isreg():

                members.append(m)

        _safe_extract_tar_members(tar, dest_dir, members)

def _detect_project_root(extracted_dir: Path) -> Path:

    """

    Many archives contain a single top-level folder. If so, treat it as project root.

    Also ignore macOS artifacts like __MACOSX.

    """

    try:

        entries = [p for p in extracted_dir.iterdir() if p.name not in {"__MACOSX"} and not p.name.startswith(".")]

    except Exception:

        return extracted_dir

    dirs = [p for p in entries if p.is_dir()]

    files = [p for p in entries if p.is_file()]

    if len(dirs) == 1 and not files:

        return dirs[0]

    return extracted_dir

def _parse_systemd_unit_text(text: str) -> Dict[str, str]:

    out: Dict[str, str] = {}

    for raw_line in (text or "").splitlines():

        line = raw_line.strip()

        if not line or line.startswith("#"):

            continue

        if "=" not in line:

            continue

        key, val = line.split("=", 1)

        key = key.strip()

        val = val.strip()

        if not key:

            continue

        # Keep last value for duplicates (systemd allows repeating keys)

        out[key] = val

    return out

def _extract_port_from_text(text: str) -> Optional[int]:

    if not text:

        return None

    # Environment="PORT=5025" or PORT=5025

    m = re.search(r"\bPORT\s*=\s*([0-9]{2,5})\b", text)

    if m:

        try:

            p = int(m.group(1))

            return p if 1 <= p <= 65535 else None

        except Exception:

            return None

    # os.getenv("PORT", "5000") / os.environ.get("PORT", 5000)

    m = re.search(r"['\"]PORT['\"]\s*,\s*['\"]([0-9]{2,5})['\"]", text)

    if m:

        try:

            p = int(m.group(1))

            return p if 1 <= p <= 65535 else None

        except Exception:

            return None

    m = re.search(r"['\"]PORT['\"]\s*,\s*([0-9]{2,5})\s*\)", text)

    if m:

        try:

            p = int(m.group(1))

            return p if 1 <= p <= 65535 else None

        except Exception:

            return None

    # app.run(... port=5000) / uvicorn.run(... port=8000)

    m = re.search(r"\bport\s*=\s*([0-9]{2,5})\b", text)

    if m:

        try:

            p = int(m.group(1))

            return p if 1 <= p <= 65535 else None

        except Exception:

            return None

    return None

def analyze_project_root(project_root: Path) -> Dict[str, object]:

    analysis: Dict[str, object] = {

        "root": str(project_root),

        "service_files": [],

        "requirements": None,

        "entrypoints": [],

        "suggested_entrypoint": None,

        "port": None,

        "framework": "unknown",

        "unit_suggestions": {},

        "python_candidates": _resolve_python_candidates(),

        "python_bin": None,

    }

    # requirements.txt

    req = project_root / "requirements.txt"

    if req.exists() and req.is_file():

        analysis["requirements"] = "requirements.txt"

    # candidate entrypoints (best-effort)

    candidates: List[str] = []

    seen: set[str] = set()

    def _add(rel: str) -> None:

        rel = (rel or "").strip().lstrip("/")

        if not rel or rel in seen:

            return

        seen.add(rel)

        candidates.append(rel)

    common_names = ("run.py", "app.py", "main.py", "server.py", "wsgi.py", "bot.py", "start.py")

    # 1) common names in root

    for name in common_names:

        p = project_root / name

        if p.exists() and p.is_file():

            _add(name)

    # 2) common names in subfolders (if root not found)

    if not candidates:

        try:

            for name in common_names:

                for p in project_root.rglob(name):

                    if any(part in {"venv", ".venv", "__pycache__", "node_modules"} for part in p.parts):

                        continue

                    if p.exists() and p.is_file():

                        _add(str(p.relative_to(project_root)))

                        break

                if len(candidates) >= 10:

                    break

        except Exception:

            pass

    # 3) fallback: any *.py in root

    if not candidates:

        try:

            for p in sorted(project_root.glob("*.py"))[:10]:

                _add(p.name)

        except Exception:

            pass

    analysis["entrypoints"] = candidates

    if candidates:

        analysis["suggested_entrypoint"] = candidates[0]

    # find *.service inside project (limited search)

    svc_files: List[Path] = []

    try:

        for p in sorted(project_root.rglob("*.service"))[:5]:

            # ignore venv/system stuff

            if any(part in {"venv", ".venv", "__pycache__"} for part in p.parts):

                continue

            svc_files.append(p)

    except Exception:

        svc_files = []

    analysis["service_files"] = [str(p.relative_to(project_root)) if _is_relative_to(p, project_root) else str(p) for p in svc_files]

    # Parse service file for hints (port/user/exec)

    port: Optional[int] = None

    unit_suggestions: Dict[str, object] = {}

    for svc in svc_files:

        try:

            txt = svc.read_text(encoding="utf-8", errors="replace")

        except Exception:

            continue

        info = _parse_systemd_unit_text(txt)

        unit_suggestions = {

            "service_file": str(svc),

            "User": info.get("User", ""),

            "WorkingDirectory": info.get("WorkingDirectory", ""),

            "ExecStart": info.get("ExecStart", ""),

        }

        # port from Environment lines

        p = _extract_port_from_text(txt)

        if p:

            port = p

            break

    # Port from .env (only read PORT line; do not expose secrets)

    if not port:

        for env_name in (".env", "env.example", ".env.example"):

            envp = project_root / env_name

            if not envp.exists() or not envp.is_file():

                continue

            try:

                txt = envp.read_text(encoding="utf-8", errors="replace")

            except Exception:

                continue

            p = _extract_port_from_text(txt)

            if p:

                port = p

                break

    # Port from code (best-effort)

    if not port:

        for ep in candidates[:5]:

            pth = project_root / ep

            try:

                txt = pth.read_text(encoding="utf-8", errors="replace")

            except Exception:

                continue

            p = _extract_port_from_text(txt)

            if p:

                port = p

                break

    analysis["port"] = port

    analysis["unit_suggestions"] = unit_suggestions

    try:

        requested_python = str(unit_suggestions.get("ExecStart") or "").strip().split(" ")[0].strip()

    except Exception:

        requested_python = ""

    analysis["python_bin"] = _pick_python_bin(requested_python)[0]

    # Very rough framework detection

    try:

        if analysis.get("requirements") == "requirements.txt":

            req_txt = (project_root / "requirements.txt").read_text(encoding="utf-8", errors="replace").lower()

            if "flask" in req_txt:

                analysis["framework"] = "flask"

            elif "fastapi" in req_txt:

                analysis["framework"] = "fastapi"

            elif "django" in req_txt:

                analysis["framework"] = "django"

    except Exception:

        pass

    return analysis

def _deploy_project_job(job_id: str, cfg: Dict[str, object]) -> None:

    """Background deployment worker."""

    try:

        _wizard_job_update(job_id, status="deploying", error=None, result={})

        _wizard_job_log(job_id, "Начинаю деплой...")

        job = _wizard_job_get(job_id) or {}

        project_root = Path(str(job.get("project_root") or ""))

        if not project_root.exists() or not project_root.is_dir():

            raise RuntimeError("Нет загруженных файлов проекта (upload шаг не выполнен)")

        project_name = _validate_project_name(str(cfg.get("project_name") or ""))

        dest_dir = PROJECTS_DIR / project_name

        if dest_dir.exists():

            raise RuntimeError(f"Проект уже существует: {dest_dir}")

        requested_python_bin = str(cfg.get("python_bin") or "").strip()

        python_bin, warnings = _pick_python_bin(requested_python_bin)

        use_venv = bool(cfg.get("use_venv") or False)

        hidden = _coerce_bool(cfg.get("hidden"), default=False)

        entrypoint_rel = str(cfg.get("entrypoint") or "").strip().lstrip("/")

        if not entrypoint_rel:

            raise RuntimeError("Не указан entrypoint")

        port = None

        try:

            if cfg.get("port") is not None and str(cfg.get("port")).strip() != "":

                port = int(cfg.get("port"))

        except Exception:

            port = None

        domain = str(cfg.get("domain") or "").strip()

        create_nginx = bool(cfg.get("create_nginx") or False)

        create_ssl = bool(cfg.get("create_ssl") or False)

        email = str(cfg.get("email") or "").strip()

        skip_dns_check = bool(cfg.get("skip_dns_check") or False)

        create_service = bool(cfg.get("create_service") or False)

        enable_autostart = bool(cfg.get("enable_autostart") or False)

        start_service = bool(cfg.get("start_service") or False)

        service_user = str(cfg.get("service_user") or "dream").strip() or "dream"

        service_name = _validate_project_name(str(cfg.get("service_name") or project_name).strip() or project_name)

        install_deps = bool(cfg.get("install_deps") or False)

        requirements_rel = str(cfg.get("requirements") or "requirements.txt").strip().lstrip("/")

        pip_packages = str(cfg.get("pip_packages") or "").strip()

        _wizard_job_log(job_id, f"Проект: {project_name}")

        _wizard_job_log(job_id, f"Папка назначения: {dest_dir}")

        _wizard_job_log(job_id, f"Python: {python_bin}")

        for warning in warnings:

            _wizard_job_log(job_id, f"WARN: {warning}")

        _wizard_job_log(job_id, "Переношу файлы в projects/...")

        dest_dir.parent.mkdir(parents=True, exist_ok=True)

        shutil.move(str(project_root), str(dest_dir))

        entrypoint_path = dest_dir / entrypoint_rel

        if not entrypoint_path.exists() or not entrypoint_path.is_file():

            raise RuntimeError(f"Entrypoint не найден: {entrypoint_path}")

        if service_user and service_user != "root":

            ok, out = safe_run(

                f"chown -R {shlex.quote(service_user)}:{shlex.quote(service_user)} {shlex.quote(str(dest_dir))}",

                timeout=60,

            )

            if ok:

                _wizard_job_log(job_id, "Права на файлы обновлены (chown)")

            else:

                _append_warning(warnings, out or "chown завершился с предупреждением")

                _wizard_job_log(job_id, f"WARN: {warnings[-1]}")

        python_exec = python_bin

        if use_venv:

            venv_dir = dest_dir / "venv"

            _wizard_job_log(job_id, f"Создаю venv: {venv_dir}")

            ok, out = safe_run(f"{shlex.quote(python_bin)} -m venv {shlex.quote(str(venv_dir))}", timeout=120)

            _wizard_job_log(job_id, f"venv: {'OK' if ok else 'FAIL'}")

            if ok:

                python_exec = str(venv_dir / "bin" / "python")

            else:

                use_venv = False

                _append_warning(warnings, out or "Не удалось создать venv, продолжаю на системном Python")

                _wizard_job_log(job_id, f"WARN: {warnings[-1]}")

        if install_deps:

            _wizard_job_log(job_id, "Устанавливаю зависимости...")

            req_path = dest_dir / requirements_rel

            if req_path.exists() and req_path.is_file():

                cmd = f"{shlex.quote(python_exec)} -m pip install -r {shlex.quote(str(req_path))}"

                ok, out = safe_run(cmd, timeout=900)

                _wizard_job_log(job_id, f"pip -r: {'OK' if ok else 'FAIL'}")

                if out:

                    _wizard_job_log(job_id, out[:4000])

                if not ok:

                    _append_warning(warnings, out or "pip install -r завершился с ошибкой")

                    _wizard_job_log(job_id, f"WARN: {warnings[-1]}")

            elif pip_packages:

                try:

                    pkg_parts = shlex.split(pip_packages)

                except Exception:

                    pkg_parts = pip_packages.split()

                pkg_args = " ".join(shlex.quote(p) for p in pkg_parts if str(p).strip())

                if pkg_args:

                    cmd = f"{shlex.quote(python_exec)} -m pip install {pkg_args}"

                    ok, out = safe_run(cmd, timeout=900)

                    _wizard_job_log(job_id, f"pip packages: {'OK' if ok else 'FAIL'}")

                    if out:

                        _wizard_job_log(job_id, out[:4000])

                    if not ok:

                        _append_warning(warnings, out or "pip install завершился с ошибкой")

                        _wizard_job_log(job_id, f"WARN: {warnings[-1]}")

                else:

                    _wizard_job_log(job_id, "pip packages: пусто (пропускаю)")

            else:

                _wizard_job_log(job_id, "Зависимости не указаны (пропускаю)")

        nginx_config_name = None

        if create_nginx:

            if not domain or not port:

                _append_warning(warnings, "Nginx пропущен: для proxy нужны domain и port")

                _wizard_job_log(job_id, f"WARN: {warnings[-1]}")

            else:

                if not skip_dns_check:

                    _wizard_job_log(job_id, "Проверяю DNS...")

                    dns_ok, server_ip, domain_ip, dns_error = check_dns_resolves(domain)

                    if not dns_ok:

                        _append_warning(warnings, dns_error or f"DNS не настроен корректно (server={server_ip}, domain={domain_ip})")

                        _wizard_job_log(job_id, f"WARN: {warnings[-1]}")

                nginx_config_content = f"""server {{

    listen 80;

    server_name {domain} www.{domain};

    location / {{

        proxy_pass http://127.0.0.1:{port};

        proxy_http_version 1.1;

        proxy_set_header Upgrade $http_upgrade;

        proxy_set_header Connection 'upgrade';

        proxy_set_header Host $host;

        proxy_set_header X-Real-IP $remote_addr;

        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;

        proxy_set_header X-Forwarded-Proto $scheme;

        proxy_cache_bypass $http_upgrade;

    }}

}}"""

                nginx_config_name = domain if domain.endswith((".conf", ".online", ".ru")) else (domain + ".conf")

                cfg_path = NGINX_SITES_DIR / nginx_config_name

                _wizard_job_log(job_id, f"Пишу nginx конфиг: {cfg_path}")

                cfg_path.write_text(nginx_config_content, encoding="utf-8")

                ok, out = safe_run("nginx -t", timeout=15)

                if not ok:

                    try:

                        cfg_path.unlink()

                    except Exception:

                        pass

                    nginx_config_name = None

                    _append_warning(warnings, out or "nginx -t завершился ошибкой, конфиг откатан")

                    _wizard_job_log(job_id, f"WARN: {warnings[-1]}")

                else:

                    safe_run("systemctl reload nginx", timeout=15)

                    _wizard_job_log(job_id, "Nginx: OK (reload)")

                    if create_ssl:

                        _wizard_job_log(job_id, "SSL: запускаю certbot...")

                        default_email = (os.environ.get("CERTBOT_DEFAULT_EMAIL", "") or "").strip()

                        email_to_use = email or default_email

                        if email_to_use:

                            cmd = (

                                f"certbot certonly --nginx -d {shlex.quote(domain)} "

                                f"--email {shlex.quote(email_to_use)} --agree-tos --non-interactive"

                            )

                        else:

                            cmd = (

                                f"certbot certonly --nginx -d {shlex.quote(domain)} "

                                "--register-unsafely-without-email --agree-tos --non-interactive"

                            )

                        ok, out = safe_run(cmd, timeout=240)

                        _wizard_job_log(job_id, f"certbot: {'OK' if ok else 'FAIL'}")

                        if ok:

                            safe_run("systemctl reload nginx", timeout=15)

                            _wizard_job_log(job_id, "Nginx: reload после SSL")

                        else:

                            _append_warning(warnings, out or "Certbot не выпустил сертификат")

                            _wizard_job_log(job_id, f"WARN: {warnings[-1]}")

        created_service_unit = None

        if create_service:

            unit = service_name if service_name.endswith(".service") else (service_name + ".service")

            service_path = SYSTEMD_DIR / unit

            if service_path.exists():

                _append_warning(warnings, f"systemd unit уже существует: {service_path}")

                _wizard_job_log(job_id, f"WARN: {warnings[-1]}")

                created_service_unit = unit

            else:

                created_service_unit = unit

                env_port_line = f'Environment="PORT={int(port)}"' if port else ""

                env_file_line = f"EnvironmentFile=-{dest_dir}/.env"

                content = f"""[Unit]

Description={project_name} (created by admin panel)

After=network.target

[Service]

Type=simple

User={service_user}

WorkingDirectory={dest_dir}

Environment="PYTHONUNBUFFERED=1"

{env_port_line}

{env_file_line}

ExecStart={python_exec} {entrypoint_path}

Restart=always

RestartSec=5

LimitNOFILE=2048

LimitNPROC=512

MemoryMax=2G

StandardOutput=journal

StandardError=journal

[Install]

WantedBy=multi-user.target

"""

                content = "\n".join([ln for ln in content.splitlines() if ln.strip() != ""])

                service_path.write_text(content + "\n", encoding="utf-8")

                ok, out = safe_run("systemctl daemon-reload", timeout=20)

                if not ok:

                    try:

                        service_path.unlink()

                    except Exception:

                        pass

                    safe_run("systemctl daemon-reload", timeout=20)

                    raise RuntimeError(f"daemon-reload: {out}")

                _wizard_job_log(job_id, "systemd: daemon-reload OK")

                if enable_autostart:

                    ok, out = safe_run(f"systemctl enable {shlex.quote(unit)}", timeout=20)

                    if ok:

                        _wizard_job_log(job_id, "systemd: enable OK")

                    else:

                        _append_warning(warnings, out or f"Не удалось включить autostart для {unit}")

                        _wizard_job_log(job_id, f"WARN: {warnings[-1]}")

                if start_service:

                    ok, out = safe_run(f"systemctl restart {shlex.quote(unit)}", timeout=30)

                    if ok:

                        _wizard_job_log(job_id, "systemd: restart OK")

                        _, active_out = safe_run(f"systemctl is-active {shlex.quote(unit)}", timeout=10)

                        _wizard_job_log(job_id, f"is-active: {active_out}")

                    else:

                        _append_warning(warnings, out or f"Не удалось запустить {unit}")

                        _wizard_job_log(job_id, f"WARN: {warnings[-1]}")

        now_iso = datetime.utcnow().isoformat()

        _write_project_marker(dest_dir, {

            "name": project_name,

            "created_at": now_iso,

            "updated_at": now_iso,

            "domain": domain or None,

            "port": port,

            "service": created_service_unit,

            "entrypoint": entrypoint_rel,

            "python_bin": python_bin,

            "use_venv": use_venv,

            "nginx_config": nginx_config_name,

            "hidden": hidden,

            "visible_in_catalogs": not hidden,

            "warnings": warnings,

        })

        _wizard_job_log(job_id, "Готово" if not warnings else f"Готово с предупреждениями: {len(warnings)}")

        _wizard_job_update(job_id, status="done", result={

            "project_name": project_name,

            "project_path": str(dest_dir),

            "domain": domain or None,

            "port": port,

            "service": created_service_unit,

            "nginx_config": nginx_config_name,

            "python_bin": python_bin,

            "warnings": warnings,

        })

    except Exception as e:

        _wizard_job_log(job_id, f"Ошибка: {e}")

        _wizard_job_update(job_id, status="error", error=str(e))

@app.route("/api/projects/wizard/job", methods=["POST"])



def api_projects_wizard_create_job():

    job = _wizard_create_job()

    return jsonify({"success": True, "job_id": job["id"]})

@app.route("/api/projects/wizard/job/<job_id>", methods=["GET"])



def api_projects_wizard_job_status(job_id: str):

    job = _wizard_job_get(job_id)

    if not job:

        return jsonify({"success": False, "error": "Job not found"}), 404

    # Only return safe fields

    return jsonify({

        "success": True,

        "job_id": job.get("id"),

        "status": job.get("status"),

        "created_at": job.get("created_at"),

        "logs": job.get("logs", []),

        "analysis": job.get("analysis", {}),

        "result": job.get("result", {}),

        "error": job.get("error"),

    })

@app.route("/api/projects/wizard/job/<job_id>/upload", methods=["POST"])



def api_projects_wizard_upload(job_id: str):

    job = _wizard_job_get(job_id)

    if not job:

        return jsonify({"success": False, "error": "Job not found"}), 404

    if "archive" not in request.files:

        return jsonify({"success": False, "error": "archive file is required"}), 400

    f = request.files["archive"]

    if not f or not getattr(f, "filename", ""):

        return jsonify({"success": False, "error": "empty filename"}), 400

    tmp_dir = Path(str(job.get("tmp_dir") or ""))

    if not tmp_dir.exists():

        return jsonify({"success": False, "error": "job temp dir missing"}), 500

    filename = secure_filename(f.filename)

    archive_path = tmp_dir / filename

    extracted_dir = tmp_dir / "extracted"

    # Reset extracted dir to avoid mixing multiple uploads in the same job

    try:

        if extracted_dir.exists():

            shutil.rmtree(extracted_dir)

    except Exception:

        pass

    extracted_dir.mkdir(parents=True, exist_ok=True)

    try:

        _wizard_job_log(job_id, f"Загружаю архив: {filename}")

        f.save(str(archive_path))

        lower = filename.lower()

        _wizard_job_log(job_id, "Распаковываю…")

        if lower.endswith(".zip"):

            _safe_extract_zip(archive_path, extracted_dir)

        elif lower.endswith(".tar") or lower.endswith(".tar.gz") or lower.endswith(".tgz"):

            _safe_extract_tar(archive_path, extracted_dir)

        else:

            return jsonify({"success": False, "error": "Поддерживаются только .zip / .tar.gz / .tgz / .tar"}), 400

        project_root = _detect_project_root(extracted_dir)

        analysis = analyze_project_root(project_root)

        _wizard_job_update(job_id, status="uploaded", extracted_dir=str(extracted_dir), project_root=str(project_root), analysis=analysis)

        _wizard_job_log(job_id, "Файлы загружены и распакованы")

        return jsonify({"success": True, "analysis": analysis})

    except Exception as e:

        _wizard_job_update(job_id, status="error", error=str(e))

        _wizard_job_log(job_id, f"Upload error: {e}")

        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/projects/wizard/job/<job_id>/deploy", methods=["POST"])



def api_projects_wizard_deploy(job_id: str):

    job = _wizard_job_get(job_id)

    if not job:

        return jsonify({"success": False, "error": "Job not found"}), 404

    cfg = request.json or {}

    # start background worker

    t = threading.Thread(target=_deploy_project_job, args=(job_id, cfg), daemon=True)

    t.start()

    _wizard_job_log(job_id, "Deploy запущен в фоне")

    return jsonify({"success": True})

# Системные папки в /var/www, которые НЕ считаются сайтами

WWW_SYSTEM_FOLDERS = {

    'errors', 'html', 'cgi-bin', 'logs', 'tmp', 'temp', 'backup', 'backups',

    'old', 'old_files', 'test', 'tests', 'dev', 'development', 'staging',

    'cache', 'tmp', 'temp', '.git', '.svn', '.hg',

}

PANEL_SITE_MARKER = '.panel_site.json'

def _is_domain_like(name: str) -> bool:

    """Лёгкая проверка, что папка похожа на домен (dreampartners.online)."""

    n = (name or '').strip()

    if '.' not in n:

        return False

    if len(n) > 253 or len(n) < 3:

        return False

    if n.startswith('.') or n.endswith('.') or '..' in n:

        return False

    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-.")

    if any(ch not in allowed for ch in n):

        return False

    return True

def is_real_site(folder_name: str, folder_path: Path) -> bool:

    """

    Проверяет, является ли папка реальным сайтом (не системной).

    Критерии:

    1. Не в списке системных папок

    2. Имеет marker от панели ИЛИ nginx конфиг

    3. Либо (для старых/ручных) похожа на домен и содержит index.*

    """

    if folder_name.lower() in WWW_SYSTEM_FOLDERS:

        return False

    # marker от панели управления

    try:

        if (folder_path / PANEL_SITE_MARKER).exists():

            return True

    except Exception:

        pass

    # Проверяем наличие nginx конфига для этого домена

    for ext in ['.conf', '.online', '.ru']:

        config_name = folder_name + ext

        if (NGINX_SITES_DIR / config_name).exists():

            return True

    # Если не похоже на домен — не считаем сайтом (решает проблему errors/html и т.п.)

    if not _is_domain_like(folder_name):

        return False

    # Проверяем наличие index файлов (признак сайта)

    index_files = ['index.html', 'index.php', 'index.htm', 'index.py', 'app.py', 'server.py']

    for idx_file in index_files:

        if (folder_path / idx_file).exists():

            return True

    return False

@app.route('/api/www')



def api_www():

    """API: Список сайтов в /var/www (только реальные сайты, не системные папки)."""

    sites = []

    if WWW_DIR.exists():

        for item in WWW_DIR.iterdir():

            if item.is_dir() and not item.name.startswith('.') and is_real_site(item.name, item):

                sites.append({

                    'name': item.name,

                    'path': str(item),

                    'size': sum(f.stat().st_size for f in item.rglob('*') if f.is_file()),

                })

    return jsonify(sites)

@app.route('/api/nginx')



def api_nginx():

    """API: Список nginx конфигов."""

    configs = []

    if NGINX_SITES_DIR.exists():

        for config_file in NGINX_SITES_DIR.iterdir():

            if config_file.is_file():

                try:

                    content = config_file.read_text(encoding="utf-8")

                    # Извлекаем server_name

                    server_names = []

                    for line in content.splitlines():

                        if 'server_name' in line and not line.strip().startswith('#'):

                            parts = line.split('server_name')[1].strip().rstrip(';').split()

                            server_names.extend(parts)

                    configs.append({

                        'name': config_file.name,

                        'path': str(config_file),

                        'server_names': server_names,

                        'size': config_file.stat().st_size,

                    })

                except:

                    pass

    return jsonify(configs)

@app.route('/api/nginx/reload', methods=['POST'])



def api_nginx_reload():

    """API: Перезагрузка nginx."""

    ok, output = safe_run("nginx -t", timeout=10)

    if not ok:

        return jsonify({'success': False, 'error': f'Ошибка конфигурации: {output}'}), 400

    ok, output = safe_run("systemctl reload nginx", timeout=10)

    if ok:

        return jsonify({'success': True})

    else:

        return jsonify({'success': False, 'error': output}), 500

@app.route('/api/nginx/config/<name>', methods=['GET'])



def api_nginx_get_config(name):

    """API: Получение содержимого nginx конфига."""

    config_path = NGINX_SITES_DIR / name

    if not config_path.exists() or not config_path.is_file():

        return jsonify({'error': 'Конфиг не найден'}), 404

    try:

        content = config_path.read_text(encoding="utf-8")

        return jsonify({'name': name, 'content': content})

    except Exception as e:

        return jsonify({'error': str(e)}), 500

@app.route('/api/nginx/config', methods=['POST'])



def api_nginx_create_config():

    """API: Создание нового nginx конфига."""

    data = request.json

    name = data.get('name', '').strip()

    content = data.get('content', '')

    if not name:

        return jsonify({'success': False, 'error': 'Имя конфига обязательно'}), 400

    if not name.endswith('.conf') and not name.endswith('.online') and not name.endswith('.ru'):

        name = name + '.conf'

    config_path = NGINX_SITES_DIR / name

    try:

        config_path.write_text(content, encoding="utf-8")

        # Проверяем конфиг

        ok, output = safe_run("nginx -t", timeout=10)

        if not ok:

            config_path.unlink()  # Удаляем если ошибка

            return jsonify({'success': False, 'error': f'Ошибка конфигурации: {output}'}), 400

        return jsonify({'success': True, 'name': name})

    except Exception as e:

        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/nginx/config/<name>', methods=['PUT'])



def api_nginx_update_config(name):

    """API: Обновление nginx конфига."""

    config_path = NGINX_SITES_DIR / name

    if not config_path.exists():

        return jsonify({'error': 'Конфиг не найден'}), 404

    data = request.json

    content = data.get('content', '')

    try:

        # Сохраняем старую версию

        backup_path = config_path.with_suffix(config_path.suffix + '.backup')

        config_path.rename(backup_path)

        # Записываем новую

        config_path = NGINX_SITES_DIR / name

        config_path.write_text(content, encoding="utf-8")

        # Проверяем конфиг

        ok, output = safe_run("nginx -t", timeout=10)

        if not ok:

            # Восстанавливаем из backup

            config_path.unlink()

            backup_path.rename(config_path)

            return jsonify({'success': False, 'error': f'Ошибка конфигурации: {output}'}), 400

        # Удаляем backup если успешно

        backup_path.unlink()

        return jsonify({'success': True})

    except Exception as e:

        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/nginx/config/<name>', methods=['DELETE'])



def api_nginx_delete_config(name):

    """API: Удаление nginx конфига."""

    config_path = NGINX_SITES_DIR / name

    if not config_path.exists():

        return jsonify({'error': 'Конфиг не найден'}), 404

    try:

        config_path.unlink()

        # Проверяем конфиг

        ok, output = safe_run("nginx -t", timeout=10)

        if not ok:

            return jsonify({'success': False, 'error': f'Ошибка после удаления: {output}'}), 400

        return jsonify({'success': True})

    except Exception as e:

        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/nginx/enable/<name>', methods=['POST'])



def api_nginx_enable(name):

    """API: Включение nginx конфига (создание симлинка)."""

    config_path = NGINX_SITES_DIR / name

    if not config_path.exists():

        return jsonify({'error': 'Конфиг не найден'}), 404

    # Если уже включен (не симлинк), то ничего не делаем

    if config_path.is_file() and not config_path.is_symlink():

        return jsonify({'success': True, 'message': 'Уже включен'})

    return jsonify({'success': True})

@app.route('/api/nginx/disable/<name>', methods=['POST'])



def api_nginx_disable(name):

    """API: Отключение nginx конфига (удаление симлинка)."""

    config_path = NGINX_SITES_DIR / name

    if not config_path.exists():

        return jsonify({'error': 'Конфиг не найден'}), 404

    # Если это симлинк, удаляем его

    if config_path.is_symlink():

        config_path.unlink()

        return jsonify({'success': True})

    return jsonify({'success': True, 'message': 'Не является симлинком'})

def _safe_extract_tar_members(tar: tarfile.TarFile, dest_dir: Path, members) -> None:

    """Safely extract tar members into dest_dir (prevents path traversal)."""

    dest_dir = dest_dir.resolve()

    for m in members:

        # Normalize and validate

        target = (dest_dir / m.name).resolve()

        if not _is_relative_to(target, dest_dir):

            raise ValueError(f"Unsafe path in archive: {m.name}")

    tar.extractall(path=str(dest_dir), members=members)

def install_wordpress_to(site_path: Path) -> Tuple[bool, str]:

    """Download and extract WordPress into site_path."""

    url = "https://wordpress.org/latest.tar.gz"

    tmp_path: Optional[Path] = None

    try:

        with urllib.request.urlopen(url, timeout=60) as resp:

            with tempfile.NamedTemporaryFile(delete=False) as tmp:

                shutil.copyfileobj(resp, tmp)

                tmp_path = Path(tmp.name)

        with tarfile.open(tmp_path, "r:gz") as tar:

            members = []

            prefix = "wordpress/"

            for m in tar.getmembers():

                if not m.name.startswith(prefix):

                    continue

                new_name = m.name[len(prefix):].lstrip("/").lstrip("\\")

                if not new_name:

                    continue

                m.name = new_name

                members.append(m)

            _safe_extract_tar_members(tar, site_path, members)

        return True, "WordPress extracted"

    except Exception as e:

        return False, str(e)

    finally:

        if tmp_path:

            try:

                tmp_path.unlink()

            except Exception:

                pass

@app.route('/api/www/check-dns', methods=['POST'])



def api_www_check_dns():

    """API: Проверка DNS для домена."""

    data = request.json

    domain = (data.get('domain') or '').strip()

    if not domain:

        return jsonify({'success': False, 'error': 'Домен обязателен'}), 400

    ok, server_ip, domain_ip, error = check_dns_resolves(domain)

    return jsonify({

        'success': ok,

        'server_ip': server_ip,

        'domain_ip': domain_ip,

        'error': error,

        'message': 'Домен указывает на этот сервер' if ok else error,

    })

@app.route('/api/www/site', methods=['POST'])



def api_www_create_site():

    """API: Создание нового сайта в /var/www с опциональным nginx конфигом и SSL."""

    data = request.json

    name = data.get('name', '').strip()

    create_nginx = data.get('create_nginx', False)

    create_ssl = data.get('create_ssl', False)

    nginx_config = data.get('nginx_config', '')

    email = data.get('email', '')

    site_type = data.get('type', 'static') # static, php, wordpress, node, python

    port = data.get('port', 3000) # для node/python

    skip_dns_check = data.get('skip_dns_check', False)  # для тестов/локальных доменов

    if not name:

        return jsonify({'success': False, 'error': 'Имя сайта обязательно'}), 400

    # Проверка DNS (опционально, можно пропустить)

    if not skip_dns_check:

        dns_ok, server_ip, domain_ip, dns_error = check_dns_resolves(name)

        if not dns_ok:

            return jsonify({

                'success': False,

                'error': dns_error or 'DNS не настроен',

                'dns_check': {

                    'server_ip': server_ip,

                    'domain_ip': domain_ip,

                    'ok': False,

                }

            }), 400

    site_path = WWW_DIR / name

    if site_path.exists():

        return jsonify({'success': False, 'error': 'Сайт уже существует'}), 400

    try:

        # Создаем директорию сайта

        site_path.mkdir(parents=True, exist_ok=True)

        # Создаем красивый index.html с информацией о настройке

        index_file = site_path / 'index.html'

        if not index_file.exists():

            welcome_html = f"""<!DOCTYPE html>

<html lang="ru">

<head>

    <meta charset="UTF-8">

    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title>{name} - Сайт настроен</title>

    <style>

        * {{ margin: 0; padding: 0; box-sizing: border-box; }}

        body {{

            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;

            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);

            min-height: 100vh;

            display: flex;

            align-items: center;

            justify-content: center;

            padding: 20px;

        }}

        .container {{

            background: white;

            border-radius: 20px;

            padding: 40px;

            max-width: 600px;

            width: 100%;

            box-shadow: 0 20px 60px rgba(0,0,0,0.3);

            text-align: center;

        }}

        .icon {{

            font-size: 64px;

            margin-bottom: 20px;

        }}

        h1 {{

            color: #333;

            margin-bottom: 10px;

            font-size: 32px;

        }}

        .domain {{

            color: #667eea;

            font-weight: 600;

            font-size: 24px;

            margin-bottom: 20px;

        }}

        .status {{

            background: #e8f5e9;

            color: #2e7d32;

            padding: 12px 24px;

            border-radius: 8px;

            display: inline-block;

            margin-bottom: 30px;

            font-weight: 500;

        }}

        .info {{

            background: #f5f5f5;

            padding: 20px;

            border-radius: 12px;

            margin-top: 20px;

            text-align: left;

        }}

        .info-item {{

            margin: 10px 0;

            color: #666;

        }}

        .info-item strong {{

            color: #333;

        }}

        .actions {{

            margin-top: 30px;

            padding-top: 20px;

            border-top: 1px solid #eee;

        }}

        .actions p {{

            color: #666;

            font-size: 14px;

            margin-top: 10px;

        }}

    </style>

</head>

<body>

    <div class="container">

        <div class="icon">вњ…</div>

        <h1>Сайт настроен</h1>

        <div class="domain">{name}</div>

        <div class="status">✓ Готов к работе</div>

        <div class="info">

            <div class="info-item"><strong>Тип:</strong> {site_type}</div>

            <div class="info-item"><strong>Директория:</strong> {site_path}</div>

            <div class="info-item"><strong>Статус:</strong> Сайт успешно создан и настроен</div>

        </div>

        <div class="actions">

            <p>Вы можете редактировать файлы в директории сайта через панель управления.</p>

        </div>

    </div>

</body>

</html>"""

            index_file.write_text(welcome_html, encoding="utf-8")

        result = {'success': True, 'path': str(site_path), 'steps': []}

        result['steps'].append('Директория создана')

        # Маркер панели (чтобы отличать реальные сайты от служебных папок)

        try:

            marker = site_path / PANEL_SITE_MARKER

            if not marker.exists():

                marker.write_text(

                    json.dumps(

                        {

                            "domain": name,

                            "created_at": datetime.utcnow().isoformat() + "Z",

                            "type": site_type,

                            "create_nginx": bool(create_nginx),

                            "create_ssl": bool(create_ssl),

                        },

                        ensure_ascii=False,

                        indent=2,

                    ),

                    encoding="utf-8",

                )

        except Exception:

            pass

        # Optional: install WordPress files

        if site_type == 'wordpress':

            ok_wp, msg = install_wordpress_to(site_path)

            if not ok_wp:

                try:

                    shutil.rmtree(site_path)

                except Exception:

                    pass

                return jsonify({'success': False, 'error': f'Ошибка установки WordPress: {msg}'}), 500

            result['steps'].append('WordPress файлы установлены')

        # Создаем nginx конфиг если нужно

        if create_nginx:

            if nginx_config:

                config_content = nginx_config

            else:

                # Генерация конфига в зависимости от типа

                if site_type in ('php', 'wordpress'):

                    config_content = f"""server {{

    listen 80;

    server_name {name} www.{name};

    root {site_path};

    index index.php index.html index.htm;

    location / {{

        try_files $uri $uri/ =404;

    }}

    location ~ \\.php$ {{

        include snippets/fastcgi-php.conf;

        fastcgi_pass unix:/var/run/php/php8.1-fpm.sock; # Adjust version as needed

    }}

}}"""

                elif site_type in ['node', 'python']:

                    config_content = f"""server {{

    listen 80;

    server_name {name} www.{name};

    location / {{

        proxy_pass http://127.0.0.1:{port};

        proxy_http_version 1.1;

        proxy_set_header Upgrade $http_upgrade;

        proxy_set_header Connection 'upgrade';

        proxy_set_header Host $host;

        proxy_cache_bypass $http_upgrade;

    }}

}}"""

                else: # static

                    config_content = f"""server {{

    listen 80;

    server_name {name} www.{name};

    root {site_path};

    index index.html;

    location / {{

        try_files $uri $uri/ =404;

    }}

}}"""

            config_name = name if name.endswith(('.conf', '.online', '.ru')) else name + '.conf'

            config_path = NGINX_SITES_DIR / config_name

            config_path.write_text(config_content, encoding="utf-8")

            # Проверяем конфиг

            ok, output = safe_run("nginx -t", timeout=10)

            if not ok:

                config_path.unlink()

                return jsonify({'success': False, 'error': f'Ошибка nginx конфига: {output}'}), 400

            # Перезагружаем nginx

            safe_run("systemctl reload nginx", timeout=10)

            result['steps'].append('Nginx конфиг создан и загружен')

            # Получаем SSL если нужно

            if create_ssl:

                email = (email or "").strip()

                default_email = (os.environ.get("CERTBOT_DEFAULT_EMAIL", "") or "").strip()

                email_to_use = email or default_email

                if email_to_use:

                    cmd = (

                        f"certbot certonly --nginx -d {shlex.quote(name)} "

                        f"--email {shlex.quote(email_to_use)} --agree-tos --non-interactive"

                    )

                else:

                    # email не обязателен — используем небезопасную регистрацию без email (по запросу)

                    cmd = (

                        f"certbot certonly --nginx -d {shlex.quote(name)} "

                        "--register-unsafely-without-email --agree-tos --non-interactive"

                    )

                ok, output = safe_run(cmd, timeout=120)

                if ok:

                    result['steps'].append('SSL сертификат получен')

                else:

                    result['steps'].append(f'Ошибка получения SSL: {output}')

        return jsonify(result)

    except Exception as e:

        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/www/site/<name>', methods=['DELETE'])



def api_www_delete_site(name):

    """API: Удаление сайта из /var/www."""

    site_path = WWW_DIR / name

    if not site_path.exists():

        return jsonify({'error': 'Сайт не найден'}), 404

    try:

        shutil.rmtree(site_path)

        return jsonify({'success': True})

    except Exception as e:

        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/www/site/<name>/enable', methods=['POST'])



def api_www_enable_site(name):

    """API: Включение сайта (создание/включение nginx конфига)."""

    # Ищем соответствующий nginx конфиг

    config_name = name

    if not config_name.endswith(('.conf', '.online', '.ru')):

        # Пробуем найти конфиг с таким доменом

        for ext in ['.conf', '.online', '.ru']:

            test_name = name + ext

            if (NGINX_SITES_DIR / test_name).exists():

                config_name = test_name

                break

    config_path = NGINX_SITES_DIR / config_name

    if not config_path.exists():

        return jsonify({'success': False, 'error': 'Nginx конфиг не найден'}), 404

    # Если это симлинк, значит уже включен

    if config_path.is_symlink():

        return jsonify({'success': True, 'message': 'Уже включен'})

    # Проверяем nginx конфиг

    ok, output = safe_run("nginx -t", timeout=10)

    if not ok:

        return jsonify({'success': False, 'error': f'Ошибка конфигурации: {output}'}), 400

    return jsonify({'success': True, 'message': 'Сайт включен'})

@app.route('/api/www/site/<name>/disable', methods=['POST'])



def api_www_disable_site(name):

    """API: Отключение сайта (отключение nginx конфига)."""

    # Ищем соответствующий nginx конфиг

    config_name = name

    if not config_name.endswith(('.conf', '.online', '.ru')):

        for ext in ['.conf', '.online', '.ru']:

            test_name = name + ext

            if (NGINX_SITES_DIR / test_name).exists():

                config_name = test_name

                break

    config_path = NGINX_SITES_DIR / config_name

    if not config_path.exists():

        return jsonify({'success': False, 'error': 'Nginx конфиг не найден'}), 404

    # Если это симлинк, удаляем его

    if config_path.is_symlink():

        config_path.unlink()

        # Проверяем nginx

        ok, output = safe_run("nginx -t", timeout=10)

        if not ok:

            return jsonify({'success': False, 'error': f'Ошибка после отключения: {output}'}), 400

        return jsonify({'success': True, 'message': 'Сайт отключен'})

    return jsonify({'success': True, 'message': 'Не является симлинком'})

@app.route('/api/certbot/obtain', methods=['POST'])



def api_certbot_obtain():

    """API: Получение SSL сертификата через certbot."""

    data = request.json

    domain = data.get('domain', '').strip()

    email = data.get('email', '').strip()

    if not domain:

        return jsonify({'success': False, 'error': 'Домен обязателен'}), 400

    try:

        # Запускаем certbot

        email = (email or "").strip()

        default_email = (os.environ.get("CERTBOT_DEFAULT_EMAIL", "") or "").strip()

        email_to_use = email or default_email

        if email_to_use:

            cmd = (

                f"certbot certonly --nginx -d {shlex.quote(domain)} "

                f"--email {shlex.quote(email_to_use)} --agree-tos --non-interactive"

            )

        else:

            cmd = (

                f"certbot certonly --nginx -d {shlex.quote(domain)} "

                "--register-unsafely-without-email --agree-tos --non-interactive"

            )

        ok, output = safe_run(cmd, timeout=120)

        if ok:

            return jsonify({'success': True, 'message': 'Сертификат успешно получен', 'output': output})

        else:

            return jsonify({'success': False, 'error': output}), 500

    except Exception as e:

        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/certbot/renew', methods=['POST'])



def api_certbot_renew():

    """API: Обновление всех SSL сертификатов."""

    try:

        ok, output = safe_run("certbot renew --quiet", timeout=300)

        if ok:

            return jsonify({'success': True, 'message': 'Сертификаты обновлены', 'output': output})

        else:

            return jsonify({'success': False, 'error': output}), 500

    except Exception as e:

        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/certbot/list', methods=['GET'])



def api_certbot_list():

    """API: Список всех SSL сертификатов."""

    certs = []

    certs_dir = Path('/etc/letsencrypt/live')

    if certs_dir.exists():

        for cert_dir in certs_dir.iterdir():

            if cert_dir.is_dir() and not cert_dir.name.startswith('.'):

                cert_file = cert_dir / 'fullchain.pem'

                if cert_file.exists():

                    try:

                        stat = cert_file.stat()

                        certs.append({

                            'domain': cert_dir.name,

                            'path': str(cert_dir),

                            'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),

                        })

                    except:

                        pass

    return jsonify({'certificates': certs})

@app.route('/api/systemd/service', methods=['POST'])



def api_systemd_create_service():

    """API: Создание нового systemd сервиса."""

    data = request.json

    name = data.get('name', '').strip()

    description = data.get('description', '')

    exec_start = data.get('exec_start', '')

    working_directory = data.get('working_directory', '')

    user = data.get('user', 'root')

    restart = data.get('restart', 'always')

    if not name or not exec_start:

        return jsonify({'success': False, 'error': 'Имя и ExecStart обязательны'}), 400

    if not name.endswith('.service'):

        name = name + '.service'

    service_path = SYSTEMD_DIR / name

    if service_path.exists():

        return jsonify({'success': False, 'error': 'Сервис уже существует'}), 400

    try:

        content = f"""[Unit]

Description={description or name}

After=network.target

[Service]

Type=simple

User={user}

WorkingDirectory={working_directory or '/'}

ExecStart={exec_start}

Restart={restart}

RestartSec=5

StandardOutput=journal

StandardError=journal

[Install]

WantedBy=multi-user.target

"""

        service_path.write_text(content, encoding="utf-8")

        # Перезагружаем systemd

        ok, output = safe_run("systemctl daemon-reload", timeout=10)

        if not ok:

            service_path.unlink()

            return jsonify({'success': False, 'error': f'Ошибка daemon-reload: {output}'}), 500

        return jsonify({'success': True, 'name': name})

    except Exception as e:

        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/systemd/service/<name>', methods=['DELETE'])



def api_systemd_delete_service(name):

    """API: Удаление systemd сервиса."""

    if not name.endswith('.service'):

        name = name + '.service'

    service_path = SYSTEMD_DIR / name

    if not service_path.exists():

        return jsonify({'error': 'Сервис не найден'}), 404

    if name in SYSTEM_SERVICES:

        return jsonify({'error': 'Нельзя удалить системный сервис'}), 403

    try:

        # Останавливаем и отключаем сервис

        safe_run(f"systemctl stop {shlex.quote(name)}", timeout=10)

        safe_run(f"systemctl disable {shlex.quote(name)}", timeout=10)

        # Удаляем файл

        service_path.unlink()

        # Перезагружаем systemd

        safe_run("systemctl daemon-reload", timeout=10)

        return jsonify({'success': True})

    except Exception as e:

        return jsonify({'success': False, 'error': str(e)}), 500

# ==================== File Manager Routes ====================

@app.route('/api/files/list', methods=['GET'])



def api_files_list():

    """List files and directories."""

    req_path = request.args.get('path', str(WWW_DIR))

    try:

        abs_path = _resolve_read_path(req_path)

        if not abs_path.exists():

            return jsonify({'error': 'Path does not exist'}), 404

        if not abs_path.is_dir():

            return jsonify({'error': 'Not a directory'}), 400

        items = []

        for item in abs_path.iterdir():

            try:

                stat = item.stat()

                items.append({

                    'name': item.name,

                    'path': str(item),

                    'is_dir': item.is_dir(),

                    'size': stat.st_size,

                    'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),

                    'permissions': oct(stat.st_mode)[-3:],

                    'is_symlink': item.is_symlink(),

                })

            except PermissionError:

                continue # Skip files we can't read

        # Sort: directories first, then files

        items.sort(key=lambda x: (not x['is_dir'], x['name'].lower()))

        parent_path = None

        try:

            parent = abs_path.parent

            if parent != abs_path and _is_read_allowed_path(parent):

                parent_path = str(parent)

        except Exception:

            parent_path = None

        return jsonify({

            'current_path': str(abs_path),

            'parent_path': parent_path,

            'items': items

        })

    except PermissionError as e:

        return jsonify({'error': str(e) or 'Доступ запрещен'}), 403

    except Exception as e:

        return jsonify({'error': str(e)}), 500

@app.route('/api/files/create_folder', methods=['POST'])



def api_files_create_folder():

    """Create a new folder."""

    data = request.json

    path = data.get('path')

    name = data.get('name')

    if not path or not name:

        return jsonify({'error': 'Path and name are required'}), 400

    try:

        name = _validate_entry_name(name)

        base_dir = _resolve_write_path(path)

        if not base_dir.exists() or not base_dir.is_dir():

            return jsonify({'error': 'Not a directory'}), 400

        new_folder_path = (base_dir / name)

        # Ensure target stays in allowed roots (handles traversal like ../)

        if not _is_write_allowed_path(new_folder_path):

            return jsonify({'error': 'Доступ запрещен'}), 403

        new_folder_path.mkdir(exist_ok=False)

        return jsonify({'success': True})

    except FileExistsError:

        return jsonify({'error': 'Folder already exists'}), 400

    except PermissionError as e:

        return jsonify({'error': str(e) or 'Доступ запрещен'}), 403

    except Exception as e:

        return jsonify({'error': str(e)}), 500

@app.route('/api/files/create_file', methods=['POST'])



def api_files_create_file():

    """Create a new empty file."""

    data = request.json

    path = data.get('path')

    name = data.get('name')

    if not path or not name:

        return jsonify({'error': 'Path and name are required'}), 400

    try:

        name = _validate_entry_name(name)

        base_dir = _resolve_write_path(path)

        if not base_dir.exists() or not base_dir.is_dir():

            return jsonify({'error': 'Not a directory'}), 400

        new_file_path = (base_dir / name)

        if not _is_write_allowed_path(new_file_path):

            return jsonify({'error': 'Доступ запрещен'}), 403

        new_file_path.touch(exist_ok=False)

        return jsonify({'success': True})

    except FileExistsError:

        return jsonify({'error': 'File already exists'}), 400

    except PermissionError as e:

        return jsonify({'error': str(e) or 'Доступ запрещен'}), 403

    except Exception as e:

        return jsonify({'error': str(e)}), 500

@app.route('/api/files/content', methods=['GET'])



def api_files_get_content():

    """Get file content."""

    path = request.args.get('path')

    if not path:

        return jsonify({'error': 'Path is required'}), 400

    try:

        file_path = _resolve_read_path(path)

        if not file_path.is_file():

            return jsonify({'error': 'Not a file'}), 400

        try:

            size = file_path.stat().st_size

            if size > MAX_EDITOR_BYTES:

                return jsonify({'error': f'Файл слишком большой для редактора ({size} bytes). Скачайте его.'}), 400

        except Exception:

            pass

        # Read text content

        content = file_path.read_text(encoding='utf-8', errors='replace')

        return jsonify({'content': content})

    except PermissionError as e:

        return jsonify({'error': str(e) or 'Доступ запрещен'}), 403

    except Exception as e:

        return jsonify({'error': str(e)}), 500

@app.route('/api/files/save', methods=['POST'])



def api_files_save():

    """Save file content."""

    data = request.json

    path = data.get('path')

    content = data.get('content')

    if not path:

        return jsonify({'error': 'Path is required'}), 400

    try:

        file_path = _resolve_write_path(path)

        if file_path.exists() and not file_path.is_file():

            return jsonify({'error': 'Not a file'}), 400

        file_path.write_text(content, encoding='utf-8')

        return jsonify({'success': True})

    except PermissionError as e:

        return jsonify({'error': str(e) or 'Доступ запрещен'}), 403

    except Exception as e:

        return jsonify({'error': str(e)}), 500

@app.route('/api/files/delete', methods=['DELETE'])



def api_files_delete():

    """Delete file or folder."""

    data = request.json

    path = data.get('path')

    if not path:

        return jsonify({'error': 'Path is required'}), 400

    try:

        target_path = _resolve_write_path(path)

        # Protect roots from deletion

        for root in FILE_MANAGER_WRITE_ROOTS:

            try:

                if target_path == root.resolve():

                    return jsonify({'error': 'Нельзя удалить корневую директорию'}), 403

            except Exception:

                continue

        if target_path.is_dir():

            shutil.rmtree(target_path)

        else:

            target_path.unlink()

        return jsonify({'success': True})

    except PermissionError as e:

        return jsonify({'error': str(e) or 'Доступ запрещен'}), 403

    except Exception as e:

        return jsonify({'error': str(e)}), 500

@app.route('/api/files/rename', methods=['POST'])



def api_files_rename():

    """Rename file or folder."""

    data = request.json

    old_path = data.get('old_path')

    new_name = data.get('new_name')

    if not old_path or not new_name:

        return jsonify({'error': 'Old path and new name are required'}), 400

    try:

        new_name = _validate_entry_name(new_name)

        target_path = _resolve_write_path(old_path)

        # Protect roots from rename

        for root in FILE_MANAGER_WRITE_ROOTS:

            try:

                if target_path == root.resolve():

                    return jsonify({'error': 'Нельзя переименовать корневую директорию'}), 403

            except Exception:

                continue

        new_path = target_path.parent / new_name

        if not _is_write_allowed_path(new_path):

            return jsonify({'error': 'Доступ запрещен'}), 403

        target_path.rename(new_path)

        return jsonify({'success': True})

    except PermissionError as e:

        return jsonify({'error': str(e) or 'Доступ запрещен'}), 403

    except Exception as e:

        return jsonify({'error': str(e)}), 500

@app.route('/api/files/upload', methods=['POST'])



def api_files_upload():

    """Upload file."""

    if 'file' not in request.files:

        return jsonify({'error': 'No file part'}), 400

    file = request.files['file']

    path = request.form.get('path')

    if file.filename == '':

        return jsonify({'error': 'No selected file'}), 400

    if not path:

        return jsonify({'error': 'Path is required'}), 400

    try:

        filename = secure_filename(file.filename)

        base_dir = _resolve_write_path(path)

        if not base_dir.exists() or not base_dir.is_dir():

            return jsonify({'error': 'Not a directory'}), 400

        save_path = base_dir / filename

        if not _is_write_allowed_path(save_path):

            return jsonify({'error': 'Доступ запрещен'}), 403

        file.save(str(save_path))

        return jsonify({'success': True})

    except PermissionError as e:

        return jsonify({'error': str(e) or 'Доступ запрещен'}), 403

    except Exception as e:

        return jsonify({'error': str(e)}), 500

@app.route('/api/files/download', methods=['GET'])



def api_files_download():

    """Download file."""

    path = request.args.get('path')

    if not path:

        return jsonify({'error': 'Path is required'}), 400

    try:

        file_path = _resolve_read_path(path)

        if not file_path.is_file():

            return jsonify({'error': 'Not a file'}), 400

        return send_file(str(file_path), as_attachment=True)

    except PermissionError as e:

        return jsonify({'error': str(e) or 'Доступ запрещен'}), 403

    except Exception as e:

        return jsonify({'error': str(e)}), 500

# ==================== Backups & Security ====================

def _human_bytes(num: int) -> str:

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

def _validate_backup_filename(name: str) -> str:

    name = (name or "").strip()

    if not name:

        raise ValueError("Name is required")

    if "/" in name or "\\" in name:

        raise ValueError("Invalid name")

    if name in {".", ".."}:

        raise ValueError("Invalid name")

    if not name.endswith(".tar.gz"):

        raise ValueError("Only .tar.gz backups are supported")

    return name

def _validate_backup_target_name(name: str) -> str:

    """Validate site/project name for backup creation (no separators)."""

    name = (name or "").strip()

    if not name:

        raise ValueError("Name is required")

    if "/" in name or "\\" in name:

        raise ValueError("Invalid name")

    if name in {".", ".."}:

        raise ValueError("Invalid name")

    return name

@app.route('/api/backups', methods=['GET'])



def api_backups_list():

    """List backup archives."""

    items = []

    try:

        if BACKUPS_DIR.exists():

            for f in BACKUPS_DIR.iterdir():

                if not f.is_file():

                    continue

                if not f.name.endswith(".tar.gz"):

                    continue

                try:

                    st = f.stat()

                    items.append({

                        "name": f.name,

                        "size": st.st_size,

                        "size_human": _human_bytes(st.st_size),

                        "modified": datetime.fromtimestamp(st.st_mtime).isoformat(),

                    })

                except Exception:

                    continue

        items.sort(key=lambda x: x.get("modified", ""), reverse=True)

        return jsonify(items)

    except Exception as e:

        return jsonify({"error": str(e)}), 500

@app.route('/api/backups', methods=['POST'])



def api_backups_create():

    """Create a backup archive for a site, project, or curated server bundle."""

    data = request.json or {}

    kind = (data.get("kind") or "").strip()

    name = (data.get("name") or "").strip()

    try:

        ts = datetime.utcnow().strftime("%Y%m%d-%H%M%S")

        dereference = _coerce_bool(data.get("dereference"), default=True)

        preserve_permissions = _coerce_bool(data.get("preserve_permissions"), default=True)

        tar_flags = "-cz"

        if dereference:

            tar_flags += "h"

        if preserve_permissions:

            tar_flags += "p"

        tar_flags += "f"

        if kind in {"site", "project"}:

            name = _validate_backup_target_name(name)

            src = (WWW_DIR / name) if kind == "site" else (PROJECTS_DIR / name)

            if not src.exists() or not src.is_dir():

                return jsonify({"success": False, "error": "Папка не найдена"}), 404

            safe_name = "".join(ch if ch.isalnum() or ch in "._-@" else "_" for ch in name)

            filename = f"{kind}-{safe_name}-{ts}.tar.gz"

            dst = BACKUPS_DIR / filename

            # Исключаем runtime-папки, чтобы бэкап не забирал сам себя
            # (backups теперь хранится внутри папки проекта/сайта) и лишний мусор
            excludes = " ".join(
                f"--exclude={shlex.quote(part)}"
                for part in (".env", ".env.*", "settings.json", "backups", ".git", "__pycache__", "sessions", ".venv", "venv", "node_modules", "*.pyc", "*.log")
            )

            cmd = f"tar {excludes} {tar_flags} {shlex.quote(str(dst))} -C {shlex.quote(str(src.parent))} {shlex.quote(src.name)}"

        elif kind == "bundle":

            selected_paths = []

            if _coerce_bool(data.get("include_www"), default=True):

                selected_paths.append("var/www")

            if _coerce_bool(data.get("include_projects"), default=True):

                selected_paths.append("home/dream/projects")

            if _coerce_bool(data.get("include_nginx"), default=True):

                selected_paths.append("etc/nginx")

            if _coerce_bool(data.get("include_systemd"), default=True):

                selected_paths.append("etc/systemd/system")

            if _coerce_bool(data.get("include_letsencrypt"), default=False):

                selected_paths.append("etc/letsencrypt")

            if _coerce_bool(data.get("include_xray"), default=False):

                selected_paths.append("usr/local/etc/xray")

            if _coerce_bool(data.get("include_root_links"), default=True):

                selected_paths.append("root")

            if not selected_paths:

                return jsonify({"success": False, "error": "Ничего не выбрано для бэкапа"}), 400

            label = (data.get("bundle_name") or name or "server").strip()

            safe_name = "".join(ch if ch.isalnum() or ch in "._-@" else "_" for ch in label)

            filename = f"bundle-{safe_name}-{ts}.tar.gz"

            dst = BACKUPS_DIR / filename

            items_arg = " ".join(shlex.quote(p) for p in selected_paths)

            # Не забираем бэкапы (теперь лежат внутри проектов) и мусорные папки
            excludes = " ".join(
                f"--exclude={shlex.quote(part)}"
                for part in (".env", ".env.*", "settings.json", "backups", "__pycache__", "sessions", ".venv", "venv", "node_modules", "*.pyc", "*.log")
            )

            cmd = f"tar {excludes} {tar_flags} {shlex.quote(str(dst))} -C / {items_arg}"

        else:

            return jsonify({"success": False, "error": "kind must be site, project, or bundle"}), 400

        ok, output = safe_run(cmd, timeout=1800)

        if not ok:

            try:

                if dst.exists():

                    dst.unlink()

            except Exception:

                pass

            return jsonify({"success": False, "error": output}), 500

        return jsonify({"success": True, "name": filename})

    except Exception as e:

        return jsonify({"success": False, "error": str(e)}), 400

@app.route('/api/backups', methods=['DELETE'])



def api_backups_delete():

    """Delete a backup archive."""

    data = request.json or {}

    name = data.get("name")

    try:

        name = _validate_backup_filename(name)

        p = BACKUPS_DIR / name

        if not p.exists() or not p.is_file():

            return jsonify({"success": False, "error": "Файл не найден"}), 404

        p.unlink()

        return jsonify({"success": True})

    except ValueError as e:

        return jsonify({"success": False, "error": str(e)}), 400

    except Exception as e:

        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/backups/download', methods=['GET'])



def api_backups_download():

    """Download a backup archive."""

    name = request.args.get("name")

    try:

        name = _validate_backup_filename(name)

        p = BACKUPS_DIR / name

        if not p.exists() or not p.is_file():

            return jsonify({"error": "Файл не найден"}), 404

        return send_file(str(p), as_attachment=True)

    except ValueError as e:

        return jsonify({"error": str(e)}), 400

    except Exception as e:

        return jsonify({"error": str(e)}), 500

@app.route('/api/security', methods=['GET'])

def api_security():
    """Detailed security status (firewall / fail2ban / open ports)."""
    # UFW Status
    ufw_ok, ufw_out = safe_run("ufw status verbose", timeout=10)
    ufw_data = {"ok": ufw_ok, "status": "unknown", "rules": [], "raw": ufw_out}
    if ufw_ok:
        if "Status: active" in ufw_out:
            ufw_data["status"] = "active"
        elif "Status: inactive" in ufw_out:
            ufw_data["status"] = "inactive"
        
        # Parse rules (simplified)
        lines = ufw_out.split('\n')
        parsing_rules = False
        for line in lines:
            if "To " in line and "Action" in line:
                parsing_rules = True
                continue
            if parsing_rules and line.strip() and not line.startswith("-"):
                parts = re.split(r'\s{2,}', line.strip())
                if len(parts) >= 2:
                    ufw_data["rules"].append({"to": parts[0], "action": parts[1], "from": parts[2] if len(parts) > 2 else "Anywhere"})

    # Fail2ban detailed
    f2b_ok, f2b_out = safe_run("fail2ban-client status", timeout=10)
    f2b_data = {"ok": f2b_ok, "jails": [], "raw": f2b_out}
    if f2b_ok:
        match = re.search(r"Jail list:\s+(.+)", f2b_out)
        if match:
            jails = [j.strip() for j in match.group(1).split(",")]
            for jail in jails:
                ok_j, out_j = safe_run(f"fail2ban-client status {shlex.quote(jail)}", timeout=10)
                if ok_j:
                    curr = 0
                    total = 0
                    ips = []
                    m_curr = re.search(r"Currently banned:\s+(\d+)", out_j)
                    m_total = re.search(r"Total banned:\s+(\d+)", out_j)
                    m_ips = re.search(r"Banned IP list:\s+(.+)", out_j)
                    if m_curr: curr = int(m_curr.group(1))
                    if m_total: total = int(m_total.group(1))
                    if m_ips: ips = m_ips.group(1).split()
                    f2b_data["jails"].append({
                        "name": jail,
                        "currently_banned": curr,
                        "total_banned": total,
                        "banned_ips": ips[:10] # Top 10 for UI
                    })

    # Open Ports
    ports_ok, ports_out = safe_run("ss -tulpen", timeout=10)
    
    return jsonify({
        "ufw": ufw_data,
        "fail2ban": f2b_data,
        "ports": {"ok": ports_ok, "output": ports_out},
    })

@app.route('/api/console/exec', methods=['POST'])



def api_console_exec():

    """API: execute a console command with basic safety rails."""

    data = request.json or {}

    command = (data.get('command') or '').strip()

    cwd = (data.get('cwd') or '').strip() or '/root'

    shell_name = (data.get('shell') or 'bash').strip().lower()

    try:

        timeout = int(data.get('timeout') or 60)

    except Exception:

        timeout = 60

    timeout = max(5, min(timeout, 600))

    if not command:

        return jsonify({'success': False, 'error': 'Команда обязательна'}), 400

    dangerous_patterns = ['rm -rf /', 'mkfs', 'dd if=', ':(){', 'fork bomb']

    lowered = command.lower()

    for pattern in dangerous_patterns:

        if pattern in lowered:

            return jsonify({'success': False, 'error': f'Опасная команда заблокирована: {pattern}'}), 403

    try:

        resolved_cwd = _resolve_read_path(cwd)

        if not resolved_cwd.exists() or not resolved_cwd.is_dir():

            return jsonify({'success': False, 'error': 'Рабочая директория не найдена'}), 400

    except Exception as e:

        return jsonify({'success': False, 'error': str(e)}), 400

    if shell_name == 'sh':

        shell_cmd = f"cd {shlex.quote(str(resolved_cwd))} && /bin/sh -lc {shlex.quote(command)}"

    else:

        shell_cmd = f"cd {shlex.quote(str(resolved_cwd))} && /bin/bash -lc {shlex.quote(command)}"

    ok, output = safe_run(shell_cmd, timeout=timeout)

    return jsonify({

        'success': ok,

        'output': output or '(пустой вывод)',

        'exit_code': 0 if ok else 1,

        'cwd': str(resolved_cwd),

        'timeout': timeout,

        'shell': shell_name,

        'command': command,

    })

# ==================== Bots Manager (subprocess-based) ====================

import bot_manager as bm

import proxy_manager as pm

BOTS_DIR = Path(os.environ.get('BOTS_DIR', str(Path.home() / 'bots')))

try:

    BOTS_DIR.mkdir(parents=True, exist_ok=True)

except Exception:

    pass

# Add bots dir to file manager roots

try:

    if BOTS_DIR not in FILE_MANAGER_WRITE_ROOTS:

        FILE_MANAGER_WRITE_ROOTS.append(BOTS_DIR)

    if BOTS_DIR not in FILE_MANAGER_READ_ROOTS:

        FILE_MANAGER_READ_ROOTS.append(BOTS_DIR)

except Exception:

    pass

BOT_MARKER_FILE = '.bot_config.json'

TOKEN_PATTERNS = [

    (r'["\']?(?:TOKEN|BOT_TOKEN|TELEGRAM_TOKEN|TG_TOKEN|API_TOKEN)["\']?\s*[=:]\s*["\']([0-9]{8,10}:[A-Za-z0-9_-]{35})["\']', 'telegram_token'),

    (r'["\']?(?:API_KEY|SECRET_KEY|ACCESS_KEY|PRIVATE_KEY)["\']?\s*[=:]\s*["\']([A-Za-z0-9_-]{20,})["\']', 'api_key'),

    (r'["\']?(?:DATABASE_URL|DB_URL|MONGO_URI|REDIS_URL)["\']?\s*[=:]\s*["\']([^"\']+)["\']', 'database_url'),

    (r'["\']?(?:ADMIN_ID|OWNER_ID|ADMIN_TELEGRAM_ID)["\']?\s*[=:]\s*["\']?(\d{5,15})["\']?', 'admin_id'),

    (r'["\']?PORT["\']?\s*[=:]\s*["\']?(\d{2,5})["\']?', 'port'),

    (r'["\']?(?:SECRET|PASSWORD|PASS)["\']?\s*[=:]\s*["\']([^"\']{4,})["\']', 'secret'),

]

def scan_file_for_configs(file_path: Path) -> List[Dict[str, str]]:

    configs = []

    try:

        content = file_path.read_text(encoding='utf-8', errors='replace')

        for pattern, config_type in TOKEN_PATTERNS:

            for match in re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE):

                value = match.group(1)

                line_start = content[:match.start()].count('\n') + 1

                lines = content.splitlines()

                context = lines[line_start - 1] if line_start <= len(lines) else ''

                configs.append({

                    'type': config_type,

                    'value': value,

                    'file': str(file_path.name),

                    'line': line_start,

                    'context': context.strip()[:100],

                })

    except Exception:

        pass

    return configs

def scan_bot_for_configs(bot_dir: Path) -> List[Dict[str, str]]:

    all_configs = []

    try:

        for py_file in bot_dir.rglob('*.py'):

            if any(part in {'venv', '.venv', '__pycache__', 'node_modules'} for part in py_file.parts):

                continue

            all_configs.extend(scan_file_for_configs(py_file))

        for env_file in bot_dir.glob('.env*'):

            if env_file.is_file():

                all_configs.extend(scan_file_for_configs(env_file))

        for cfg_file in bot_dir.glob('config*'):

            if cfg_file.is_file():

                all_configs.extend(scan_file_for_configs(cfg_file))

    except Exception:

        pass

    return all_configs

def get_bot_info(bot_dir: Path) -> Dict[str, object]:

    info = {

        'name': bot_dir.name,

        'path': str(bot_dir),

        'enabled': False,

        'running': False,

        'port': None,

        'entrypoint': None,

        'has_requirements': False,

        'has_env': False,

        'configs': [],

        'files': [],

        'size': 0,

        'created_at': None,

        'pid': None,

        'memory': 0,

        'cpu': 0.0,

    }

    marker = bot_dir / BOT_MARKER_FILE

    if marker.exists():

        try:

            meta = json.loads(marker.read_text(encoding='utf-8'))

            info.update({

                'port': meta.get('port'),

                'entrypoint': meta.get('entrypoint'),

                'created_at': meta.get('created_at'),

                'autostart': meta.get('autostart', False),

            })

        except Exception:

            pass

    else:

        info['autostart'] = False

    info['has_requirements'] = (bot_dir / 'requirements.txt').exists()

    info['has_env'] = (bot_dir / '.env').exists()

    if not info['entrypoint']:

        for name in ('main.py', 'bot.py', 'app.py', 'run.py', 'start.py'):

            if (bot_dir / name).exists():

                info['entrypoint'] = name

                break

    try:

        for f in sorted(bot_dir.iterdir()):

            if f.name.startswith('.') and f.name != '.env':

                continue

            if f.name in {'venv', '.venv', '__pycache__', 'node_modules'}:

                continue

            info['files'].append({

                'name': f.name,

                'is_dir': f.is_dir(),

                'size': f.stat().st_size if f.is_file() else 0,

            })

    except Exception:

        pass

    try:

        info['size'] = sum(f.stat().st_size for f in bot_dir.rglob('*') if f.is_file())

    except Exception:

        pass

    # Получаем статус из bot_manager (subprocess)

    status = bm.get_bot_status(bot_dir.name)

    info['running'] = status.get('running', False)

    info['enabled'] = status.get('enabled', False)

    info['pid'] = status.get('pid')

    if info['pid']:

        try:

            rss, cpu = bm.get_pid_resources(info['pid'])

            info['memory'] = rss

            info['cpu'] = cpu

        except Exception:

            pass

    return info

def _write_bot_marker(bot_dir: Path, meta: Dict[str, object]) -> None:

    try:

        marker = bot_dir / BOT_MARKER_FILE

        marker.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding='utf-8')

    except Exception:

        pass

@app.route('/api/bots')



def api_bots_list():
    bots = []
    if BOTS_DIR.exists():
        for item in sorted(BOTS_DIR.iterdir()):
            if item.is_dir() and not item.name.startswith('.'):
                bots.append(bm.get_bot_info(item))
    return jsonify(bots)

@app.route('/api/bots/<name>')



def api_bot_get(name: str):

    name = _validate_entry_name(name)

    bot_dir = BOTS_DIR / name

    if not bot_dir.exists() or not bot_dir.is_dir():

        return jsonify({'error': 'Bot not found'}), 404

    info = get_bot_info(bot_dir)

    info['configs'] = scan_bot_for_configs(bot_dir)

    return jsonify(info)

@app.route('/api/bots/<name>/logs')



def api_bot_logs(name: str):

    name = _validate_entry_name(name)

    bot_dir = BOTS_DIR / name

    if not bot_dir.exists():

        return jsonify({'error': 'Bot not found'}), 404

    lines = request.args.get('lines', 100, type=int)

    logs = bm.get_bot_logs(name, lines=lines)

    return jsonify({'success': True, 'logs': logs})

@app.route('/api/bots/<name>/action', methods=['POST'])



def api_bot_action(name: str):

    name = _validate_entry_name(name)

    bot_dir = BOTS_DIR / name

    if not bot_dir.exists():

        return jsonify({'error': 'Bot not found'}), 404

    data = request.json or {}

    action = data.get('action', '').strip()

    if action not in ('start', 'stop', 'restart', 'enable', 'disable'):

        return jsonify({'error': 'Unknown action'}), 400

    # Получить entrypoint из маркера

    marker = bot_dir / BOT_MARKER_FILE

    entrypoint = None

    python_bin = '/usr/bin/python3'

    if marker.exists():

        try:

            meta = json.loads(marker.read_text(encoding='utf-8'))

            entrypoint = meta.get('entrypoint')

            python_bin = meta.get('python_bin', python_bin)

        except Exception:

            pass

    if not entrypoint:

        for ep in ('main.py', 'bot.py', 'app.py', 'run.py', 'start.py'):

            if (bot_dir / ep).exists():

                entrypoint = ep

                break

    if not entrypoint:

        return jsonify({'error': 'Entrypoint not found'}), 400

    # Выполнить действие через bot_manager

    if action == 'start':

        ok, msg = bm.start_bot(name, bot_dir, entrypoint, python_bin)

    elif action == 'stop':

        ok, msg = bm.stop_bot(name)

    elif action == 'restart':

        ok, msg = bm.restart_bot(name)

    elif action == 'enable':

        ok, msg = bm.enable_bot(name, bot_dir, entrypoint, python_bin)

    elif action == 'disable':

        ok, msg = bm.disable_bot(name)

    else:

        return jsonify({'error': 'Unknown action'}), 400

    time.sleep(0.3)

    status = bm.get_bot_status(name)

    return jsonify({

        'success': ok,

        'message': msg,

        'running': status.get('running', False),

        'enabled': status.get('enabled', False),

    })

@app.route('/api/bots/<name>/autostart', methods=['POST'])



def api_bot_autostart(name: str):

    """Управление автозапуском бота с панелью"""

    name = _validate_entry_name(name)

    bot_dir = BOTS_DIR / name

    if not bot_dir.exists():

        return jsonify({'error': 'Bot not found'}), 404

    data = request.json or {}

    enabled = data.get('enabled', False)

    try:

        # Обновляем маркер бота

        marker = bot_dir / BOT_MARKER_FILE

        meta = {}

        if marker.exists():

            try:

                meta = json.loads(marker.read_text(encoding='utf-8'))

            except Exception:

                pass

        meta['autostart'] = enabled

        _write_bot_marker(bot_dir, meta)

        return jsonify({'success': True, 'autostart': enabled})

    except Exception as e:

        return jsonify({'error': str(e)}), 500

@app.route('/api/bots/<name>/file', methods=['GET'])



def api_bot_file_get(name: str):

    name = _validate_entry_name(name)

    bot_dir = BOTS_DIR / name

    if not bot_dir.exists():

        return jsonify({'error': 'Bot not found'}), 404

    filename = request.args.get('file', '').strip()

    if not filename:

        return jsonify({'error': 'File not specified'}), 400

    file_path = (bot_dir / filename).resolve()

    if not _is_relative_to(file_path, bot_dir):

        return jsonify({'error': 'Access denied'}), 403

    if not file_path.exists() or not file_path.is_file():

        return jsonify({'error': 'File not found'}), 404

    try:

        content = file_path.read_text(encoding='utf-8', errors='replace')

        return jsonify({'name': filename, 'content': content, 'size': len(content)})

    except Exception as e:

        return jsonify({'error': str(e)}), 500

@app.route('/api/bots/<name>/file', methods=['PUT'])



def api_bot_file_save(name: str):

    name = _validate_entry_name(name)

    bot_dir = BOTS_DIR / name

    if not bot_dir.exists():

        return jsonify({'error': 'Bot not found'}), 404

    data = request.json or {}

    filename = data.get('file', '').strip()

    content = data.get('content', '')

    if not filename:

        return jsonify({'error': 'File not specified'}), 400

    file_path = (bot_dir / filename).resolve()

    if not _is_relative_to(file_path, bot_dir):

        return jsonify({'error': 'Access denied'}), 403

    try:

        file_path.write_text(content, encoding='utf-8')

        return jsonify({'success': True})

    except Exception as e:

        return jsonify({'error': str(e)}), 500

@app.route('/api/bots/<name>/config', methods=['PUT'])



def api_bot_update_config(name: str):

    name = _validate_entry_name(name)

    bot_dir = BOTS_DIR / name

    if not bot_dir.exists():

        return jsonify({'error': 'Bot not found'}), 404

    data = request.json or {}

    filename = data.get('file', '').strip()

    old_value = data.get('old_value', '')

    new_value = data.get('new_value', '')

    if not filename or not old_value:

        return jsonify({'error': 'Parameters missing'}), 400

    file_path = (bot_dir / filename).resolve()

    if not _is_relative_to(file_path, bot_dir):

        return jsonify({'error': 'Access denied'}), 403

    if not file_path.exists():

        return jsonify({'error': 'File not found'}), 404

    try:

        content = file_path.read_text(encoding='utf-8')

        if old_value not in content:

            return jsonify({'error': 'Value not found in file'}), 400

        new_content = content.replace(old_value, new_value, 1)

        file_path.write_text(new_content, encoding='utf-8')

        return jsonify({'success': True})

    except Exception as e:

        return jsonify({'error': str(e)}), 500

@app.route('/api/bots/upload', methods=['POST'])



def api_bots_upload():

    if 'file' not in request.files:

        return jsonify({'error': 'No file uploaded'}), 400

    f = request.files['file']

    if not f or not f.filename:

        return jsonify({'error': 'Empty filename'}), 400

    bot_name = request.form.get('name', '').strip()

    filename = secure_filename(f.filename)

    lower = filename.lower()

    # Determine bot name from filename if not provided

    if not bot_name:

        if lower.endswith('.zip'):

            bot_name = filename[:-4]

        elif lower.endswith('.tar.gz'):

            bot_name = filename[:-7]

        elif lower.endswith('.tgz'):

            bot_name = filename[:-4]

        elif lower.endswith('.py'):

            bot_name = filename[:-3]

        else:

            bot_name = filename.split('.')[0]

    bot_name = re.sub(r'[^A-Za-z0-9_-]', '_', bot_name)

    if not bot_name:

        return jsonify({'error': 'Invalid bot name'}), 400

    bot_dir = BOTS_DIR / bot_name

    if bot_dir.exists():

        return jsonify({'error': f'Bot {bot_name} already exists'}), 400

    try:

        if lower.endswith('.py'):

            # Single file bot

            bot_dir.mkdir(parents=True, exist_ok=True)

            target = bot_dir / filename

            f.save(str(target))

            entrypoint = filename

        elif lower.endswith('.zip') or lower.endswith('.tar.gz') or lower.endswith('.tgz'):

            # Archive

            tmp_dir = Path(tempfile.mkdtemp())

            archive_path = tmp_dir / filename

            f.save(str(archive_path))

            extracted_dir = tmp_dir / 'extracted'

            extracted_dir.mkdir()

            if lower.endswith('.zip'):

                _safe_extract_zip(archive_path, extracted_dir)

            else:

                _safe_extract_tar(archive_path, extracted_dir)

            project_root = _detect_project_root(extracted_dir)

            shutil.move(str(project_root), str(bot_dir))

            shutil.rmtree(tmp_dir, ignore_errors=True)

            # Find entrypoint

            entrypoint = None

            for name in ('main.py', 'bot.py', 'app.py', 'run.py', 'start.py'):

                if (bot_dir / name).exists():

                    entrypoint = name

                    break

        else:

            return jsonify({'error': 'Supported formats: .py, .zip, .tar.gz, .tgz'}), 400

        # Write marker

        _write_bot_marker(bot_dir, {

            'name': bot_name,

            'created_at': datetime.utcnow().isoformat(),

            'entrypoint': entrypoint,

        })

        return jsonify({

            'success': True,

            'name': bot_name,

            'path': str(bot_dir),

            'entrypoint': entrypoint,

        })

    except Exception as e:

        if bot_dir.exists():

            shutil.rmtree(bot_dir, ignore_errors=True)

        return jsonify({'error': str(e)}), 500

@app.route('/api/bots/<name>', methods=['DELETE'])



def api_bot_delete(name: str):

    name = _validate_entry_name(name)

    bot_dir = BOTS_DIR / name

    if not bot_dir.exists():

        return jsonify({'error': 'Bot not found'}), 404

    # Остановить и очистить через bot_manager

    bm.cleanup_bot(name)

    try:

        shutil.rmtree(bot_dir)

        return jsonify({'success': True})

    except Exception as e:

        return jsonify({'error': str(e)}), 500

@app.route('/api/bots/<name>/setup', methods=['POST'])



def api_bot_setup(name: str):

    """Настроить и запустить бота (без systemd, через subprocess)"""

    name = _validate_entry_name(name)

    bot_dir = BOTS_DIR / name

    if not bot_dir.exists():

        return jsonify({'error': 'Bot not found'}), 404

    data = request.json or {}

    entrypoint = data.get('entrypoint', '').strip()

    port = data.get('port')

    python_bin = data.get('python_bin', '/usr/bin/python3').strip() or '/usr/bin/python3'

    install_deps = data.get('install_deps', False)

    auto_start = data.get('auto_start', True)

    if not entrypoint:

        for ep in ('main.py', 'bot.py', 'app.py', 'run.py', 'start.py'):

            if (bot_dir / ep).exists():

                entrypoint = ep

                break

    if not entrypoint:

        return jsonify({'error': 'Entrypoint not specified and not found'}), 400

    entrypoint_path = bot_dir / entrypoint

    if not entrypoint_path.exists():

        return jsonify({'error': f'Entrypoint {entrypoint} not found'}), 400

    # Установить зависимости если запрошено

    if install_deps:

        req_path = bot_dir / 'requirements.txt'

        if req_path.exists():

            cmd = f"{shlex.quote(python_bin)} -m pip install -r {shlex.quote(str(req_path))}"

            ok, out = safe_run(cmd, timeout=600)

            if not ok:

                return jsonify({'error': f'Failed to install deps: {out}'}), 500

    # Обновить маркер

    marker = bot_dir / BOT_MARKER_FILE

    meta = {}

    if marker.exists():

        try:

            meta = json.loads(marker.read_text(encoding='utf-8'))

        except Exception:

            pass

    meta['entrypoint'] = entrypoint

    meta['port'] = port

    meta['python_bin'] = python_bin

    _write_bot_marker(bot_dir, meta)

    # Запустить бота если запрошено

    if auto_start:

        ok, msg = bm.start_bot(name, bot_dir, entrypoint, python_bin)

        time.sleep(0.5)

        status = bm.get_bot_status(name)

        return jsonify({

            'success': ok,

            'message': msg,

            'running': status.get('running', False),

        })

    return jsonify({'success': True, 'message': 'Bot configured'})

@app.route('/api/bots/<name>/install-deps', methods=['POST'])



def api_bot_install_deps(name: str):

    name = _validate_entry_name(name)

    bot_dir = BOTS_DIR / name

    if not bot_dir.exists():

        return jsonify({'error': 'Bot not found'}), 404

    req_path = bot_dir / 'requirements.txt'

    if not req_path.exists():

        return jsonify({'error': 'requirements.txt not found'}), 400

    # Determine python executable

    marker = bot_dir / BOT_MARKER_FILE

    python_exec = '/usr/bin/python3'

    if marker.exists():

        try:

            meta = json.loads(marker.read_text(encoding='utf-8'))

            python_exec = meta.get('python_bin', python_exec)

        except Exception:

            pass

    venv_python = bot_dir / 'venv' / 'bin' / 'python'

    if venv_python.exists():

        python_exec = str(venv_python)

    cmd = f"{shlex.quote(python_exec)} -m pip install -r {shlex.quote(str(req_path))}"

    ok, out = safe_run(cmd, timeout=600)

    return jsonify({'success': ok, 'output': out})

# ==================== Proxy Manager API ====================

@app.route('/api/proxy/rules')



def api_proxy_rules():

    """Получить все правила проксирования"""

    rules = pm.get_proxy_rules()

    return jsonify({'success': True, 'rules': rules})

@app.route('/api/proxy/rules', methods=['POST'])



def api_proxy_add_rule():

    """Добавить правило проксирования"""

    data = request.json or {}

    path_prefix = data.get('path_prefix', '').strip()

    target_url = data.get('target_url', '').strip()

    description = data.get('description', '').strip()

    enabled = data.get('enabled', True)

    if not path_prefix or not target_url:

        return jsonify({'error': 'path_prefix and target_url required'}), 400

    # Проверяем что правило не существует

    if pm.get_proxy_rule(path_prefix):

        return jsonify({'error': f'Rule for {path_prefix} already exists'}), 400

    pm.add_proxy_rule(path_prefix, target_url, description, enabled)

    return jsonify({'success': True})

@app.route('/api/proxy/rules/<path:path_prefix>', methods=['DELETE'])



def api_proxy_delete_rule(path_prefix: str):

    """Удалить правило проксирования"""

    if not path_prefix.startswith('/'):

        path_prefix = '/' + path_prefix

    if pm.remove_proxy_rule(path_prefix):

        return jsonify({'success': True})

    return jsonify({'error': 'Rule not found'}), 404

@app.route('/api/proxy/rules/<path:path_prefix>/toggle', methods=['POST'])



def api_proxy_toggle_rule(path_prefix: str):

    """Переключить состояние правила"""

    if not path_prefix.startswith('/'):

        path_prefix = '/' + path_prefix

    if pm.toggle_proxy_rule(path_prefix):

        return jsonify({'success': True})

    return jsonify({'error': 'Rule not found'}), 404

# ==================== Proxy Catch-All Route ====================

# Этот роут должен быть последним, чтобы не перехватывать другие маршруты

@app.route('/p/<path:full_path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'])

def proxy_handler(full_path: str):

    """Проксирование запросов к ботам через /p/prefix/..."""

    # Находим правило

    rule = pm.find_matching_rule(full_path)

    if not rule:

        return "Service not found or disabled", 404

    # Собираем данные запроса

    method = request.method

    headers = dict(request.headers)

    params = dict(request.args)

    body = request.get_data()

    # Проксируем

    status, resp_headers, content = pm.forward_request(rule, '/' + full_path, method, headers, params, body)

    from flask import Response

    return Response(content, status=status, headers=resp_headers)

# ==================== Icons Microservice Management ====================

@app.route('/api/icons/projects', methods=['GET'])

def api_icons_list_projects():
    """Получить список всех проектов иконок"""
    try:
        response = requests.get(f'{ICONS_API_URL}/projects', timeout=5)
        # Проверяем, что ответ содержит валидный JSON
        if response.status_code == 200:
            try:
                data = response.json()
                return jsonify(data), 200
            except ValueError:
                return jsonify({'error': 'Icons API вернул невалидный JSON', 'raw_response': response.text[:500]}), 502
        else:
            return jsonify({'error': f'Icons API вернул ошибку: {response.status_code}', 'raw_response': response.text[:500]}), response.status_code
    except requests.exceptions.ConnectionError:
        return jsonify({'error': f'Не удалось подключиться к Icons API по адресу {ICONS_API_URL}. Убедитесь, что сервис icons-api запущен.'}), 503
    except requests.exceptions.Timeout:
        return jsonify({'error': 'Таймаут при подключении к Icons API'}), 504
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/icons/projects', methods=['POST'])

def api_icons_create_project():
    """Создать новый проект иконок"""
    try:
        files = {}
        if 'logo_file' in request.files:
            logo_file = request.files['logo_file']
            files['logo_file'] = (logo_file.filename, logo_file.stream, logo_file.content_type)
        
        data = {'name': request.form.get('name')}
        headers = {'X-API-Token': ICONS_API_TOKEN}
        response = requests.post(
            f'{ICONS_API_URL}/projects',
            data=data,
            files=files,
            headers=headers,
            timeout=30
        )
        if response.status_code == 200 or response.status_code == 201:
            try:
                return jsonify(response.json()), response.status_code
            except ValueError:
                return jsonify({'error': 'Icons API вернул невалидный JSON', 'raw_response': response.text[:500]}), 502
        else:
            return jsonify({'error': f'Icons API вернул ошибку: {response.status_code}', 'raw_response': response.text[:500]}), response.status_code
    except requests.exceptions.ConnectionError:
        return jsonify({'error': f'Не удалось подключиться к Icons API по адресу {ICONS_API_URL}'}), 503
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/icons/projects/<project_name>', methods=['PUT'])

def api_icons_update_project(project_name):
    """Обновить проект иконок"""
    try:
        files = {}
        if 'logo_file' in request.files:
            logo_file = request.files['logo_file']
            files['logo_file'] = (logo_file.filename, logo_file.stream, logo_file.content_type)
        
        headers = {'X-API-Token': ICONS_API_TOKEN}
        response = requests.put(
            f'{ICONS_API_URL}/projects/{project_name}',
            files=files,
            headers=headers,
            timeout=30
        )
        if response.status_code == 200 or response.status_code == 201:
            try:
                return jsonify(response.json()), response.status_code
            except ValueError:
                return jsonify({'error': 'Icons API вернул невалидный JSON', 'raw_response': response.text[:500]}), 502
        else:
            return jsonify({'error': f'Icons API вернул ошибку: {response.status_code}', 'raw_response': response.text[:500]}), response.status_code
    except requests.exceptions.ConnectionError:
        return jsonify({'error': f'Не удалось подключиться к Icons API по адресу {ICONS_API_URL}'}), 503
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/icons/projects/<project_name>', methods=['DELETE'])

def api_icons_delete_project(project_name):
    """Удалить проект иконок"""
    try:
        headers = {'X-API-Token': ICONS_API_TOKEN}
        response = requests.delete(
            f'{ICONS_API_URL}/projects/{project_name}',
            headers=headers,
            timeout=10
        )
        if response.status_code == 200 or response.status_code == 204:
            try:
                return jsonify(response.json()), response.status_code
            except ValueError:
                return jsonify({'success': True, 'message': 'Проект удален'}), 200
        else:
            return jsonify({'error': f'Icons API вернул ошибку: {response.status_code}', 'raw_response': response.text[:500]}), response.status_code
    except requests.exceptions.ConnectionError:
        return jsonify({'error': f'Не удалось подключиться к Icons API по адресу {ICONS_API_URL}'}), 503
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/icons/projects/<project_name>/info', methods=['GET'])

def api_icons_project_info(project_name):
    """Получить информацию о проекте"""
    try:
        response = requests.get(f'{ICONS_API_URL}/{project_name}/list', timeout=5)
        if response.status_code == 200:
            try:
                return jsonify(response.json()), 200
            except ValueError:
                return jsonify({'error': 'Icons API вернул невалидный JSON', 'raw_response': response.text[:500]}), 502
        else:
            return jsonify({'error': f'Icons API вернул ошибку: {response.status_code}', 'raw_response': response.text[:500]}), response.status_code
    except requests.exceptions.ConnectionError:
        return jsonify({'error': f'Не удалось подключиться к Icons API по адресу {ICONS_API_URL}'}), 503
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/icons/projects/<project_name>/files', methods=['GET'])

def api_icons_list_files(project_name):
    """Получить список всех файлов проекта"""
    try:
        response = requests.get(f'{ICONS_API_URL}/projects/{project_name}/files', timeout=5)
        if response.status_code == 200:
            try:
                return jsonify(response.json()), 200
            except ValueError:
                return jsonify({'error': 'Icons API вернул невалидный JSON', 'raw_response': response.text[:500]}), 502
        else:
            return jsonify({'error': f'Icons API вернул ошибку: {response.status_code}', 'raw_response': response.text[:500]}), response.status_code
    except requests.exceptions.ConnectionError:
        return jsonify({'error': f'Не удалось подключиться к Icons API по адресу {ICONS_API_URL}'}), 503
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/icons/projects/<project_name>/files/<file_type>', methods=['POST'])

def api_icons_upload_file(project_name, file_type):
    """Загрузить конкретный файл иконки"""
    try:
        files = {}
        if 'file' in request.files:
            icon_file = request.files['file']
            files['file'] = (icon_file.filename, icon_file.stream, icon_file.content_type)
        
        headers = {'X-API-Token': ICONS_API_TOKEN}
        response = requests.post(
            f'{ICONS_API_URL}/projects/{project_name}/files/{file_type}',
            files=files,
            headers=headers,
            timeout=30
        )
        if response.status_code in (200, 201):
            try:
                return jsonify(response.json()), response.status_code
            except ValueError:
                return jsonify({'error': 'Icons API вернул невалидный JSON', 'raw_response': response.text[:500]}), 502
        else:
            return jsonify({'error': f'Icons API вернул ошибку: {response.status_code}', 'raw_response': response.text[:500]}), response.status_code
    except requests.exceptions.ConnectionError:
        return jsonify({'error': f'Не удалось подключиться к Icons API по адресу {ICONS_API_URL}'}), 503
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/icons/projects/<project_name>/files/<file_type>', methods=['DELETE'])

def api_icons_delete_file(project_name, file_type):
    """Удалить конкретный файл иконки"""
    try:
        headers = {'X-API-Token': ICONS_API_TOKEN}
        response = requests.delete(
            f'{ICONS_API_URL}/projects/{project_name}/files/{file_type}',
            headers=headers,
            timeout=10
        )
        if response.status_code in (200, 204):
            try:
                return jsonify(response.json()), response.status_code
            except ValueError:
                return jsonify({'success': True, 'message': 'Файл удален'}), 200
        else:
            return jsonify({'error': f'Icons API вернул ошибку: {response.status_code}', 'raw_response': response.text[:500]}), response.status_code
    except requests.exceptions.ConnectionError:
        return jsonify({'error': f'Не удалось подключиться к Icons API по адресу {ICONS_API_URL}'}), 503
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/icons/projects/<project_name>/cache', methods=['DELETE'])

def api_icons_clear_cache(project_name):
    """Очистить кэш проекта"""
    try:
        headers = {'X-API-Token': ICONS_API_TOKEN}
        response = requests.delete(
            f'{ICONS_API_URL}/projects/{project_name}/cache',
            headers=headers,
            timeout=10
        )
        if response.status_code in (200, 204):
            try:
                return jsonify(response.json()), response.status_code
            except ValueError:
                return jsonify({'success': True, 'message': 'Кэш очищен'}), 200
        else:
            return jsonify({'error': f'Icons API вернул ошибку: {response.status_code}', 'raw_response': response.text[:500]}), response.status_code
    except requests.exceptions.ConnectionError:
        return jsonify({'error': f'Не удалось подключиться к Icons API по адресу {ICONS_API_URL}'}), 503
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ==================== Dream API Data Management ====================

DREAM_API_DATA_DIR = Path(os.environ.get('DREAM_API_DATA_DIR', str(PROJECTS_DIR / 'api' / 'data')))

def _get_api_data_dir() -> Path:

    """Возвращает директорию с data-файлами API, проверяя несколько мест."""

    candidates = [

        DREAM_API_DATA_DIR,

        Path('/var/www/api.dreampartners.online/data'),

        Path.home() / 'projects' / 'api' / 'data',

    ]

    for c in candidates:

        if c.exists():

            return c

    # Фаллбек — вернём первый путь (create on demand)

    return DREAM_API_DATA_DIR

@app.route('/api/dream-data/projects', methods=['GET'])



def api_dream_data_projects_get():

    """Получить список проектов из projects.json"""

    try:

        data_dir = _get_api_data_dir()

        path = data_dir / 'projects.json'

        if not path.exists():

            return jsonify([])

        with open(path, 'r', encoding='utf-8') as f:

            return jsonify(json.load(f))

    except Exception as e:

        return jsonify({'error': str(e)}), 500

@app.route('/api/dream-data/projects', methods=['POST'])



def api_dream_data_projects_create():

    """Добавить проект в projects.json"""

    try:

        data_dir = _get_api_data_dir()

        path = data_dir / 'projects.json'

        projects = []

        if path.exists():

            with open(path, 'r', encoding='utf-8') as f:

                projects = json.load(f)

        new_project = request.get_json()

        if not new_project or not new_project.get('id') or not new_project.get('title'):

            return jsonify({'error': 'id и title обязательны'}), 400

        # Проверяем уникальность id

        if any(p.get('id') == new_project['id'] for p in projects):

            return jsonify({'error': f'Проект с id "{new_project["id"]}" уже существует'}), 409

        projects.append(new_project)

        data_dir.mkdir(parents=True, exist_ok=True)

        with open(path, 'w', encoding='utf-8') as f:

            json.dump(projects, f, ensure_ascii=False, indent=4)

        return jsonify({'success': True, 'project': new_project})

    except Exception as e:

        return jsonify({'error': str(e)}), 500

@app.route('/api/dream-data/projects/<project_id>', methods=['PUT'])



def api_dream_data_projects_update(project_id):

    """Обновить проект в projects.json"""

    try:

        data_dir = _get_api_data_dir()

        path = data_dir / 'projects.json'

        if not path.exists():

            return jsonify({'error': 'projects.json не найден'}), 404

        with open(path, 'r', encoding='utf-8') as f:

            projects = json.load(f)

        updated = request.get_json()

        found = False

        for i, p in enumerate(projects):
            if p.get('id') == project_id:
                # Обновляем поля, сохраняя id
                projects[i] = {**p, **updated, 'id': project_id}
                # Гарантируем типы для флагов
                projects[i]['hidden'] = bool(updated.get('hidden', p.get('hidden', False)))
                projects[i]['dreamid'] = bool(updated.get('dreamid', p.get('dreamid', False)))
                found = True
                break

        if not found:

            return jsonify({'error': f'Проект "{project_id}" не найден'}), 404

        with open(path, 'w', encoding='utf-8') as f:

            json.dump(projects, f, ensure_ascii=False, indent=4)

        return jsonify({'success': True})

    except Exception as e:

        return jsonify({'error': str(e)}), 500



@app.route('/api/dream-data/projects/<project_id>/toggle', methods=['POST'])

def api_dream_data_projects_toggle(project_id):
    try:
        data = request.json
        hidden = data.get('hidden', False)
        data_dir = _get_api_data_dir()
        if not data_dir:
            return jsonify({'error': 'Директория data не найдена'}), 404
        path = data_dir / 'projects.json'
        if not path.exists():
            return jsonify({'error': 'projects.json не найден'}), 404
        with open(path, 'r', encoding='utf-8') as f:
            projects = json.load(f)
        idx = next((i for i, p in enumerate(projects) if p.get('id') == project_id), -1)
        if idx == -1:
            return jsonify({'error': 'Проект не найден'}), 404
        
        projects[idx]['hidden'] = hidden
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(projects, f, ensure_ascii=False, indent=4)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
@app.route('/api/dream-data/projects/<project_id>', methods=['DELETE'])


def api_dream_data_projects_delete(project_id):

    """Удалить проект из projects.json"""

    try:

        data_dir = _get_api_data_dir()

        path = data_dir / 'projects.json'

        if not path.exists():

            return jsonify({'error': 'projects.json не найден'}), 404

        with open(path, 'r', encoding='utf-8') as f:

            projects = json.load(f)

        new_projects = [p for p in projects if p.get('id') != project_id]

        if len(new_projects) == len(projects):

            return jsonify({'error': f'Проект "{project_id}" не найден'}), 404

        with open(path, 'w', encoding='utf-8') as f:

            json.dump(new_projects, f, ensure_ascii=False, indent=4)

        return jsonify({'success': True})

    except Exception as e:

        return jsonify({'error': str(e)}), 500

@app.route('/api/dream-data/status', methods=['GET'])



def api_dream_data_status_get():

    """Получить статус сервиса"""

    try:

        data_dir = _get_api_data_dir()

        path = data_dir / 'status.json'

        if not path.exists():

            return jsonify({'status': 'unknown'})

        with open(path, 'r', encoding='utf-8') as f:

            return jsonify(json.load(f))

    except Exception as e:

        return jsonify({'error': str(e)}), 500

@app.route('/api/dream-data/status', methods=['PUT'])



def api_dream_data_status_update():

    """Обновить статус сервиса"""

    try:

        data_dir = _get_api_data_dir()

        path = data_dir / 'status.json'

        new_status = request.get_json()

        if not new_status or 'status' not in new_status:

            return jsonify({'error': 'status обязателен'}), 400

        allowed = {'available', 'maintenance', 'unavailable'}

        if new_status['status'] not in allowed:

            return jsonify({'error': f'status должен быть одним из: {", ".join(allowed)}'}), 400

        current = {}

        if path.exists():

            with open(path, 'r', encoding='utf-8') as f:

                current = json.load(f)

        current['status'] = new_status['status']
        current['contact'] = new_status.get('contact', 'dreamcatch_r')

        current['last_updated'] = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')

        data_dir.mkdir(parents=True, exist_ok=True)

        with open(path, 'w', encoding='utf-8') as f:

            json.dump(current, f, ensure_ascii=False, indent=4)

        return jsonify({'success': True, 'status': current})

    except Exception as e:

        return jsonify({'error': str(e)}), 500

# Регистрируем публичный read-only API (после определения всех функций)

try:

    from app_api import api_blueprint

    app.register_blueprint(api_blueprint)

except ImportError:

    pass  # Если модуль не найден, пропускаем

# Регистрируем API для управления Cloudflare
try:
    from app_cloudflare import cloudflare_blueprint
    app.register_blueprint(cloudflare_blueprint)
except ImportError:
    pass

if __name__ == '__main__':

    app.run(host='0.0.0.0', port=PORT, debug=False)
