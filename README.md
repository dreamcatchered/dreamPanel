# dreamPanel

A self-hosted web admin panel + Telegram bot for managing your Linux server.

Deploy on any server to get a clean web dashboard for controlling systemd services, managing files, configuring nginx proxies and monitoring everything — from a browser or Telegram bot.

## Features

- systemd service management (start / stop / restart / status / logs)
- File manager with web editor (allowlist-based read/write roots)
- Nginx proxy & static site configurator with path-based proxy rules
- SSL certificate management (certbot integration)
- Backup system (full-server bundles or per-site/per-project archives)
- Telegram bot manager: deploy, run and monitor multiple bots from the panel
- Cloudflare DNS records management (`app_cloudflare.py`, token via env)
- Projects catalog ("microservices") driven by a JSON data directory
- Public status page + interactive web console presets
- DreamID SSO authentication and Telegram WebApp login
- Demo mode (`/demo`) with static demo data

## Security

This release includes a security audit pass. Summary of the hardening:

- **No hardcoded credentials.** All secrets (bot tokens, admin password, Flask `SECRET_KEY`, SSO `client_secret`, Cloudflare API token) are read exclusively from environment variables. `env.example` contains placeholders only.
- **No default admin password.** If `ADMIN_PASSWORD`/`ADMIN_PASSWORD_HASH` are not set, a random temporary password is generated at startup and printed once to the console.
- **Password hashing.** Form login verifies against a Werkzeug password hash; set `ADMIN_PASSWORD_HASH` to avoid storing plaintext passwords in `.env`.
- **Hardened session cookies.** `HttpOnly`, `Secure`, `SameSite=Lax`, 1-hour lifetime. `SECRET_KEY` falls back to a per-process random value instead of a constant.
- **Rate limiting** via flask-limiter on all routes.
- **Security headers** on every response: CSP, HSTS, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`.
- **File manager sandboxing.** Explicit write/read root allowlists with symlink-safe path resolution; full-filesystem read access is opt-in via `FILE_MANAGER_ALLOW_READ_ALL`.
- **Backups stored outside the application directory**, configurable via `BACKUPS_DIR`.
- **Server paths are not hardcoded in the frontend.** The panel injects configured directories (projects/bots/backups) into the UI dynamically; defaults are derived from the user's home directory and overridable via `PROJECTS_DIR`/`BOTS_DIR`.
- Runtime state (sessions, logs, uploads, databases, `settings.json`) is excluded from version control.

## Stack

![Python](https://img.shields.io/badge/Python-3776AB?style=flat&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-000000?style=flat&logo=flask&logoColor=white)
![JavaScript](https://img.shields.io/badge/JavaScript-F7DF1E?style=flat&logo=javascript&logoColor=black)
![SQLite](https://img.shields.io/badge/SQLite-003B57?style=flat&logo=sqlite&logoColor=white)

## Setup

```bash
pip install -r requirements.txt
cp env.example .env
# Fill in your values in .env
python run.py
```

## Configuration

```env
TELEGRAM_BOT_TOKEN=your_bot_token
ADMIN_TELEGRAM_ID=your_telegram_id
ADMIN_USERNAME=admin
ADMIN_PASSWORD_HASH=your_werkzeug_password_hash
DREAMID_CLIENT_SECRET=your_sso_secret
CLOUDFLARE_API_TOKEN=your_cloudflare_api_token
SECRET_KEY=your_flask_secret
```

See `env.example` for the full list of supported variables (ports, alerts, backup paths, file manager limits, etc.).

## Contact

Telegram: [@dreamcatch_r](https://t.me/dreamcatch_r)

---

# dreamPanel (RU)

Самостоятельно размещаемая веб-админка + Telegram-бот для управления вашим Linux-сервером.

Разверните на любом сервере и получите аккуратную веб-панель для управления systemd-сервисами, файлами, настройки nginx-прокси и мониторинга — из браузера или через Telegram-бота.

## Возможности

- Управление systemd-сервисами (запуск / остановка / перезапуск / статус / логи)
- Файловый менеджер с веб-редактором (чтение/запись только по allowlist)
- Конфигуратор nginx-прокси и статических сайтов с правилами по путям
- Управление SSL-сертификатами (интеграция с certbot)
- Система бэкапов (архивы всего сервера или отдельных сайтов/проектов)
- Менеджер Telegram-ботов: развертывание, запуск и мониторинг нескольких ботов из панели
- Управление DNS-записями Cloudflare (`app_cloudflare.py`, токен через переменные окружения)
- Каталог проектов («микросервисов») на основе JSON-каталога данных
- Публичная страница статуса + интерактивные пресеты веб-консоли
- Аутентификация DreamID SSO и вход через Telegram WebApp
- Демо-режим (`/demo`) со статическими демо-данными

## Безопасность

Этот релиз включает аудит безопасности. Кратко об усилении защиты:

- **Нет захардкоженных учетных данных.** Все секреты (токены ботов, пароль администратора, Flask `SECRET_KEY`, SSO `client_secret`, API-токен Cloudflare) читаются исключительно из переменных окружения. В `env.example` — только плейсхолдеры.
- **Нет пароля администратора по умолчанию.** Если `ADMIN_PASSWORD`/`ADMIN_PASSWORD_HASH` не заданы, при запуске генерируется случайный временный пароль и один раз выводится в консоль.
- **Хеширование паролей.** Вход через форму проверяется по хешу Werkzeug; задайте `ADMIN_PASSWORD_HASH`, чтобы не хранить пароли в `.env` открытым текстом.
- **Усиленные cookie сессий.** `HttpOnly`, `Secure`, `SameSite=Lax`, срок жизни 1 час. `SECRET_KEY` в качестве запасного варианта использует случайное значение на процесс вместо константы.
- **Ограничение частоты запросов** через flask-limiter на всех маршрутах.
- **Заголовки безопасности** в каждом ответе: CSP, HSTS, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`.
- **Изоляция файлового менеджера.** Явные allowlist корней чтения/записи с безопасным разрешением симлинков; полный доступ к файловой системе на чтение включается явно через `FILE_MANAGER_ALLOW_READ_ALL`.
- **Бэкапы хранятся вне каталога приложения**, путь настраивается через `BACKUPS_DIR`.
- **Пути сервера не захардкожены во фронтенде.** Панель динамически передает настроенные каталоги (проекты/боты/бэкапы) в UI; значения по умолчанию выводятся из домашнего каталога пользователя и переопределяются через `PROJECTS_DIR`/`BOTS_DIR`.
- Состояние времени выполнения (сессии, логи, загрузки, базы данных, `settings.json`) исключено из системы контроля версий.

## Стек

![Python](https://img.shields.io/badge/Python-3776AB?style=flat&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-000000?style=flat&logo=flask&logoColor=white)
![JavaScript](https://img.shields.io/badge/JavaScript-F7DF1E?style=flat&logo=javascript&logoColor=black)
![SQLite](https://img.shields.io/badge/SQLite-003B57?style=flat&logo=sqlite&logoColor=white)

## Установка

```bash
pip install -r requirements.txt
cp env.example .env
# Заполните свои значения в .env
python run.py
```

## Настройка

```env
TELEGRAM_BOT_TOKEN=your_bot_token
ADMIN_TELEGRAM_ID=your_telegram_id
ADMIN_USERNAME=admin
ADMIN_PASSWORD_HASH=your_werkzeug_password_hash
DREAMID_CLIENT_SECRET=your_sso_secret
CLOUDFLARE_API_TOKEN=your_cloudflare_api_token
SECRET_KEY=your_flask_secret
```

Полный список поддерживаемых переменных (порты, оповещения, пути бэкапов, лимиты файлового менеджера и т.д.) смотрите в `env.example`.

## Контакты

Telegram: [@dreamcatch_r](https://t.me/dreamcatch_r)
