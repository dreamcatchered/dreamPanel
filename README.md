# dreamPanel

A self-hosted web admin panel + Telegram bot for managing your Linux server.

Deploy on any server to get a clean web dashboard for controlling systemd services, managing files, configuring nginx proxies and monitoring everything — from a browser or Telegram bot.

## Features

- systemd service management (start / stop / restart / status / logs)
- File manager with web editor
- Nginx proxy configurator
- SSL certificate management (certbot integration)
- Telegram bot for remote control
- DreamID SSO authentication

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
DREAMID_CLIENT_SECRET=your_sso_secret
SECRET_KEY=your_flask_secret
```

## Contact

Telegram: [@dreamcatch_r](https://t.me/dreamcatch_r)
