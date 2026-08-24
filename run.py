"""
Запуск админ-бота и Flask веб-панели одновременно
"""

import os
import threading
import time
import sys
from pathlib import Path
from dotenv import load_dotenv

# Добавляем текущую директорию в путь
sys.path.insert(0, str(Path(__file__).parent))

# Загружаем переменные окружения из .env
load_dotenv()
if Path("/etc/admin_bot.env").exists():
    load_dotenv("/etc/admin_bot.env")

# Импортируем бота и Flask приложение
from bot import bot, main as bot_main
from app import app
import bot_manager as bm
from pathlib import Path
import json

def run_bot():
    """Запуск Telegram бота в отдельном потоке."""
    print("🤖 Запуск Telegram бота...")
    try:
        bot_main()
    except Exception as e:
        print(f"❌ Ошибка бота: {e}")
        time.sleep(5)
        run_bot()  # Перезапуск при ошибке

def start_autostart_bots():
    """Запуск ботов с включенным автозапуском"""
    bots_dir = Path(os.environ.get('BOTS_DIR', str(Path.home() / 'bots')))
    if not bots_dir.exists():
        return

    print("🤖 Проверка автозапуска ботов...")
    autostart_count = 0

    for bot_dir in sorted(bots_dir.iterdir()):
        if not bot_dir.is_dir() or bot_dir.name.startswith('.'):
            continue

        # Проверяем маркер автозапуска
        marker = bot_dir / '.bot_config.json'
        if not marker.exists():
            continue

        try:
            meta = json.loads(marker.read_text(encoding='utf-8'))
            if meta.get('autostart', False):
                # Запускаем бота
                entrypoint = meta.get('entrypoint')
                python_bin = meta.get('python_bin', '/usr/bin/python3')

                if not entrypoint:
                    # Ищем entrypoint автоматически
                    for name in ('main.py', 'bot.py', 'app.py', 'run.py', 'start.py'):
                        if (bot_dir / name).exists():
                            entrypoint = name
                            break

                if entrypoint and (bot_dir / entrypoint).exists():
                    print(f"  🚀 Автозапуск бота: {bot_dir.name}")
                    ok, msg = bm.start_bot(bot_dir.name, bot_dir, entrypoint, python_bin)
                    if ok:
                        autostart_count += 1
                        print(f"    ✅ {bot_dir.name} запущен")
                    else:
                        print(f"    ❌ {bot_dir.name}: {msg}")
                else:
                    print(f"    ⚠️ {bot_dir.name}: не найден entrypoint")
        except Exception as e:
            print(f"    ❌ {bot_dir.name}: ошибка автозапуска - {e}")

    if autostart_count > 0:
        print(f"✅ Автозапущено ботов: {autostart_count}")
    else:
        print("ℹ️ Нет ботов с автозапуском")

def run_web():
    """Запуск Flask веб-панели в отдельном потоке."""
    port = int(os.environ.get("PORT", "5001"))
    panel_url = os.environ.get("PANEL_URL", "https://manage.dreampartners.online")
    print(f"🌐 Запуск веб-панели на порту {port}...")
    print(f"🌐 Панель доступна: {panel_url}")

    # Запускаем боты с автозапуском
    start_autostart_bots()

    try:
        app.run(host='0.0.0.0', port=port, debug=False, use_reloader=False)
    except Exception as e:
        print(f"❌ Ошибка веб-панели: {e}")

if __name__ == '__main__':
    print("🚀 Запуск админ-панели управления сервером")
    print("=" * 50)

    # Запускаем бота в отдельном потоке (можно отключить через BOT_ENABLED=0,
    # например если этот же бот-токен уже работает на другом сервере)
    if os.environ.get("BOT_ENABLED", "1").lower() in ("1", "true", "yes", "y", "on"):
        bot_thread = threading.Thread(target=run_bot, daemon=True)
        bot_thread.start()
    else:
        print("🤖 Telegram-бот отключен (BOT_ENABLED=0)")

    # Запускаем Flask в главном потоке
    run_web()
