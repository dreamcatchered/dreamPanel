"""
Запуск админ-бота и Flask веб-панели одновременно
"""

import os
import threading
import time
import sys
from pathlib import Path

# Добавляем текущую директорию в путь
sys.path.insert(0, str(Path(__file__).parent))

# --- load env files (optional) ---
def _load_env_file(path: Path) -> None:
    """
    Простая загрузка KEY=VALUE из файла.
    Не перезаписывает уже заданные переменные окружения.
    """
    try:
        if not path.exists() or not path.is_file():
            return
        for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip("'").strip('"')
            if not key:
                continue
            os.environ.setdefault(key, value)
    except Exception:
        return


_load_env_file(Path("/etc/admin_bot.env"))
_load_env_file(Path(__file__).parent / ".env")

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
    bots_dir = Path(os.environ.get('BOTS_DIR', '/home/dream/bots'))
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
    print(f"🌐 Запуск веб-панели на порту {port}...")
    print("🌐 Панель доступна: https://manage.dreampartners.online")
    
    # Запускаем боты с автозапуском
    start_autostart_bots()
    
    try:
        app.run(host='0.0.0.0', port=port, debug=False, use_reloader=False)
    except Exception as e:
        print(f"❌ Ошибка веб-панели: {e}")

if __name__ == '__main__':
    print("🚀 Запуск админ-панели управления сервером")
    print("=" * 50)
    
    # Запускаем бота в отдельном потоке
    bot_thread = threading.Thread(target=run_bot, daemon=True)
    bot_thread.start()
    
    # Запускаем Flask в главном потоке
    run_web()

