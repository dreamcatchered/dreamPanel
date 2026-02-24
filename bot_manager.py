"""
Bot Manager - управление ботами через subprocess (без systemd)
Боты работают пока работает админ-панель
"""
import subprocess
import threading
import time
import re
import json
import os
import shutil
import tempfile
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from collections import deque

# Глобальное хранилище процессов ботов
_bot_processes: Dict[str, dict] = {}
_bot_logs: Dict[str, deque] = {}
_bot_lock = threading.Lock()

MAX_LOG_LINES = 1000
PYTHON_BIN = '/usr/bin/python3'

# Паттерны для поиска недостающих модулей
IMPORT_ERROR_PATTERNS = [
    r"ModuleNotFoundError: No module named ['\"]([^'\"]+)['\"]",
    r"ImportError: No module named ['\"]?([^'\"]+)['\"]?",
    r"No module named ['\"]([^'\"]+)['\"]",
]

# Маппинг имён модулей на pip пакеты (для популярных случаев)
MODULE_TO_PACKAGE = {
    'cv2': 'opencv-python',
    'PIL': 'Pillow',
    'sklearn': 'scikit-learn',
    'yaml': 'PyYAML',
    'bs4': 'beautifulsoup4',
    'dotenv': 'python-dotenv',
    'telebot': 'pyTelegramBotAPI',
    'telegram': 'python-telegram-bot',
    'flask': 'Flask',
    'requests': 'requests',
    'aiohttp': 'aiohttp',
    'pytz': 'pytz',
    'jwt': 'PyJWT',
    'redis': 'redis',
    'pymongo': 'pymongo',
    'sqlalchemy': 'SQLAlchemy',
    'psycopg2': 'psycopg2-binary',
    'mysql': 'mysql-connector-python',
    'numpy': 'numpy',
    'pandas': 'pandas',
}


def get_package_name(module_name: str) -> str:
    """Получить имя pip пакета по имени модуля"""
    base_module = module_name.split('.')[0]
    return MODULE_TO_PACKAGE.get(base_module, base_module)


def install_package(package_name: str, python_bin: str = PYTHON_BIN) -> Tuple[bool, str]:
    """Установить pip пакет"""
    try:
        result = subprocess.run(
            [python_bin, '-m', 'pip', 'install', package_name],
            capture_output=True,
            text=True,
            timeout=300
        )
        output = result.stdout + result.stderr
        return result.returncode == 0, output
    except Exception as e:
        return False, str(e)


def parse_import_error(error_text: str) -> Optional[str]:
    """Извлечь имя модуля из ошибки импорта"""
    for pattern in IMPORT_ERROR_PATTERNS:
        match = re.search(pattern, error_text)
        if match:
            return match.group(1)
    return None


def _log_output(bot_name: str, line: str, stream: str = 'stdout'):
    """Добавить строку в лог бота"""
    with _bot_lock:
        if bot_name not in _bot_logs:
            _bot_logs[bot_name] = deque(maxlen=MAX_LOG_LINES)
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        prefix = '' if stream == 'stdout' else '[ERR] '
        _bot_logs[bot_name].append(f"[{timestamp}] {prefix}{line}")


def _read_stream(bot_name: str, stream, stream_name: str):
    """Читать поток вывода процесса"""
    try:
        for line in iter(stream.readline, ''):
            if not line:
                break
            _log_output(bot_name, line.rstrip(), stream_name)
    except Exception:
        pass


def _bot_runner(bot_name: str, bot_dir: Path, entrypoint: str, python_bin: str, auto_install: bool = True):
    """Запустить бота и следить за процессом"""
    max_retries = 5
    retry_count = 0
    installed_packages = set()
    
    while retry_count < max_retries:
        with _bot_lock:
            if bot_name not in _bot_processes:
                return
            if _bot_processes[bot_name].get('stop_requested'):
                _bot_processes[bot_name]['running'] = False
                _bot_processes[bot_name]['pid'] = None
                return
        
        _log_output(bot_name, f"=== Запуск бота (попытка {retry_count + 1}/{max_retries}) ===")
        
        try:
            env = os.environ.copy()
            env['PYTHONUNBUFFERED'] = '1'
            
            # Загрузить .env если есть
            env_file = bot_dir / '.env'
            if env_file.exists():
                try:
                    for line in env_file.read_text().splitlines():
                        line = line.strip()
                        if line and not line.startswith('#') and '=' in line:
                            key, _, value = line.partition('=')
                            env[key.strip()] = value.strip().strip('"\'')
                except Exception:
                    pass
            
            process = subprocess.Popen(
                [python_bin, str(bot_dir / entrypoint)],
                cwd=str(bot_dir),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env,
                bufsize=1
            )
            
            with _bot_lock:
                if bot_name in _bot_processes:
                    _bot_processes[bot_name]['pid'] = process.pid
                    _bot_processes[bot_name]['running'] = True
                    _bot_processes[bot_name]['process'] = process
                    _bot_processes[bot_name]['started_at'] = datetime.now().isoformat()
            
            _log_output(bot_name, f"Процесс запущен с PID {process.pid}")
            
            # Читать stdout и stderr в отдельных потоках
            stdout_thread = threading.Thread(
                target=_read_stream, 
                args=(bot_name, process.stdout, 'stdout'),
                daemon=True
            )
            stderr_thread = threading.Thread(
                target=_read_stream, 
                args=(bot_name, process.stderr, 'stderr'),
                daemon=True
            )
            stdout_thread.start()
            stderr_thread.start()
            
            # Ждать завершения процесса
            exit_code = process.wait()
            
            stdout_thread.join(timeout=1)
            stderr_thread.join(timeout=1)
            
            _log_output(bot_name, f"Процесс завершился с кодом {exit_code}")
            
            with _bot_lock:
                if bot_name in _bot_processes:
                    _bot_processes[bot_name]['running'] = False
                    _bot_processes[bot_name]['pid'] = None
                    _bot_processes[bot_name]['exit_code'] = exit_code
            
            # Проверить на ошибку импорта
            if exit_code != 0 and auto_install:
                recent_logs = get_bot_logs(bot_name, lines=50)
                missing_module = parse_import_error(recent_logs)
                
                if missing_module and missing_module not in installed_packages:
                    package_name = get_package_name(missing_module)
                    _log_output(bot_name, f"=== Обнаружен недостающий модуль: {missing_module} ===")
                    _log_output(bot_name, f"=== Устанавливаю пакет: {package_name} ===")
                    
                    ok, output = install_package(package_name, python_bin)
                    for line in output.splitlines():
                        _log_output(bot_name, f"[pip] {line}")
                    
                    if ok:
                        installed_packages.add(missing_module)
                        _log_output(bot_name, f"=== Пакет {package_name} установлен, перезапуск... ===")
                        retry_count += 1
                        time.sleep(1)
                        continue
                    else:
                        _log_output(bot_name, f"=== Ошибка установки пакета {package_name} ===")
            
            # Если процесс завершился с ошибкой и это не запрос на остановку
            with _bot_lock:
                if bot_name in _bot_processes and _bot_processes[bot_name].get('stop_requested'):
                    return
            
            if exit_code != 0:
                retry_count += 1
                _log_output(bot_name, f"=== Перезапуск через 5 секунд... ===")
                time.sleep(5)
            else:
                # Нормальное завершение
                return
                
        except Exception as e:
            _log_output(bot_name, f"Ошибка запуска: {str(e)}")
            retry_count += 1
            time.sleep(5)
    
    _log_output(bot_name, f"=== Превышено максимальное количество попыток запуска ===")


def start_bot(bot_name: str, bot_dir: Path, entrypoint: str, python_bin: str = PYTHON_BIN) -> Tuple[bool, str]:
    """Запустить бота"""
    with _bot_lock:
        if bot_name in _bot_processes and _bot_processes[bot_name].get('running'):
            return False, "Бот уже запущен"
        
        _bot_processes[bot_name] = {
            'running': False,
            'pid': None,
            'stop_requested': False,
            'enabled': True,
            'bot_dir': str(bot_dir),
            'entrypoint': entrypoint,
            'python_bin': python_bin,
        }
    
    # Запустить в отдельном потоке
    thread = threading.Thread(
        target=_bot_runner,
        args=(bot_name, bot_dir, entrypoint, python_bin),
        daemon=True
    )
    thread.start()
    
    return True, "Бот запускается"


def stop_bot(bot_name: str) -> Tuple[bool, str]:
    """Остановить бота"""
    with _bot_lock:
        if bot_name not in _bot_processes:
            return False, "Бот не найден"
        
        info = _bot_processes[bot_name]
        info['stop_requested'] = True
        info['enabled'] = False
        
        process = info.get('process')
        if process and process.poll() is None:
            try:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                _log_output(bot_name, "=== Бот остановлен ===")
            except Exception as e:
                return False, str(e)
        
        info['running'] = False
        info['pid'] = None
    
    return True, "Бот остановлен"


def restart_bot(bot_name: str) -> Tuple[bool, str]:
    """Перезапустить бота"""
    with _bot_lock:
        if bot_name not in _bot_processes:
            return False, "Бот не найден"
        info = _bot_processes[bot_name]
        bot_dir = Path(info['bot_dir'])
        entrypoint = info['entrypoint']
        python_bin = info.get('python_bin', PYTHON_BIN)
    
    stop_bot(bot_name)
    time.sleep(1)
    return start_bot(bot_name, bot_dir, entrypoint, python_bin)


def get_bot_status(bot_name: str) -> dict:
    """Получить статус бота"""
    with _bot_lock:
        if bot_name not in _bot_processes:
            return {'running': False, 'enabled': False, 'pid': None}
        
        info = _bot_processes[bot_name]
        process = info.get('process')
        
        # Проверить реальный статус процесса
        if process and process.poll() is not None:
            info['running'] = False
            info['pid'] = None
        
        return {
            'running': info.get('running', False),
            'enabled': info.get('enabled', False),
            'pid': info.get('pid'),
            'started_at': info.get('started_at'),
            'exit_code': info.get('exit_code'),
        }


def get_bot_logs(bot_name: str, lines: int = 100) -> str:
    """Получить логи бота"""
    with _bot_lock:
        if bot_name not in _bot_logs:
            return "Нет логов"
        logs = list(_bot_logs[bot_name])
    
    return '\n'.join(logs[-lines:])


def get_all_bots_status() -> Dict[str, dict]:
    """Получить статус всех ботов"""
    with _bot_lock:
        result = {}
        for name, info in _bot_processes.items():
            process = info.get('process')
            if process and process.poll() is not None:
                info['running'] = False
                info['pid'] = None
            
            result[name] = {
                'running': info.get('running', False),
                'enabled': info.get('enabled', False),
                'pid': info.get('pid'),
            }
        return result


def enable_bot(bot_name: str, bot_dir: Path, entrypoint: str, python_bin: str = PYTHON_BIN) -> Tuple[bool, str]:
    """Включить автозапуск бота (и запустить если не запущен)"""
    with _bot_lock:
        if bot_name in _bot_processes:
            _bot_processes[bot_name]['enabled'] = True
            if _bot_processes[bot_name].get('running'):
                return True, "Автозапуск включен"
    
    return start_bot(bot_name, bot_dir, entrypoint, python_bin)


def disable_bot(bot_name: str) -> Tuple[bool, str]:
    """Отключить автозапуск бота (не останавливает)"""
    with _bot_lock:
        if bot_name in _bot_processes:
            _bot_processes[bot_name]['enabled'] = False
            return True, "Автозапуск отключен"
    return False, "Бот не найден"


def cleanup_bot(bot_name: str):
    """Очистить данные бота при удалении"""
    stop_bot(bot_name)
    with _bot_lock:
        _bot_processes.pop(bot_name, None)
        _bot_logs.pop(bot_name, None)


def get_pid_resources(pid: int) -> Tuple[int, float]:
    """Получить использование памяти и CPU процессом"""
    try:
        with open(f'/proc/{pid}/statm', 'r') as f:
            parts = f.read().split()
            rss_pages = int(parts[1])
            rss_bytes = rss_pages * 4096
        
        with open(f'/proc/{pid}/stat', 'r') as f:
            parts = f.read().split()
            utime = int(parts[13])
            stime = int(parts[14])
            total_time = utime + stime
            cpu_percent = total_time / os.sysconf(os.sysconf_names['SC_CLK_TCK'])
        
        return rss_bytes, cpu_percent
    except Exception:
        return 0, 0.0
