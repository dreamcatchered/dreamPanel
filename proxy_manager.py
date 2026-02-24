"""
Proxy Manager - встроенный reverse proxy для ботов
Позволяет проксировать HTTP запросы к ботам через единый домен
"""
import threading
import logging
import json
from pathlib import Path
from typing import Dict, Optional, Tuple
from datetime import datetime

import httpx

logger = logging.getLogger(__name__)

# Хранилище правил проксирования
_proxy_rules: Dict[str, dict] = {}
_proxy_lock = threading.Lock()

# HTTP клиент для проксирования
_http_client: Optional[httpx.Client] = None

# Файл для сохранения правил
PROXY_RULES_FILE = Path(__file__).parent / 'proxy_rules.json'


def _load_rules():
    """Загрузить правила из файла"""
    global _proxy_rules
    if PROXY_RULES_FILE.exists():
        try:
            with open(PROXY_RULES_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)
                with _proxy_lock:
                    _proxy_rules = {r['path_prefix']: r for r in data}
        except Exception as e:
            logger.error(f"Failed to load proxy rules: {e}")


def _save_rules():
    """Сохранить правила в файл"""
    try:
        with _proxy_lock:
            data = list(_proxy_rules.values())
        with open(PROXY_RULES_FILE, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except Exception as e:
        logger.error(f"Failed to save proxy rules: {e}")


# Загружаем правила при импорте
_load_rules()


def get_http_client() -> httpx.Client:
    """Получить или создать HTTP клиент"""
    global _http_client
    if _http_client is None:
        _http_client = httpx.Client(timeout=30.0, follow_redirects=True)
    return _http_client


def add_proxy_rule(path_prefix: str, target_url: str, description: str = '', enabled: bool = True) -> bool:
    """Добавить правило проксирования"""
    if not path_prefix.startswith('/'):
        path_prefix = '/' + path_prefix
    path_prefix = path_prefix.rstrip('/')
    
    with _proxy_lock:
        _proxy_rules[path_prefix] = {
            'path_prefix': path_prefix,
            'target_url': target_url.rstrip('/'),
            'description': description,
            'enabled': enabled,
            'created_at': datetime.now().isoformat(),
        }
    _save_rules()
    return True


def remove_proxy_rule(path_prefix: str) -> bool:
    """Удалить правило проксирования"""
    if not path_prefix.startswith('/'):
        path_prefix = '/' + path_prefix
    path_prefix = path_prefix.rstrip('/')
    
    with _proxy_lock:
        if path_prefix in _proxy_rules:
            del _proxy_rules[path_prefix]
            _save_rules()
            return True
    return False


def toggle_proxy_rule(path_prefix: str) -> bool:
    """Переключить состояние правила"""
    if not path_prefix.startswith('/'):
        path_prefix = '/' + path_prefix
    path_prefix = path_prefix.rstrip('/')
    
    with _proxy_lock:
        if path_prefix in _proxy_rules:
            _proxy_rules[path_prefix]['enabled'] = not _proxy_rules[path_prefix]['enabled']
            _save_rules()
            return True
    return False


def get_proxy_rules() -> list:
    """Получить все правила"""
    with _proxy_lock:
        return list(_proxy_rules.values())


def get_proxy_rule(path_prefix: str) -> Optional[dict]:
    """Получить правило по префиксу"""
    if not path_prefix.startswith('/'):
        path_prefix = '/' + path_prefix
    path_prefix = path_prefix.rstrip('/')
    
    with _proxy_lock:
        return _proxy_rules.get(path_prefix)


def find_matching_rule(full_path: str) -> Optional[dict]:
    """Найти подходящее правило для пути"""
    if not full_path:
        return None
    
    if not full_path.startswith('/'):
        full_path = '/' + full_path
    
    # Получаем первый сегмент пути
    parts = full_path.split('/')
    if len(parts) < 2:
        return None
    
    first_segment = '/' + parts[1]
    
    with _proxy_lock:
        rule = _proxy_rules.get(first_segment)
        if rule and rule.get('enabled'):
            return rule
    return None


def forward_request(rule: dict, full_path: str, method: str, headers: dict, 
                    params: dict, body: bytes) -> Tuple[int, dict, bytes]:
    """
    Проксировать запрос на целевой сервис.
    Возвращает (status_code, headers, content)
    """
    path_prefix = rule['path_prefix']
    target_url = rule['target_url']
    
    # Вычисляем подпуть (убираем префикс)
    if full_path.startswith(path_prefix):
        subpath = full_path[len(path_prefix):]
    else:
        subpath = full_path
    
    # Формируем финальный URL
    if subpath and not subpath.startswith('/'):
        subpath = '/' + subpath
    final_url = target_url + subpath
    
    # Исключаем hop-by-hop заголовки
    excluded_headers = {'content-encoding', 'content-length', 'transfer-encoding', 
                        'connection', 'host', 'keep-alive', 'proxy-authenticate',
                        'proxy-authorization', 'te', 'trailers', 'upgrade'}
    clean_headers = {k: v for k, v in headers.items() if k.lower() not in excluded_headers}
    
    try:
        client = get_http_client()
        response = client.request(
            method,
            final_url,
            headers=clean_headers,
            params=params,
            content=body
        )
        
        # Фильтруем заголовки ответа
        excluded_response = {'content-encoding', 'content-length', 'transfer-encoding', 'connection'}
        resp_headers = {k: v for k, v in response.headers.items() if k.lower() not in excluded_response}
        
        return response.status_code, resp_headers, response.content
        
    except httpx.RequestError as e:
        logger.error(f"Proxy error to {final_url}: {e}")
        return 502, {}, b"Bad Gateway: Upstream service unavailable"
    except Exception as e:
        logger.error(f"Unexpected proxy error: {e}")
        return 500, {}, b"Internal Server Error"
