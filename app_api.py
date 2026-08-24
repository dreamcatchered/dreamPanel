"""
Read-only API для внешнего доступа
Только просмотр, никаких действий
"""

import os
import shlex
import json
from functools import wraps
from flask import Blueprint, jsonify, request
from pathlib import Path
from utils import safe_run, discover_services, get_system_metrics

# Импортируем пути из app.py (lazy import)
def get_app_paths():
    from app import PROJECTS_DIR, WWW_DIR, NGINX_SITES_DIR
    return PROJECTS_DIR, WWW_DIR, NGINX_SITES_DIR

api_blueprint = Blueprint('api', __name__, url_prefix='/api/public')

# Секретный ключ для API. Если не задан, API отключен из соображений безопасности.
API_TOKEN = os.environ.get('API_PUBLIC_TOKEN')

def require_api_token(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not API_TOKEN:
            return "Not Found", 404
        
        auth_header = request.headers.get('Authorization')
        token = None
        
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
        
        if not token:
            token = request.args.get('token')
            
        if token != API_TOKEN:
            return "Not Found", 404
            
        return f(*args, **kwargs)
    return decorated

@api_blueprint.route('/services')
def api_public_services():
    """Публичный API: Список сервисов (только безопасные, публичные)"""
    from app import get_service_state, _get_settings
    settings = _get_settings()
    
    if not settings.get('status_page_enabled', True):
        return jsonify({"services": []}), 403

    services = discover_services()
    public_units = set(settings.get('public_services', []))

    result = []

    for svc in services:
        if svc["unit"] not in public_units:
            continue

        state = get_service_state(svc["unit"])
        result.append({
            "unit": svc["unit"],
            "name": svc["name"],
            "description": svc["description"],
            "state": state.get("ActiveState", "unknown"),
            "substate": state.get("SubState", "-"),
            "enabled": state.get("UnitFileState", "unknown"),
        })

    return jsonify({"services": result})

@api_blueprint.route('/metrics')
@require_api_token
def api_public_metrics():
    """Публичный API: Системные метрики (только просмотр)"""
    return jsonify(get_system_metrics())

@api_blueprint.route('/sites')
@require_api_token
def api_public_sites():
    """Публичный API: Список сайтов (только просмотр)"""
    _, WWW_DIR, _ = get_app_paths()
    sites = []

    if WWW_DIR.exists():
        for item in WWW_DIR.iterdir():
            if item.is_dir() and not item.name.startswith('.'):
                sites.append({
                    'name': item.name,
                    'path': str(item),
                })

    return jsonify({"sites": sites})

@api_blueprint.route('/nginx')
@require_api_token
def api_public_nginx():
    """Публичный API: Список nginx конфигов (только просмотр)"""
    _, _, NGINX_SITES_DIR = get_app_paths()
    configs = []

    if NGINX_SITES_DIR.exists():
        for config_file in NGINX_SITES_DIR.iterdir():
            if config_file.is_file():
                try:
                    content = config_file.read_text(encoding="utf-8")
                    server_names = []
                    for line in content.splitlines():
                        if 'server_name' in line and not line.strip().startswith('#'):
                            parts = line.split('server_name')[1].strip().rstrip(';').split()
                            server_names.extend(parts)

                    configs.append({
                        'name': config_file.name,
                        'server_names': server_names,
                    })
                except:
                    pass

    return jsonify({"configs": configs})

@api_blueprint.route('/projects')
@require_api_token
def api_public_projects():
    """Публичный API: Список проектов из projects.json"""
    from app import _get_api_data_dir
    try:
        data_dir = _get_api_data_dir()
        path = data_dir / 'projects.json'
        if not path.exists():
            return jsonify([])
        with open(path, 'r', encoding='utf-8') as f:
            projects = json.load(f)
            # Отдаем только те, что помечены для dreamID
            public_projects = [p for p in projects if p.get('dreamid')]
            return jsonify(public_projects)
    except Exception as e:
        return jsonify({'error': str(e)}), 500
