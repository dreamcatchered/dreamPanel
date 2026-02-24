"""
Read-only API для внешнего доступа
Только просмотр, никаких действий
"""

from flask import Blueprint, jsonify
from pathlib import Path
import shlex

# Импортируем функции из app.py
# ВАЖНО: импорт должен быть после определения app, поэтому используем lazy import
def get_app_functions():
    from app import safe_run, discover_services, get_service_state, get_system_metrics
    from app import PROJECTS_DIR, WWW_DIR, NGINX_SITES_DIR
    return safe_run, discover_services, get_service_state, get_system_metrics, PROJECTS_DIR, WWW_DIR, NGINX_SITES_DIR

api_blueprint = Blueprint('api', __name__, url_prefix='/api/public')


@api_blueprint.route('/services')
def api_public_services():
    """Публичный API: Список сервисов (только безопасные, публичные)"""
    _, discover_services, get_service_state, _, _, _, _ = get_app_functions()
    services = discover_services()
    
    # Список безопасных сервисов для публичного отображения (из dev/index.html)
    SAFE_SERVICES = {
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
    }
    
    result = []
    
    for svc in services:
        # Фильтруем только безопасные сервисы
        if svc["unit"] not in SAFE_SERVICES:
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
def api_public_metrics():
    """Публичный API: Системные метрики (только просмотр)"""
    _, _, _, get_system_metrics, _, _, _ = get_app_functions()
    return jsonify(get_system_metrics())


@api_blueprint.route('/sites')
def api_public_sites():
    """Публичный API: Список сайтов (только просмотр)"""
    _, _, _, _, _, WWW_DIR, _ = get_app_functions()
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
def api_public_nginx():
    """Публичный API: Список nginx конфигов (только просмотр)"""
    _, _, _, _, _, _, NGINX_SITES_DIR = get_app_functions()
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

