import os
import requests
from flask import Blueprint, jsonify, request

cloudflare_blueprint = Blueprint('cloudflare', __name__, url_prefix='/api/cloudflare')

# CLOUDFLARE_API_TOKEN задаётся через .env (обязательно!)
CF_API_TOKEN = os.environ.get('CLOUDFLARE_API_TOKEN', '')
CF_API_BASE = 'https://api.cloudflare.com/client/v4'

def _get_headers():
    token = CF_API_TOKEN
    return {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json'
    }

@cloudflare_blueprint.route('/zones', methods=['GET'])
def list_zones():
    try:
        resp = requests.get(f'{CF_API_BASE}/zones', headers=_get_headers(), timeout=10)
        data = resp.json()
        if not data.get('success'):
            return jsonify({'success': False, 'error': data.get('errors', [{'message': 'Unknown error'}])[0]['message']}), 400
        return jsonify({'success': True, 'zones': data.get('result', [])})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@cloudflare_blueprint.route('/zones/<zone_id>/dns_records', methods=['GET'])
def list_dns_records(zone_id):
    try:
        resp = requests.get(f'{CF_API_BASE}/zones/{zone_id}/dns_records', headers=_get_headers(), timeout=10)
        data = resp.json()
        if not data.get('success'):
            return jsonify({'success': False, 'error': data.get('errors', [{'message': 'Unknown error'}])[0]['message']}), 400
        return jsonify({'success': True, 'records': data.get('result', [])})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@cloudflare_blueprint.route('/zones/<zone_id>/dns_records', methods=['POST'])
def add_dns_record(zone_id):
    try:
        payload = request.json
        resp = requests.post(f'{CF_API_BASE}/zones/{zone_id}/dns_records', headers=_get_headers(), json=payload, timeout=10)
        data = resp.json()
        if not data.get('success'):
            return jsonify({'success': False, 'error': data.get('errors', [{'message': 'Unknown error'}])[0]['message']}), 400
        return jsonify({'success': True, 'record': data.get('result')})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@cloudflare_blueprint.route('/zones/<zone_id>/dns_records/<record_id>', methods=['DELETE'])
def delete_dns_record(zone_id, record_id):
    try:
        resp = requests.delete(f'{CF_API_BASE}/zones/{zone_id}/dns_records/{record_id}', headers=_get_headers(), timeout=10)
        data = resp.json()
        if not data.get('success'):
            return jsonify({'success': False, 'error': data.get('errors', [{'message': 'Unknown error'}])[0]['message']}), 400
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@cloudflare_blueprint.route('/zones/<zone_id>/dns_records/<record_id>', methods=['PUT', 'PATCH'])
def update_dns_record(zone_id, record_id):
    try:
        payload = request.json
        resp = requests.put(f'{CF_API_BASE}/zones/{zone_id}/dns_records/{record_id}', headers=_get_headers(), json=payload, timeout=10)
        data = resp.json()
        if not data.get('success'):
            return jsonify({'success': False, 'error': data.get('errors', [{'message': 'Unknown error'}])[0]['message']}), 400
        return jsonify({'success': True, 'record': data.get('result')})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
