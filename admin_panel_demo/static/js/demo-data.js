// Демо-данные для панели управления

const DEMO_DATA = {
    services: [
        {
            unit: 'dreamgpt.service',
            name: 'dreamGPT AI',
            description: 'AI платформа с поддержкой GPT-4 и работы с документами',
            state: 'active',
            substate: 'running',
            enabled: 'enabled',
            pid: 12345,
            rss_bytes: 512 * 1024 * 1024, // 512 MB
            cpu_percent: 12.5
        },
        {
            unit: 'dreamshare.service',
            name: 'dreamShare',
            description: 'Сервис быстрой передачи файлов между устройствами',
            state: 'active',
            substate: 'running',
            enabled: 'enabled',
            pid: 12346,
            rss_bytes: 128 * 1024 * 1024, // 128 MB
            cpu_percent: 3.2
        },
        {
            unit: 'dreampartners.service',
            name: 'dreamPartners CPA',
            description: 'CPA платформа для партнерских программ',
            state: 'active',
            substate: 'running',
            enabled: 'enabled',
            pid: 12347,
            rss_bytes: 256 * 1024 * 1024, // 256 MB
            cpu_percent: 8.1
        },
        {
            unit: 'swagplayer.service',
            name: 'SwagPlayer',
            description: 'Музыкальный сервис',
            state: 'active',
            substate: 'running',
            enabled: 'enabled',
            pid: 12348,
            rss_bytes: 64 * 1024 * 1024, // 64 MB
            cpu_percent: 2.5
        },
        {
            unit: 'nginx.service',
            name: 'Nginx',
            description: 'Веб-сервер и обратный прокси',
            state: 'active',
            substate: 'running',
            enabled: 'enabled',
            pid: 12349,
            rss_bytes: 32 * 1024 * 1024, // 32 MB
            cpu_percent: 1.8
        },
        {
            unit: 'postgresql.service',
            name: 'PostgreSQL',
            description: 'База данных PostgreSQL',
            state: 'active',
            substate: 'running',
            enabled: 'enabled',
            pid: 12350,
            rss_bytes: 384 * 1024 * 1024, // 384 MB
            cpu_percent: 5.3
        },
        {
            unit: 'redis.service',
            name: 'Redis',
            description: 'Кэш и хранилище данных в памяти',
            state: 'active',
            substate: 'running',
            enabled: 'enabled',
            pid: 12351,
            rss_bytes: 48 * 1024 * 1024, // 48 MB
            cpu_percent: 0.9
        }
    ],

    sites: [
        {
            domain: 'dreampartners.ru',
            path: '/var/www/dreampartners',
            enabled: true,
            ssl: true,
            nginx_config: 'dreampartners.ru'
        },
        {
            domain: 'ai.dreampartners.online',
            path: '/var/www/dreamgpt',
            enabled: true,
            ssl: true,
            nginx_config: 'ai.dreampartners.online'
        },
        {
            domain: 'share.dreampartners.online',
            path: '/var/www/dreamshare',
            enabled: true,
            ssl: true,
            nginx_config: 'share.dreampartners.online'
        },
        {
            domain: 'swag.dreampartners.online',
            path: '/var/www/swagplayer',
            enabled: true,
            ssl: true,
            nginx_config: 'swag.dreampartners.online'
        },
        {
            domain: 'auth.dreampartners.online',
            path: '/var/www/dreamid',
            enabled: true,
            ssl: true,
            nginx_config: 'auth.dreampartners.online'
        }
    ],

    nginx: [
        {
            name: 'dreampartners.ru',
            path: '/etc/nginx/sites-enabled/dreampartners.ru',
            enabled: true
        },
        {
            name: 'ai.dreampartners.online',
            path: '/etc/nginx/sites-enabled/ai.dreampartners.online',
            enabled: true
        },
        {
            name: 'share.dreampartners.online',
            path: '/etc/nginx/sites-enabled/share.dreampartners.online',
            enabled: true
        },
        {
            name: 'swag.dreampartners.online',
            path: '/etc/nginx/sites-enabled/swag.dreampartners.online',
            enabled: true
        },
        {
            name: 'auth.dreampartners.online',
            path: '/etc/nginx/sites-enabled/auth.dreampartners.online',
            enabled: true
        }
    ],

    ssl: {
        certificates: [
            {
                domain: 'dreampartners.ru',
                expiry: '2025-12-18',
                days_left: 365
            },
            {
                domain: 'ai.dreampartners.online',
                expiry: '2025-12-18',
                days_left: 365
            },
            {
                domain: 'share.dreampartners.online',
                expiry: '2025-12-18',
                days_left: 365
            },
            {
                domain: 'swag.dreampartners.online',
                expiry: '2025-12-18',
                days_left: 365
            },
            {
                domain: 'auth.dreampartners.online',
                expiry: '2025-12-18',
                days_left: 365
            }
        ]
    },

    backups: [
        {
            name: 'backup-2025-12-18-10-30.tar.gz',
            size: 2.5 * 1024 * 1024 * 1024, // 2.5 GB
            date: '2025-12-18 10:30:00'
        },
        {
            name: 'backup-2025-12-17-10-30.tar.gz',
            size: 2.4 * 1024 * 1024 * 1024, // 2.4 GB
            date: '2025-12-17 10:30:00'
        },
        {
            name: 'backup-2025-12-16-10-30.tar.gz',
            size: 2.3 * 1024 * 1024 * 1024, // 2.3 GB
            date: '2025-12-16 10:30:00'
        }
    ],

    projects: [
        {
            name: 'dreamgpt',
            path: '/home/user/projects/dreamgpt',
            type: 'flask',
            port: 5000,
            status: 'running'
        },
        {
            name: 'dreamshare',
            path: '/home/user/projects/dreamshare',
            type: 'flask',
            port: 5028,
            status: 'running'
        },
        {
            name: 'dreampartners',
            path: '/home/user/projects/dreampartners',
            type: 'php',
            port: 80,
            status: 'running'
        }
    ],

    metrics: {
        memory_total: 8 * 1024 * 1024 * 1024, // 8 GB
        memory_used: 3.2 * 1024 * 1024 * 1024, // 3.2 GB
        memory_percent: 40,
        disk_total: 500 * 1024 * 1024 * 1024, // 500 GB
        disk_used: 150 * 1024 * 1024 * 1024, // 150 GB
        disk_percent: 30,
        uptime: '15 days, 3 hours',
        load_1min: '0.45',
        load_5min: '0.52',
        load_15min: '0.48'
    },

    // Демо-файлы для файлового менеджера
    files: {
        '/var/www': [
            { name: 'dreampartners', type: 'directory' },
            { name: 'dreamgpt', type: 'directory' },
            { name: 'dreamshare', type: 'directory' },
            { name: 'swagplayer', type: 'directory' },
            { name: 'dreamid', type: 'directory' },
            { name: 'index.html', type: 'file', size: 1024 }
        ],
        '/var/www/dreamshare': [
            { name: 'app.py', type: 'file', size: 15234 },
            { name: 'templates', type: 'directory' },
            { name: 'static', type: 'directory' },
            { name: 'uploads', type: 'directory' },
            { name: 'requirements.txt', type: 'file', size: 256 },
            { name: 'README.md', type: 'file', size: 1024 },
            { name: '.env.example', type: 'file', size: 512 },
            { name: 'config.py', type: 'file', size: 2048 }
        ],
        '/var/www/dreamshare/templates': [
            { name: 'index.html', type: 'file', size: 8192 },
            { name: 'upload.html', type: 'file', size: 4096 }
        ],
        '/var/www/dreamshare/static': [
            { name: 'css', type: 'directory' },
            { name: 'js', type: 'directory' },
            { name: 'images', type: 'directory' }
        ],
        '/var/www/dreamshare/static/css': [
            { name: 'style.css', type: 'file', size: 4096 },
            { name: 'responsive.css', type: 'file', size: 2048 }
        ],
        '/var/www/dreamshare/static/js': [
            { name: 'main.js', type: 'file', size: 8192 },
            { name: 'upload.js', type: 'file', size: 4096 }
        ],
        '/home/user/projects': [
            { name: 'dreamgpt', type: 'directory' },
            { name: 'dreamshare', type: 'directory' },
            { name: 'dreampartners', type: 'directory' }
        ],
        '/home/user/projects/dreamshare': [
            { name: 'app.py', type: 'file', size: 15234 },
            { name: 'run.py', type: 'file', size: 512 },
            { name: 'requirements.txt', type: 'file', size: 256 },
            { name: 'README.md', type: 'file', size: 1024 },
            { name: 'templates', type: 'directory' },
            { name: 'static', type: 'directory' }
        ],
        '/etc/nginx/sites-enabled': [
            { name: 'dreampartners.ru', type: 'file', size: 2048 },
            { name: 'ai.dreampartners.online', type: 'file', size: 2048 },
            { name: 'share.dreampartners.online', type: 'file', size: 2048 },
            { name: 'swag.dreampartners.online', type: 'file', size: 2048 },
            { name: 'auth.dreampartners.online', type: 'file', size: 2048 }
        ]
    },

    // Содержимое демо-файлов
    fileContents: {
        '/var/www/dreamshare/app.py': `from flask import Flask, render_template

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5028)`,

        '/var/www/dreamshare/requirements.txt': `Flask==3.0.0
Werkzeug==3.0.1`,

        '/var/www/dreamshare/README.md': `# dreamShare

Сервис быстрой передачи файлов между устройствами.

## Возможности

- Передача файлов до 10 GB
- Синхронизация между устройствами
- WebSocket для реального времени
- Безопасное шифрование`,

        '/etc/nginx/sites-enabled/share.dreampartners.online': `server {
    listen 80;
    server_name share.dreampartners.online;

    location / {
        proxy_pass http://127.0.0.1:5028;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}`,

        '/var/www/dreamshare/config.py': `import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key'
    UPLOAD_FOLDER = 'uploads'
    MAX_CONTENT_LENGTH = 10 * 1024 * 1024 * 1024  # 10 GB
    ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'zip', 'tar', 'gz'}`,

        '/var/www/dreamshare/static/css/style.css': `body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    margin: 0;
    padding: 0;
    background: #f5f5f5;
}

.container {
    max-width: 1200px;
    margin: 0 auto;
    padding: 20px;
}

.upload-area {
    border: 2px dashed #ccc;
    border-radius: 8px;
    padding: 40px;
    text-align: center;
    background: white;
}`,

        '/var/www/dreamshare/static/js/main.js': `document.addEventListener('DOMContentLoaded', function() {
    const uploadInput = document.getElementById('file-upload');
    const uploadArea = document.querySelector('.upload-area');

    uploadArea.addEventListener('dragover', (e) => {
        e.preventDefault();
        uploadArea.style.borderColor = '#007bff';
    });

    uploadArea.addEventListener('drop', (e) => {
        e.preventDefault();
        uploadArea.style.borderColor = '#ccc';
        const files = e.dataTransfer.files;
        handleFiles(files);
    });
});

function handleFiles(files) {
    console.log('Files selected:', files);
    // Upload logic here
}`
    }
};
