// Демо-функции для панели управления

// Проверка авторизации
if (!sessionStorage.getItem('authenticated')) {
    window.location.href = '/demo';
}

// ========= Generic helpers =========
function escapeHtml(str) {
    return String(str)
        .replace(/&/g, '&')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function showToast(msg, type = 'info') {
    const container = document.querySelector('.toast-container');
    if (!container) return;

    const bg = type === 'success' ? 'success' : (type === 'danger' ? 'danger' : (type === 'warning' ? 'warning' : 'primary'));

    const el = document.createElement('div');
    el.className = `toast align-items-center text-white bg-${bg} border-0 shadow`;
    el.setAttribute('role', 'alert');
    el.setAttribute('aria-live', 'assertive');
    el.setAttribute('aria-atomic', 'true');
    el.innerHTML = `
        <div class="d-flex">
            <div class="toast-body">${escapeHtml(msg)}</div>
            <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
        </div>
    `;

    container.appendChild(el);
    const toast = new bootstrap.Toast(el, { delay: 4000 });
    toast.show();
    el.addEventListener('hidden.bs.toast', () => el.remove());
}

// Симуляция задержки для реалистичности
function delay(ms = 300) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

// ========= Navigation =========
function bindNavigation() {
    document.querySelectorAll('.nav-link[data-section]').forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            const section = link.getAttribute('data-section');
            switchSection(section);

            const sidebar = document.getElementById('sidebarMenu');
            if (sidebar && sidebar.classList.contains('show')) {
                const bsOffcanvas = bootstrap.Offcanvas.getInstance(sidebar);
                if (bsOffcanvas) bsOffcanvas.hide();
            }
        });
    });
}

function switchSection(section) {
    document.querySelectorAll('.content-section').forEach(el => el.style.display = 'none');
    document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));

    const target = document.getElementById(`section-${section}`);
    if (!target) return;

    target.style.display = 'block';
    document.querySelectorAll(`.nav-link[data-section="${section}"]`).forEach(l => l.classList.add('active'));

    if (section === 'dashboard') loadDashboard();
    else if (section === 'services') loadServices();
    else if (section === 'sites') loadSites();
    else if (section === 'files') loadFiles(currentPath);
    else if (section === 'nginx') loadNginx();
    else if (section === 'ssl') loadSSL();
    else if (section === 'backups') loadBackups();
    else if (section === 'security') loadSecurity();
    else if (section === 'projects') loadProjects();
}

// ========= LocalStorage для файлов =========
const STORAGE_KEY = 'dreamPanel_files';
const STORAGE_CONTENTS_KEY = 'dreamPanel_fileContents';

function initStorage() {
    if (!localStorage.getItem(STORAGE_KEY)) {
        // Инициализируем базовую структуру с правильной иерархией
        const initialFiles = {
            '/': [
                { name: 'var', type: 'directory' },
                { name: 'home', type: 'directory' },
                { name: 'etc', type: 'directory' }
            ],
            '/var': [
                { name: 'www', type: 'directory' }
            ],
            '/var/www': [
                { name: 'index.html', type: 'file', size: 1024 }
            ],
            '/home': [
                { name: 'user', type: 'directory' }
            ],
            '/home/user': [
                { name: 'projects', type: 'directory' },
                { name: 'backups', type: 'directory' }
            ],
            '/home/user/projects': [],
            '/home/user/backups': [],
            '/etc': [
                { name: 'nginx', type: 'directory' },
                { name: 'systemd', type: 'directory' },
                { name: 'letsencrypt', type: 'directory' }
            ],
            '/etc/nginx': [
                { name: 'sites-enabled', type: 'directory' }
            ],
            '/etc/nginx/sites-enabled': [],
            '/etc/systemd': [
                { name: 'system', type: 'directory' }
            ],
            '/etc/systemd/system': [],
            '/etc/letsencrypt': []
        };
        localStorage.setItem(STORAGE_KEY, JSON.stringify(initialFiles));
    } else {
        // При загрузке проверяем, что все родительские директории существуют
        const files = getStoredFiles();
        const allPaths = Object.keys(files);
        const missingDirs = {};

        allPaths.forEach(path => {
            if (path === '/') return;
            const parts = path.split('/').filter(p => p);
            for (let i = 1; i < parts.length; i++) {
                const parentPath = '/' + parts.slice(0, i).join('/');
                if (!files[parentPath]) {
                    if (!missingDirs[parentPath]) {
                        missingDirs[parentPath] = [];
                    }
                    const dirName = parts[i - 1];
                    if (!missingDirs[parentPath].find(item => item.name === dirName)) {
                        missingDirs[parentPath].push({ name: dirName, type: 'directory' });
                    }
                }
            }
        });

        // Добавляем недостающие директории
        Object.keys(missingDirs).forEach(path => {
            if (!files[path]) {
                files[path] = missingDirs[path];
            } else {
                missingDirs[path].forEach(item => {
                    if (!files[path].find(f => f.name === item.name)) {
                        files[path].push(item);
                    }
                });
            }
        });

        setStoredFiles(files);
    }

    if (!localStorage.getItem(STORAGE_CONTENTS_KEY)) {
        const initialContents = {
            '/var/www/index.html': '<!DOCTYPE html>\n<html>\n<head>\n    <title>Welcome</title>\n</head>\n<body>\n    <h1>Welcome</h1>\n</body>\n</html>'
        };
        localStorage.setItem(STORAGE_CONTENTS_KEY, JSON.stringify(initialContents));
    }
}

function getStoredFiles() {
    const data = localStorage.getItem(STORAGE_KEY);
    return data ? JSON.parse(data) : {};
}

function setStoredFiles(files) {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(files));
}

function getStoredContents() {
    const data = localStorage.getItem(STORAGE_CONTENTS_KEY);
    return data ? JSON.parse(data) : {};
}

function setStoredContents(contents) {
    localStorage.setItem(STORAGE_CONTENTS_KEY, JSON.stringify(contents));
}

function addFileToStorage(path, name, type, size = 0) {
    const files = getStoredFiles();

    // Создаем родительские директории, если их нет
    const parts = path.split('/').filter(p => p);
    for (let i = 1; i < parts.length; i++) {
        const parentPath = '/' + parts.slice(0, i).join('/');
        if (!files[parentPath]) {
            files[parentPath] = [];
        }
        const dirName = parts[i];
        if (!files[parentPath].find(item => item.name === dirName)) {
            files[parentPath].push({ name: dirName, type: 'directory' });
        }
    }

    // Добавляем файл/папку
    if (!files[path]) files[path] = [];
    if (!files[path].find(item => item.name === name)) {
        files[path].push({ name, type, size });
    }
    setStoredFiles(files);
}

function addFileContent(path, content) {
    const contents = getStoredContents();
    contents[path] = content;
    setStoredContents(contents);
}

function getFileContent(path) {
    const contents = getStoredContents();
    return contents[path];
}

// Инициализация при загрузке
initStorage();

// ========= Global state =========
let currentPath = '/var/www';
const FILE_ROOTS = [
    { label: '/var/www', path: '/var/www' },
    { label: '/home/user/projects', path: '/home/user/projects' },
    { label: '/etc/nginx/sites-enabled', path: '/etc/nginx/sites-enabled' },
    { label: '/etc/systemd/system', path: '/etc/systemd/system' },
    { label: '/etc/letsencrypt', path: '/etc/letsencrypt' },
    { label: '/home/user/backups', path: '/home/user/backups' }
];

function isAutostartEnabledState(unitFileState) {
    const s = String(unitFileState || '').trim().toLowerCase();
    return s === 'enabled' || s === 'enabled-runtime' || s === 'linked' || s === 'linked-runtime';
}

function isAutostartToggleableState(unitFileState) {
    const s = String(unitFileState || '').trim().toLowerCase();
    return (
        s === 'enabled' ||
        s === 'disabled' ||
        s === 'enabled-runtime' ||
        s === 'disabled-runtime' ||
        s === 'linked' ||
        s === 'linked-runtime' ||
        s === 'indirect'
    );
}

function renderAutostartBadge(unitFileState) {
    const raw = String(unitFileState || '').trim();
    const s = raw.toLowerCase();

    let badge = 'warning';
    if (isAutostartEnabledState(s)) badge = 'success';
    else if (s === 'disabled' || s === 'disabled-runtime') badge = 'danger';
    else if (s === 'static') badge = 'secondary';
    else if (s === 'masked') badge = 'dark';

    const label = raw || 'unknown';
    return `<span class="badge bg-${badge} bg-opacity-10 text-${badge}">${escapeHtml(label)}</span>`;
}

function renderServiceStateBadge(activeState, subState) {
    const raw = String(activeState || '').trim();
    const s = raw.toLowerCase();
    const sub = String(subState || '').trim();

    let badge = 'warning';
    let label = raw || 'unknown';
    let hint = sub ? `${raw} / ${sub}` : raw;

    if (s === 'active') {
        badge = 'success';
        label = 'active';
        hint = sub ? `Работает • ${sub}` : 'Работает';
    } else if (s === 'inactive') {
        badge = 'danger';
        label = 'inactive';
        hint = sub ? `Остановлен • ${sub}` : 'Остановлен';
    } else if (s === 'failed') {
        badge = 'danger';
        label = 'failed';
        hint = sub ? `Ошибка • ${sub}` : 'Ошибка';
    } else if (s === 'activating' || s === 'deactivating' || s === 'reloading') {
        badge = 'warning';
        label = raw || 'loading';
        hint = sub ? `Переходное состояние • ${sub}` : 'Переходное состояние';
    }

    return `
        <span class="badge bg-${badge} bg-opacity-10 text-${badge}" title="${escapeHtml(hint)}">
            <span class="d-inline-block rounded-circle bg-${badge} me-1" style="width: 6px; height: 6px;"></span>
            ${escapeHtml(label)}
        </span>
    `.trim();
}

function formatFileSize(bytes) {
    if (!bytes) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// ========= Dashboard =========
async function loadDashboard() {
    const metricsEl = document.getElementById('metrics-content');
    if (metricsEl) {
        metricsEl.innerHTML = `
            <div class="text-center py-4">
                <div class="spinner-border text-primary" role="status"></div>
                <p class="mt-2 text-muted">Загрузка данных...</p>
            </div>
        `;
    }

    await delay(500);

    const services = DEMO_DATA.services;
    const sites = DEMO_DATA.sites;
    const nginx = DEMO_DATA.nginx;
    const ssl = DEMO_DATA.ssl;
    const metrics = DEMO_DATA.metrics;

    if (Array.isArray(services)) document.getElementById('stat-services').textContent = services.length;
    if (Array.isArray(sites)) document.getElementById('stat-sites').textContent = sites.length;
    if (Array.isArray(nginx)) document.getElementById('stat-nginx').textContent = nginx.length;
    document.getElementById('stat-ssl').textContent = (ssl && ssl.certificates) ? ssl.certificates.length : 0;

    renderMetrics(metrics);
}

function renderMetrics(metrics) {
    const metricsEl = document.getElementById('metrics-content');
    if (!metricsEl) return;

    const formatBytes = (bytes) => {
        const n = Number(bytes || 0);
        if (!n) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(n) / Math.log(k));
        return parseFloat((n / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    };

    metricsEl.innerHTML = `
        <div class="row g-4">
            <div class="col-md-6">
                <div class="mb-3">
                    <div class="d-flex justify-content-between mb-1">
                        <span class="fw-medium">RAM</span>
                        <span class="text-muted small">${formatBytes(metrics.memory_used)} / ${formatBytes(metrics.memory_total)} (${metrics.memory_percent || 0}%)</span>
                    </div>
                    <div class="progress" style="height: 10px;">
                        <div class="progress-bar bg-primary" role="progressbar" style="width: ${metrics.memory_percent || 0}%"></div>
                    </div>
                </div>
                <div class="mb-3">
                    <div class="d-flex justify-content-between mb-1">
                        <span class="fw-medium">Disk (/)</span>
                        <span class="text-muted small">${formatBytes(metrics.disk_used)} / ${formatBytes(metrics.disk_total)} (${metrics.disk_percent || 0}%)</span>
                    </div>
                    <div class="progress" style="height: 10px;">
                        <div class="progress-bar bg-success" role="progressbar" style="width: ${metrics.disk_percent || 0}%"></div>
                    </div>
                </div>
            </div>
            <div class="col-md-6">
                <ul class="list-group list-group-flush border rounded-3">
                    <li class="list-group-item d-flex justify-content-between align-items-center bg-transparent">
                        <span class="text-muted">Uptime</span>
                        <span class="fw-medium font-monospace">${escapeHtml(metrics.uptime || 'N/A')}</span>
                    </li>
                    <li class="list-group-item d-flex justify-content-between align-items-center bg-transparent">
                        <span class="text-muted">Load Avg</span>
                        <span class="fw-medium font-monospace">${escapeHtml(metrics.load_1min || '0')} / ${escapeHtml(metrics.load_5min || '0')} / ${escapeHtml(metrics.load_15min || '0')}</span>
                    </li>
                </ul>
            </div>
        </div>
    `;
}

function refreshAll() {
    loadDashboard();
}

// ========= Services =========
async function loadServices() {
    const container = document.getElementById('services-content');
    container.innerHTML = '<div class="text-center py-4"><div class="spinner-border text-primary"></div></div>';

    await delay(500);

    const services = DEMO_DATA.services;
    const metrics = DEMO_DATA.metrics;
    const memTotal = Number(metrics?.memory_total || 0);

    if (!Array.isArray(services) || services.length === 0) {
        container.innerHTML = '<div class="alert alert-light text-center">Нет сервисов</div>';
        return;
    }

    container.innerHTML = `
        <div class="d-flex flex-column flex-md-row gap-2 justify-content-between align-items-md-center mb-3">
            <div class="input-group input-group-sm" style="max-width: 420px;">
                <span class="input-group-text bg-white"><i class="bi bi-search"></i></span>
                <input type="text" class="form-control" id="services-search" placeholder="Поиск сервиса…">
            </div>
            <div class="d-flex gap-2">
                <select class="form-select form-select-sm w-auto" id="services-filter">
                    <option value="all" selected>Все</option>
                    <option value="active">active</option>
                    <option value="inactive">inactive</option>
                    <option value="failed">failed</option>
                </select>
            </div>
        </div>
        <div class="table-responsive">
            <table class="table table-hover mb-0">
                <thead>
                    <tr>
                        <th>Сервис</th>
                        <th>Статус</th>
                        <th class="text-center">Автозапуск</th>
                        <th class="text-end">Действия</th>
                    </tr>
                </thead>
                <tbody>
                    ${services.map(svc => {
                        const isActive = String(svc.state || '') === 'active';
                        const rss = Number(svc.rss_bytes || 0);
                        const cpu = Number(svc.cpu_percent || 0);
                        const memPct = memTotal > 0 ? Math.min(100, (rss / memTotal) * 100) : 0;
                        const memBar = memPct >= 30 ? 'danger' : (memPct >= 15 ? 'warning' : (memPct >= 5 ? 'info' : 'success'));
                        const memLabel = rss > 0 ? `${formatFileSize(rss)} • ${memPct.toFixed(1)}%` : '—';
                        const cpuLabel = `${(cpu || 0).toFixed(1)}%`;
                        const enabledState = String(svc.enabled || 'unknown');
                        const autostartOn = isAutostartEnabledState(enabledState);
                        const autostartToggleable = isAutostartToggleableState(enabledState);
                        const autostartTitle = autostartToggleable
                            ? (autostartOn ? 'Отключить автозапуск' : 'Включить автозапуск')
                            : `Недоступно: ${enabledState}`;
                        const stateBadgeHtml = renderServiceStateBadge(svc.state, svc.substate);
                        return `
                            <tr data-state="${escapeHtml(String(svc.state || ''))}">
                                <td>
                                    <div class="fw-bold">${escapeHtml(svc.name)}</div>
                                    <div class="small text-muted text-truncate" style="max-width: 260px;">${escapeHtml(svc.description || '')}</div>
                                    <div class="mt-2">
                                        <div class="d-flex justify-content-between small text-muted">
                                            <span>RAM</span>
                                            <span>${escapeHtml(memLabel)}</span>
                                        </div>
                                        <div class="progress" style="height: 6px;">
                                            <div class="progress-bar bg-${memBar}" role="progressbar" style="width: ${memPct.toFixed(2)}%"></div>
                                        </div>
                                        <div class="small text-muted mt-1 d-none d-md-block">
                                            CPU: <span class="font-monospace">${escapeHtml(cpuLabel)}</span> · PID: <span class="font-monospace">${escapeHtml(String(svc.pid || '0'))}</span>
                                        </div>
                                    </div>
                                </td>
                                <td>
                                    ${stateBadgeHtml}
                                    <div class="mt-2">
                                        <div class="form-check form-switch m-0 service-state-switch">
                                            <input
                                                class="form-check-input service-state-toggle"
                                                type="checkbox"
                                                role="switch"
                                                aria-label="Запущен"
                                                title="${escapeHtml(isActive ? 'Остановить' : 'Запустить')}"
                                                data-unit="${escapeHtml(svc.unit)}"
                                                ${isActive ? 'checked' : ''}
                                            >
                                        </div>
                                    </div>
                                </td>
                                <td class="text-center">
                                    <div class="d-inline-flex flex-column align-items-center">
                                        <div class="form-check form-switch m-0 service-autostart-switch">
                                            <input
                                                class="form-check-input service-autostart-toggle"
                                                type="checkbox"
                                                role="switch"
                                                aria-label="Автозапуск"
                                                title="${escapeHtml(autostartTitle)}"
                                                data-unit="${escapeHtml(svc.unit)}"
                                                ${autostartOn ? 'checked' : ''}
                                                ${autostartToggleable ? '' : 'disabled'}
                                            >
                                        </div>
                                        <div class="mt-1 d-none d-md-block service-autostart-state">${renderAutostartBadge(enabledState)}</div>
                                    </div>
                                </td>
                                <td class="text-end">
                                    <div class="btn-group btn-group-sm">
                                        <button class="btn btn-outline-secondary" onclick="serviceAction('${escapeHtml(svc.unit)}','${isActive ? 'stop' : 'start'}')" title="${isActive ? 'Остановить' : 'Запустить'}">
                                            <i class="bi bi-${isActive ? 'stop-fill' : 'play-fill'}"></i>
                                        </button>
                                        <button class="btn btn-outline-secondary" onclick="serviceAction('${escapeHtml(svc.unit)}','restart')" title="Перезапустить">
                                            <i class="bi bi-arrow-clockwise"></i>
                                        </button>
                                        <button class="btn btn-outline-secondary d-none d-sm-inline-block" onclick="openLogs('${escapeHtml(svc.unit)}')" title="Логи">
                                            <i class="bi bi-journal-text"></i>
                                        </button>
                                    </div>
                                </td>
                            </tr>
                        `;
                    }).join('')}
                </tbody>
            </table>
        </div>
    `;

    // Client-side filtering
    const qEl = container.querySelector('#services-search');
    const fEl = container.querySelector('#services-filter');
    const applyFilter = () => {
        const q = (qEl?.value || '').trim().toLowerCase();
        const state = (fEl?.value || 'all').trim();
        const rows = container.querySelectorAll('tbody tr');
        rows.forEach(tr => {
            const text = (tr.textContent || '').toLowerCase();
            const st = tr.getAttribute('data-state') || '';
            const ok = (!q || text.includes(q)) && (state === 'all' || st === state);
            tr.style.display = ok ? '' : 'none';
        });
    };
    if (qEl) qEl.addEventListener('input', applyFilter);
    if (fEl) fEl.addEventListener('change', applyFilter);

    // Bind toggles
    bindServiceStateToggles();
    bindServiceAutostartToggles();
}

// Состояние сервисов (для переключения)
let servicesState = {};
function initServicesState() {
    DEMO_DATA.services.forEach(svc => {
        servicesState[svc.unit] = {
            state: svc.state,
            substate: svc.substate,
            enabled: svc.enabled
        };
    });
}

async function serviceAction(unit, action) {
    await delay(300);

    if (!servicesState[unit]) {
        const svc = DEMO_DATA.services.find(s => s.unit === unit);
        if (svc) {
            servicesState[unit] = {
                state: svc.state,
                substate: svc.substate,
                enabled: svc.enabled
            };
        }
    }

    if (action === 'start') {
        servicesState[unit].state = 'active';
        servicesState[unit].substate = 'running';
        showToast(`Сервис ${unit} запущен`, 'success');
    } else if (action === 'stop') {
        servicesState[unit].state = 'inactive';
        servicesState[unit].substate = 'dead';
        showToast(`Сервис ${unit} остановлен`, 'success');
    } else if (action === 'restart') {
        servicesState[unit].state = 'activating';
        await delay(200);
        servicesState[unit].state = 'active';
        servicesState[unit].substate = 'running';
        showToast(`Сервис ${unit} перезапущен`, 'success');
    }

    // Обновляем DEMO_DATA
    const svc = DEMO_DATA.services.find(s => s.unit === unit);
    if (svc) {
        svc.state = servicesState[unit].state;
        svc.substate = servicesState[unit].substate;
    }

    setTimeout(loadServices, 500);
}

// Переключение состояния сервиса через switch
function bindServiceStateToggles() {
    const container = document.getElementById('services-content');
    if (!container) return;

    container.addEventListener('change', async (e) => {
        const input = e.target;
        if (!input || !input.classList || !input.classList.contains('service-state-toggle')) return;

        const unit = input.getAttribute('data-unit') || '';
        if (!unit) return;

        const shouldRun = !!input.checked;
        const action = shouldRun ? 'start' : 'stop';

        input.disabled = true;
        await serviceAction(unit, action);
        input.disabled = false;
    });
}

// Переключение автозапуска
function bindServiceAutostartToggles() {
    const container = document.getElementById('services-content');
    if (!container) return;

    container.addEventListener('change', async (e) => {
        const input = e.target;
        if (!input || !input.classList || !input.classList.contains('service-autostart-toggle')) return;

        const unit = input.getAttribute('data-unit') || '';
        if (!unit) return;

        const wasChecked = !input.checked;
        const action = input.checked ? 'enable' : 'disable';

        input.disabled = true;
        await delay(300);

        const svc = DEMO_DATA.services.find(s => s.unit === unit);
        if (svc) {
            svc.enabled = input.checked ? 'enabled' : 'disabled';
        }

        input.disabled = false;
        showToast(`Автозапуск ${input.checked ? 'включен' : 'выключен'}`, 'success');
        setTimeout(loadServices, 300);
    });
}

function openLogs(unit) {
    showToast('Логи открыты (демо)', 'info');
}

function showCreateServiceModal() {
    showToast('Создание сервиса (демо)', 'info');
}

// ========= Sites =========
async function loadSites() {
    const container = document.getElementById('sites-content');
    container.innerHTML = '<div class="text-center py-4"><div class="spinner-border text-primary"></div></div>';

    await delay(500);

    const sites = DEMO_DATA.sites;

    if (!Array.isArray(sites) || sites.length === 0) {
        container.innerHTML = '<div class="alert alert-light text-center">Нет сайтов</div>';
        return;
    }

    container.innerHTML = `
        <div class="table-responsive">
            <table class="table table-hover mb-0">
                <thead>
                    <tr>
                        <th>Домен</th>
                        <th>Путь</th>
                        <th>Статус</th>
                        <th>SSL</th>
                        <th class="text-end">Действия</th>
                    </tr>
                </thead>
                <tbody>
                    ${sites.map(site => `
                        <tr>
                            <td><strong>${escapeHtml(site.domain)}</strong></td>
                            <td><code class="small">${escapeHtml(site.path)}</code></td>
                            <td>
                                <span class="badge bg-${site.enabled ? 'success' : 'secondary'} bg-opacity-10 text-${site.enabled ? 'success' : 'secondary'}">
                                    ${site.enabled ? 'Включен' : 'Выключен'}
                                </span>
                            </td>
                            <td>
                                ${site.ssl ? '<span class="badge bg-success bg-opacity-10 text-success">✓ SSL</span>' : '<span class="badge bg-secondary bg-opacity-10 text-secondary">—</span>'}
                            </td>
                            <td class="text-end">
                                <div class="btn-group btn-group-sm">
                                    <button class="btn btn-outline-secondary" onclick="openNginxForSite('${escapeHtml(site.domain)}', '${escapeHtml(site.nginx_config)}')" title="Nginx">
                                        <i class="bi bi-file-earmark-code"></i>
                                    </button>
                                    <button class="btn btn-outline-secondary" onclick="openSslForSite('${escapeHtml(site.domain)}', ${site.ssl})" title="SSL">
                                        <i class="bi bi-shield-check"></i>
                                    </button>
                                </div>
                            </td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        </div>
    `;
}

function openNginxForSite(domain, cfgName) {
    const path = `/etc/nginx/sites-enabled/${cfgName}`;
    // Убеждаемся, что контент есть в DEMO_DATA
    if (!DEMO_DATA.fileContents[path]) {
        DEMO_DATA.fileContents[path] = `server {
    listen 80;
    server_name ${domain};

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}`;
    }
    editFile(path);
}

function openSslForSite(domain, hasSsl) {
    if (hasSsl) {
        showObtainCertModal(domain);
    } else {
        showObtainCertModal(domain);
    }
}

function showCreateSiteModal() {
    let currentStep = 1;
    let wizardData = {};

    const modalHtml = `
        <div class="modal fade" id="createSiteModal" tabindex="-1">
            <div class="modal-dialog modal-lg modal-dialog-scrollable modal-fullscreen-md-down">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">Менеджер создания сайта</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body">
                        <!-- Step 1: Domain -->
                        <div id="wizard-step-1" class="wizard-step">
                            <div class="text-center mb-4">
                                <div class="mb-3" style="font-size: 48px;">🌐</div>
                                <h4>Шаг 1: Введите домен</h4>
                                <p class="text-muted">Укажите доменное имя для нового сайта</p>
                            </div>
                            <div class="mb-3">
                                <label class="form-label fw-bold">Домен</label>
                                <input type="text" class="form-control form-control-lg" id="wizard-domain" placeholder="example.com" required>
                                <div class="form-text">Например: mysite.com или subdomain.example.com</div>
                            </div>
                            <div class="d-flex justify-content-end">
                                <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">Отмена</button>
                                <button type="button" class="btn btn-black ms-2" onclick="wizardNextStep()">Проверить DNS →</button>
                            </div>
                        </div>

                        <!-- Step 2: DNS Check -->
                        <div id="wizard-step-2" class="wizard-step" style="display:none;">
                            <div class="text-center mb-4">
                                <div class="mb-3" style="font-size: 48px;" id="wizard-dns-icon">🔍</div>
                                <h4>Шаг 2: Проверка DNS</h4>
                                <p class="text-muted" id="wizard-dns-status">Проверяю настройки домена...</p>
                            </div>
                            <div id="wizard-dns-result" class="mb-3"></div>
                            <div class="d-flex justify-content-between">
                                <button type="button" class="btn btn-outline-secondary" onclick="wizardPrevStep()">← Назад</button>
                                <button type="button" class="btn btn-black" id="wizard-dns-next" style="display:none;" onclick="wizardNextStep()">Продолжить →</button>
                            </div>
                        </div>

                        <!-- Step 3: Configuration -->
                        <div id="wizard-step-3" class="wizard-step" style="display:none;">
                            <div class="text-center mb-4">
                                <div class="mb-3" style="font-size: 48px;">⚙️</div>
                                <h4>Шаг 3: Настройка</h4>
                                <p class="text-muted">Выберите параметры сайта</p>
                            </div>
                            <div class="row g-3">
                                <div class="col-12 col-md-6">
                                    <label class="form-label fw-bold">Тип сайта</label>
                                    <select class="form-select" id="wizard-type">
                                        <option value="static" selected>Static (HTML)</option>
                                        <option value="php">PHP</option>
                                        <option value="wordpress">WordPress (PHP)</option>
                                        <option value="node">Node.js</option>
                                        <option value="python">Python (Flask/Django)</option>
                                    </select>
                                </div>
                                <div class="col-12 col-md-6" id="wizard-port-group" style="display:none;">
                                    <label class="form-label fw-bold">Порт приложения</label>
                                    <input type="number" class="form-control" id="wizard-port" value="3000">
                                </div>
                                <div class="col-12">
                                    <div class="form-check">
                                        <input class="form-check-input" type="checkbox" id="wizard-nginx" checked>
                                        <label class="form-check-label fw-bold" for="wizard-nginx">Создать Nginx конфиг</label>
                                    </div>
                                </div>
                                <div class="col-12">
                                    <div class="form-check">
                                        <input class="form-check-input" type="checkbox" id="wizard-ssl">
                                        <label class="form-check-label fw-bold" for="wizard-ssl">Получить SSL (Let's Encrypt)</label>
                                    </div>
                                </div>
                                <div class="col-12" id="wizard-email-group" style="display:none;">
                                    <label class="form-label fw-bold">Email для SSL (необязательно)</label>
                                    <input type="email" class="form-control" id="wizard-email" placeholder="admin@example.com">
                                    <div class="form-text">Можно оставить пустым</div>
                                </div>
                            </div>
                            <div class="d-flex justify-content-between mt-4">
                                <button type="button" class="btn btn-outline-secondary" onclick="wizardPrevStep()">← Назад</button>
                                <button type="button" class="btn btn-black" onclick="wizardCreateSite()">Создать сайт</button>
                            </div>
                        </div>

                        <!-- Step 4: Success -->
                        <div id="wizard-step-4" class="wizard-step" style="display:none;">
                            <div class="text-center mb-4">
                                <div class="mb-3" style="font-size: 64px;">✅</div>
                                <h4 class="text-success">Сайт успешно создан!</h4>
                                <p class="text-muted" id="wizard-success-msg"></p>
                            </div>
                            <div class="alert alert-light">
                                <div class="fw-bold mb-2">Что дальше?</div>
                                <ul class="text-start mb-0">
                                    <li>Вы можете редактировать файлы в директории сайта</li>
                                    <li>Перейдите в раздел "Сайты" для управления</li>
                                    <li>Или откройте файлы сайта прямо сейчас</li>
                                </ul>
                            </div>
                            <div class="d-flex justify-content-center gap-2">
                                <button type="button" class="btn btn-black" onclick="wizardOpenSiteFiles()">
                                    <i class="bi bi-folder2-open me-2"></i>Открыть файлы сайта
                                </button>
                                <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">Закрыть</button>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `;

    document.getElementById('modal-container').innerHTML = modalHtml;
    const modalEl = document.getElementById('createSiteModal');
    const modal = new bootstrap.Modal(modalEl);
    modal.show();

    // Wizard functions
    window.wizardNextStep = async () => {
        if (currentStep === 1) {
            const domain = document.getElementById('wizard-domain').value.trim();
            if (!domain) {
                showToast('Введите домен', 'warning');
                return;
            }
            wizardData.domain = domain;

            // Переходим к шагу 2 (DNS check)
            document.getElementById('wizard-step-1').style.display = 'none';
            document.getElementById('wizard-step-2').style.display = 'block';
            currentStep = 2;

            // Проверяем DNS
            const dnsIcon = document.getElementById('wizard-dns-icon');
            const dnsStatus = document.getElementById('wizard-dns-status');
            const dnsResult = document.getElementById('wizard-dns-result');
            const dnsNext = document.getElementById('wizard-dns-next');

            dnsIcon.textContent = '🔍';
            dnsStatus.textContent = 'Проверяю настройки DNS...';
            dnsResult.innerHTML = '';
            dnsNext.style.display = 'none';

            await delay(1500);

            // Симуляция проверки DNS
            const serverIp = '185.123.45.67';
            const domainIp = '185.123.45.67';
            const dnsOk = Math.random() > 0.3; // 70% успех

            if (dnsOk) {
                dnsIcon.textContent = '✅';
                dnsStatus.textContent = 'DNS настроен правильно';
                dnsResult.innerHTML = `
                    <div class="alert alert-success">
                        <div class="fw-bold mb-2">✓ Домен указывает на этот сервер</div>
                        <div class="small">
                            <div>IP сервера: <code>${escapeHtml(serverIp)}</code></div>
                            <div>IP домена: <code>${escapeHtml(domainIp)}</code></div>
                        </div>
                    </div>
                `;
                dnsNext.style.display = 'block';
            } else {
                dnsIcon.textContent = '⚠️';
                dnsStatus.textContent = 'DNS не настроен';
                dnsResult.innerHTML = `
                    <div class="alert alert-warning">
                        <div class="fw-bold mb-2">⚠️ Проблема с DNS</div>
                        <div class="small mb-3">Домен не указывает на этот сервер</div>
                        <div class="small text-muted mb-2">
                            <div>IP сервера: <code>${escapeHtml(serverIp)}</code></div>
                            <div>IP домена: <code>${escapeHtml(domainIp)}</code></div>
                        </div>
                        <div class="form-check mt-3">
                            <input class="form-check-input" type="checkbox" id="wizard-skip-dns">
                            <label class="form-check-label" for="wizard-skip-dns">
                                Продолжить без проверки DNS (для тестов/локальных доменов)
                            </label>
                        </div>
                    </div>
                `;
                document.getElementById('wizard-skip-dns').addEventListener('change', (e) => {
                    dnsNext.style.display = e.target.checked ? 'block' : 'none';
                });
            }
        } else if (currentStep === 2) {
            // Переходим к шагу 3 (Configuration)
            document.getElementById('wizard-step-2').style.display = 'none';
            document.getElementById('wizard-step-3').style.display = 'block';
            currentStep = 3;

            // Настройка динамических полей
            const typeSelect = document.getElementById('wizard-type');
            const portGroup = document.getElementById('wizard-port-group');
            const sslCb = document.getElementById('wizard-ssl');
            const emailGroup = document.getElementById('wizard-email-group');

            function refreshWizardForm() {
                const type = typeSelect.value;
                portGroup.style.display = (type === 'node' || type === 'python') ? 'block' : 'none';
                emailGroup.style.display = sslCb.checked ? 'block' : 'none';
            }

            typeSelect.addEventListener('change', refreshWizardForm);
            sslCb.addEventListener('change', refreshWizardForm);
            refreshWizardForm();
        }
    };

    window.wizardPrevStep = () => {
        if (currentStep === 2) {
            document.getElementById('wizard-step-2').style.display = 'none';
            document.getElementById('wizard-step-1').style.display = 'block';
            currentStep = 1;
        } else if (currentStep === 3) {
            document.getElementById('wizard-step-3').style.display = 'none';
            document.getElementById('wizard-step-2').style.display = 'block';
            currentStep = 2;
        }
    };

    window.wizardCreateSite = async () => {
        const domain = wizardData.domain;
        const type = document.getElementById('wizard-type').value;
        const port = parseInt(document.getElementById('wizard-port').value) || 3000;
        const createNginx = document.getElementById('wizard-nginx').checked;
        const createSSL = document.getElementById('wizard-ssl').checked;
        const email = document.getElementById('wizard-email').value.trim();
        const skipDns = document.getElementById('wizard-skip-dns')?.checked || false;

        showToast('Создаю сайт...', 'info');
        await delay(1000);

        // Создаем директорию сайта в localStorage
        const sitePath = `/var/www/${domain}`;
        addFileToStorage('/var/www', domain, 'directory');
        addFileToStorage(sitePath, 'index.html', 'file', 1024);
        addFileContent(`${sitePath}/index.html`, `<!DOCTYPE html>
<html>
<head>
    <title>${domain}</title>
</head>
<body>
    <h1>Welcome to ${domain}</h1>
</body>
</html>`);

        // Добавляем сайт в демо-данные
        const newSite = {
            domain: domain,
            path: sitePath,
            enabled: true,
            ssl: createSSL,
            nginx_config: domain
        };
        DEMO_DATA.sites.push(newSite);

        if (createNginx) {
            const nginxConfig = {
                name: domain,
                path: `/etc/nginx/sites-enabled/${domain}`,
                enabled: true
            };
            DEMO_DATA.nginx.push(nginxConfig);
            const nginxContent = `server {
    listen 80;
    server_name ${domain}${createSSL ? ' www.' + domain : ''};

    root /var/www/${domain};
    index index.html;

    location / {
        try_files $uri $uri/ =404;
    }
}`;
            addFileContent(`/etc/nginx/sites-enabled/${domain}`, nginxContent);
            DEMO_DATA.fileContents[`/etc/nginx/sites-enabled/${domain}`] = nginxContent;
        }

        // Переходим к шагу 4 (Success)
        document.getElementById('wizard-step-3').style.display = 'none';
        document.getElementById('wizard-step-4').style.display = 'block';
        currentStep = 4;

        const steps = [];
        steps.push('Директория создана');
        if (createNginx) steps.push('Nginx конфиг создан');
        if (createSSL) steps.push('SSL сертификат получен');

        document.getElementById('wizard-success-msg').textContent = steps.length > 0 ? steps.join(' • ') : 'Сайт успешно создан и настроен';
        wizardData.sitePath = `/var/www/${domain}`;
        wizardData.siteName = domain;

        loadSites();
    };

    window.wizardOpenSiteFiles = () => {
        if (wizardData.sitePath) {
            modal.hide();
            switchSection('files');
            setTimeout(() => {
                setFileRoot(wizardData.sitePath);
            }, 300);
        }
    };

    // Enter на домене -> следующий шаг
    document.getElementById('wizard-domain').addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            e.preventDefault();
            wizardNextStep();
        }
    });
}

// ========= Files =========
function initFileRoots() {
    const sel = document.getElementById('file-root-select');
    if (!sel) return;

    const match = FILE_ROOTS
        .slice()
        .sort((a, b) => (b.path || '').length - (a.path || '').length)
        .find(r => currentPath === r.path || (r.path === '/' ? currentPath.startsWith('/') : currentPath.startsWith(r.path + '/')));

    sel.innerHTML = FILE_ROOTS.map(r => `<option value="${escapeHtml(r.path)}">${escapeHtml(r.label)}</option>`).join('');
    if (match) sel.value = match.path;
}

function setFileRoot(path) {
    currentPath = path || '/var/www';
    initFileRoots();
    loadFiles(currentPath);
}

function reloadFiles() {
    loadFiles(currentPath);
}

async function loadFiles(path) {
    const container = document.getElementById('files-content');
    if (!container) return;

    container.innerHTML = '<div class="text-center py-4"><div class="spinner-border text-primary"></div></div>';

    await delay(300);

    currentPath = path || '/var/www';
    // Объединяем данные из localStorage и DEMO_DATA
    const storedFiles = getStoredFiles()[currentPath] || [];
    const demoFiles = DEMO_DATA.files[currentPath] || [];
    // Объединяем, убирая дубликаты
    const allFiles = [...storedFiles];
    demoFiles.forEach(df => {
        if (!allFiles.find(f => f.name === df.name)) {
            allFiles.push(df);
        }
    });
    const files = allFiles;

    // Обновляем breadcrumbs (как в оригинале - кликабельные части пути)
    const bc = document.getElementById('file-breadcrumbs');
    if (bc) {
        const parts = currentPath.split('/').filter(p => p);
        bc.innerHTML = `
            <li class="breadcrumb-item">
                <a href="#" class="breadcrumb-link" data-path="/">/</a>
            </li>
            ${parts.map((part, i) => {
                const pathTo = '/' + parts.slice(0, i + 1).join('/');
                return `
                    <li class="breadcrumb-item">
                        <a href="#" class="breadcrumb-link" data-path="${escapeHtml(pathTo)}">${escapeHtml(part)}</a>
                    </li>
                `;
            }).join('')}
        `;

        // Bind breadcrumbs
        bc.querySelectorAll('.breadcrumb-link').forEach(link => {
            link.addEventListener('click', (e) => {
                e.preventDefault();
                const path = link.getAttribute('data-path') || '';
                if (path) loadFiles(path);
            });
        });
    }

    if (files.length === 0) {
        container.innerHTML = '<div class="alert alert-light text-center py-4">Папка пуста</div>';
        return;
    }

    container.innerHTML = files.map(item => {
        const fullPath = currentPath === '/' ? `/${item.name}` : `${currentPath}/${item.name}`;
        const icon = item.type === 'directory' ? '<i class="bi bi-folder-fill folder-icon"></i>' : '<i class="bi bi-file-earmark file-icon-default"></i>';
        return `
            <div class="file-item" onclick="handleFileClick('${escapeHtml(fullPath)}', ${item.type === 'directory' ? 'true' : 'false'})" style="cursor: pointer;">
                <div class="file-icon">${icon}</div>
                <div class="flex-grow-1">
                    <div class="fw-medium">${escapeHtml(item.name)}</div>
                    <div class="small text-muted">${item.type === 'directory' ? 'Папка' : formatFileSize(item.size || 0)}</div>
                </div>
                <div class="btn-group btn-group-sm">
                    ${item.type === 'file' ? `
                        <button class="btn btn-outline-secondary btn-sm" onclick="event.stopPropagation(); editFile('${escapeHtml(fullPath)}')" title="Редактировать">
                            <i class="bi bi-pencil"></i>
                        </button>
                    ` : ''}
                </div>
            </div>
        `;
    }).join('');

}

function handleFileClick(path, isDirectory) {
    if (isDirectory) {
        loadFiles(path);
    } else {
        editFile(path);
    }
}

function guessCodeMirrorModeByPath(path) {
    const ext = path.split('.').pop()?.toLowerCase() || '';
    if (['js', 'json'].includes(ext)) return 'javascript';
    if (['html', 'htm'].includes(ext)) return 'htmlmixed';
    if (ext === 'css') return 'css';
    if (ext === 'py') return 'python';
    if (ext === 'sh') return 'shell';
    if (ext === 'php') return 'php';
    if (ext === 'conf' || path.includes('nginx')) return 'shell';
    return 'text/plain';
}

async function editFile(path) {
    // Сначала проверяем localStorage, потом DEMO_DATA
    const storedContent = getFileContent(path);
    const demoContent = DEMO_DATA.fileContents[path];
    const content = storedContent || demoContent || '// Демо-файл\n// Содержимое файла недоступно в демо-версии';

    const modal = document.createElement('div');
    modal.className = 'modal fade';
    modal.innerHTML = `
        <div class="modal-dialog modal-xl">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">Редактировать: ${escapeHtml(path)}</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body p-0">
                    <textarea id="file-editor-content" style="width: 100%; height: 65vh; font-family: monospace; padding: 15px; border: none; outline: none;">${escapeHtml(content)}</textarea>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Отмена</button>
                    <button type="button" class="btn btn-black" onclick="saveFile('${escapeHtml(path)}')">Сохранить</button>
                </div>
            </div>
        </div>
    `;

    document.getElementById('modal-container').appendChild(modal);
    const bsModal = new bootstrap.Modal(modal);
    bsModal.show();

    // Try to use CodeMirror if available
    setTimeout(() => {
        if (window.CodeMirror) {
            const textarea = document.getElementById('file-editor-content');
            const mode = guessCodeMirrorModeByPath(path);
            const editor = CodeMirror.fromTextArea(textarea, {
                lineNumbers: true,
                mode: mode,
                theme: 'eclipse',
                indentUnit: 4,
                lineWrapping: true,
                indentWithTabs: false,
                tabSize: 4,
                gutters: ['CodeMirror-linenumbers'],
                lineNumberFormatter: (line) => line
            });
            // Исправляем отступ для контента - он должен быть справа от номеров строк
            setTimeout(() => {
                const cmWrapper = editor.getWrapperElement();
                const cmLines = cmWrapper.querySelector('.CodeMirror-lines');
                if (cmLines) {
                    // Устанавливаем margin-left чтобы контент был справа от gutter
                    cmLines.style.marginLeft = '3.5em';
                    cmLines.style.paddingLeft = '0';
                }
                const gutters = cmWrapper.querySelector('.CodeMirror-gutters');
                if (gutters) {
                    gutters.style.borderRight = '1px solid #ddd';
                    gutters.style.backgroundColor = '#f7f7f7';
                    gutters.style.width = '3.5em';
                }
                const sizer = cmWrapper.querySelector('.CodeMirror-sizer');
                if (sizer) {
                    sizer.style.marginLeft = '3.5em';
                }
                // Исправляем все номера строк
                const lineNumbers = cmWrapper.querySelectorAll('.CodeMirror-linenumber');
                lineNumbers.forEach(ln => {
                    ln.style.paddingRight = '8px';
                    ln.style.minWidth = '3em';
                    ln.style.textAlign = 'right';
                });
            }, 100);
            window.currentFileEditor = editor;
            window.currentFilePath = path;
        }
    }, 100);

    modal.addEventListener('hidden.bs.modal', () => {
        modal.remove();
        window.currentFileEditor = null;
        window.currentFilePath = null;
    });
}

async function saveFile(path, content) {
    const editor = window.currentFileEditor;
    const contentToSave = editor ? editor.getValue() : (content || document.getElementById('file-editor-content')?.value || '');

    await delay(300);

    // Сохраняем в localStorage
    addFileContent(path, contentToSave);

    // Также обновляем в DEMO_DATA для совместимости
    DEMO_DATA.fileContents[path] = contentToSave;

    showToast('Файл сохранён', 'success');

    const modalEl = document.querySelector('.modal.show');
    if (modalEl) {
        const bsModal = bootstrap.Modal.getInstance(modalEl);
        if (bsModal) bsModal.hide();
    }

    reloadFiles();
}

function showCreateFolderModal() {
    showToast('Создание папки (демо)', 'info');
}

function showCreateFileModal() {
    showToast('Создание файла (демо)', 'info');
}

function uploadFile(input) {
    if (input.files && input.files.length > 0) {
        showToast('Файл загружен (демо)', 'success');
    }
}

// ========= Nginx =========
async function loadNginx() {
    const container = document.getElementById('nginx-content');
    container.innerHTML = '<div class="text-center py-4"><div class="spinner-border text-primary"></div></div>';

    await delay(500);

    const nginx = DEMO_DATA.nginx;

    container.innerHTML = `
        <div class="table-responsive">
            <table class="table table-hover mb-0">
                <thead>
                    <tr>
                        <th>Конфиг</th>
                        <th>Путь</th>
                        <th>Статус</th>
                        <th class="text-end">Действия</th>
                    </tr>
                </thead>
                <tbody>
                    ${nginx.map(cfg => `
                        <tr>
                            <td><strong>${escapeHtml(cfg.name)}</strong></td>
                            <td><code class="small">${escapeHtml(cfg.path)}</code></td>
                            <td>
                                <span class="badge bg-${cfg.enabled ? 'success' : 'secondary'} bg-opacity-10 text-${cfg.enabled ? 'success' : 'secondary'}">
                                    ${cfg.enabled ? 'Включен' : 'Выключен'}
                                </span>
                            </td>
                            <td class="text-end">
                                <button class="btn btn-outline-secondary btn-sm" onclick="editNginxConfig('${escapeHtml(cfg.name)}')" title="Редактировать">
                                    <i class="bi bi-pencil"></i>
                                </button>
                            </td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        </div>
    `;
}

function showCreateNginxModal() {
    const modal = document.createElement('div');
    modal.className = 'modal fade';
    modal.innerHTML = `
        <div class="modal-dialog modal-lg modal-dialog-scrollable">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">Создать Nginx конфиг</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <form id="createNginxForm">
                    <div class="modal-body">
                        <div class="mb-3">
                            <label class="form-label">Имя (example.com.conf)</label>
                            <input class="form-control" name="name" id="nginx-name" required placeholder="example.com">
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Содержимое</label>
                            <textarea class="form-control font-monospace" name="content" id="nginx-content" rows="18" required>server {
    listen 80;
    server_name example.com www.example.com;

    root /var/www/example.com;
    index index.html;

    location / {
        try_files $uri $uri/ =404;
    }
}</textarea>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">Отмена</button>
                        <button type="submit" class="btn btn-black">Создать</button>
                    </div>
                </form>
            </div>
        </div>
    `;

    document.getElementById('modal-container').appendChild(modal);
    const bsModal = new bootstrap.Modal(modal);
    bsModal.show();

    document.getElementById('createNginxForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const name = document.getElementById('nginx-name').value.trim();
        const content = document.getElementById('nginx-content').value;

        if (!name) {
            showToast('Введите имя конфига', 'warning');
            return;
        }

        await delay(500);

        // Добавляем в демо-данные
        const newConfig = {
            name: name,
            path: `/etc/nginx/sites-enabled/${name}`,
            enabled: true
        };
        DEMO_DATA.nginx.push(newConfig);
        DEMO_DATA.fileContents[`/etc/nginx/sites-enabled/${name}`] = content;

        showToast('Конфиг создан', 'success');
        bsModal.hide();
        setTimeout(loadNginx, 300);

        modal.addEventListener('hidden.bs.modal', () => modal.remove());
    });

    modal.addEventListener('hidden.bs.modal', () => modal.remove());
}

async function editNginxConfig(name) {
    const path = `/etc/nginx/sites-enabled/${name}`;
    const content = DEMO_DATA.fileContents[path] || `server {\n    listen 80;\n    server_name ${name};\n}`;
    await editFile(path);
}

async function reloadNginx() {
    await delay(500);
    showToast('Nginx перезагружен (демо)', 'success');
}

// ========= SSL =========
async function loadSSL() {
    const container = document.getElementById('ssl-content');
    container.innerHTML = '<div class="text-center py-4"><div class="spinner-border text-primary"></div></div>';

    await delay(500);

    const ssl = DEMO_DATA.ssl;

    container.innerHTML = `
        <div class="table-responsive">
            <table class="table table-hover mb-0">
                <thead>
                    <tr>
                        <th>Домен</th>
                        <th>Истекает</th>
                        <th>Осталось дней</th>
                        <th class="text-end">Действия</th>
                    </tr>
                </thead>
                <tbody>
                    ${ssl.certificates.map(cert => `
                        <tr>
                            <td><strong>${escapeHtml(cert.domain)}</strong></td>
                            <td>${escapeHtml(cert.expiry)}</td>
                            <td>
                                <span class="badge bg-${cert.days_left > 30 ? 'success' : 'warning'} bg-opacity-10 text-${cert.days_left > 30 ? 'success' : 'warning'}">
                                    ${cert.days_left} дней
                                </span>
                            </td>
                            <td class="text-end">
                                <button class="btn btn-outline-secondary btn-sm" onclick="renewCert('${escapeHtml(cert.domain)}')" title="Обновить">
                                    <i class="bi bi-arrow-repeat"></i>
                                </button>
                            </td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        </div>
    `;
}

function showObtainCertModal(domainPrefill = '') {
    const modal = document.createElement('div');
    modal.className = 'modal fade';
    modal.innerHTML = `
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">Получение SSL сертификата</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <div class="mb-3">
                        <label class="form-label">Домен</label>
                        <input type="text" class="form-control" id="ssl-domain" placeholder="example.com" value="${domainPrefill}">
                        <small class="text-muted">Введите домен для получения сертификата</small>
                    </div>
                    <div class="mb-3">
                        <div class="form-check">
                            <input class="form-check-input" type="checkbox" id="ssl-www" checked>
                            <label class="form-check-label" for="ssl-www">
                                Включить www поддомен
                            </label>
                        </div>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Email для уведомлений</label>
                        <input type="email" class="form-control" id="ssl-email" placeholder="admin@example.com" value="admin@example.com">
                    </div>
                    <div id="ssl-dns-check" class="alert alert-info" style="display: none;">
                        <h6>Проверка DNS записей</h6>
                        <div class="mb-2">
                            <strong>A запись:</strong><br>
                            <code>${domainPrefill || 'example.com'}</code> → <code>185.123.45.67</code>
                            <span class="badge bg-success ms-2" id="dns-a-status">✓ Настроена</span>
                        </div>
                        ${document.getElementById('ssl-www')?.checked ? `
                        <div class="mb-2">
                            <strong>A запись (www):</strong><br>
                            <code>www.${domainPrefill || 'example.com'}</code> → <code>185.123.45.67</code>
                            <span class="badge bg-success ms-2" id="dns-www-status">✓ Настроена</span>
                        </div>
                        ` : ''}
                    </div>
                    <div id="ssl-cert-progress" style="display: none;">
                        <div class="progress mb-3" style="height: 25px;">
                            <div class="progress-bar progress-bar-striped progress-bar-animated" role="progressbar" style="width: 0%" id="ssl-progress-bar">0%</div>
                        </div>
                        <div id="ssl-cert-logs" class="bg-dark text-light p-3 rounded" style="font-family: monospace; font-size: 12px; max-height: 200px; overflow-y: auto;"></div>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Отмена</button>
                    <button type="button" class="btn btn-black" id="ssl-obtain-btn" onclick="obtainSSLCert()">Получить сертификат</button>
                </div>
            </div>
        </div>
    `;

    document.getElementById('modal-container').appendChild(modal);
    const bsModal = new bootstrap.Modal(modal);
    bsModal.show();

    // Показываем проверку DNS при вводе домена
    const domainInput = modal.querySelector('#ssl-domain');
    domainInput.addEventListener('input', () => {
        const domain = domainInput.value;
        if (domain) {
            modal.querySelector('#ssl-dns-check').style.display = 'block';
            modal.querySelector('#ssl-dns-check h6').nextElementSibling.querySelector('code').textContent = domain;
        }
    });

    modal.addEventListener('hidden.bs.modal', () => modal.remove());
}

function obtainSSLCert() {
    const domain = document.getElementById('ssl-domain')?.value;
    if (!domain) {
        showToast('Введите домен', 'warning');
        return;
    }

    document.getElementById('ssl-obtain-btn').disabled = true;
    document.getElementById('ssl-cert-progress').style.display = 'block';
    const logs = document.getElementById('ssl-cert-logs');
    const progress = document.getElementById('ssl-progress-bar');

    const steps = [
        { text: 'Проверка DNS записей...', delay: 800 },
        { text: '✓ DNS записи настроены корректно', delay: 500 },
        { text: 'Запрос сертификата в Let\'s Encrypt...', delay: 1200 },
        { text: 'Прохождение ACME challenge...', delay: 1000 },
        { text: '✓ Сертификат получен успешно', delay: 500 },
        { text: 'Настройка Nginx...', delay: 600 },
        { text: 'Перезагрузка Nginx...', delay: 400 },
        { text: '✓ SSL сертификат установлен и активен!', delay: 300 }
    ];

    let p = 0;
    steps.forEach((step, i) => {
        setTimeout(() => {
            p = Math.min(100, ((i + 1) / steps.length) * 100);
            progress.style.width = p + '%';
            progress.textContent = Math.round(p) + '%';
            logs.innerHTML += `<div>${step.text}</div>`;
            logs.scrollTop = logs.scrollHeight;

            if (i === steps.length - 1) {
                showToast(`SSL сертификат для ${domain} получен!`, 'success');
                document.getElementById('ssl-obtain-btn').disabled = false;
                setTimeout(() => {
                    const bsModal = bootstrap.Modal.getInstance(document.querySelector('.modal.show'));
                    if (bsModal) bsModal.hide();
                    setTimeout(loadSSL, 500);
                }, 1000);
            }
        }, steps.slice(0, i).reduce((sum, s) => sum + s.delay, 0));
    });
}

async function renewAllCerts() {
    await delay(1000);
    showToast('Все SSL сертификаты обновлены (демо)', 'success');
}

function renewCert(domain) {
    showToast(`SSL сертификат для ${domain} обновлён (демо)`, 'success');
}

// ========= Backups =========
async function loadBackups() {
    const container = document.getElementById('backups-content');
    container.innerHTML = '<div class="text-center py-4"><div class="spinner-border text-primary"></div></div>';

    await delay(500);

    const backups = DEMO_DATA.backups;

    container.innerHTML = `
        <div class="table-responsive">
            <table class="table table-hover mb-0">
                <thead>
                    <tr>
                        <th>Имя</th>
                        <th>Размер</th>
                        <th>Дата</th>
                        <th class="text-end">Действия</th>
                    </tr>
                </thead>
                <tbody>
                    ${backups.map(backup => `
                        <tr>
                            <td><code>${escapeHtml(backup.name)}</code></td>
                            <td>${formatFileSize(backup.size)}</td>
                            <td>${escapeHtml(backup.date)}</td>
                            <td class="text-end">
                                <div class="btn-group btn-group-sm">
                                    <button class="btn btn-outline-secondary" onclick="downloadBackup('${escapeHtml(backup.name)}')" title="Скачать">
                                        <i class="bi bi-download"></i>
                                    </button>
                                    <button class="btn btn-outline-danger" onclick="deleteBackup('${escapeHtml(backup.name)}')" title="Удалить">
                                        <i class="bi bi-trash"></i>
                                    </button>
                                </div>
                            </td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        </div>
    `;
}

function showCreateBackupModal() {
    const modal = document.createElement('div');
    modal.className = 'modal fade';
    modal.innerHTML = `
        <div class="modal-dialog modal-lg modal-dialog-scrollable">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">Создать бэкап</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <form id="createBackupForm">
                    <div class="modal-body">
                        <div class="row g-3">
                            <div class="col-12 col-md-4">
                                <label class="form-label">Тип</label>
                                <select class="form-select" name="kind" id="backupKind">
                                    <option value="site" selected>Сайт (/var/www)</option>
                                    <option value="project">Проект (/home/user/projects)</option>
                                </select>
                            </div>
                            <div class="col-12 col-md-8">
                                <label class="form-label">Имя</label>
                                <input class="form-control" name="name" id="backupName" required placeholder="example.com или my-project" list="backupSuggestions">
                                <datalist id="backupSuggestions">
                                    ${DEMO_DATA.sites.map(s => `<option value="${escapeHtml(s.domain)}"></option>`).join('')}
                                    ${DEMO_DATA.projects.map(p => `<option value="${escapeHtml(p.name)}"></option>`).join('')}
                                </datalist>
                                <div class="form-text">Будет создан архив .tar.gz</div>
                            </div>
                            <div class="col-12">
                                <div class="alert alert-light mb-0">
                                    Подсказка: в разделе <b>Сайты</b> можно открыть папку сайта и проверить содержимое перед бэкапом.
                                </div>
                            </div>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">Отмена</button>
                        <button type="submit" class="btn btn-black">Создать</button>
                    </div>
                </form>
            </div>
        </div>
    `;

    document.getElementById('modal-container').appendChild(modal);
    const bsModal = new bootstrap.Modal(modal);
    bsModal.show();

    document.getElementById('createBackupForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const kind = document.getElementById('backupKind').value;
        const name = document.getElementById('backupName').value.trim();

        if (!name) {
            showToast('Введите имя', 'warning');
            return;
        }

        showToast('Создаю бэкап...', 'info');

        // Симуляция создания бэкапа
        await delay(1500);

        const now = new Date();
        const backupName = `backup-${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}-${String(now.getDate()).padStart(2, '0')}-${String(now.getHours()).padStart(2, '0')}-${String(now.getMinutes()).padStart(2, '0')}.tar.gz`;

        const newBackup = {
            name: backupName,
            size: Math.floor(Math.random() * 2 * 1024 * 1024 * 1024) + 1024 * 1024 * 1024, // 1-3 GB
            date: now.toLocaleString('ru-RU')
        };

        DEMO_DATA.backups.unshift(newBackup);

        showToast('Бэкап создан', 'success');
        bsModal.hide();
        setTimeout(loadBackups, 300);

        modal.addEventListener('hidden.bs.modal', () => modal.remove());
    });

    modal.addEventListener('hidden.bs.modal', () => modal.remove());
}

function downloadBackup(name) {
    showToast(`Скачивание ${name} (демо)`, 'info');
}

function deleteBackup(name) {
    if (confirm(`Удалить бэкап ${name}?`)) {
        showToast(`Бэкап ${name} удалён (демо)`, 'success');
        setTimeout(loadBackups, 500);
    }
}

// ========= Security =========
async function loadSecurity() {
    const container = document.getElementById('security-content');
    container.innerHTML = '<div class="text-center py-4"><div class="spinner-border text-primary"></div></div>';

    await delay(500);

    container.innerHTML = `
        <div class="row g-3 mb-4">
            <div class="col-md-6">
                <div class="stat-card">
                    <h6 class="mb-3">Firewall (UFW)</h6>
                    <div class="d-flex justify-content-between align-items-center mb-2">
                        <span>Статус</span>
                        <span class="badge bg-success bg-opacity-10 text-success">Активен</span>
                    </div>
                    <div class="d-flex justify-content-between align-items-center mb-2">
                        <span>Разрешенных правил</span>
                        <strong>12</strong>
                    </div>
                    <div class="d-flex justify-content-between align-items-center">
                        <span>Заблокированных IP</span>
                        <strong class="text-danger">3</strong>
                    </div>
                </div>
            </div>
            <div class="col-md-6">
                <div class="stat-card">
                    <h6 class="mb-3">SSH</h6>
                    <div class="d-flex justify-content-between align-items-center mb-2">
                        <span>Порт</span>
                        <code>22</code>
                    </div>
                    <div class="d-flex justify-content-between align-items-center mb-2">
                        <span>Авторизация по ключам</span>
                        <span class="badge bg-success bg-opacity-10 text-success">Включена</span>
                    </div>
                    <div class="d-flex justify-content-between align-items-center">
                        <span>Авторизация по паролю</span>
                        <span class="badge bg-danger bg-opacity-10 text-danger">Отключена</span>
                    </div>
                </div>
            </div>
        </div>

        <div class="row g-3 mb-4">
            <div class="col-md-6">
                <div class="stat-card">
                    <h6 class="mb-3">Обновления системы</h6>
                    <div class="d-flex justify-content-between align-items-center mb-2">
                        <span>Доступно обновлений</span>
                        <span class="badge bg-warning bg-opacity-10 text-warning">5</span>
                    </div>
                    <div class="d-flex justify-content-between align-items-center mb-2">
                        <span>Последняя проверка</span>
                        <small class="text-muted">2 часа назад</small>
                    </div>
                    <button class="btn btn-outline-primary btn-sm w-100 mt-2">
                        <i class="bi bi-arrow-clockwise"></i> Проверить обновления
                    </button>
                </div>
            </div>
            <div class="col-md-6">
                <div class="stat-card">
                    <h6 class="mb-3">Логи безопасности</h6>
                    <div class="d-flex justify-content-between align-items-center mb-2">
                        <span>Попыток входа за 24ч</span>
                        <strong>127</strong>
                    </div>
                    <div class="d-flex justify-content-between align-items-center mb-2">
                        <span>Неудачных попыток</span>
                        <strong class="text-danger">23</strong>
                    </div>
                    <div class="d-flex justify-content-between align-items-center">
                        <span>Заблокированных IP</span>
                        <strong class="text-danger">3</strong>
                    </div>
                </div>
            </div>
        </div>

        <div class="stat-card">
            <h6 class="mb-3">Активные подключения</h6>
            <div class="table-responsive">
                <table class="table table-sm mb-0">
                    <thead>
                        <tr>
                            <th>IP адрес</th>
                            <th>Порт</th>
                            <th>Протокол</th>
                            <th>Статус</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td><code>185.123.45.67</code></td>
                            <td>443</td>
                            <td>HTTPS</td>
                            <td><span class="badge bg-success bg-opacity-10 text-success">Активен</span></td>
                        </tr>
                        <tr>
                            <td><code>185.123.45.67</code></td>
                            <td>80</td>
                            <td>HTTP</td>
                            <td><span class="badge bg-success bg-opacity-10 text-success">Активен</span></td>
                        </tr>
                        <tr>
                            <td><code>192.168.1.100</code></td>
                            <td>22</td>
                            <td>SSH</td>
                            <td><span class="badge bg-info bg-opacity-10 text-info">Подключен</span></td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>
    `;
}

// ========= Projects =========
async function loadProjects() {
    const container = document.getElementById('projects-content');
    container.innerHTML = '<div class="text-center py-4"><div class="spinner-border text-primary"></div></div>';

    await delay(500);

    const projects = DEMO_DATA.projects;

    container.innerHTML = `
        <div class="table-responsive">
            <table class="table table-hover mb-0">
                <thead>
                    <tr>
                        <th>Проект</th>
                        <th>Путь</th>
                        <th>Тип</th>
                        <th>Порт</th>
                        <th>Статус</th>
                        <th class="text-end">Действия</th>
                    </tr>
                </thead>
                <tbody>
                    ${projects.map(proj => `
                        <tr>
                            <td><strong>${escapeHtml(proj.name)}</strong></td>
                            <td><code class="small">${escapeHtml(proj.path)}</code></td>
                            <td><span class="badge bg-secondary bg-opacity-10 text-secondary">${escapeHtml(proj.type)}</span></td>
                            <td>${escapeHtml(String(proj.port))}</td>
                            <td>
                                <span class="badge bg-${proj.status === 'running' ? 'success' : 'secondary'} bg-opacity-10 text-${proj.status === 'running' ? 'success' : 'secondary'}">
                                    ${proj.status === 'running' ? 'Запущен' : 'Остановлен'}
                                </span>
                            </td>
                            <td class="text-end">
                                <button class="btn btn-outline-secondary btn-sm" onclick="showProjectDetails('${escapeHtml(proj.name)}')" title="Детали">
                                    <i class="bi bi-info-circle"></i>
                                </button>
                            </td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        </div>
    `;
}

function showCreateProjectWizardModal() {
    let currentStep = 1;
    const wizardData = {
        jobId: null,
        projectName: '',
        analysis: null,
        domain: '',
        skipDns: false,
        pollTimer: null,
    };

    const modalHtml = `
        <div class="modal fade" id="createProjectWizardModal" tabindex="-1">
            <div class="modal-dialog modal-lg modal-dialog-scrollable modal-fullscreen-md-down">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">Мастер создания проекта</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body">
                        <!-- Step 1: Name -->
                        <div id="pw-step-1" class="wizard-step">
                            <div class="text-center mb-4">
                                <div class="mb-3" style="font-size: 48px;">📦</div>
                                <h4>Шаг 1: Название проекта</h4>
                                <p class="text-muted">Папка будет создана в <code>/home/user/projects</code></p>
                            </div>
                            <div class="mb-3">
                                <label class="form-label fw-bold">Название</label>
                                <input type="text" class="form-control form-control-lg" id="pw-name" placeholder="myproject" required>
                                <div class="form-text">Разрешены: буквы/цифры/точка/подчёркивание/дефис (до 64 символов)</div>
                            </div>
                            <div class="d-flex justify-content-end">
                                <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">Отмена</button>
                                <button type="button" class="btn btn-black ms-2" id="pw-to-upload">Далее →</button>
                            </div>
                        </div>

                        <!-- Step 2: Upload -->
                        <div id="pw-step-2" class="wizard-step" style="display:none;">
                            <div class="text-center mb-4">
                                <div class="mb-3" style="font-size: 48px;">⬆️</div>
                                <h4>Шаг 2: Загрузка файлов</h4>
                                <p class="text-muted">Загрузите архив проекта (<code>.zip</code> или <code>.tar.gz</code>)</p>
                            </div>
                            <div class="mb-3">
                                <input type="file" class="form-control" id="pw-archive" accept=".zip,.tar,.tar.gz,.tgz" disabled />
                                <div class="form-text">В демо-версии загрузка файлов отключена</div>
                            </div>
                            <div class="d-flex gap-2 mb-3">
                                <button type="button" class="btn btn-black" id="pw-upload-btn" disabled>
                                    <i class="bi bi-upload"></i> Загрузить и проанализировать
                                </button>
                                <button type="button" class="btn btn-outline-secondary" id="pw-upload-refresh" style="display:none;">
                                    <i class="bi bi-arrow-clockwise"></i>
                                </button>
                            </div>
                            <div id="pw-analysis-box" style="display:none;">
                                <div class="alert alert-light">
                                    <div class="fw-bold mb-2">Определено автоматически</div>
                                    <div class="small text-muted" id="pw-analysis-text"></div>
                                </div>
                                <div class="row g-3">
                                    <div class="col-12 col-md-6">
                                        <label class="form-label fw-bold">Entrypoint (что запускать)</label>
                                        <select class="form-select" id="pw-entrypoint"></select>
                                    </div>
                                    <div class="col-12 col-md-6">
                                        <label class="form-label fw-bold">PORT</label>
                                        <input type="number" class="form-control" id="pw-port" placeholder="5025">
                                        <div class="form-text">Если проект не использует PORT — можно оставить пустым</div>
                                    </div>
                                </div>
                            </div>
                            <div class="d-flex justify-content-between mt-4">
                                <button type="button" class="btn btn-outline-secondary" id="pw-back-to-name">← Назад</button>
                                <button type="button" class="btn btn-black" id="pw-to-domain" style="display:none;">Далее →</button>
                            </div>
                        </div>

                        <!-- Step 3: Domain + DNS -->
                        <div id="pw-step-3" class="wizard-step" style="display:none;">
                            <div class="text-center mb-4">
                                <div class="mb-3" style="font-size: 48px;" id="pw-dns-icon">🌐</div>
                                <h4>Шаг 3: Домен и DNS</h4>
                                <p class="text-muted" id="pw-dns-status">Укажите домен (если нужен nginx proxy)</p>
                            </div>
                            <div class="mb-3">
                                <label class="form-label fw-bold">Домен (необязательно)</label>
                                <input type="text" class="form-control form-control-lg" id="pw-domain" placeholder="myproject.dreampartners.online">
                                <div class="form-text">Если оставить пустым — шаг nginx/DNS будет пропущен</div>
                            </div>
                            <div id="pw-dns-result" class="mb-3"></div>
                            <div class="d-flex justify-content-between">
                                <button type="button" class="btn btn-outline-secondary" id="pw-back-to-upload">← Назад</button>
                                <div class="d-flex gap-2">
                                    <button type="button" class="btn btn-outline-secondary" id="pw-check-dns">Проверить DNS</button>
                                    <button type="button" class="btn btn-black" id="pw-to-config">Далее →</button>
                                </div>
                            </div>
                        </div>

                        <!-- Step 4: Deploy config -->
                        <div id="pw-step-4" class="wizard-step" style="display:none;">
                            <div class="text-center mb-4">
                                <div class="mb-3" style="font-size: 48px;">⚙️</div>
                                <h4>Шаг 4: Деплой</h4>
                                <p class="text-muted">Создание сервиса, автозапуск, nginx, зависимости</p>
                            </div>

                            <div class="row g-3">
                                <div class="col-12 col-md-6">
                                    <label class="form-label fw-bold">Python</label>
                                    <input type="text" class="form-control" id="pw-python-bin" value="/usr/bin/python3.13">
                                </div>
                                <div class="col-12 col-md-6">
                                    <label class="form-label fw-bold">Venv (опционально)</label>
                                    <div class="form-check mt-2">
                                        <input class="form-check-input" type="checkbox" id="pw-use-venv">
                                        <label class="form-check-label" for="pw-use-venv">Создать <code>venv/</code> внутри проекта</label>
                                    </div>
                                </div>

                                <div class="col-12">
                                    <div class="form-check">
                                        <input class="form-check-input" type="checkbox" id="pw-install-deps" checked>
                                        <label class="form-check-label fw-bold" for="pw-install-deps">Установить зависимости</label>
                                    </div>
                                    <div class="form-text" id="pw-req-hint">Найден <code>requirements.txt</code></div>
                                </div>
                                <div class="col-12">
                                    <label class="form-label fw-bold">Доп. зависимости (pip install ...)</label>
                                    <textarea class="form-control" id="pw-pip-packages" rows="2" placeholder="gunicorn requests ... (можно пусто)"></textarea>
                                </div>

                                <div class="col-12">
                                    <hr class="my-2">
                                </div>

                                <div class="col-12 col-md-6">
                                    <div class="form-check">
                                        <input class="form-check-input" type="checkbox" id="pw-create-service" checked>
                                        <label class="form-check-label fw-bold" for="pw-create-service">Создать systemd сервис</label>
                                    </div>
                                </div>
                                <div class="col-12 col-md-6">
                                    <label class="form-label fw-bold">Имя сервиса</label>
                                    <input type="text" class="form-control" id="pw-service-name" placeholder="">
                                    <div class="form-text">Будет создан <code>&lt;name&gt;.service</code></div>
                                </div>
                                <div class="col-12 col-md-6">
                                    <label class="form-label fw-bold">User</label>
                                    <input type="text" class="form-control" id="pw-service-user" value="user">
                                </div>
                                <div class="col-12 col-md-6">
                                    <div class="form-check mt-4">
                                        <input class="form-check-input" type="checkbox" id="pw-enable-autostart" checked>
                                        <label class="form-check-label fw-bold" for="pw-enable-autostart">Включить автозапуск (enable)</label>
                                    </div>
                                    <div class="form-check mt-2">
                                        <input class="form-check-input" type="checkbox" id="pw-start-service" checked>
                                        <label class="form-check-label fw-bold" for="pw-start-service">Запустить сервис (restart)</label>
                                    </div>
                                </div>

                                <div class="col-12">
                                    <hr class="my-2">
                                </div>

                                <div class="col-12">
                                    <div class="form-check">
                                        <input class="form-check-input" type="checkbox" id="pw-create-nginx">
                                        <label class="form-check-label fw-bold" for="pw-create-nginx">Создать nginx конфиг (proxy на PORT)</label>
                                    </div>
                                </div>
                                <div class="col-12">
                                    <div class="form-check">
                                        <input class="form-check-input" type="checkbox" id="pw-create-ssl">
                                        <label class="form-check-label fw-bold" for="pw-create-ssl">Получить SSL (Let's Encrypt)</label>
                                    </div>
                                </div>
                                <div class="col-12" id="pw-email-group" style="display:none;">
                                    <label class="form-label fw-bold">Email для SSL (необязательно)</label>
                                    <input type="email" class="form-control" id="pw-email" placeholder="admin@example.com">
                                </div>
                                <div class="col-12" id="pw-skipdns-group" style="display:none;">
                                    <div class="form-check">
                                        <input class="form-check-input" type="checkbox" id="pw-skip-dns">
                                        <label class="form-check-label" for="pw-skip-dns">Пропустить проверку DNS</label>
                                    </div>
                                </div>
                            </div>

                            <div class="d-flex justify-content-between mt-4">
                                <button type="button" class="btn btn-outline-secondary" id="pw-back-to-domain2">← Назад</button>
                                <button type="button" class="btn btn-black" id="pw-deploy-btn">Запустить деплой</button>
                            </div>
                        </div>

                        <!-- Step 5: Logs -->
                        <div id="pw-step-5" class="wizard-step" style="display:none;">
                            <div class="text-center mb-3">
                                <div class="mb-2" style="font-size: 56px;" id="pw-final-icon">⏳</div>
                                <h4 id="pw-final-title">Выполняю…</h4>
                                <p class="text-muted" id="pw-final-subtitle">Логи будут обновляться автоматически</p>
                            </div>
                            <pre id="pw-logs" class="small bg-light p-3 rounded" style="white-space: pre-wrap; height: 45vh; overflow:auto; font-family: monospace; font-size: 12px;"></pre>
                            <div class="d-flex justify-content-center gap-2 mt-3 flex-wrap">
                                <button type="button" class="btn btn-black" id="pw-open-project" style="display:none;">
                                    <i class="bi bi-folder2-open me-2"></i>Открыть файлы проекта
                                </button>
                                <button type="button" class="btn btn-outline-secondary" id="pw-open-service-logs" style="display:none;">
                                    <i class="bi bi-journal-text me-2"></i>Логи сервиса
                                </button>
                                <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">Закрыть</button>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `;

    document.getElementById('modal-container').innerHTML = modalHtml;
    const modalEl = document.getElementById('createProjectWizardModal');
    const modal = new bootstrap.Modal(modalEl);
    modal.show();

    // Step 1 -> 2
    document.getElementById('pw-to-upload').onclick = () => {
        const name = document.getElementById('pw-name').value.trim();
        if (!name) {
            showToast('Введите название проекта', 'warning');
            return;
        }
        wizardData.projectName = name;
        document.getElementById('pw-step-1').style.display = 'none';
        document.getElementById('pw-step-2').style.display = 'block';
        currentStep = 2;

        // Prefill service name
        document.getElementById('pw-service-name').value = name;
    };

    // Step 2 -> 3
    document.getElementById('pw-to-domain').onclick = () => {
        document.getElementById('pw-step-2').style.display = 'none';
        document.getElementById('pw-step-3').style.display = 'block';
        currentStep = 3;
    };

    // Step 3 -> 4
    document.getElementById('pw-to-config').onclick = () => {
        document.getElementById('pw-step-3').style.display = 'none';
        document.getElementById('pw-step-4').style.display = 'block';
        currentStep = 4;

        const domain = document.getElementById('pw-domain').value.trim();
        if (domain) {
            document.getElementById('pw-create-nginx').checked = true;
            document.getElementById('pw-email-group').style.display = document.getElementById('pw-create-ssl').checked ? 'block' : 'none';
        }
    };

    // Back buttons
    document.getElementById('pw-back-to-name').onclick = () => {
        document.getElementById('pw-step-2').style.display = 'none';
        document.getElementById('pw-step-1').style.display = 'block';
        currentStep = 1;
    };

    document.getElementById('pw-back-to-upload').onclick = () => {
        document.getElementById('pw-step-3').style.display = 'none';
        document.getElementById('pw-step-2').style.display = 'block';
        currentStep = 2;
    };

    document.getElementById('pw-back-to-domain2').onclick = () => {
        document.getElementById('pw-step-4').style.display = 'none';
        document.getElementById('pw-step-3').style.display = 'block';
        currentStep = 3;
    };

    // Автоматически заполняем анализ (в демо файл не загружается)
    setTimeout(() => {
        wizardData.analysis = {
            framework: 'Flask',
            port: '5000',
            requirements: 'requirements.txt',
            entrypoints: ['app.py', 'run.py', 'main.py'],
            suggested_entrypoint: 'app.py'
        };

        const a = wizardData.analysis;
        const epSel = document.getElementById('pw-entrypoint');
        epSel.innerHTML = a.entrypoints.map(x => `<option value="${escapeHtml(x)}">${escapeHtml(x)}</option>`).join('');
        epSel.value = a.suggested_entrypoint;

        document.getElementById('pw-port').value = a.port;
        document.getElementById('pw-req-hint').innerHTML = `Найден <code>${escapeHtml(a.requirements)}</code>`;

        const box = document.getElementById('pw-analysis-box');
        const txt = document.getElementById('pw-analysis-text');
        box.style.display = 'block';
        txt.innerHTML = `Framework: <code>${escapeHtml(a.framework)}</code> • PORT: <code>${escapeHtml(a.port)}</code> • Deps: <code>${escapeHtml(a.requirements)}</code>`;

        document.getElementById('pw-to-domain').style.display = 'inline-block';
    }, 500);

    // Check DNS
    document.getElementById('pw-check-dns').onclick = async () => {
        const domain = document.getElementById('pw-domain').value.trim();
        if (!domain) {
            showToast('Введите домен', 'warning');
            return;
        }

        const icon = document.getElementById('pw-dns-icon');
        const status = document.getElementById('pw-dns-status');
        const result = document.getElementById('pw-dns-result');

        icon.textContent = '🔍';
        status.textContent = 'Проверяю DNS…';
        result.innerHTML = '';

        await delay(1500);

        const serverIp = '185.123.45.67';
        const domainIp = '185.123.45.67';
        const dnsOk = Math.random() > 0.3;

        if (dnsOk) {
            icon.textContent = '✅';
            status.textContent = 'DNS настроен правильно';
            result.innerHTML = `
                <div class="alert alert-success">
                    <div class="fw-bold mb-2">✓ Домен указывает на этот сервер</div>
                    <div class="small">
                        <div>IP сервера: <code>${escapeHtml(serverIp)}</code></div>
                        <div>IP домена: <code>${escapeHtml(domainIp)}</code></div>
                    </div>
                </div>
            `;
        } else {
            icon.textContent = '⚠️';
            status.textContent = 'DNS не настроен';
            result.innerHTML = `
                <div class="alert alert-warning">
                    <div class="fw-bold mb-2">⚠️ Проблема с DNS</div>
                    <div class="small mb-3">Домен не указывает на этот сервер</div>
                    <div class="small text-muted mb-2">
                        <div>IP сервера: <code>${escapeHtml(serverIp)}</code></div>
                        <div>IP домена: <code>${escapeHtml(domainIp)}</code></div>
                    </div>
                    <div class="form-check mt-3">
                        <input class="form-check-input" type="checkbox" id="pw-skip-dns-step3">
                        <label class="form-check-label" for="pw-skip-dns-step3">
                            Продолжить без проверки DNS (для тестов/локальных доменов)
                        </label>
                    </div>
                </div>
            `;
        }
    };

    // SSL checkbox
    document.getElementById('pw-create-ssl').addEventListener('change', (e) => {
        document.getElementById('pw-email-group').style.display = e.target.checked ? 'block' : 'none';
        document.getElementById('pw-skipdns-group').style.display = e.target.checked ? 'block' : 'none';
    });

    // Deploy
    document.getElementById('pw-deploy-btn').onclick = async () => {
        const projectName = wizardData.projectName;
        const entrypoint = document.getElementById('pw-entrypoint').value;
        const port = document.getElementById('pw-port').value;

        if (!entrypoint) {
            showToast('Выберите entrypoint', 'warning');
            return;
        }

        document.getElementById('pw-step-4').style.display = 'none';
        document.getElementById('pw-step-5').style.display = 'block';
        currentStep = 5;

        const logsEl = document.getElementById('pw-logs');
        const icon = document.getElementById('pw-final-icon');
        const title = document.getElementById('pw-final-title');
        const subtitle = document.getElementById('pw-final-subtitle');
        const openBtn = document.getElementById('pw-open-project');

        let logs = 'Запускаю деплой…\n\n';
        logsEl.textContent = logs;

        const deploySteps = [
            { text: 'Создание директории проекта...', delay: 500 },
            { text: '✓ Директория создана: /home/user/projects/' + projectName, delay: 300 },
            { text: 'Копирование файлов проекта...', delay: 800 },
            { text: '✓ Файлы скопированы', delay: 300 },
            { text: 'Создание виртуального окружения...', delay: 600 },
            { text: '✓ venv создан', delay: 300 },
            { text: 'Установка зависимостей из requirements.txt...', delay: 1200 },
            { text: '✓ Зависимости установлены', delay: 300 },
            { text: 'Создание systemd сервиса...', delay: 600 },
            { text: '✓ Сервис ' + projectName + '.service создан', delay: 300 },
            { text: 'Включение автозапуска...', delay: 400 },
            { text: '✓ Автозапуск включен', delay: 300 },
            { text: 'Запуск сервиса...', delay: 500 },
            { text: '✓ Сервис запущен и работает', delay: 300 }
        ];

        if (document.getElementById('pw-create-nginx').checked) {
            deploySteps.push(
                { text: 'Создание Nginx конфига...', delay: 400 },
                { text: '✓ Nginx конфиг создан', delay: 300 },
                { text: 'Перезагрузка Nginx...', delay: 500 },
                { text: '✓ Nginx перезагружен', delay: 300 }
            );
        }

        if (document.getElementById('pw-create-ssl').checked) {
            deploySteps.push(
                { text: 'Получение SSL сертификата...', delay: 1500 },
                { text: '✓ SSL сертификат получен', delay: 300 }
            );
        }

        deploySteps.push({ text: '\n✓ Деплой завершен успешно!', delay: 500 });

        for (const step of deploySteps) {
            await delay(step.delay);
            logs += step.text + '\n';
            logsEl.textContent = logs;
            logsEl.scrollTop = logsEl.scrollHeight;
        }

        icon.textContent = '✅';
        title.textContent = 'Готово!';
        subtitle.textContent = 'Проект успешно развернут';
        openBtn.style.display = 'inline-block';

        // Создаем директорию проекта в localStorage
        const projectPath = `/home/user/projects/${projectName}`;
        addFileToStorage('/home/user/projects', projectName, 'directory');
        addFileToStorage(projectPath, 'app.py', 'file', 2048);
        addFileToStorage(projectPath, 'requirements.txt', 'file', 256);
        addFileContent(`${projectPath}/app.py`, `from flask import Flask

app = Flask(__name__)

@app.route('/')
def hello():
    return 'Hello, World!'

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=${parseInt(port) || 5000})
`);
        addFileContent(`${projectPath}/requirements.txt`, `Flask==2.3.0
gunicorn==21.2.0
`);

        // Добавляем проект в демо-данные
        const newProject = {
            name: projectName,
            path: projectPath,
            type: 'flask',
            port: parseInt(port) || 5000,
            status: 'running'
        };
        DEMO_DATA.projects.push(newProject);

        openBtn.onclick = () => {
            modal.hide();
            switchSection('files');
            setTimeout(() => {
                setFileRoot(newProject.path);
            }, 300);
        };

        loadProjects();
    };
}

function showProjectDetails(name) {
    const proj = DEMO_DATA.projects.find(p => p.name === name);
    if (!proj) return;

    const modal = document.createElement('div');
    modal.className = 'modal fade';
    modal.innerHTML = `
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">Детали проекта: ${escapeHtml(name)}</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <div class="row mb-3">
                        <div class="col-md-6">
                            <strong>Путь:</strong><br>
                            <code>${escapeHtml(proj.path)}</code>
                        </div>
                        <div class="col-md-6">
                            <strong>Тип:</strong><br>
                            <span class="badge bg-secondary">${escapeHtml(proj.type)}</span>
                        </div>
                    </div>
                    <div class="row mb-3">
                        <div class="col-md-6">
                            <strong>Порт:</strong><br>
                            ${escapeHtml(String(proj.port))}
                        </div>
                        <div class="col-md-6">
                            <strong>Статус:</strong><br>
                            <span class="badge bg-${proj.status === 'running' ? 'success' : 'secondary'}">${proj.status === 'running' ? 'Запущен' : 'Остановлен'}</span>
                        </div>
                    </div>
                    <div class="mt-3">
                        <button class="btn btn-outline-primary btn-sm" onclick="openProjectFiles('${escapeHtml(proj.path)}')">
                            <i class="bi bi-folder2-open"></i> Открыть файлы проекта
                        </button>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Закрыть</button>
                </div>
            </div>
        </div>
    `;

    document.getElementById('modal-container').appendChild(modal);
    const bsModal = new bootstrap.Modal(modal);
    bsModal.show();

    modal.addEventListener('hidden.bs.modal', () => modal.remove());
}

function openProjectFiles(path) {
    // Переключаемся на раздел файлов и открываем путь проекта
    switchSection('files');
    setTimeout(() => {
        setFileRoot(path);
        const bsModal = bootstrap.Modal.getInstance(document.querySelector('.modal.show'));
        if (bsModal) bsModal.hide();
    }, 300);
}

// ========= Init =========
document.addEventListener('DOMContentLoaded', () => {
    bindNavigation();
    initFileRoots();
    initServicesState();
    loadDashboard();
});
