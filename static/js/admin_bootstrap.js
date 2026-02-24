// Bootstrap Admin Panel JavaScript (responsive + Telegram WebApp auth)

// ========= Telegram WebApp helpers =========
function getTelegramInitData() {
    try {
        if (window.Telegram && window.Telegram.WebApp && window.Telegram.WebApp.initData) {
            return window.Telegram.WebApp.initData;
        }
    } catch (_) {}
    return '';
}

function withAuthQuery(url) {
    const initData = getTelegramInitData();
    if (!initData) return url;

    try {
        const u = new URL(url, window.location.origin);
        u.searchParams.set('tgWebAppData', initData);
        return u.toString();
    } catch (_) {
        const sep = url.includes('?') ? '&' : '?';
        return `${url}${sep}tgWebAppData=${encodeURIComponent(initData)}`;
    }
}

// ========= Generic helpers =========
function escapeHtml(str) {
    return String(str)
        .replace(/&/g, '&amp;')
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

async function apiFetch(url, options = {}) {
    const headers = new Headers(options.headers || {});

    const initData = getTelegramInitData();
    if (initData) {
        headers.set('X-Telegram-Init-Data', initData);
    }

    // Fix Mixed Content: ensure HTTPS for API requests
    if (url.startsWith('/')) {
        const protocol = window.location.protocol;
        const host = window.location.host;
        url = `${protocol}//${host}${url}`;
    }

    // Add cache busting for POST requests to prevent stale HTTP URLs
    if (options.method === 'POST' && !url.includes('_=')) {
        const separator = url.includes('?') ? '&' : '?';
        url += `${separator}_=${Date.now()}`;
    }

    const res = await fetch(url, {
        credentials: 'same-origin',
        cache: 'no-store',
        ...options,
        headers,
    });

    const ct = (res.headers.get('content-type') || '').toLowerCase();
    let data;

    if (ct.includes('application/json')) {
        data = await res.json().catch(() => ({}));
    } else {
        data = await res.text().catch(() => '');
    }

    if (!res.ok) {
        const msg = (data && typeof data === 'object' && data.error) ? data.error : (typeof data === 'string' ? data : `HTTP ${res.status}`);
        throw new Error(msg);
    }

    return data;
}

// ========= Navigation =========
function bindNavigation() {
    document.querySelectorAll('.nav-link[data-section]').forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            const section = link.getAttribute('data-section');
            // Update URL hash without page reload
            window.location.hash = section;
            switchSection(section);

            // Close sidebar on mobile if open
            const sidebar = document.getElementById('sidebarMenu');
            if (sidebar && sidebar.classList.contains('show')) {
                const bsOffcanvas = bootstrap.Offcanvas.getInstance(sidebar);
                if (bsOffcanvas) bsOffcanvas.hide();
            }
        });
    });
    
    // Handle browser back/forward buttons
    window.addEventListener('hashchange', () => {
        const hash = window.location.hash.slice(1) || 'dashboard';
        switchSection(hash);
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
    else if (section === 'bots') loadBots();
    else if (section === 'sites') loadSites();
    else if (section === 'files') loadFiles(currentPath);
    else if (section === 'nginx') loadNginx();
    else if (section === 'ssl') loadSSL();
    else if (section === 'backups') loadBackups();
    else if (section === 'security') loadSecurity();
    else if (section === 'projects') loadProjects();
    else if (section === 'proxy') loadProxyRules();
    else if (section === 'console') initConsole();
    else if (section === 'microservices') refreshIconsProjects();
}

// ========= Global state =========
let currentPath = '/var/www';
let botEditorInstance = null;
const FILE_ROOTS = [
    { label: '/var/www', path: '/var/www' },
    { label: '/home/dream/projects', path: '/home/dream/projects' },
    { label: '/home/dream/bots', path: '/home/dream/bots' },
    { label: '/etc/nginx/sites-enabled', path: '/etc/nginx/sites-enabled' },
    { label: '/etc/systemd/system', path: '/etc/systemd/system' },
    { label: '/etc/letsencrypt', path: '/etc/letsencrypt' },
    { label: '/home/dream/backups/panel', path: '/home/dream/backups/panel' },
    { label: '/', path: '/' },
];

function isAutostartEnabledState(unitFileState) {
    const s = String(unitFileState || '').trim().toLowerCase();
    return s === 'enabled' || s === 'enabled-runtime' || s === 'linked' || s === 'linked-runtime';
}

function isAutostartToggleableState(unitFileState) {
    const s = String(unitFileState || '').trim().toLowerCase();
    // безопасный whitelist (не ломаемся на static/masked/transient/etc.)
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

function bindFileActions() {
    const container = document.getElementById('files-content');
    if (!container) return;

    // Event delegation for dynamic file list
    container.addEventListener('click', (e) => {
        const el = e.target.closest('[data-file-action]');
        if (!el) return;

        const action = el.getAttribute('data-file-action');
        const path = el.getAttribute('data-path') || '';
        const isDir = el.getAttribute('data-is-dir') === '1';
        const name = el.getAttribute('data-name') || '';

        // Prevent navigation for real links (download)
        if (el.tagName === 'A' && el.getAttribute('href') && !el.getAttribute('data-file-action')) {
            return;
        }

        // For buttons/anchors with JS actions
        if (el.tagName === 'A') e.preventDefault();

        if (action === 'open') {
            if (isDir) loadFiles(path);
            else editFile(path);
            return;
        }
        if (action === 'edit') {
            editFile(path);
            return;
        }
        if (action === 'rename') {
            renameItem(path, name);
            return;
        }
        if (action === 'delete') {
            deleteFileItem(path);
            return;
        }
    });
}

function bindBreadcrumbs() {
    const bc = document.getElementById('file-breadcrumbs');
    if (!bc) return;

    // Event delegation: click on breadcrumb segments
    bc.addEventListener('click', (e) => {
        const link = e.target.closest('.breadcrumb-link');
        if (!link) return;
        e.preventDefault();
        const path = link.getAttribute('data-path') || '';
        if (path) loadFiles(path);
    });
}

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

        const td = input.closest('td');
        const stateEl = td ? td.querySelector('.service-autostart-state') : null;
        const prevHtml = stateEl ? String(stateEl.innerHTML || '') : '';

        input.disabled = true;
        if (stateEl) stateEl.innerHTML = `<span class="text-muted small">…</span>`;

        try {
            const res = await apiFetch(`/api/service/${encodeURIComponent(unit)}/action`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action }),
            });
            if (res && res.success === false) throw new Error(res.error || 'Ошибка');

            const newEnabled = String(res?.enabled || 'unknown');
            const on = isAutostartEnabledState(newEnabled);
            const toggleable = isAutostartToggleableState(newEnabled);

            input.checked = on;
            input.title = toggleable ? (on ? 'Отключить автозапуск' : 'Включить автозапуск') : `Недоступно: ${newEnabled}`;
            if (stateEl) stateEl.innerHTML = renderAutostartBadge(newEnabled);

            // Если вдруг пришло состояние без поддержки переключения — оставляем disabled
            input.disabled = !toggleable;

            showToast('Автозапуск обновлён', 'success');
        } catch (err) {
            input.checked = wasChecked;
            if (stateEl) stateEl.innerHTML = prevHtml;
            input.disabled = false;
            showToast(err?.message || 'Ошибка', 'danger');
        }
    });
}

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
        const prev = !shouldRun;

        input.disabled = true;
        try {
            const res = await apiFetch(`/api/service/${encodeURIComponent(unit)}/action`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action }),
            });
            if (res && res.success === false) throw new Error(res.error || 'Ошибка');
            showToast(shouldRun ? 'Сервис запущен' : 'Сервис остановлен', 'success');
            setTimeout(() => loadServices(true), 600);
        } catch (err) {
            input.checked = prev;
            input.disabled = false;
            showToast(err?.message || 'Ошибка', 'danger');
        }
    });
}

function initFileRoots() {
    const sel = document.getElementById('file-root-select');
    if (!sel) return;

    // Choose best match for currentPath (prefer the most specific/longest root)
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

    try {
        const [services, sites, nginx, ssl, metrics] = await Promise.all([
            apiFetch('/api/services'),
            apiFetch('/api/www'),
            apiFetch('/api/nginx'),
            apiFetch('/api/certbot/list'),
            apiFetch('/api/metrics'),
        ]);

        if (Array.isArray(services)) document.getElementById('stat-services').textContent = services.length;
        if (Array.isArray(sites)) document.getElementById('stat-sites').textContent = sites.length;
        if (Array.isArray(nginx)) document.getElementById('stat-nginx').textContent = nginx.length;
        document.getElementById('stat-ssl').textContent = (ssl && ssl.certificates) ? ssl.certificates.length : 0;

        renderMetrics(metrics);
    } catch (e) {
        console.error(e);
        if (metricsEl) {
            metricsEl.innerHTML = `<div class="alert alert-danger">Ошибка загрузки: ${escapeHtml(e.message)}</div>`;
        }
        showToast(e.message, 'danger');
    }
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
function renderServiceRowContent(svc, memTotal) {
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
                <button class="btn btn-outline-warning d-none d-sm-inline-block" onclick="serviceAction('${escapeHtml(svc.unit)}','kill')" title="Остановить принудительно (SIGKILL)">
                    <i class="bi bi-x-octagon"></i>
                </button>
                <button class="btn btn-outline-secondary d-none d-sm-inline-block" onclick="openLogs('${escapeHtml(svc.unit)}')" title="Логи">
                    <i class="bi bi-journal-text"></i>
                </button>
                <button class="btn btn-outline-secondary d-none d-sm-inline-block" onclick="clearServiceJournal('${escapeHtml(svc.unit)}')" title="Очистить журнал">
                    <i class="bi bi-eraser"></i>
                </button>
                <button class="btn btn-outline-danger d-none d-sm-inline-block" onclick="deleteServiceUnit('${escapeHtml(svc.unit)}')" title="Удалить unit">
                    <i class="bi bi-trash"></i>
                </button>
            </div>
        </td>
    `;
}

async function loadServices(silent = false) {
    const container = document.getElementById('services-content');
    
    // Check if table structure exists
    const hasTable = !!container.querySelector('table');

    // Show spinner only if no table and not silent
    if (!silent && !hasTable) {
        container.innerHTML = '<div class="text-center py-4"><div class="spinner-border text-primary"></div></div>';
    }

    try {
        const [services, metrics] = await Promise.all([
            apiFetch('/api/services'),
            apiFetch('/api/metrics'),
        ]);
        const memTotal = Number(metrics?.memory_total || 0);
        
        if (!Array.isArray(services)) throw new Error('Неверный формат ответа');
        
        if (services.length === 0) {
            container.innerHTML = '<div class="alert alert-light text-center">Нет сервисов</div>';
            return;
        }

        // If table doesn't exist, create the structure
        if (!container.querySelector('table')) {
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
                        <tbody></tbody>
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
        }

        const tbody = container.querySelector('tbody');
        if (!tbody) return;

        const existingRows = new Map();
        tbody.querySelectorAll('tr[data-unit]').forEach(tr => existingRows.set(tr.dataset.unit, tr));
        const processedUnits = new Set();

        services.forEach(svc => {
            processedUnits.add(svc.unit);
            const contentHtml = renderServiceRowContent(svc, memTotal);
            let tr = existingRows.get(svc.unit);
            
            if (tr) {
                // Update existing row if content changed
                if (tr.innerHTML !== contentHtml) {
                    tr.innerHTML = contentHtml;
                }
                tr.setAttribute('data-state', svc.state || '');
            } else {
                // Create new row
                const newTr = document.createElement('tr');
                newTr.setAttribute('data-unit', svc.unit);
                newTr.setAttribute('data-state', svc.state || '');
                newTr.innerHTML = contentHtml;
                tbody.appendChild(newTr);
            }
        });

        // Remove old rows
        existingRows.forEach((tr, unit) => {
            if (!processedUnits.has(unit)) {
                tr.remove();
            }
        });

        // Re-apply filter
        const qEl = container.querySelector('#services-search');
        if (qEl) qEl.dispatchEvent(new Event('input'));

    } catch (e) {
        if (!silent && !hasTable) {
            container.innerHTML = `<div class="alert alert-danger">Ошибка: ${escapeHtml(e.message)}</div>`;
        } else {
             console.error('Refresh failed:', e);
        }
    }
}

async function serviceAction(unit, action) {
    try {
        const res = await apiFetch(`/api/service/${encodeURIComponent(unit)}/action`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ action }),
        });
        if (res && res.success === false) {
            throw new Error(res.error || 'Ошибка');
        }
        showToast('Команда выполнена', 'success');
        setTimeout(() => loadServices(true), 500);
    } catch (e) {
        showToast(e.message, 'danger');
    }
}

function openLogs(unit) {
    const url = withAuthQuery(`/api/service/${encodeURIComponent(unit)}/logs?lines=200`);
    window.open(url, '_blank');
}

async function clearServiceJournal(unit) {
    if (!confirm(`Очистить журнал для ${unit}?`)) return;

    try {
        const res = await apiFetch(`/api/service/${encodeURIComponent(unit)}/clear-journal`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
        });
        if (res && res.success === false) throw new Error(res.error || 'Ошибка');
        showToast('Журнал очищен', 'success');
    } catch (e) {
        showToast(e.message, 'danger');
    }
}

async function deleteServiceUnit(unit) {
    if (!confirm(`Удалить systemd unit ${unit}?`)) return;

    try {
        const name = unit.endsWith('.service') ? unit : `${unit}.service`;
        const res = await apiFetch(`/api/systemd/service/${encodeURIComponent(name)}`, { method: 'DELETE' });
        if (res && res.success === false) throw new Error(res.error || 'Ошибка');
        showToast('Сервис удалён', 'success');
        loadServices();
    } catch (e) {
        showToast(e.message, 'danger');
    }
}

function showCreateServiceModal() {
    const modalHtml = `
        <div class="modal fade" id="createServiceModal" tabindex="-1">
            <div class="modal-dialog modal-lg modal-dialog-scrollable">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">Создать systemd сервис</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                    </div>
                    <form id="createServiceForm">
                        <div class="modal-body">
                            <div class="row g-3">
                                <div class="col-12 col-md-6">
                                    <label class="form-label">Имя (без .service)</label>
                                    <input class="form-control" name="name" placeholder="my-app" required>
                                </div>
                                <div class="col-12 col-md-6">
                                    <label class="form-label">User</label>
                                    <input class="form-control" name="user" value="root">
                                </div>
                                <div class="col-12">
                                    <label class="form-label">Description</label>
                                    <input class="form-control" name="description" placeholder="My app service">
                                </div>
                                <div class="col-12">
                                    <label class="form-label">WorkingDirectory</label>
                                    <input class="form-control" name="working_directory" placeholder="/home/dream/projects/my-app">
                                </div>
                                <div class="col-12">
                                    <label class="form-label">ExecStart</label>
                                    <input class="form-control" name="exec_start" placeholder="/usr/bin/python3 app.py" required>
                                </div>
                                <div class="col-12 col-md-6">
                                    <label class="form-label">Restart</label>
                                    <select class="form-select" name="restart">
                                        <option value="always" selected>always</option>
                                        <option value="on-failure">on-failure</option>
                                        <option value="no">no</option>
                                    </select>
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
        </div>
    `;

    document.getElementById('modal-container').innerHTML = modalHtml;
    const modalEl = document.getElementById('createServiceModal');
    const modal = new bootstrap.Modal(modalEl);
    modal.show();

    document.getElementById('createServiceForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const fd = new FormData(e.target);
        const payload = Object.fromEntries(fd);

        try {
            const res = await apiFetch('/api/systemd/service', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload),
            });
            if (res && res.success === false) throw new Error(res.error || 'Ошибка');
            showToast('Сервис создан', 'success');
            modal.hide();
            loadServices();
        } catch (err) {
            showToast(err.message, 'danger');
        }
    });
}

// ========= Sites =========
async function loadSites() {
    const container = document.getElementById('sites-content');
    container.innerHTML = '<div class="text-center py-4"><div class="spinner-border text-primary"></div></div>';

    try {
        const [sites, nginxConfigs, ssl] = await Promise.all([
            apiFetch('/api/www'),
            apiFetch('/api/nginx'),
            apiFetch('/api/certbot/list'),
        ]);

        if (!Array.isArray(sites) || sites.length === 0) {
            container.innerHTML = '<div class="alert alert-light text-center">Нет сайтов</div>';
            return;
        }

        const nginxByDomain = new Map();
        if (Array.isArray(nginxConfigs)) {
            nginxConfigs.forEach(cfg => {
                (cfg.server_names || []).forEach(d => {
                    if (!nginxByDomain.has(d)) nginxByDomain.set(d, cfg.name);
                });
            });
        }

        const certDomains = new Set();
        (ssl && ssl.certificates ? ssl.certificates : []).forEach(c => {
            if (c && c.domain) certDomains.add(c.domain);
        });

        const rowsHtml = sites
            .sort((a, b) => String(a.name || '').localeCompare(String(b.name || '')))
            .map(site => {
                const domain = site.name;
                const path = site.path;
                const sizeHuman = formatFileSize(site.size || 0);

                const cfgName = nginxByDomain.get(domain) || nginxByDomain.get(`www.${domain}`) || '';
                const hasSsl = certDomains.has(domain) || certDomains.has(`www.${domain}`);
                const openUrl = hasSsl ? `https://${domain}` : `http://${domain}`;

                const sslBadge = hasSsl
                    ? '<span class="badge bg-success bg-opacity-10 text-success">SSL</span>'
                    : '<span class="badge bg-secondary bg-opacity-10 text-secondary">no SSL</span>';

                const nginxBadge = cfgName
                    ? `<span class="badge bg-primary bg-opacity-10 text-primary">nginx: ${escapeHtml(cfgName)}</span>`
                    : '<span class="badge bg-secondary bg-opacity-10 text-secondary">no nginx</span>';

                return `
                    <tr data-domain="${escapeHtml(String(domain || ''))}" data-has-ssl="${hasSsl ? '1' : '0'}" data-has-nginx="${cfgName ? '1' : '0'}">
                        <td>
                            <div class="fw-bold">${escapeHtml(domain)}</div>
                            <div class="d-flex gap-2 flex-wrap mt-1">
                                ${sslBadge}
                                ${nginxBadge}
                            </div>
                        </td>
                        <td class="d-none d-md-table-cell text-muted small">
                            <div class="font-monospace">${escapeHtml(path)}</div>
                            <div class="small text-muted">Размер: ${escapeHtml(sizeHuman)}</div>
                        </td>
                        <td class="text-end">
                            <div class="btn-group btn-group-sm">
                                <a class="btn btn-outline-secondary" href="${escapeHtml(openUrl)}" target="_blank" title="Открыть сайт">
                                    <i class="bi bi-box-arrow-up-right"></i>
                                </a>
                                <button class="btn btn-outline-secondary" onclick="openFileManager('${escapeHtml(path)}')" title="Файлы сайта">
                                    <i class="bi bi-folder2-open"></i>
                                </button>
                                <button class="btn btn-outline-secondary" onclick="openNginxForSite('${escapeHtml(domain)}','${escapeHtml(cfgName)}')" title="Nginx конфиг">
                                    <i class="bi bi-file-earmark-code"></i>
                                </button>
                                <button class="btn btn-outline-secondary" onclick="openSslForSite('${escapeHtml(domain)}',${hasSsl ? 'true' : 'false'})" title="SSL">
                                    <i class="bi bi-shield-lock"></i>
                                </button>
                                <button class="btn btn-outline-danger" onclick="deleteSite('${escapeHtml(domain)}')" title="Удалить папку">
                                    <i class="bi bi-trash"></i>
                                </button>
                            </div>
                        </td>
                    </tr>
                `;
            })
            .join('');

        container.innerHTML = `
            <div class="d-flex flex-column flex-md-row gap-2 justify-content-between align-items-md-center mb-3">
                <div class="input-group input-group-sm" style="max-width: 420px;">
                    <span class="input-group-text bg-white"><i class="bi bi-search"></i></span>
                    <input type="text" class="form-control" id="sites-search" placeholder="Поиск сайта…">
                </div>
                <div class="d-flex gap-2">
                    <select class="form-select form-select-sm w-auto" id="sites-filter">
                        <option value="all" selected>Все</option>
                        <option value="ssl">Только с SSL</option>
                        <option value="no_ssl">Без SSL</option>
                        <option value="nginx">Только с nginx</option>
                        <option value="no_nginx">Без nginx</option>
                    </select>
                </div>
            </div>
            <div class="table-responsive">
                <table class="table table-hover mb-0">
                    <thead>
                        <tr>
                            <th>Сайт</th>
                            <th class="d-none d-md-table-cell">Путь</th>
                            <th class="text-end">Действия</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${rowsHtml}
                    </tbody>
                </table>
            </div>
        `;

        // Client-side filtering
        const qEl = container.querySelector('#sites-search');
        const fEl = container.querySelector('#sites-filter');
        const applyFilter = () => {
            const q = (qEl?.value || '').trim().toLowerCase();
            const filt = (fEl?.value || 'all').trim();
            const rows = container.querySelectorAll('tbody tr');
            rows.forEach(tr => {
                const text = (tr.textContent || '').toLowerCase();
                const hasSsl = tr.getAttribute('data-has-ssl') === '1';
                const hasNginx = tr.getAttribute('data-has-nginx') === '1';
                let ok = (!q || text.includes(q));
                if (ok) {
                    if (filt === 'ssl') ok = hasSsl;
                    else if (filt === 'no_ssl') ok = !hasSsl;
                    else if (filt === 'nginx') ok = hasNginx;
                    else if (filt === 'no_nginx') ok = !hasNginx;
                }
                tr.style.display = ok ? '' : 'none';
            });
        };
        if (qEl) qEl.addEventListener('input', applyFilter);
        if (fEl) fEl.addEventListener('change', applyFilter);
    } catch (e) {
        container.innerHTML = `<div class="alert alert-danger">Ошибка: ${escapeHtml(e.message)}</div>`;
    }
}

function openNginxForSite(domain, cfgName) {
    if (!cfgName) {
        showToast(`Не найден nginx конфиг для ${domain}`, 'warning');
        switchSection('nginx');
        return;
    }
    switchSection('nginx');
    editNginxConfig(cfgName);
}

function openSslForSite(domain, hasSsl) {
    switchSection('ssl');
    if (!hasSsl) {
        showObtainCertModal(domain);
    }
}

async function enableSite(name) {
    try {
        const res = await apiFetch(`/api/www/site/${encodeURIComponent(name)}/enable`, { method: 'POST' });
        if (res && res.success === false) throw new Error(res.error || 'Ошибка');
        showToast('Сайт включён', 'success');
        loadSites();
    } catch (e) {
        showToast(e.message, 'danger');
    }
}

async function disableSite(name) {
    try {
        const res = await apiFetch(`/api/www/site/${encodeURIComponent(name)}/disable`, { method: 'POST' });
        if (res && res.success === false) throw new Error(res.error || 'Ошибка');
        showToast('Сайт отключён', 'success');
        loadSites();
    } catch (e) {
        showToast(e.message, 'danger');
    }
}

async function deleteSite(name) {
    if (!confirm(`Удалить сайт ${name}? Будет удалена папка /var/www/${name}`)) return;

    try {
        const res = await apiFetch(`/api/www/site/${encodeURIComponent(name)}`, { method: 'DELETE' });
        if (res && res.success === false) throw new Error(res.error || 'Ошибка');
        showToast('Сайт удалён', 'success');
        loadSites();
    } catch (e) {
        showToast(e.message, 'danger');
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

            try {
                const res = await apiFetch('/api/www/check-dns', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ domain }),
                });

                if (res.success) {
                    dnsIcon.textContent = '✅';
                    dnsStatus.textContent = 'DNS настроен правильно';
                    dnsResult.innerHTML = `
                        <div class="alert alert-success">
                            <div class="fw-bold mb-2">✓ Домен указывает на этот сервер</div>
                            <div class="small">
                                <div>IP сервера: <code>${escapeHtml(res.server_ip || 'N/A')}</code></div>
                                <div>IP домена: <code>${escapeHtml(res.domain_ip || 'N/A')}</code></div>
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
                            <div class="small mb-3">${escapeHtml(res.error || res.message || 'Домен не указывает на этот сервер')}</div>
                            <div class="small text-muted mb-2">
                                <div>IP сервера: <code>${escapeHtml(res.server_ip || 'N/A')}</code></div>
                                <div>IP домена: <code>${escapeHtml(res.domain_ip || 'N/A')}</code></div>
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
            } catch (err) {
                dnsIcon.textContent = '❌';
                dnsStatus.textContent = 'Ошибка проверки DNS';
                dnsResult.innerHTML = `<div class="alert alert-danger">${escapeHtml(err.message)}</div>`;
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

        const payload = {
            name: domain,
            type,
            port,
            create_nginx: createNginx,
            create_ssl: createSSL,
            email: email || '',
            skip_dns_check: skipDns,
        };

        try {
            showToast('Создаю сайт...', 'info');
            const res = await apiFetch('/api/www/site', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload),
            });

            if (res && res.success === false) throw new Error(res.error || 'Ошибка');

            // Переходим к шагу 4 (Success)
            document.getElementById('wizard-step-3').style.display = 'none';
            document.getElementById('wizard-step-4').style.display = 'block';
            currentStep = 4;

            const steps = res.steps || [];
            document.getElementById('wizard-success-msg').textContent = steps.length > 0 ? steps.join(' • ') : 'Сайт успешно создан и настроен';
            wizardData.sitePath = res.path || `/var/www/${domain}`;
            wizardData.siteName = domain;

            loadSites();
        } catch (err) {
            showToast(err.message, 'danger');
        }
    };

    window.wizardOpenSiteFiles = () => {
        if (wizardData.sitePath) {
            modal.hide();
            openFileManager(wizardData.sitePath);
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

// ========= File Manager =========
async function loadFiles(path) {
    currentPath = path || '/var/www';
    initFileRoots();

    const container = document.getElementById('files-content');
    const breadcrumbs = document.getElementById('file-breadcrumbs');

    container.innerHTML = '<div class="text-center py-5"><div class="spinner-border text-primary"></div></div>';

    try {
        const data = await apiFetch(`/api/files/list?path=${encodeURIComponent(currentPath)}`);

        // Breadcrumbs (all segments clickable, no inline onclick)
        const curPath = String(data.current_path || '');
        const rootMatch =
            FILE_ROOTS
                .slice()
                .sort((a, b) => (b.path || '').length - (a.path || '').length)
                .find(r => curPath === r.path || (r.path === '/' ? curPath.startsWith('/') : curPath.startsWith(r.path + '/'))) ||
            { label: curPath, path: curPath };

        let crumbsHtml = `<li class="breadcrumb-item"><a href="#" class="breadcrumb-link" data-path="${escapeHtml(rootMatch.path)}">${escapeHtml(rootMatch.label)}</a></li>`;

        const rel = curPath === rootMatch.path ? '' : curPath.replace(rootMatch.path, '');
        const relParts = rel.split('/').filter(Boolean);
        let pathAccum = rootMatch.path === '/' ? '' : rootMatch.path;

        relParts.forEach((part, idx) => {
            pathAccum += '/' + part;
            if (idx === relParts.length - 1) {
                crumbsHtml += `<li class="breadcrumb-item active" aria-current="page">${escapeHtml(part)}</li>`;
            } else {
                crumbsHtml += `<li class="breadcrumb-item"><a href="#" class="breadcrumb-link" data-path="${escapeHtml(pathAccum)}">${escapeHtml(part)}</a></li>`;
            }
        });

        breadcrumbs.innerHTML = crumbsHtml;

        const items = Array.isArray(data.items) ? data.items : [];
        if (items.length === 0) {
            container.innerHTML = '<div class="text-center py-5 text-muted">Папка пуста</div>';
            return;
        }

        const html = `
            <div class="list-group list-group-flush">
                ${data.parent_path ? `
                    <div class="list-group-item list-group-item-action file-item" data-file-action="open" data-path="${escapeHtml(String(data.parent_path))}" data-is-dir="1">
                        <div class="file-icon"><i class="bi bi-arrow-90deg-up text-secondary"></i></div>
                        <div class="flex-grow-1 text-muted">..</div>
                    </div>
                ` : ''}
                ${items.map(item => {
                    const isDir = !!item.is_dir;
                    const icon = isDir ? 'bi-folder-fill folder-icon' : 'bi-file-earmark-text file-icon-default';
                    const p = String(item.path || '').replace(/\\/g, '/');
                    const size = isDir ? '' : formatFileSize(item.size);
                    const perms = item.permissions ? String(item.permissions) : '';

                    const downloadUrl = !isDir ? withAuthQuery(`/api/files/download?path=${encodeURIComponent(item.path)}`) : '';

                    return `
                        <div class="list-group-item list-group-item-action file-item">
                            <div class="d-flex align-items-center flex-grow-1" data-file-action="open" data-path="${escapeHtml(p)}" data-is-dir="${isDir ? '1' : '0'}">
                                <div class="file-icon"><i class="bi ${icon}"></i></div>
                                <div class="flex-grow-1 text-truncate">
                                    <div class="fw-medium">${escapeHtml(item.name || '')}</div>
                                    <div class="small text-muted d-md-none">${escapeHtml(size)}</div>
                                </div>
                                <div class="text-muted small d-none d-md-block me-3">${escapeHtml(size)}</div>
                                <div class="text-muted small d-none d-md-block font-monospace me-3">${escapeHtml(perms)}</div>
                            </div>
                            <div class="dropdown">
                                <button class="btn btn-link btn-sm text-secondary p-0" data-bs-toggle="dropdown">
                                    <i class="bi bi-three-dots-vertical"></i>
                                </button>
                                <ul class="dropdown-menu dropdown-menu-end shadow">
                                    ${!isDir ? `<li><a class="dropdown-item" href="#" data-file-action="edit" data-path="${escapeHtml(p)}"><i class="bi bi-pencil me-2"></i>Редактировать</a></li>` : ''}
                                    <li><a class="dropdown-item" href="#" data-file-action="rename" data-path="${escapeHtml(p)}" data-name="${escapeHtml(item.name || '')}"><i class="bi bi-pencil-square me-2"></i>Переименовать</a></li>
                                    ${!isDir ? `<li><a class="dropdown-item" href="${escapeHtml(downloadUrl)}" target="_blank"><i class="bi bi-download me-2"></i>Скачать</a></li>` : ''}
                                    <li><hr class="dropdown-divider"></li>
                                    <li><a class="dropdown-item text-danger" href="#" data-file-action="delete" data-path="${escapeHtml(p)}"><i class="bi bi-trash me-2"></i>Удалить</a></li>
                                </ul>
                            </div>
                        </div>
                    `;
                }).join('')}
            </div>
        `;

        container.innerHTML = html;
    } catch (e) {
        container.innerHTML = `<div class="alert alert-danger m-3">Ошибка: ${escapeHtml(e.message)}</div>`;
    }
}

function formatFileSize(bytes) {
    const n = Number(bytes || 0);
    if (!n) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(n) / Math.log(k));
    return parseFloat((n / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

function guessCodeMirrorModeByPath(path) {
    const p = String(path || '').toLowerCase();
    if (p.endsWith('.html') || p.endsWith('.htm')) return 'htmlmixed';
    if (p.endsWith('.css')) return 'css';
    if (p.endsWith('.js')) return 'javascript';
    if (p.endsWith('.json')) return { name: 'javascript', json: true };
    if (p.endsWith('.py')) return 'python';
    if (p.endsWith('.sh') || p.endsWith('.bash')) return 'shell';
    if (p.endsWith('.php')) return 'php';
    if (p.endsWith('.service') || p.endsWith('.timer') || p.endsWith('.mount')) return 'shell';
    if (p.endsWith('.conf') || p.includes('nginx')) return 'shell';
    return 'text/plain';
}

function openFileManager(path) {
    currentPath = path;
    switchSection('files');
    loadFiles(currentPath);
}

function showCreateFolderModal() {
    const modalHtml = `
        <div class="modal fade" id="createFolderModal" tabindex="-1">
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">Создать папку</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                    </div>
                    <form id="createFolderForm">
                        <div class="modal-body">
                            <label class="form-label">Имя папки</label>
                            <input class="form-control" name="name" required>
                            <div class="small text-muted mt-2">Текущий путь: <span class="font-monospace">${escapeHtml(currentPath)}</span></div>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">Отмена</button>
                            <button type="submit" class="btn btn-black">Создать</button>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    `;

    document.getElementById('modal-container').innerHTML = modalHtml;
    const modalEl = document.getElementById('createFolderModal');
    const modal = new bootstrap.Modal(modalEl);
    modal.show();

    document.getElementById('createFolderForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const name = new FormData(e.target).get('name');
        try {
            const res = await apiFetch('/api/files/create_folder', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ path: currentPath, name }),
            });
            if (res && res.success === false) throw new Error(res.error || 'Ошибка');
            modal.hide();
            showToast('Папка создана', 'success');
            loadFiles(currentPath);
        } catch (err) {
            showToast(err.message, 'danger');
        }
    });
}

function showCreateFileModal() {
    const modalHtml = `
        <div class="modal fade" id="createFileModal" tabindex="-1">
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">Создать файл</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                    </div>
                    <form id="createFileForm">
                        <div class="modal-body">
                            <label class="form-label">Имя файла</label>
                            <input class="form-control" name="name" required placeholder="index.html">
                            <div class="small text-muted mt-2">Текущий путь: <span class="font-monospace">${escapeHtml(currentPath)}</span></div>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">Отмена</button>
                            <button type="submit" class="btn btn-black">Создать</button>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    `;

    document.getElementById('modal-container').innerHTML = modalHtml;
    const modalEl = document.getElementById('createFileModal');
    const modal = new bootstrap.Modal(modalEl);
    modal.show();

    document.getElementById('createFileForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const name = new FormData(e.target).get('name');
        try {
            const res = await apiFetch('/api/files/create_file', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ path: currentPath, name }),
            });
            if (res && res.success === false) throw new Error(res.error || 'Ошибка');
            modal.hide();
            showToast('Файл создан', 'success');
            loadFiles(currentPath);
        } catch (err) {
            showToast(err.message, 'danger');
        }
    });
}

async function uploadFile(input) {
    if (!input.files || !input.files.length) return;

    const formData = new FormData();
    formData.append('file', input.files[0]);
    formData.append('path', currentPath);

    try {
        showToast('Загрузка...', 'info');
        const res = await apiFetch('/api/files/upload', {
            method: 'POST',
            body: formData,
        });
        if (res && res.success === false) throw new Error(res.error || 'Ошибка');
        showToast('Файл загружен', 'success');
        loadFiles(currentPath);
    } catch (e) {
        showToast(e.message, 'danger');
    } finally {
        input.value = '';
    }
}

async function editFile(path) {
    try {
        const data = await apiFetch(`/api/files/content?path=${encodeURIComponent(path)}`);

        const modalHtml = `
            <div class="modal fade" id="editorModal" tabindex="-1">
                <div class="modal-dialog modal-xl modal-fullscreen-lg-down">
                    <div class="modal-content">
                        <div class="modal-header">
                            <h5 class="modal-title text-truncate" style="max-width: 75%">${escapeHtml(path)}</h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                        </div>
                        <div class="modal-body p-0">
                            <textarea id="fileEditorContent" class="form-control border-0 font-monospace p-3" style="min-height: 65vh; resize: none;"></textarea>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">Закрыть</button>
                            <button type="button" class="btn btn-black" id="fileEditorSaveBtn">Сохранить</button>
                        </div>
                    </div>
                </div>
            </div>
        `;

        document.getElementById('modal-container').innerHTML = modalHtml;

        const textarea = document.getElementById('fileEditorContent');
        textarea.value = data.content || '';

        const modalEl = document.getElementById('editorModal');
        const modal = new bootstrap.Modal(modalEl);
        modal.show();

        // CodeMirror (nice editor like ISPmanager) - optional
        let cm = null;
        try {
            if (window.CodeMirror) {
                cm = window.CodeMirror.fromTextArea(textarea, {
                    lineNumbers: true,
                    lineWrapping: true,
                    theme: 'eclipse',
                    mode: guessCodeMirrorModeByPath(path),
                });
            }
        } catch (_) {
            cm = null;
        }

        modalEl.addEventListener('hidden.bs.modal', () => {
            try {
                if (cm) cm.toTextArea();
            } catch (_) {}
        }, { once: true });

        document.getElementById('fileEditorSaveBtn').onclick = async () => {
            const value = cm ? cm.getValue() : textarea.value;
            await saveFile(path, value);
            modal.hide();
        };
    } catch (e) {
        showToast(e.message, 'danger');
    }
}

async function saveFile(path, content) {
    try {
        const res = await apiFetch('/api/files/save', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ path, content }),
        });
        if (res && res.success === false) throw new Error(res.error || 'Ошибка');
        showToast('Сохранено', 'success');
    } catch (e) {
        showToast(e.message, 'danger');
        throw e;
    }
}

async function deleteFileItem(path) {
    if (!confirm('Удалить? Это действие необратимо.')) return;

    try {
        const res = await apiFetch('/api/files/delete', {
            method: 'DELETE',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ path }),
        });
        if (res && res.success === false) throw new Error(res.error || 'Ошибка');
        showToast('Удалено', 'success');
        loadFiles(currentPath);
    } catch (e) {
        showToast(e.message, 'danger');
    }
}

async function renameItem(path, oldName) {
    const newName = prompt('Новое имя:', oldName);
    if (!newName || newName === oldName) return;

    try {
        const res = await apiFetch('/api/files/rename', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ old_path: path, new_name: newName }),
        });
        if (res && res.success === false) throw new Error(res.error || 'Ошибка');
        showToast('Переименовано', 'success');
        loadFiles(currentPath);
    } catch (e) {
        showToast(e.message, 'danger');
    }
}

// ========= Nginx =========
async function loadNginx() {
    const container = document.getElementById('nginx-content');
    container.innerHTML = '<div class="text-center py-4"><div class="spinner-border text-primary"></div></div>';

    try {
        const configs = await apiFetch('/api/nginx');
        if (!Array.isArray(configs) || configs.length === 0) {
            container.innerHTML = '<div class="alert alert-light text-center">Нет конфигов</div>';
            return;
        }

        container.innerHTML = `
            <div class="table-responsive">
                <table class="table table-hover mb-0">
                    <thead>
                        <tr>
                            <th>Конфиг</th>
                            <th class="d-none d-md-table-cell">Домены</th>
                            <th class="text-end">Действия</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${configs.map(cfg => `
                            <tr>
                                <td>
                                    <div class="fw-bold">${escapeHtml(cfg.name)}</div>
                                    <div class="small text-muted font-monospace">${escapeHtml(cfg.path || '')}</div>
                                </td>
                                <td class="d-none d-md-table-cell small text-muted">${escapeHtml((cfg.server_names || []).join(' '))}</td>
                                <td class="text-end">
                                    <div class="btn-group btn-group-sm">
                                        <button class="btn btn-outline-secondary" onclick="editNginxConfig('${escapeHtml(cfg.name)}')" title="Редактировать">
                                            <i class="bi bi-pencil"></i>
                                        </button>
                                        <button class="btn btn-outline-danger" onclick="deleteNginxConfig('${escapeHtml(cfg.name)}')" title="Удалить">
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
    } catch (e) {
        container.innerHTML = `<div class="alert alert-danger">Ошибка: ${escapeHtml(e.message)}</div>`;
    }
}

function showCreateNginxModal() {
    const modalHtml = `
        <div class="modal fade" id="createNginxModal" tabindex="-1">
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
                                <input class="form-control" name="name" required>
                            </div>
                            <div class="mb-3">
                                <label class="form-label">Содержимое</label>
                                <textarea class="form-control font-monospace" name="content" rows="18" required>server {\n    listen 80;\n    server_name example.com www.example.com;\n\n    root /var/www/example.com;\n    index index.html;\n\n    location / {\n        try_files $uri $uri/ =404;\n    }\n}</textarea>
                            </div>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">Отмена</button>
                            <button type="submit" class="btn btn-black">Создать</button>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    `;

    document.getElementById('modal-container').innerHTML = modalHtml;
    const modalEl = document.getElementById('createNginxModal');
    const modal = new bootstrap.Modal(modalEl);
    modal.show();

    document.getElementById('createNginxForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const fd = new FormData(e.target);
        const payload = Object.fromEntries(fd);

        try {
            const res = await apiFetch('/api/nginx/config', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload),
            });
            if (res && res.success === false) throw new Error(res.error || 'Ошибка');
            modal.hide();
            showToast('Конфиг создан', 'success');
            loadNginx();
        } catch (err) {
            showToast(err.message, 'danger');
        }
    });
}

async function editNginxConfig(name) {
    try {
        const data = await apiFetch(`/api/nginx/config/${encodeURIComponent(name)}`);

        const modalHtml = `
            <div class="modal fade" id="editNginxModal" tabindex="-1">
                <div class="modal-dialog modal-lg modal-dialog-scrollable">
                    <div class="modal-content">
                        <div class="modal-header">
                            <h5 class="modal-title">${escapeHtml(name)}</h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                        </div>
                        <div class="modal-body">
                            <textarea id="nginxConfigTextarea" class="form-control font-monospace" rows="22" style="font-size: 12px;"></textarea>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">Отмена</button>
                            <button type="button" class="btn btn-black" id="saveNginxBtn">Сохранить</button>
                        </div>
                    </div>
                </div>
            </div>
        `;

        document.getElementById('modal-container').innerHTML = modalHtml;
        const textarea = document.getElementById('nginxConfigTextarea');
        textarea.value = data.content || '';

        const modalEl = document.getElementById('editNginxModal');
        const modal = new bootstrap.Modal(modalEl);
        modal.show();

        // CodeMirror (optional)
        let cm = null;
        try {
            if (window.CodeMirror) {
                cm = window.CodeMirror.fromTextArea(textarea, {
                    lineNumbers: true,
                    lineWrapping: true,
                    theme: 'eclipse',
                    mode: 'text/plain',
                });
            }
        } catch (_) {
            cm = null;
        }

        modalEl.addEventListener('hidden.bs.modal', () => {
            try {
                if (cm) cm.toTextArea();
            } catch (_) {}
        }, { once: true });

        document.getElementById('saveNginxBtn').onclick = async () => {
            try {
                const res = await apiFetch(`/api/nginx/config/${encodeURIComponent(name)}`, {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ content: cm ? cm.getValue() : textarea.value }),
                });
                if (res && res.success === false) throw new Error(res.error || 'Ошибка');
                showToast('Сохранено', 'success');
                modal.hide();
                loadNginx();
            } catch (err) {
                showToast(err.message, 'danger');
            }
        };
    } catch (e) {
        showToast(e.message, 'danger');
    }
}

async function deleteNginxConfig(name) {
    if (!confirm(`Удалить конфиг ${name}?`)) return;

    try {
        const res = await apiFetch(`/api/nginx/config/${encodeURIComponent(name)}`, { method: 'DELETE' });
        if (res && res.success === false) throw new Error(res.error || 'Ошибка');
        showToast('Удалено', 'success');
        loadNginx();
    } catch (e) {
        showToast(e.message, 'danger');
    }
}

async function reloadNginx() {
    if (!confirm('Reload nginx?')) return;

    try {
        const res = await apiFetch('/api/nginx/reload', { method: 'POST' });
        if (res && res.success === false) throw new Error(res.error || 'Ошибка');
        showToast('Nginx перезагружен', 'success');
    } catch (e) {
        showToast(e.message, 'danger');
    }
}

// ========= SSL =========
async function loadSSL() {
    const container = document.getElementById('ssl-content');
    container.innerHTML = '<div class="text-center py-4"><div class="spinner-border text-primary"></div></div>';

    try {
        const data = await apiFetch('/api/certbot/list');
        const certs = data && data.certificates ? data.certificates : [];

        if (!certs.length) {
            container.innerHTML = '<div class="alert alert-light text-center">Нет сертификатов</div>';
            return;
        }

        container.innerHTML = `
            <div class="table-responsive">
                <table class="table table-hover mb-0">
                    <thead>
                        <tr>
                            <th>Домен</th>
                            <th class="d-none d-md-table-cell">Путь</th>
                            <th class="text-end">Дата</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${certs.map(c => `
                            <tr>
                                <td class="fw-bold">${escapeHtml(c.domain)}</td>
                                <td class="d-none d-md-table-cell small text-muted font-monospace">${escapeHtml(c.path || '')}</td>
                                <td class="text-end small text-muted">${escapeHtml(String(c.modified || ''))}</td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>
        `;
    } catch (e) {
        container.innerHTML = `<div class="alert alert-danger">Ошибка: ${escapeHtml(e.message)}</div>`;
    }
}

function showObtainCertModal(domainPrefill = '') {
    const modalHtml = `
        <div class="modal fade" id="obtainCertModal" tabindex="-1">
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">Получить SSL (certbot)</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                    </div>
                    <form id="obtainCertForm">
                        <div class="modal-body">
                            <div class="mb-3">
                                <label class="form-label">Домен</label>
                                <input class="form-control" name="domain" required value="${escapeHtml(domainPrefill)}" placeholder="example.com">
                            </div>
                            <div class="mb-3">
                                <label class="form-label">Email (необязательно)</label>
                                <input type="email" class="form-control" name="email" placeholder="admin@example.com (можно пусто)">
                                <div class="form-text">Если оставить пустым — certbot будет запущен без email (или возьмём CERTBOT_DEFAULT_EMAIL).</div>
                            </div>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">Отмена</button>
                            <button type="submit" class="btn btn-black">Получить</button>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    `;

    document.getElementById('modal-container').innerHTML = modalHtml;
    const modalEl = document.getElementById('obtainCertModal');
    const modal = new bootstrap.Modal(modalEl);
    modal.show();

    document.getElementById('obtainCertForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const payload = Object.fromEntries(new FormData(e.target));
        try {
            showToast('Запускаю certbot...', 'info');
            const res = await apiFetch('/api/certbot/obtain', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload),
            });
            if (res && res.success === false) throw new Error(res.error || 'Ошибка');
            modal.hide();
            showToast('Сертификат получен', 'success');
            loadSSL();
        } catch (err) {
            showToast(err.message, 'danger');
        }
    });
}

async function renewAllCerts() {
    if (!confirm('Обновить все сертификаты?')) return;

    try {
        showToast('Обновляю...', 'info');
        const res = await apiFetch('/api/certbot/renew', { method: 'POST' });
        if (res && res.success === false) throw new Error(res.error || 'Ошибка');
        showToast('Готово', 'success');
        loadSSL();
    } catch (e) {
        showToast(e.message, 'danger');
    }
}

// ========= Projects =========
async function loadProjects() {
    const container = document.getElementById('projects-content');
    container.innerHTML = '<div class="text-center py-4"><div class="spinner-border text-primary"></div></div>';

    try {
        const projects = await apiFetch('/api/projects');
        if (!Array.isArray(projects) || projects.length === 0) {
            container.innerHTML = '<div class="alert alert-light text-center">Нет проектов</div>';
            return;
        }

        container.innerHTML = `
            <div class="table-responsive">
                <table class="table table-hover mb-0">
                    <thead>
                        <tr>
                            <th>Проект</th>
                            <th class="d-none d-md-table-cell">Путь</th>
                            <th class="text-end">Действия</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${projects.map(p => {
                            const badges = [];
                            if (p.domain) badges.push(`<span class="badge bg-info bg-opacity-10 text-info me-1">🌐 ${escapeHtml(p.domain)}</span>`);
                            if (p.port) badges.push(`<span class="badge bg-secondary bg-opacity-10 text-secondary me-1">PORT ${escapeHtml(p.port)}</span>`);
                            if (p.service) badges.push(`<span class="badge bg-dark bg-opacity-10 text-dark me-1">${escapeHtml(p.service)}</span>`);
                            const meta = badges.length ? `<div class="mt-1">${badges.join('')}</div>` : '';
                            return `
                                <tr>
                                    <td>
                                        <div class="fw-bold">${escapeHtml(p.name)}</div>
                                        ${meta}
                                    </td>
                                    <td class="d-none d-md-table-cell small text-muted font-monospace">${escapeHtml(p.path || '')}</td>
                                    <td class="text-end">
                                        <div class="btn-group btn-group-sm">
                                            <button class="btn btn-outline-secondary" onclick="openFileManager('${escapeHtml(p.path || '')}')" title="Открыть файлы">
                                                <i class="bi bi-folder2-open"></i>
                                            </button>
                                            <button class="btn btn-outline-danger" onclick="deleteProject('${escapeHtml(p.name)}')" title="Удалить проект">
                                                <i class="bi bi-trash"></i>
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
    } catch (e) {
        container.innerHTML = `<div class="alert alert-danger">Ошибка: ${escapeHtml(e.message)}</div>`;
    }
}

async function deleteProject(name) {
    if (!confirm(`Удалить проект "${name}"?\n\nЭто действие удалит папку проекта и остановит связанный сервис (если есть).`)) return;

    try {
        const res = await apiFetch(`/api/projects/${encodeURIComponent(name)}`, { method: 'DELETE' });
        if (res && res.success === false) throw new Error(res.error || 'Ошибка');
        showToast('Проект удалён', 'success');
        loadProjects();
    } catch (e) {
        showToast(e.message, 'danger');
    }
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
                                <p class="text-muted">Папка будет создана в <code>/home/dream/projects</code></p>
                            </div>
                            <div class="mb-3">
                                <label class="form-label fw-bold">Название</label>
                                <input type="text" class="form-control form-control-lg" id="pw-name" placeholder="tones" required>
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
                                <input type="file" class="form-control" id="pw-archive" accept=".zip,.tar,.tar.gz,.tgz" />
                                <div class="form-text">Совет: самый удобный вариант — <b>.zip</b></div>
                            </div>
                            <div class="d-flex gap-2 mb-3">
                                <button type="button" class="btn btn-black" id="pw-upload-btn">
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
                                <input type="text" class="form-control form-control-lg" id="pw-domain" placeholder="tones.dreampartners.online">
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
                                    <div class="form-text" id="pw-req-hint"></div>
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
                                    <input type="text" class="form-control" id="pw-service-name" placeholder="tones">
                                    <div class="form-text">Будет создан <code>&lt;name&gt;.service</code></div>
                                </div>
                                <div class="col-12 col-md-6">
                                    <label class="form-label fw-bold">User</label>
                                    <input type="text" class="form-control" id="pw-service-user" value="dream">
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
                            <pre id="pw-logs" class="small bg-light p-3 rounded" style="white-space: pre-wrap; height: 45vh; overflow:auto;"></pre>
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

    function showStep(n) {
        for (let i = 1; i <= 5; i++) {
            const el = document.getElementById(`pw-step-${i}`);
            if (el) el.style.display = (i === n) ? 'block' : 'none';
        }
        currentStep = n;
    }

    async function ensureJob() {
        if (wizardData.jobId) return wizardData.jobId;
        const res = await apiFetch('/api/projects/wizard/job', { method: 'POST' });
        wizardData.jobId = res.job_id;
        return wizardData.jobId;
    }

    async function uploadArchive() {
        const file = document.getElementById('pw-archive')?.files?.[0];
        if (!file) {
            showToast('Выберите архив', 'warning');
            return;
        }
        const jobId = await ensureJob();
        const btn = document.getElementById('pw-upload-btn');
        const refreshBtn = document.getElementById('pw-upload-refresh');
        if (btn) btn.disabled = true;
        try {
            showToast('Загружаю…', 'info');
            const fd = new FormData();
            fd.append('archive', file);
            const res = await apiFetch(`/api/projects/wizard/job/${encodeURIComponent(jobId)}/upload`, {
                method: 'POST',
                body: fd,
            });

            wizardData.analysis = res.analysis || null;
            const a = wizardData.analysis || {};

            // Fill entrypoints
            const eps = Array.isArray(a.entrypoints) ? a.entrypoints : [];
            const epSel = document.getElementById('pw-entrypoint');
            if (epSel) {
                epSel.innerHTML = eps.map(x => `<option value="${escapeHtml(x)}">${escapeHtml(x)}</option>`).join('');
                const suggested = a.suggested_entrypoint || (eps[0] || '');
                if (suggested) epSel.value = suggested;
            }

            // Port
            const portEl = document.getElementById('pw-port');
            if (portEl) portEl.value = (a.port != null && String(a.port) !== 'None') ? String(a.port) : '';

            // Service user suggestion
            const userSug = a?.unit_suggestions?.User || '';
            const serviceUserEl = document.getElementById('pw-service-user');
            if (serviceUserEl && userSug) serviceUserEl.value = String(userSug).replace(/"/g, '').trim() || 'dream';

            // Requirements hint
            const reqHint = document.getElementById('pw-req-hint');
            if (reqHint) {
                const req = a.requirements ? `Найден <code>${escapeHtml(a.requirements)}</code>` : 'requirements.txt не найден (можно указать зависимости вручную)';
                reqHint.innerHTML = req;
            }

            // Analysis summary
            const box = document.getElementById('pw-analysis-box');
            const txt = document.getElementById('pw-analysis-text');
            if (box) box.style.display = 'block';
            if (txt) {
                const parts = [];
                if (a.framework) parts.push(`Framework: <code>${escapeHtml(a.framework)}</code>`);
                if (a.port) parts.push(`PORT: <code>${escapeHtml(a.port)}</code>`);
                if (a.requirements) parts.push(`Deps: <code>${escapeHtml(a.requirements)}</code>`);
                if (Array.isArray(a.service_files) && a.service_files.length) parts.push(`service файлы: <code>${escapeHtml(a.service_files.join(', '))}</code>`);
                txt.innerHTML = parts.join(' • ') || 'Ок';
            }

            // Enable next
            const nextBtn = document.getElementById('pw-to-domain');
            if (nextBtn) nextBtn.style.display = 'inline-block';
            if (refreshBtn) refreshBtn.style.display = 'inline-block';

            showToast('Готово', 'success');
        } catch (e) {
            showToast(e.message, 'danger');
        } finally {
            if (btn) btn.disabled = false;
        }
    }

    async function checkDns() {
        const domain = (document.getElementById('pw-domain')?.value || '').trim();
        wizardData.domain = domain;
        wizardData.skipDns = false;

        const icon = document.getElementById('pw-dns-icon');
        const status = document.getElementById('pw-dns-status');
        const result = document.getElementById('pw-dns-result');
        if (result) result.innerHTML = '';

        if (!domain) {
            if (icon) icon.textContent = '🌐';
            if (status) status.textContent = 'Домен не указан — nginx/DNS будет пропущен';
            return;
        }

        if (icon) icon.textContent = '🔍';
        if (status) status.textContent = 'Проверяю DNS…';

        try {
            const res = await apiFetch('/api/www/check-dns', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ domain }),
            });

            if (res.success) {
                if (icon) icon.textContent = '✅';
                if (status) status.textContent = 'DNS настроен правильно';
                if (result) {
                    result.innerHTML = `
                        <div class="alert alert-success">
                            <div class="fw-bold mb-2">✓ Домен указывает на этот сервер</div>
                            <div class="small">
                                <div>IP сервера: <code>${escapeHtml(res.server_ip || 'N/A')}</code></div>
                                <div>IP домена: <code>${escapeHtml(res.domain_ip || 'N/A')}</code></div>
                            </div>
                        </div>
                    `;
                }
            } else {
                if (icon) icon.textContent = '⚠️';
                if (status) status.textContent = 'DNS не настроен';
                if (result) {
                    result.innerHTML = `
                        <div class="alert alert-warning">
                            <div class="fw-bold mb-2">⚠️ Проблема с DNS</div>
                            <div class="small mb-3">${escapeHtml(res.error || res.message || 'Домен не указывает на этот сервер')}</div>
                            <div class="small text-muted mb-2">
                                <div>IP сервера: <code>${escapeHtml(res.server_ip || 'N/A')}</code></div>
                                <div>IP домена: <code>${escapeHtml(res.domain_ip || 'N/A')}</code></div>
                            </div>
                            <div class="form-check mt-3">
                                <input class="form-check-input" type="checkbox" id="pw-skip-dns-step3">
                                <label class="form-check-label" for="pw-skip-dns-step3">
                                    Продолжить без проверки DNS (для тестов/локальных доменов)
                                </label>
                            </div>
                        </div>
                    `;

                    const cb = document.getElementById('pw-skip-dns-step3');
                    if (cb) {
                        cb.addEventListener('change', (e) => {
                            wizardData.skipDns = !!e.target.checked;
                        });
                    }
                }
            }
        } catch (e) {
            if (icon) icon.textContent = '❌';
            if (status) status.textContent = 'Ошибка проверки DNS';
            if (result) result.innerHTML = `<div class="alert alert-danger">${escapeHtml(e.message)}</div>`;
        }
    }

    async function startDeploy() {
        const jobId = await ensureJob();
        const analysis = wizardData.analysis || {};

        const projectName = wizardData.projectName;
        const entrypoint = (document.getElementById('pw-entrypoint')?.value || '').trim();
        const portRaw = (document.getElementById('pw-port')?.value || '').trim();
        const port = portRaw ? parseInt(portRaw, 10) : null;

        const pythonBin = (document.getElementById('pw-python-bin')?.value || '').trim() || '/usr/bin/python3.13';
        const useVenv = !!document.getElementById('pw-use-venv')?.checked;
        const installDeps = !!document.getElementById('pw-install-deps')?.checked;
        const pipPackages = (document.getElementById('pw-pip-packages')?.value || '').trim();

        const createService = !!document.getElementById('pw-create-service')?.checked;
        const serviceName = (document.getElementById('pw-service-name')?.value || '').trim() || projectName;
        const serviceUser = (document.getElementById('pw-service-user')?.value || '').trim() || 'dream';
        const enableAutostart = !!document.getElementById('pw-enable-autostart')?.checked;
        const startService = !!document.getElementById('pw-start-service')?.checked;

        const createNginx = !!document.getElementById('pw-create-nginx')?.checked;
        const createSSL = !!document.getElementById('pw-create-ssl')?.checked;
        const email = (document.getElementById('pw-email')?.value || '').trim();

        const payload = {
            project_name: projectName,
            entrypoint,
            port,
            domain: wizardData.domain || '',
            skip_dns_check: !!wizardData.skipDns,
            create_nginx: createNginx,
            create_ssl: createSSL,
            email: email || '',
            python_bin: pythonBin,
            use_venv: useVenv,
            install_deps: installDeps,
            requirements: analysis.requirements || 'requirements.txt',
            pip_packages: pipPackages,
            create_service: createService,
            service_name: serviceName,
            service_user: serviceUser,
            enable_autostart: enableAutostart,
            start_service: startService,
        };

        if (!projectName) {
            showToast('Название проекта пустое', 'danger');
            return;
        }
        if (!entrypoint) {
            showToast('Выберите entrypoint', 'danger');
            return;
        }
        if (createNginx && !wizardData.domain) {
            showToast('Для nginx нужен домен', 'warning');
            return;
        }
        if (createNginx && !port) {
            showToast('Для nginx нужен PORT', 'warning');
            return;
        }
        if (createSSL && !createNginx) {
            showToast('SSL требует включённый nginx (proxy)', 'warning');
            return;
        }

        showStep(5);
        const logsEl = document.getElementById('pw-logs');
        if (logsEl) logsEl.textContent = 'Запускаю деплой…\n';

        try {
            await apiFetch(`/api/projects/wizard/job/${encodeURIComponent(jobId)}/deploy`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload),
            });
        } catch (e) {
            showToast(e.message, 'danger');
            return;
        }

        // Start polling
        const icon = document.getElementById('pw-final-icon');
        const title = document.getElementById('pw-final-title');
        const sub = document.getElementById('pw-final-subtitle');
        const openBtn = document.getElementById('pw-open-project');
        const svcLogsBtn = document.getElementById('pw-open-service-logs');

        async function poll() {
            try {
                const st = await apiFetch(`/api/projects/wizard/job/${encodeURIComponent(jobId)}`);
                const logs = Array.isArray(st.logs) ? st.logs.join('\n') : String(st.logs || '');
                if (logsEl) {
                    const atBottom = Math.abs((logsEl.scrollTop + logsEl.clientHeight) - logsEl.scrollHeight) < 24;
                    logsEl.textContent = logs;
                    if (atBottom) logsEl.scrollTop = logsEl.scrollHeight;
                }

                const status = st.status || 'unknown';
                if (status === 'done') {
                    if (icon) icon.textContent = '✅';
                    if (title) title.textContent = 'Готово!';
                    if (sub) sub.textContent = 'Проект создан и настроен';
                    if (wizardData.pollTimer) clearInterval(wizardData.pollTimer);
                    wizardData.pollTimer = null;

                    const result = st.result || {};
                    const projectPath = result.project_path || '';
                    const service = result.service || '';

                    if (openBtn && projectPath) {
                        openBtn.style.display = 'inline-block';
                        openBtn.onclick = () => {
                            modal.hide();
                            openFileManager(projectPath);
                        };
                    }
                    if (svcLogsBtn && service) {
                        svcLogsBtn.style.display = 'inline-block';
                        svcLogsBtn.onclick = () => {
                            const url = withAuthQuery(`/api/service/${encodeURIComponent(service)}/logs?lines=200`);
                            window.open(url, '_blank');
                        };
                    }

                    loadProjects();
                    showToast('Проект создан', 'success');
                    return;
                }

                if (status === 'error') {
                    if (icon) icon.textContent = '❌';
                    if (title) title.textContent = 'Ошибка';
                    if (sub) sub.textContent = st.error || 'Ошибка деплоя';
                    if (wizardData.pollTimer) clearInterval(wizardData.pollTimer);
                    wizardData.pollTimer = null;
                    showToast(st.error || 'Ошибка', 'danger');
                }
            } catch (e) {
                // keep polling but show hint
                if (sub) sub.textContent = `Ошибка обновления логов: ${e.message}`;
            }
        }

        wizardData.pollTimer = setInterval(poll, 1200);
        poll();
    }

    // Initial defaults
    const serviceNameEl = document.getElementById('pw-service-name');
    if (serviceNameEl) serviceNameEl.value = '';

    // Step 1 handlers
    document.getElementById('pw-to-upload').addEventListener('click', async () => {
        const name = (document.getElementById('pw-name')?.value || '').trim();
        if (!name) {
            showToast('Введите название проекта', 'warning');
            return;
        }
        wizardData.projectName = name;
        // create job early to fail fast
        try {
            await ensureJob();
        } catch (e) {
            showToast(e.message, 'danger');
            return;
        }
        showStep(2);

        // prefill service name/user
        const svcName = document.getElementById('pw-service-name');
        if (svcName) svcName.value = name;
        const svcUser = document.getElementById('pw-service-user');
        if (svcUser && !svcUser.value) svcUser.value = 'dream';
    });

    document.getElementById('pw-name').addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            e.preventDefault();
            document.getElementById('pw-to-upload').click();
        }
    });

    // Step 2 handlers
    document.getElementById('pw-back-to-name').addEventListener('click', () => showStep(1));
    document.getElementById('pw-upload-btn').addEventListener('click', uploadArchive);
    document.getElementById('pw-upload-refresh').addEventListener('click', uploadArchive);
    document.getElementById('pw-to-domain').addEventListener('click', () => showStep(3));

    // Step 3 handlers
    document.getElementById('pw-back-to-upload').addEventListener('click', () => showStep(2));
    document.getElementById('pw-check-dns').addEventListener('click', checkDns);
    document.getElementById('pw-to-config').addEventListener('click', () => {
        // propagate domain to nginx checkbox
        const domain = (document.getElementById('pw-domain')?.value || '').trim();
        wizardData.domain = domain;
        const createNginx = document.getElementById('pw-create-nginx');
        if (createNginx) createNginx.checked = !!domain;
        const skipGroup = document.getElementById('pw-skipdns-group');
        if (skipGroup) skipGroup.style.display = (!!domain) ? 'block' : 'none';
        const skipCb = document.getElementById('pw-skip-dns');
        if (skipCb) skipCb.checked = !!wizardData.skipDns;
        showStep(4);
    });

    // Step 4 handlers
    document.getElementById('pw-back-to-domain2').addEventListener('click', () => showStep(3));
    document.getElementById('pw-deploy-btn').addEventListener('click', startDeploy);
    document.getElementById('pw-create-ssl').addEventListener('change', (e) => {
        const grp = document.getElementById('pw-email-group');
        if (grp) grp.style.display = e.target.checked ? 'block' : 'none';
    });
    document.getElementById('pw-skip-dns').addEventListener('change', (e) => {
        wizardData.skipDns = !!e.target.checked;
    });

    // stop polling on close
    modalEl.addEventListener('hidden.bs.modal', () => {
        try {
            if (wizardData.pollTimer) clearInterval(wizardData.pollTimer);
            wizardData.pollTimer = null;
        } catch (_) {}
    });
}

// ========= Backups =========
async function loadBackups() {
    const container = document.getElementById('backups-content');
    container.innerHTML = '<div class="text-center py-4"><div class="spinner-border text-primary"></div></div>';

    try {
        const backups = await apiFetch('/api/backups');
        if (!Array.isArray(backups) || backups.length === 0) {
            container.innerHTML = '<div class="alert alert-light text-center">Бэкапов пока нет</div>';
            return;
        }

        const rows = backups.map(b => {
            const downloadUrl = withAuthQuery(`/api/backups/download?name=${encodeURIComponent(b.name)}`);
            return `
                <tr>
                    <td class="fw-bold">${escapeHtml(b.name)}</td>
                    <td class="d-none d-md-table-cell small text-muted">${escapeHtml(b.size_human || '')}</td>
                    <td class="d-none d-md-table-cell small text-muted">${escapeHtml(b.modified || '')}</td>
                    <td class="text-end">
                        <div class="btn-group btn-group-sm">
                            <a class="btn btn-outline-secondary" href="${escapeHtml(downloadUrl)}" target="_blank" title="Скачать">
                                <i class="bi bi-download"></i>
                            </a>
                            <button class="btn btn-outline-danger" onclick="deleteBackup('${escapeHtml(b.name)}')" title="Удалить">
                                <i class="bi bi-trash"></i>
                            </button>
                        </div>
                    </td>
                </tr>
            `;
        }).join('');

        container.innerHTML = `
            <div class="table-responsive">
                <table class="table table-hover mb-0">
                    <thead>
                        <tr>
                            <th>Файл</th>
                            <th class="d-none d-md-table-cell">Размер</th>
                            <th class="d-none d-md-table-cell">Дата</th>
                            <th class="text-end">Действия</th>
                        </tr>
                    </thead>
                    <tbody>${rows}</tbody>
                </table>
            </div>
        `;
    } catch (e) {
        container.innerHTML = `<div class="alert alert-danger">Ошибка: ${escapeHtml(e.message)}</div>`;
    }
}

async function deleteBackup(name) {
    if (!confirm(`Удалить бэкап ${name}?`)) return;
    try {
        const res = await apiFetch('/api/backups', {
            method: 'DELETE',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name }),
        });
        if (res && res.success === false) throw new Error(res.error || 'Ошибка');
        showToast('Удалено', 'success');
        loadBackups();
    } catch (e) {
        showToast(e.message, 'danger');
    }
}

function showCreateBackupModal() {
    const modalHtml = `
        <div class="modal fade" id="createBackupModal" tabindex="-1">
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
                                        <option value="project">Проект (/home/dream/projects)</option>
                                    </select>
                                </div>
                                <div class="col-12 col-md-8">
                                    <label class="form-label">Имя</label>
                                    <input class="form-control" name="name" id="backupName" required placeholder="example.com или my-project">
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
        </div>
    `;

    document.getElementById('modal-container').innerHTML = modalHtml;
    const modalEl = document.getElementById('createBackupModal');
    const modal = new bootstrap.Modal(modalEl);
    modal.show();

    // optional: prefill suggestions (best effort)
    Promise.allSettled([apiFetch('/api/www'), apiFetch('/api/projects')]).then(([sitesRes, projectsRes]) => {
        const kindEl = document.getElementById('backupKind');
        const nameEl = document.getElementById('backupName');
        if (!kindEl || !nameEl) return;

        const sites = sitesRes.status === 'fulfilled' ? sitesRes.value : [];
        const projects = projectsRes.status === 'fulfilled' ? projectsRes.value : [];

        const datalist = document.createElement('datalist');
        datalist.id = 'backupSuggestions';
        document.body.appendChild(datalist);

        function renderList() {
            const kind = kindEl.value;
            const list = kind === 'project' ? projects : sites;
            datalist.innerHTML = (Array.isArray(list) ? list : []).map(x => `<option value="${escapeHtml(x.name || '')}"></option>`).join('');
            nameEl.setAttribute('list', datalist.id);
        }

        kindEl.addEventListener('change', renderList);
        renderList();
    });

    document.getElementById('createBackupForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const payload = Object.fromEntries(new FormData(e.target));
        try {
            showToast('Создаю бэкап...', 'info');
            const res = await apiFetch('/api/backups', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload),
            });
            if (res && res.success === false) throw new Error(res.error || 'Ошибка');
            modal.hide();
            showToast('Бэкап создан', 'success');
            loadBackups();
        } catch (err) {
            showToast(err.message, 'danger');
        }
    });
}

// ========= Security =========
async function loadSecurity() {
    const container = document.getElementById('security-content');
    container.innerHTML = '<div class="text-center py-4"><div class="spinner-border text-primary"></div></div>';

    try {
        const data = await apiFetch('/api/security');

        const block = (title, obj) => {
            const ok = !!obj?.ok;
            const badge = ok ? 'success' : 'danger';
            const output = escapeHtml(obj?.output || '');
            return `
                <div class="stat-card mb-3">
                    <div class="d-flex justify-content-between align-items-center mb-2">
                        <h5 class="mb-0">${escapeHtml(title)}</h5>
                        <span class="badge bg-${badge} bg-opacity-10 text-${badge}">${ok ? 'OK' : 'WARN'}</span>
                    </div>
                    <pre class="small bg-light p-3 rounded mb-0" style="white-space: pre-wrap;">${output}</pre>
                </div>
            `;
        };

        container.innerHTML = `
            ${block('UFW (Firewall)', data.ufw)}
            ${block('Fail2ban', data.fail2ban)}
            ${block('Открытые порты (ss)', data.ports)}
        `;
    } catch (e) {
        container.innerHTML = `<div class="alert alert-danger">Ошибка: ${escapeHtml(e.message)}</div>`;
    }
}

// ========= Console =========
let consoleHistory = [];
let consoleHistoryIndex = -1;

function initConsole() {
    const input = document.getElementById('console-input');
    if (input) {
        input.focus();
        // Добавляем навигацию по истории команд
        input.addEventListener('keydown', (e) => {
            if (e.key === 'ArrowUp') {
                e.preventDefault();
                if (consoleHistoryIndex < consoleHistory.length - 1) {
                    consoleHistoryIndex++;
                    input.value = consoleHistory[consoleHistory.length - 1 - consoleHistoryIndex] || '';
                }
            } else if (e.key === 'ArrowDown') {
                e.preventDefault();
                if (consoleHistoryIndex > 0) {
                    consoleHistoryIndex--;
                    input.value = consoleHistory[consoleHistory.length - 1 - consoleHistoryIndex] || '';
                } else {
                    consoleHistoryIndex = -1;
                    input.value = '';
                }
            }
        });
    }
}

async function runConsoleCommand() {
    const input = document.getElementById('console-input');
    const output = document.getElementById('console-output');
    const command = (input?.value || '').trim();

    if (!command) {
        showToast('Введите команду', 'warning');
        return;
    }

    // Добавляем в историю
    if (consoleHistory[consoleHistory.length - 1] !== command) {
        consoleHistory.push(command);
        if (consoleHistory.length > 100) consoleHistory.shift();
    }
    consoleHistoryIndex = -1;

    const timestamp = new Date().toLocaleTimeString();
    output.textContent += `\n[${timestamp}] $ ${command}\n`;
    output.textContent += 'Выполняется...\n';
    output.scrollTop = output.scrollHeight;

    try {
        const res = await apiFetch('/api/console/exec', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ command }),
        });

        const statusIcon = res.success ? '✓' : '✗';
        output.textContent += `${res.output || '(пустой вывод)'}\n`;
        output.textContent += `[${statusIcon} exit: ${res.exit_code || 0}]\n`;
    } catch (e) {
        output.textContent += `Ошибка: ${e.message}\n`;
    }

    output.scrollTop = output.scrollHeight;
    input.value = '';
    input.focus();
}

function clearConsoleOutput() {
    const output = document.getElementById('console-output');
    if (output) {
        output.textContent = 'Консоль очищена. Введите команду и нажмите "Выполнить"';
    }
}

// ========= Bots Manager =========

function formatBytes(bytes) {
    if (!bytes || bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

async function loadBots() {
    const container = document.getElementById('bots-content');
    if (!container) return;

    container.innerHTML = `
        <div class="text-center py-4">
            <div class="spinner-border text-primary" role="status"></div>
            <p class="mt-2 text-muted">Загрузка ботов...</p>
        </div>
    `;

    try {
        const bots = await apiFetch('/api/bots');

        if (!bots || bots.length === 0) {
            container.innerHTML = `
                <div class="alert alert-info">
                    <i class="bi bi-info-circle me-2"></i>
                    Нет загруженных ботов. Нажмите "Загрузить" чтобы добавить бота.
                </div>
            `;
            return;
        }

        let html = '<div class="row g-3">';
        for (const bot of bots) {
            const statusBadge = bot.running
                ? '<span class="badge bg-success"><i class="bi bi-circle-fill me-1" style="font-size:6px;vertical-align:middle;"></i>Работает</span>'
                : '<span class="badge bg-danger"><i class="bi bi-circle-fill me-1" style="font-size:6px;vertical-align:middle;"></i>Остановлен</span>';

            const autostartEnabled = bot.autostart || false;
            const autostartTitle = autostartEnabled ? 'Отключить автозапуск с панелью' : 'Включить автозапуск с панелью';

            html += `
                <div class="col-12 col-md-6 col-xl-4">
                    <div class="card h-100 shadow-sm">
                        <div class="card-body">
                            <div class="d-flex justify-content-between align-items-start mb-2">
                                <h5 class="card-title mb-0">
                                    <i class="bi bi-robot text-primary me-2"></i>${escapeHtml(bot.name)}
                                </h5>
                                <div class="form-check form-switch service-state-switch">
                                    <input class="form-check-input bot-state-toggle" type="checkbox" 
                                           data-bot="${escapeHtml(bot.name)}" 
                                           ${bot.running ? 'checked' : ''}
                                           title="${bot.running ? 'Остановить' : 'Запустить'}">
                                </div>
                            </div>
                            <div class="mb-2">
                                ${statusBadge}
                            </div>
                            <p class="card-text small text-muted mb-2">
                                <i class="bi bi-file-earmark-code me-1"></i>${escapeHtml(bot.entrypoint || 'не определён')}
                                ${bot.port ? `<span class="ms-2"><i class="bi bi-hdd-network me-1"></i>:${bot.port}</span>` : ''}
                            </p>
                            <p class="card-text small text-muted mb-2">
                                <i class="bi bi-hdd me-1"></i>${formatBytes(bot.size)}
                                ${bot.pid ? `<span class="ms-2"><i class="bi bi-memory me-1"></i>${formatBytes(bot.memory)}</span>` : ''}
                            </p>
                            <div class="d-flex align-items-center justify-content-between mb-2">
                                <small class="text-muted">Автозапуск с панелью</small>
                                <div class="form-check form-switch">
                                    <input class="form-check-input bot-autostart-toggle" type="checkbox" 
                                           data-bot="${escapeHtml(bot.name)}" 
                                           ${autostartEnabled ? 'checked' : ''}
                                           title="${escapeHtml(autostartTitle)}">
                                </div>
                            </div>
                            <div class="d-flex flex-wrap gap-1 mt-3">
                                <button class="btn btn-sm btn-outline-primary" onclick="showBotDetails('${escapeHtml(bot.name)}')">
                                    <i class="bi bi-gear"></i> Настройки
                                </button>
                                <button class="btn btn-sm btn-outline-secondary" onclick="showBotLogs('${escapeHtml(bot.name)}')">
                                    <i class="bi bi-journal-text"></i> Логи
                                </button>
                                <button class="btn btn-sm btn-outline-info" onclick="showBotFiles('${escapeHtml(bot.name)}')">
                                    <i class="bi bi-code-slash"></i> Код
                                </button>
                                <button class="btn btn-sm btn-outline-danger" onclick="deleteBot('${escapeHtml(bot.name)}')">
                                    <i class="bi bi-trash"></i>
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            `;
        }
        html += '</div>';
        container.innerHTML = html;

        // Bind toggle events
        container.querySelectorAll('.bot-state-toggle').forEach(toggle => {
            toggle.addEventListener('change', async (e) => {
                const botName = e.target.dataset.bot;
                const action = e.target.checked ? 'start' : 'stop';
                e.target.disabled = true;
                try {
                    await apiFetch(`/api/bots/${encodeURIComponent(botName)}/action`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ action }),
                    });
                    showToast(`Бот ${botName} ${action === 'start' ? 'запущен' : 'остановлен'}`, 'success');
                    setTimeout(() => loadBots(), 500);
                } catch (err) {
                    showToast(err.message, 'danger');
                    e.target.checked = !e.target.checked;
                    e.target.disabled = false;
                }
            });
        });

        // Bind autostart toggle events
        container.querySelectorAll('.bot-autostart-toggle').forEach(toggle => {
            toggle.addEventListener('change', async (e) => {
                const botName = e.target.dataset.bot;
                const enabled = e.target.checked;
                e.target.disabled = true;
                try {
                    await apiFetch(`/api/bots/${encodeURIComponent(botName)}/autostart`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ enabled }),
                    });
                    showToast(`Автозапуск бота ${botName} ${enabled ? 'включен' : 'отключен'}`, 'success');
                } catch (err) {
                    showToast(err.message, 'danger');
                    e.target.checked = !e.target.checked;
                    e.target.disabled = false;
                }
            });
        });

    } catch (e) {
        container.innerHTML = `<div class="alert alert-danger">Ошибка загрузки ботов: ${escapeHtml(e.message)}</div>`;
    }
}

function showUploadBotModal() {
    const modalHtml = `
        <div class="modal fade" id="uploadBotModal" tabindex="-1">
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title"><i class="bi bi-upload me-2"></i>Загрузить бота</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body">
                        <div class="mb-3">
                            <label class="form-label">Файл бота</label>
                            <input type="file" class="form-control" id="bot-upload-file" 
                                   accept=".py,.zip,.tar.gz,.tgz">
                            <div class="form-text">Поддерживаются: .py, .zip, .tar.gz, .tgz</div>
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Название бота (опционально)</label>
                            <input type="text" class="form-control" id="bot-upload-name" 
                                   placeholder="Определится автоматически из имени файла">
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Отмена</button>
                        <button type="button" class="btn btn-black" onclick="uploadBot()">
                            <i class="bi bi-upload me-1"></i>Загрузить
                        </button>
                    </div>
                </div>
            </div>
        </div>
    `;
    document.getElementById('modal-container').innerHTML = modalHtml;
    const modal = new bootstrap.Modal(document.getElementById('uploadBotModal'));
    modal.show();
}

async function uploadBot() {
    const fileInput = document.getElementById('bot-upload-file');
    const nameInput = document.getElementById('bot-upload-name');

    if (!fileInput.files || !fileInput.files[0]) {
        showToast('Выберите файл', 'warning');
        return;
    }

    const formData = new FormData();
    formData.append('file', fileInput.files[0]);
    if (nameInput.value.trim()) {
        formData.append('name', nameInput.value.trim());
    }

    try {
        const res = await apiFetch('/api/bots/upload', {
            method: 'POST',
            body: formData,
        });

        bootstrap.Modal.getInstance(document.getElementById('uploadBotModal')).hide();
        showToast(`Бот ${res.name} загружен!`, 'success');
        loadBots();

        // Show setup modal
        setTimeout(() => showBotSetupModal(res.name), 500);
    } catch (e) {
        showToast(e.message, 'danger');
    }
}

function showBotSetupModal(botName) {
    const modalHtml = `
        <div class="modal fade" id="botSetupModal" tabindex="-1">
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title"><i class="bi bi-play-circle me-2"></i>Запуск бота: ${escapeHtml(botName)}</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body">
                        <div class="alert alert-success">
                            <i class="bi bi-info-circle me-2"></i>
                            Бот будет работать пока работает админ-панель. Недостающие библиотеки установятся автоматически!
                        </div>
                        <div class="row g-3">
                            <div class="col-md-6">
                                <label class="form-label">Entrypoint (файл запуска)</label>
                                <input type="text" class="form-control" id="setup-entrypoint" 
                                       placeholder="main.py">
                            </div>
                            <div class="col-md-6">
                                <label class="form-label">Порт (опционально)</label>
                                <input type="number" class="form-control" id="setup-port" 
                                       placeholder="5000">
                            </div>
                            <div class="col-12">
                                <label class="form-label">Python</label>
                                <input type="text" class="form-control" id="setup-python" 
                                       value="/usr/bin/python3">
                            </div>
                            <div class="col-12">
                                <div class="form-check">
                                    <input class="form-check-input" type="checkbox" id="setup-deps" checked>
                                    <label class="form-check-label">Установить зависимости из requirements.txt перед запуском</label>
                                </div>
                            </div>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Отмена</button>
                        <button type="button" class="btn btn-success" onclick="setupAndStartBot('${escapeHtml(botName)}')">
                            <i class="bi bi-play-fill me-1"></i>Запустить
                        </button>
                    </div>
                </div>
            </div>
        </div>
    `;
    document.getElementById('modal-container').innerHTML = modalHtml;
    const modal = new bootstrap.Modal(document.getElementById('botSetupModal'));
    modal.show();
}

async function setupAndStartBot(botName) {
    const data = {
        entrypoint: document.getElementById('setup-entrypoint')?.value || '',
        port: document.getElementById('setup-port')?.value || null,
        python_bin: document.getElementById('setup-python')?.value || '/usr/bin/python3',
        install_deps: document.getElementById('setup-deps')?.checked || false,
        auto_start: true,
    };

    showToast('Запуск бота...', 'info');

    try {
        const res = await apiFetch(`/api/bots/${encodeURIComponent(botName)}/setup`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data),
        });

        bootstrap.Modal.getInstance(document.getElementById('botSetupModal')).hide();
        if (res.running) {
            showToast(`Бот ${botName} запущен!`, 'success');
        } else {
            showToast(res.message || 'Бот настроен', 'info');
        }
        loadBots();
    } catch (e) {
        showToast(e.message, 'danger');
    }
}

async function showBotDetails(botName) {
    try {
        const bot = await apiFetch(`/api/bots/${encodeURIComponent(botName)}`);

        let configsHtml = '';
        if (bot.configs && bot.configs.length > 0) {
            configsHtml = `
                <h6 class="mt-4 mb-3"><i class="bi bi-key me-2"></i>Найденные конфигурации</h6>
                <div class="table-responsive">
                    <table class="table table-sm">
                        <thead><tr><th>Тип</th><th>Значение</th><th>Файл</th><th></th></tr></thead>
                        <tbody>
                            ${bot.configs.map(c => `
                                <tr>
                                    <td><span class="badge bg-secondary">${escapeHtml(c.type)}</span></td>
                                    <td><code class="text-truncate d-inline-block" style="max-width:200px;" title="${escapeHtml(c.value)}">${escapeHtml(c.value.substring(0, 30))}${c.value.length > 30 ? '...' : ''}</code></td>
                                    <td><small>${escapeHtml(c.file)}:${c.line}</small></td>
                                    <td>
                                        <button class="btn btn-sm btn-outline-primary" onclick="showEditConfigModal('${escapeHtml(botName)}', '${escapeHtml(c.file)}', '${escapeHtml(c.value)}')">
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

        const modalHtml = `
            <div class="modal fade" id="botDetailsModal" tabindex="-1">
                <div class="modal-dialog modal-lg">
                    <div class="modal-content">
                        <div class="modal-header">
                            <h5 class="modal-title"><i class="bi bi-robot me-2"></i>${escapeHtml(botName)}</h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                        </div>
                        <div class="modal-body">
                            <div class="row g-3 mb-3">
                                <div class="col-md-6">
                                    <strong>Статус:</strong> 
                                    ${bot.running ? '<span class="badge bg-success">Работает</span>' : '<span class="badge bg-danger">Остановлен</span>'}
                                </div>
                                <div class="col-md-6">
                                    <strong>Entrypoint:</strong> <code>${escapeHtml(bot.entrypoint || 'не определён')}</code>
                                </div>
                                <div class="col-md-6">
                                    <strong>Порт:</strong> ${bot.port || '<span class="text-muted">не указан</span>'}
                                </div>
                                <div class="col-md-6">
                                    <strong>Размер:</strong> ${formatBytes(bot.size)}
                                </div>
                                <div class="col-md-6">
                                    <strong>PID:</strong> ${bot.pid || '<span class="text-muted">-</span>'}
                                    ${bot.pid ? `<span class="ms-2">RAM: ${formatBytes(bot.memory)}</span>` : ''}
                                </div>
                                <div class="col-md-6">
                                    <strong>Режим:</strong> <span class="badge bg-info">subprocess</span>
                                    <small class="text-muted ms-1">(работает пока работает панель)</small>
                                </div>
                            </div>

                            <div class="d-flex flex-wrap gap-2 mb-3">
                                <button class="btn btn-sm ${bot.running ? 'btn-danger' : 'btn-success'}" onclick="botAction('${escapeHtml(botName)}', '${bot.running ? 'stop' : 'start'}')">
                                    <i class="bi bi-${bot.running ? 'stop-fill' : 'play-fill'}"></i> ${bot.running ? 'Остановить' : 'Запустить'}
                                </button>
                                ${bot.running ? `
                                    <button class="btn btn-sm btn-warning" onclick="botAction('${escapeHtml(botName)}', 'restart')">
                                        <i class="bi bi-arrow-repeat"></i> Перезапустить
                                    </button>
                                ` : ''}
                                ${bot.has_requirements ? `
                                    <button class="btn btn-sm btn-outline-info" onclick="installBotDeps('${escapeHtml(botName)}')">
                                        <i class="bi bi-box-seam"></i> Установить зависимости
                                    </button>
                                ` : ''}
                            </div>

                            ${configsHtml}
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Закрыть</button>
                        </div>
                    </div>
                </div>
            </div>
        `;
        document.getElementById('modal-container').innerHTML = modalHtml;
        const modal = new bootstrap.Modal(document.getElementById('botDetailsModal'));
        modal.show();
    } catch (e) {
        showToast(e.message, 'danger');
    }
}

async function botAction(botName, action) {
    try {
        await apiFetch(`/api/bots/${encodeURIComponent(botName)}/action`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ action }),
        });
        showToast(`Действие ${action} выполнено`, 'success');
        bootstrap.Modal.getInstance(document.getElementById('botDetailsModal'))?.hide();
        loadBots();
    } catch (e) {
        showToast(e.message, 'danger');
    }
}

async function installBotDeps(botName) {
    showToast('Установка зависимостей...', 'info');
    try {
        const res = await apiFetch(`/api/bots/${encodeURIComponent(botName)}/install-deps`, {
            method: 'POST',
        });
        if (res.success) {
            showToast('Зависимости установлены!', 'success');
        } else {
            showToast(res.output || 'Ошибка установки', 'danger');
        }
    } catch (e) {
        showToast(e.message, 'danger');
    }
}

async function showBotLogs(botName) {
    try {
        const res = await apiFetch(`/api/bots/${encodeURIComponent(botName)}/logs?lines=200`);

        const modalHtml = `
            <div class="modal fade" id="botLogsModal" tabindex="-1">
                <div class="modal-dialog modal-xl">
                    <div class="modal-content">
                        <div class="modal-header">
                            <h5 class="modal-title"><i class="bi bi-journal-text me-2"></i>Логи: ${escapeHtml(botName)}</h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                        </div>
                        <div class="modal-body p-0">
                            <pre class="bg-dark text-light p-3 m-0" style="max-height: 70vh; overflow: auto; font-size: 11px; white-space: pre-wrap;">${escapeHtml(res.logs || 'Нет логов')}</pre>
                        </div>
                        <div class="modal-footer">
                            <small class="text-muted me-auto">Режим: subprocess</small>
                            <button type="button" class="btn btn-outline-primary btn-sm" onclick="showBotLogs('${escapeHtml(botName)}')">
                                <i class="bi bi-arrow-clockwise"></i> Обновить
                            </button>
                            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Закрыть</button>
                        </div>
                    </div>
                </div>
            </div>
        `;
        document.getElementById('modal-container').innerHTML = modalHtml;
        const modal = new bootstrap.Modal(document.getElementById('botLogsModal'));
        modal.show();
    } catch (e) {
        showToast(e.message, 'danger');
    }
}

async function showBotFiles(botName) {
    try {
        const bot = await apiFetch(`/api/bots/${encodeURIComponent(botName)}`);

        let filesHtml = bot.files.map(f => `
            <div class="list-group-item list-group-item-action d-flex justify-content-between align-items-center" 
                 style="cursor: pointer;" onclick="editBotFile('${escapeHtml(botName)}', '${escapeHtml(f.name)}')">
                <span>
                    <i class="bi bi-${f.is_dir ? 'folder text-warning' : 'file-earmark-code text-primary'} me-2"></i>
                    ${escapeHtml(f.name)}
                </span>
                <small class="text-muted">${f.is_dir ? '' : formatBytes(f.size)}</small>
            </div>
        `).join('');

        const modalHtml = `
            <div class="modal fade" id="botFilesModal" tabindex="-1">
                <div class="modal-dialog">
                    <div class="modal-content">
                        <div class="modal-header">
                            <h5 class="modal-title"><i class="bi bi-folder2-open me-2"></i>Файлы: ${escapeHtml(botName)}</h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                        </div>
                        <div class="modal-body p-0">
                            <div class="list-group list-group-flush">
                                ${filesHtml || '<div class="p-3 text-muted">Нет файлов</div>'}
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `;
        document.getElementById('modal-container').innerHTML = modalHtml;
        const modal = new bootstrap.Modal(document.getElementById('botFilesModal'));
        modal.show();
        
        // Apply modal fixes
        fixModal('botFilesModal');
    } catch (e) {
        showToast(e.message, 'danger');
    }
}

async function editBotFile(botName, filename) {
    try {
        const res = await apiFetch(`/api/bots/${encodeURIComponent(botName)}/file?file=${encodeURIComponent(filename)}`);

        const modalHtml = `
            <div class="modal fade" id="botEditorModal" tabindex="-1">
                <div class="modal-dialog modal-xl">
                    <div class="modal-content">
                        <div class="modal-header">
                            <h5 class="modal-title"><i class="bi bi-code-slash me-2"></i>${escapeHtml(botName)} / ${escapeHtml(filename)}</h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                        </div>
                        <div class="modal-body p-0">
                            <textarea id="bot-editor-textarea" style="display:none;">${escapeHtml(res.content)}</textarea>
                            <div id="bot-editor-container"></div>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Отмена</button>
                            <button type="button" class="btn btn-black" onclick="saveBotFile('${escapeHtml(botName)}', '${escapeHtml(filename)}')">
                                <i class="bi bi-save me-1"></i>Сохранить
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        `;
        document.getElementById('modal-container').innerHTML = modalHtml;

        const modal = new bootstrap.Modal(document.getElementById('botEditorModal'));
        modal.show();

        // Apply modal fixes
        fixModal('botEditorModal');

        // Initialize CodeMirror after modal is shown
        document.getElementById('botEditorModal').addEventListener('shown.bs.modal', () => {
            const textarea = document.getElementById('bot-editor-textarea');
            const container = document.getElementById('bot-editor-container');

            const mode = filename.endsWith('.py') ? 'python' : 
                         filename.endsWith('.js') ? 'javascript' :
                         filename.endsWith('.html') ? 'htmlmixed' :
                         filename.endsWith('.css') ? 'css' :
                         filename.endsWith('.json') ? 'javascript' : 'shell';

            botEditorInstance = CodeMirror(container, {
                value: textarea.value,
                mode: mode,
                theme: 'eclipse',
                lineNumbers: true,
                lineWrapping: true,
                indentUnit: 4,
                tabSize: 4,
                indentWithTabs: false,
            });
            botEditorInstance.setSize('100%', '65vh');
        }, { once: true });

    } catch (e) {
        showToast(e.message, 'danger');
    }
}

async function saveBotFile(botName, filename) {
    if (!botEditorInstance) {
        showToast('Редактор не инициализирован', 'danger');
        return;
    }

    const content = botEditorInstance.getValue();

    try {
        await apiFetch(`/api/bots/${encodeURIComponent(botName)}/file`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ file: filename, content }),
        });
        showToast('Файл сохранён!', 'success');
        
        // Hide modal - fixModal will handle cleanup
        const modal = document.getElementById('botEditorModal');
        const modalInstance = bootstrap.Modal.getInstance(modal);
        if (modalInstance) {
            modalInstance.hide();
        }
    } catch (e) {
        showToast(e.message, 'danger');
    }
}

function showEditConfigModal(botName, filename, oldValue) {
    const modalHtml = `
        <div class="modal fade" id="editConfigModal" tabindex="-1">
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title"><i class="bi bi-pencil me-2"></i>Изменить значение</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body">
                        <div class="mb-3">
                            <label class="form-label">Файл</label>
                            <input type="text" class="form-control" value="${escapeHtml(filename)}" readonly>
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Текущее значение</label>
                            <input type="text" class="form-control" id="config-old-value" value="${escapeHtml(oldValue)}" readonly>
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Новое значение</label>
                            <input type="text" class="form-control" id="config-new-value" value="${escapeHtml(oldValue)}">
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Отмена</button>
                        <button type="button" class="btn btn-black" onclick="updateBotConfig('${escapeHtml(botName)}', '${escapeHtml(filename)}')">
                            <i class="bi bi-save me-1"></i>Сохранить
                        </button>
                    </div>
                </div>
            </div>
        </div>
    `;
    document.getElementById('modal-container').innerHTML = modalHtml;
    const modal = new bootstrap.Modal(document.getElementById('editConfigModal'));
    modal.show();
}

async function updateBotConfig(botName, filename) {
    const oldValue = document.getElementById('config-old-value').value;
    const newValue = document.getElementById('config-new-value').value;

    if (oldValue === newValue) {
        showToast('Значение не изменилось', 'warning');
        return;
    }

    try {
        await apiFetch(`/api/bots/${encodeURIComponent(botName)}/config`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ file: filename, old_value: oldValue, new_value: newValue }),
        });
        showToast('Конфигурация обновлена!', 'success');
        bootstrap.Modal.getInstance(document.getElementById('editConfigModal')).hide();
        showBotDetails(botName);
    } catch (e) {
        showToast(e.message, 'danger');
    }
}

async function deleteBot(botName) {
    if (!confirm(`Удалить бота "${botName}"? Это действие необратимо.`)) {
        return;
    }

    try {
        await apiFetch(`/api/bots/${encodeURIComponent(botName)}`, {
            method: 'DELETE',
        });
        showToast(`Бот ${botName} удалён`, 'success');
        loadBots();
    } catch (e) {
        showToast(e.message, 'danger');
    }
}

// ========= Proxy Manager =========

async function loadProxyRules() {
    const container = document.getElementById('proxy-content');
    if (!container) return;

    container.innerHTML = '<div class="text-center py-4"><div class="spinner-border"></div></div>';

    try {
        const res = await apiFetch('/api/proxy/rules');
        const rules = res.rules || [];

        if (rules.length === 0) {
            container.innerHTML = `
                <div class="text-center py-5 text-muted">
                    <i class="bi bi-diagram-3 display-1"></i>
                    <p class="mt-3">Нет правил проксирования</p>
                    <button class="btn btn-black" onclick="showAddProxyRuleModal()">
                        <i class="bi bi-plus-lg me-1"></i>Добавить правило
                    </button>
                </div>
            `;
            return;
        }

        let html = `
            <div class="card">
                <div class="table-responsive" style="overflow-x: auto; -webkit-overflow-scrolling: touch;">
                    <table class="table table-hover mb-0" style="min-width: 600px;">
                        <thead class="table-light">
                            <tr>
                                <th style="min-width: 100px;">Путь</th>
                                <th style="min-width: 200px;">Целевой URL</th>
                                <th style="min-width: 150px;">Описание</th>
                                <th style="min-width: 80px;">Статус</th>
                                <th style="min-width: 120px;"></th>
                            </tr>
                        </thead>
                        <tbody>
        `;

        for (const rule of rules) {
            const statusBadge = rule.enabled
                ? '<span class="badge bg-success">Активно</span>'
                : '<span class="badge bg-secondary">Выключено</span>';

            html += `
                <tr>
                    <td><code>${escapeHtml(rule.path_prefix)}</code></td>
                    <td><code>${escapeHtml(rule.target_url)}</code></td>
                    <td>${escapeHtml(rule.description || '-')}</td>
                    <td>${statusBadge}</td>
                    <td class="text-end">
                        <button class="btn btn-sm btn-outline-primary" onclick="toggleProxyRule('${escapeHtml(rule.path_prefix)}')">
                            ${rule.enabled ? 'Выкл' : 'Вкл'}
                        </button>
                        <button class="btn btn-sm btn-outline-danger" onclick="deleteProxyRule('${escapeHtml(rule.path_prefix)}')">
                            <i class="bi bi-trash"></i>
                        </button>
                    </td>
                </tr>
            `;
        }

        html += '</tbody></table></div></div>';
        container.innerHTML = html;
    } catch (e) {
        container.innerHTML = `<div class="alert alert-danger">${escapeHtml(e.message)}</div>`;
    }
}

function showAddProxyRuleModal() {
    const modalHtml = `
        <div class="modal fade" id="addProxyRuleModal" tabindex="-1">
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title"><i class="bi bi-plus-lg me-2"></i>Новое правило прокси</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body">
                        <div class="mb-3">
                            <label class="form-label">Путь (prefix)</label>
                            <input type="text" class="form-control" id="proxy-path" placeholder="/mybot">
                            <small class="text-muted">Запросы на /p/mybot/... будут проксироваться</small>
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Целевой URL</label>
                            <input type="text" class="form-control" id="proxy-target" placeholder="http://127.0.0.1:5102">
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Описание</label>
                            <input type="text" class="form-control" id="proxy-description" placeholder="Мой бот">
                        </div>
                        <div class="form-check">
                            <input class="form-check-input" type="checkbox" id="proxy-enabled" checked>
                            <label class="form-check-label">Включено сразу</label>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Отмена</button>
                        <button type="button" class="btn btn-black" onclick="addProxyRule()">
                            <i class="bi bi-plus-lg me-1"></i>Добавить
                        </button>
                    </div>
                </div>
            </div>
        </div>
    `;
    document.getElementById('modal-container').innerHTML = modalHtml;
    const modal = new bootstrap.Modal(document.getElementById('addProxyRuleModal'));
    modal.show();
    
    // Apply modal fixes
    fixModal('addProxyRuleModal');
}

async function addProxyRule() {
    const pathPrefix = document.getElementById('proxy-path').value.trim();
    const targetUrl = document.getElementById('proxy-target').value.trim();
    const description = document.getElementById('proxy-description').value.trim();
    const enabled = document.getElementById('proxy-enabled').checked;

    if (!pathPrefix || !targetUrl) {
        showToast('Укажите путь и целевой URL', 'warning');
        return;
    }

    try {
        await apiFetch('/api/proxy/rules', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ path_prefix: pathPrefix, target_url: targetUrl, description, enabled }),
        });
        bootstrap.Modal.getInstance(document.getElementById('addProxyRuleModal')).hide();
        showToast('Правило добавлено', 'success');
        loadProxyRules();
    } catch (e) {
        showToast(e.message, 'danger');
    }
}

async function toggleProxyRule(pathPrefix) {
    try {
        await apiFetch(`/api/proxy/rules/${encodeURIComponent(pathPrefix)}/toggle`, { method: 'POST' });
        loadProxyRules();
    } catch (e) {
        showToast(e.message, 'danger');
    }
}

async function deleteProxyRule(pathPrefix) {
    if (!confirm(`Удалить правило "${pathPrefix}"?`)) return;

    try {
        await apiFetch(`/api/proxy/rules/${encodeURIComponent(pathPrefix)}`, { method: 'DELETE' });
        showToast('Правило удалено', 'success');
        loadProxyRules();
    } catch (e) {
        showToast(e.message, 'danger');
    }
}

// ========= Modal Fixes =========
function fixModal(modalId) {
    const modal = document.getElementById(modalId);
    if (!modal) return;
    
    // Fix backdrop issue - ensure complete cleanup
    modal.addEventListener('hidden.bs.modal', function () {
        setTimeout(() => {
            // Remove all modal backdrops aggressively
            document.querySelectorAll('.modal-backdrop').forEach(el => {
                el.remove();
            });
            // Force body cleanup
            document.body.classList.remove('modal-open');
            document.body.style.overflow = '';
            document.body.style.paddingRight = '';
            // Remove focus from modal elements
            if (document.activeElement && modal.contains(document.activeElement)) {
                document.activeElement.blur();
            }
            // Clean up CodeMirror instance if this is editor modal
            if (modalId === 'botEditorModal' && botEditorInstance) {
                try {
                    if (typeof botEditorInstance.toTextArea === 'function') {
                        botEditorInstance.toTextArea();
                    } else {
                        // Alternative cleanup if toTextArea doesn't exist
                        const wrapper = botEditorInstance.getWrapperElement();
                        if (wrapper && wrapper.parentNode) {
                            wrapper.parentNode.removeChild(wrapper);
                        }
                    }
                } catch (e) {
                    console.warn('CodeMirror cleanup error:', e);
                }
                botEditorInstance = null;
            }
        }, 10); // Small delay to ensure Bootstrap cleanup
    });
    
    // Additional cleanup on hide event (before hidden)
    modal.addEventListener('hide.bs.modal', function () {
        // Start removing backdrops immediately
        setTimeout(() => {
            document.querySelectorAll('.modal-backdrop').forEach(el => {
                el.style.opacity = '0';
            });
        }, 0);
    });
    
    // Fix focus issue when modal is shown
    modal.addEventListener('shown.bs.modal', function () {
        // Focus on first input if available (but not CodeMirror)
        const firstInput = modal.querySelector('input:not([type="hidden"]), textarea:not(#bot-editor-textarea), select');
        if (firstInput) {
            setTimeout(() => firstInput.focus(), 100);
        }
    });
    
    // Ensure backdrop click works properly
    modal.addEventListener('click', function (e) {
        if (e.target === modal) {
            const modalInstance = bootstrap.Modal.getInstance(modal);
            if (modalInstance) {
                modalInstance.hide();
            }
        }
    });
}

// ========= Boot =========
document.addEventListener('DOMContentLoaded', () => {
    bindNavigation();
    bindFileActions();
    bindBreadcrumbs();
    bindServiceStateToggles();
    bindServiceAutostartToggles();
    initFileRoots();

    // Telegram WebApp: notify ready (no crash if not in Telegram)
    try {
        if (window.Telegram && window.Telegram.WebApp) {
            window.Telegram.WebApp.ready();
        }
    } catch (_) {}

    // Load section from URL hash or default to dashboard
    const hash = window.location.hash.slice(1) || 'dashboard';
    switchSection(hash);
    
    // Global backdrop cleanup on any click
    document.addEventListener('click', (e) => {
        // If clicking on backdrop, ensure it closes properly
        if (e.target.classList.contains('modal-backdrop')) {
            const openModals = document.querySelectorAll('.modal.show');
            openModals.forEach(modal => {
                const instance = bootstrap.Modal.getInstance(modal);
                if (instance) instance.hide();
            });
            // Force remove all backdrops
            setTimeout(() => {
                document.querySelectorAll('.modal-backdrop').forEach(el => el.remove());
                document.body.classList.remove('modal-open');
                document.body.style.overflow = '';
                document.body.style.paddingRight = '';
            }, 100);
        }
    });
});
