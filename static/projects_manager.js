/**
 * Dream API Projects Manager
 * Управление projects.json и status.json через dreamPanel
 */

// ===================== Font Awesome icons list =====================
const FA_ICONS = [
    'globe','network-wired','credit-card','brain','fingerprint','music','cloud',
    'download','comment-sms','sliders','icons','shield','share-nodes','hard-drive',
    'pen-nib','envelope','server','robot','house','gear','user','users','lock',
    'unlock','key','shield-halved','bug','code','terminal','database','folder',
    'folder-open','file','file-code','file-image','file-pdf','file-video','film',
    'image','photo-film','camera','video','microphone','headphones','radio',
    'tv','mobile-screen','laptop','desktop','keyboard','mouse-pointer','print',
    'qrcode','barcode','tag','tags','bookmark','star','heart','flag','fire',
    'bolt','sun','moon','cloud-rain','snowflake','wind','earth-americas','map',
    'location-dot','compass','paper-plane','at','link','rss','wifi','satellite',
    'tower-broadcast','phone','phone-flip','message','comment-dots','comments',
    'inbox','box-archive','boxes-stacked','cart-shopping','bag-shopping','store',
    'shop','receipt','money-bill','coins','chart-line','chart-bar','chart-pie',
    'arrow-trend-up','percent','calculator','wallet','piggy-bank','building',
    'briefcase','graduation-cap','book','book-open','bookmark','newspaper',
    'pen','pencil','scissors','palette','wand-magic-sparkles','magic','atom',
    'flask','microscope','dna','capsules','hospital','stethoscope','truck',
    'bicycle','car','plane','rocket','ship','train','bus','motorcycle',
    'gas-pump','road','traffic-light','anchor','umbrella','leaf','tree','spa',
    'paw','fish','horse','dog','cat','crow','dove','frog','otter',
    'shield-cat','dragon','skull','ghost','robot','android','apple',
    'windows','linux','github','gitlab','docker','aws',
    'google','facebook','twitter','instagram','youtube','tiktok','telegram',
    'discord','slack','zoom','spotify','twitch','steam','playstation','xbox',
];

// ===================== Status helpers =====================
const STATUS_CONFIG = {
    available:   { badge: 'bg-success',  label: 'available',    icon: 'bi-check-circle-fill' },
    maintenance: { badge: 'bg-warning text-dark', label: 'maintenance', icon: 'bi-tools' },
    unavailable: { badge: 'bg-danger',   label: 'unavailable',  icon: 'bi-x-circle-fill' },
};

function statusBadgeHtml(status) {
    const cfg = STATUS_CONFIG[status] || { badge: 'bg-secondary', label: status || 'unknown', icon: 'bi-question-circle' };
    return `<span class="badge ${cfg.badge}"><i class="bi ${cfg.icon} me-1"></i>${cfg.label}</span>`;
}

// ===================== Refresh all microservices =====================
async function refreshMicroservices() {
    await Promise.all([refreshApiProjects(), refreshIconsProjects()]);
}

// ===================== API Status =====================
async function loadApiStatus() {
    try {
        const r = await fetch('/api/dream-data/status');
        const data = await r.json();
        const el = document.getElementById('api-status-badge');
        if (el) el.innerHTML = statusBadgeHtml(data.status);
        
        // Fill contact input in modal
        const contactInput = document.getElementById('api-status-contact');
        if (contactInput && data.contact) {
            contactInput.value = data.contact;
        }
    } catch (e) {
        const el = document.getElementById('api-status-badge');
        if (el) el.innerHTML = '<span class="badge bg-secondary">ошибка</span>';
    }
}

function showStatusModal() {
    const modal = new bootstrap.Modal(document.getElementById('statusModal'));
    modal.show();
}

async function setApiStatus(status) {
    const contact = document.getElementById('api-status-contact').value.trim() || 'dreamcatch_r';
    try {
        const r = await fetch('/api/dream-data/status', {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ status, contact }),
        });
        const data = await r.json();
        if (!r.ok) throw new Error(data.error || 'Ошибка');
        showToast(`Статус обновлён: ${status}`, 'success');
        bootstrap.Modal.getInstance(document.getElementById('statusModal'))?.hide();
        loadApiStatus();
    } catch (e) {
        showToast('Ошибка: ' + e.message, 'danger');
    }
}

// ===================== Project Cards =====================
async function refreshApiProjects() {
    const container = document.getElementById('api-projects-container');
    if (!container) return;
    container.innerHTML = `<div class="text-center py-4"><div class="spinner-border text-primary" role="status"></div><p class="mt-2 text-muted small">Загрузка...</p></div>`;
    await loadApiStatus();
    try {
        const r = await fetch('/api/dream-data/projects');
        const projects = await r.json();
        if (!r.ok) throw new Error(projects.error || 'Ошибка загрузки');
        renderApiProjects(projects);
    } catch (e) {
        container.innerHTML = `<div class="alert alert-danger"><i class="bi bi-exclamation-triangle me-2"></i>${escHtml(e.message)}</div>`;
    }
}

function renderApiProjects(projects) {
    const container = document.getElementById('api-projects-container');
    if (!projects || projects.length === 0) {
        container.innerHTML = `<div class="text-center py-4 text-muted"><i class="bi bi-inbox fs-2"></i><p class="mt-2">Нет проектов. Добавьте первый!</p></div>`;
        return;
    }

    const cards = projects.map((p, idx) => {
        const iconHtml = buildIconHtml(p.icon, p.id);
        const isHidden = !!p.hidden;
        return `
        <div class="col-6 col-md-4 col-lg-3 col-xl-2">
            <div class="proj-card d-flex flex-column ${isHidden ? 'opacity-75' : ''}">
                <div class="d-flex align-items-start gap-2 mb-1">
                    <div class="proj-icon-wrap">${iconHtml}</div>
                    <div class="overflow-hidden w-100">
                        <div class="d-flex justify-content-between align-items-center">
                            <div class="proj-title" title="${escHtml(p.title)}">${escHtml(p.title)}</div>
                        </div>
                        <div class="proj-desc" title="${escHtml(p.desc || '')}">${escHtml(p.desc || '—')}</div>
                    </div>
                </div>
                ${p.url ? `<a href="${escHtml(p.url)}" target="_blank" class="proj-url" title="${escHtml(p.url)}">${escHtml(p.url)}</a>` : ''}
                
                <div class="mt-2 mb-2">
                    <div class="form-check form-switch m-0">
                        <input class="form-check-input" type="checkbox" role="switch" 
                            id="toggle-${escHtml(p.id)}" 
                            ${!isHidden ? 'checked' : ''} 
                            onchange="toggleProjectVisibility('${escHtml(p.id)}', this.checked)">
                        <label class="form-check-label small" for="toggle-${escHtml(p.id)}">${!isHidden ? 'Активен' : 'Скрыт'}</label>
                    </div>
                </div>

                <div class="proj-actions mt-auto">
                    <button class="btn btn-sm btn-outline-primary flex-fill" onclick="editProject('${escHtml(p.id)}')">
                        <i class="bi bi-pencil"></i>
                    </button>
                    <button class="btn btn-sm btn-outline-danger flex-fill" onclick="deleteProject('${escHtml(p.id)}', '${escHtml(p.title)}')">
                        <i class="bi bi-trash"></i>
                    </button>
                </div>
            </div>
        </div>`;
    }).join('');

    container.innerHTML = `<div class="row g-3">${cards}</div>`;
}

function buildIconHtml(iconName, projectId) {
    if (!iconName) return `<i class="fa-solid fa-question fa-fw"></i>`;
    // Пробуем показать реальную иконку иконок API
    const faName = iconName.replace(/^fa-/, '');
    return `<i class="fa-solid fa-${escHtml(faName)} fa-fw"></i>`;
}

// ===================== Add / Edit Modal =====================
let _editingProjectId = null;

function showAddProjectModal() {
    _editingProjectId = null;
    document.getElementById('projectModalTitle').innerHTML = '<i class="bi bi-plus-circle"></i> Добавить проект';
    document.getElementById('projectModalSaveBtn').innerHTML = '<i class="bi bi-check-lg"></i> Добавить';
    document.getElementById('proj-edit-id').value = '';
    document.getElementById('proj-id').value = '';
    document.getElementById('proj-id').disabled = false;
    document.getElementById('proj-title').value = '';
    document.getElementById('proj-desc').value = '';
    document.getElementById('proj-url').value = '';
    document.getElementById('proj-icon').value = '';
    document.getElementById('proj-hidden').checked = false;
    document.getElementById('proj-dreamid').checked = false;
    updateIconPreview();
    document.getElementById('icon-picker-grid').style.display = 'none';
    const modal = new bootstrap.Modal(document.getElementById('projectModal'));
    modal.show();
}

async function editProject(id) {
    try {
        const r = await fetch('/api/dream-data/projects');
        const projects = await r.json();
        const p = projects.find(x => x.id === id);
        if (!p) { showToast('Проект не найден', 'warning'); return; }

        _editingProjectId = id;
        document.getElementById('projectModalTitle').innerHTML = `<i class="bi bi-pencil"></i> Редактировать: ${escHtml(p.title)}`;
        document.getElementById('projectModalSaveBtn').innerHTML = '<i class="bi bi-check-lg"></i> Сохранить';
        document.getElementById('proj-edit-id').value = id;
        document.getElementById('proj-id').value = p.id;
        document.getElementById('proj-id').disabled = true; // нельзя менять id
        document.getElementById('proj-title').value = p.title || '';
        document.getElementById('proj-desc').value = p.desc || '';
        document.getElementById('proj-url').value = p.url || '';
        document.getElementById('proj-icon').value = p.icon || '';
        document.getElementById('proj-hidden').checked = !!p.hidden;
        document.getElementById('proj-dreamid').checked = !!p.dreamid;
        updateIconPreview();
        document.getElementById('icon-picker-grid').style.display = 'none';
        const modal = new bootstrap.Modal(document.getElementById('projectModal'));
        modal.show();
    } catch (e) {
        showToast('Ошибка: ' + e.message, 'danger');
    }
}

async function saveProject() {
    const id = _editingProjectId;
    const isEdit = !!id;
    const payload = {
        id: document.getElementById('proj-id').value.trim(),
        title: document.getElementById('proj-title').value.trim(),
        desc: document.getElementById('proj-desc').value.trim(),
        url: document.getElementById('proj-url').value.trim(),
        icon: document.getElementById('proj-icon').value.trim(),
        hidden: document.getElementById('proj-hidden').checked,
        dreamid: document.getElementById('proj-dreamid').checked,
    };
    if (!payload.title) { showToast('Укажите название', 'warning'); return; }
    if (!isEdit && !payload.id) { showToast('Укажите ID', 'warning'); return; }

    try {
        let r;
        if (isEdit) {
            r = await fetch(`/api/dream-data/projects/${encodeURIComponent(id)}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload),
            });
        } else {
            r = await fetch('/api/dream-data/projects', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload),
            });
        }
        const data = await r.json();
        if (!r.ok) throw new Error(data.error || 'Ошибка');
        showToast(isEdit ? 'Проект обновлён' : 'Проект добавлен', 'success');
        bootstrap.Modal.getInstance(document.getElementById('projectModal'))?.hide();
        refreshApiProjects();
    } catch (e) {
        showToast('Ошибка: ' + e.message, 'danger');
    }
}

async function deleteProject(id, title) {
    if (!confirm(`Удалить проект «${title}»?`)) return;
    try {
        const r = await fetch(`/api/dream-data/projects/${encodeURIComponent(id)}`, { method: 'DELETE' });
        const data = await r.json();
        if (!r.ok) throw new Error(data.error || 'Ошибка');
        showToast(`Проект «${title}» удалён`, 'success');
        refreshApiProjects();
    } catch (e) {
        showToast('Ошибка: ' + e.message, 'danger');
    }
}

// ===================== Icon Picker =====================
let _iconPickerBuilt = false;

function toggleIconPicker() {
    const grid = document.getElementById('icon-picker-grid');
    const isVisible = grid.style.display !== 'none';
    grid.style.display = isVisible ? 'none' : 'block';
    if (!isVisible && !_iconPickerBuilt) {
        buildIconGrid(FA_ICONS);
        _iconPickerBuilt = true;
    }
}

function buildIconGrid(icons) {
    const container = document.getElementById('icon-grid');
    container.innerHTML = icons.map(name => `
        <button type="button" class="icon-picker-btn" title="${name}" onclick="selectIcon('${name}')" data-icon="${name}">
            <i class="fa-solid fa-${name} fa-fw"></i>
        </button>
    `).join('');
}

function filterIcons() {
    const q = document.getElementById('icon-search').value.toLowerCase();
    const filtered = FA_ICONS.filter(n => n.includes(q));
    buildIconGrid(filtered);
    _iconPickerBuilt = true; // already filtered
}

function selectIcon(name) {
    document.getElementById('proj-icon').value = name;
    updateIconPreview();
    // highlight selected
    document.querySelectorAll('#icon-grid .icon-picker-btn').forEach(btn => {
        btn.classList.toggle('selected', btn.dataset.icon === name);
    });
    // hide picker after short delay
    setTimeout(() => {
        document.getElementById('icon-picker-grid').style.display = 'none';
    }, 300);
}

function updateIconPreview() {
    const val = (document.getElementById('proj-icon').value || '').trim().replace(/^fa-/, '');
    const preview = document.getElementById('proj-icon-preview');
    if (preview) {
        preview.className = `fa-solid fa-${val || 'question'} fa-fw`;
    }
}

// ===================== Utility =====================
function escHtml(s) {
    if (s == null) return '';
    return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

async function toggleProjectVisibility(id, isActive) {
    try {
        const checkbox = document.getElementById(`toggle-${id}`);
        if(checkbox) checkbox.disabled = true;
        
        const response = await fetch(`/api/dream-data/projects/${encodeURIComponent(id)}/toggle`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ hidden: !isActive })
        });
        const res = await response.json();
        if (res.success) {
            showToast('Видимость обновлена', 'success');
            refreshMicroservices();
        } else {
            showToast(res.error || 'Ошибка', 'danger');
            if(checkbox) checkbox.checked = !isActive;
        }
    } catch (e) {
        showToast('Ошибка сети', 'danger');
    } finally {
        const checkbox = document.getElementById(`toggle-${id}`);
        if(checkbox) checkbox.disabled = false;
    }
}
