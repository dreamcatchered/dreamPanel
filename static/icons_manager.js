// Icons API Management
// Управление иконками через админ-панель

let iconsProjects = [];

// Загрузка списка проектов
async function refreshIconsProjects() {
    const container = document.getElementById('icons-projects-container');
    if (!container) return;
    
    container.innerHTML = `
        <div class="text-center py-5">
            <div class="spinner-border text-primary" role="status">
                <span class="visually-hidden">Загрузка...</span>
            </div>
            <p class="mt-3 text-muted">Загрузка проектов...</p>
        </div>
    `;
    
    try {
        const response = await fetch('/api/icons/projects');
        const data = await response.json();
        
        if (response.ok && data.projects) {
            iconsProjects = data.projects;
            renderIconsProjects(data.projects);
        } else {
            container.innerHTML = `
                <div class="alert alert-danger">
                    <i class="bi bi-exclamation-triangle"></i> Ошибка загрузки: ${data.error || 'Неизвестная ошибка'}
                </div>
            `;
        }
    } catch (error) {
        container.innerHTML = `
            <div class="alert alert-danger">
                <i class="bi bi-exclamation-triangle"></i> Ошибка подключения к Icons API: ${error.message}
            </div>
        `;
    }
}

// Отрисовка проектов
function renderIconsProjects(projects) {
    const container = document.getElementById('icons-projects-container');
    
    if (!projects || projects.length === 0) {
        container.innerHTML = `
            <div class="text-center py-5">
                <i class="bi bi-inbox fs-1 text-muted"></i>
                <p class="mt-3 text-muted">Нет проектов. Создайте первый проект иконок.</p>
            </div>
        `;
        return;
    }
    
    const projectsHTML = projects.map(project => `
        <div class="col-md-6 col-lg-4">
            <div class="card h-100 shadow-sm hover-shadow">
                <div class="card-body">
                    <div class="d-flex justify-content-between align-items-start mb-3">
                        <h6 class="card-title mb-0 fw-bold">${escapeHtml(project.name)}</h6>
                        <div class="dropdown">
                            <button class="btn btn-sm btn-link text-dark p-0" type="button" data-bs-toggle="dropdown">
                                <i class="bi bi-three-dots-vertical"></i>
                            </button>
                            <ul class="dropdown-menu dropdown-menu-end">
                                <li><a class="dropdown-item" href="#" onclick="viewIconProject('${escapeHtml(project.name)}'); return false;">
                                    <i class="bi bi-eye"></i> Просмотр
                                </a></li>
                                <li><a class="dropdown-item" href="#" onclick="showUpdateIconProjectModal('${escapeHtml(project.name)}'); return false;">
                                    <i class="bi bi-pencil"></i> Обновить
                                </a></li>
                                <li><hr class="dropdown-divider"></li>
                                <li><a class="dropdown-item text-danger" href="#" onclick="deleteIconProject('${escapeHtml(project.name)}'); return false;">
                                    <i class="bi bi-trash"></i> Удалить
                                </a></li>
                            </ul>
                        </div>
                    </div>
                    
                    <!-- Preview Grid -->
                    <div class="row g-2 mb-3">
                        <div class="col-4">
                            <div class="border rounded p-2 text-center bg-light">
                                <img src="https://api.dreampartners.online/icons/${encodeURIComponent(project.name)}/favicon/32" 
                                     alt="32x32" width="32" height="32" class="img-fluid"
                                     onerror="this.src='data:image/svg+xml,%3Csvg xmlns=%22http://www.w3.org/2000/svg%22 width=%2232%22 height=%2232%22%3E%3Crect fill=%22%23ddd%22 width=%2232%22 height=%2232%22/%3E%3C/svg%3E'">
                                <small class="d-block text-muted mt-1">32px</small>
                            </div>
                        </div>
                        <div class="col-4">
                            <div class="border rounded p-2 text-center bg-light">
                                <img src="https://api.dreampartners.online/icons/${encodeURIComponent(project.name)}/favicon/64" 
                                     alt="64x64" width="64" height="64" class="img-fluid"
                                     onerror="this.src='data:image/svg+xml,%3Csvg xmlns=%22http://www.w3.org/2000/svg%22 width=%2264%22 height=%2264%22%3E%3Crect fill=%22%23ddd%22 width=%2264%22 height=%2264%22/%3E%3C/svg%3E'">
                                <small class="d-block text-muted mt-1">64px</small>
                            </div>
                        </div>
                        <div class="col-4">
                            <div class="border rounded p-2 text-center bg-light">
                                <img src="https://api.dreampartners.online/icons/${encodeURIComponent(project.name)}/favicon/128" 
                                     alt="128x128" width="64" height="64" class="img-fluid"
                                     onerror="this.src='data:image/svg+xml,%3Csvg xmlns=%22http://www.w3.org/2000/svg%22 width=%22128%22 height=%22128%22%3E%3Crect fill=%22%23ddd%22 width=%22128%22 height=%22128%22/%3E%3C/svg%3E'">
                                <small class="d-block text-muted mt-1">128px</small>
                            </div>
                        </div>
                    </div>
                    
                    <div class="small text-muted">
                        <i class="bi bi-clock"></i> ${project.last_modified || 'Неизвестно'}
                    </div>
                </div>
                <div class="card-footer bg-white border-top-0">
                    <button class="btn btn-sm btn-outline-primary w-100" onclick="viewIconProject('${escapeHtml(project.name)}')">
                        <i class="bi bi-box-arrow-up-right"></i> Открыть
                    </button>
                </div>
            </div>
        </div>
    `).join('');
    
    container.innerHTML = `<div class="row g-3">${projectsHTML}</div>`;
}

// Модальное окно создания проекта
function showCreateIconProjectModal() {
    const modalHTML = `
        <div class="modal fade" id="createIconProjectModal" tabindex="-1">
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title"><i class="bi bi-plus-circle"></i> Создать проект иконок</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body">
                        <form id="createIconProjectForm">
                            <div class="mb-3">
                                <label class="form-label fw-bold">Название проекта</label>
                                <input type="text" class="form-control" id="iconProjectName" required
                                       pattern="[a-zA-Z0-9_-]+" 
                                       placeholder="myproject">
                                <div class="form-text">Только буквы, цифры, дефисы и подчеркивания</div>
                            </div>
                            <div class="mb-3">
                                <label class="form-label fw-bold">Файл логотипа</label>
                                <input type="file" class="form-control" id="iconProjectFile" required
                                       accept=".svg,.png,.jpg,.jpeg,.webp">
                                <div class="form-text">Поддерживаются: SVG, PNG, JPG, WEBP. Рекомендуется SVG.</div>
                            </div>
                            <div id="createIconProjectPreview" class="mb-3" style="display: none;">
                                <label class="form-label fw-bold">Предпросмотр</label>
                                <div class="border rounded p-3 text-center bg-light">
                                    <img id="createIconProjectPreviewImg" src="" alt="Preview" style="max-width: 200px; max-height: 200px;">
                                </div>
                            </div>
                        </form>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Отмена</button>
                        <button type="button" class="btn btn-primary" onclick="createIconProject()">
                            <i class="bi bi-check-circle"></i> Создать
                        </button>
                    </div>
                </div>
            </div>
        </div>
    `;
    
    document.getElementById('modal-container').innerHTML = modalHTML;
    const modalElement = document.getElementById('createIconProjectModal');
    const modal = new bootstrap.Modal(modalElement);
    
    // Fix backdrop cleanup
    modalElement.addEventListener('hidden.bs.modal', function handler() {
        setTimeout(() => {
            document.querySelectorAll('.modal-backdrop').forEach(el => el.remove());
            document.body.classList.remove('modal-open');
            document.body.style.overflow = '';
            document.body.style.paddingRight = '';
        }, 10);
        modalElement.removeEventListener('hidden.bs.modal', handler);
    });
    
    modal.show();
    
    // Preview on file select
    document.getElementById('iconProjectFile').addEventListener('change', function(e) {
        const file = e.target.files[0];
        if (file) {
            const reader = new FileReader();
            reader.onload = function(e) {
                document.getElementById('createIconProjectPreviewImg').src = e.target.result;
                document.getElementById('createIconProjectPreview').style.display = 'block';
            };
            reader.readAsDataURL(file);
        }
    });
}

// Создание проекта
async function createIconProject() {
    const name = document.getElementById('iconProjectName').value.trim();
    const fileInput = document.getElementById('iconProjectFile');
    const file = fileInput.files[0];
    
    if (!name || !file) {
        showToast('Заполните все поля', 'warning');
        return;
    }
    
    const formData = new FormData();
    formData.append('name', name);
    formData.append('logo_file', file);
    
    try {
        const response = await fetch('/api/icons/projects', {
            method: 'POST',
            body: formData
        });
        
        const data = await response.json();
        
        if (response.ok) {
            showToast(`Проект "${name}" успешно создан!`, 'success');
            bootstrap.Modal.getInstance(document.getElementById('createIconProjectModal')).hide();
            refreshIconsProjects();
        } else {
            showToast(`Ошибка: ${data.error || data.message || 'Неизвестная ошибка'}`, 'danger');
        }
    } catch (error) {
        showToast(`Ошибка: ${error.message}`, 'danger');
    }
}

// Модальное окно обновления проекта
function showUpdateIconProjectModal(projectName) {
    const modalHTML = `
        <div class="modal fade" id="updateIconProjectModal" tabindex="-1">
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title"><i class="bi bi-pencil"></i> Обновить проект: ${escapeHtml(projectName)}</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body">
                        <form id="updateIconProjectForm">
                            <input type="hidden" id="updateIconProjectName" value="${escapeHtml(projectName)}">
                            <div class="mb-3">
                                <label class="form-label fw-bold">Новый файл логотипа</label>
                                <input type="file" class="form-control" id="updateIconProjectFile" required
                                       accept=".svg,.png,.jpg,.jpeg,.webp">
                                <div class="form-text">Поддерживаются: SVG, PNG, JPG, WEBP</div>
                            </div>
                            <div id="updateIconProjectPreview" class="mb-3" style="display: none;">
                                <label class="form-label fw-bold">Предпросмотр</label>
                                <div class="border rounded p-3 text-center bg-light">
                                    <img id="updateIconProjectPreviewImg" src="" alt="Preview" style="max-width: 200px; max-height: 200px;">
                                </div>
                            </div>
                        </form>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Отмена</button>
                        <button type="button" class="btn btn-primary" onclick="updateIconProject()">
                            <i class="bi bi-check-circle"></i> Обновить
                        </button>
                    </div>
                </div>
            </div>
        </div>
    `;
    
    document.getElementById('modal-container').innerHTML = modalHTML;
    const modalElement = document.getElementById('updateIconProjectModal');
    const modal = new bootstrap.Modal(modalElement);
    
    // Fix backdrop cleanup
    modalElement.addEventListener('hidden.bs.modal', function handler() {
        setTimeout(() => {
            document.querySelectorAll('.modal-backdrop').forEach(el => el.remove());
            document.body.classList.remove('modal-open');
            document.body.style.overflow = '';
            document.body.style.paddingRight = '';
        }, 10);
        modalElement.removeEventListener('hidden.bs.modal', handler);
    });
    
    modal.show();
    
    // Preview on file select
    document.getElementById('updateIconProjectFile').addEventListener('change', function(e) {
        const file = e.target.files[0];
        if (file) {
            const reader = new FileReader();
            reader.onload = function(e) {
                document.getElementById('updateIconProjectPreviewImg').src = e.target.result;
                document.getElementById('updateIconProjectPreview').style.display = 'block';
            };
            reader.readAsDataURL(file);
        }
    });
}

// Обновление проекта
async function updateIconProject() {
    const name = document.getElementById('updateIconProjectName').value;
    const fileInput = document.getElementById('updateIconProjectFile');
    const file = fileInput.files[0];
    
    if (!file) {
        showToast('Выберите файл', 'warning');
        return;
    }
    
    const formData = new FormData();
    formData.append('logo_file', file);
    
    try {
        const response = await fetch(`/api/icons/projects/${encodeURIComponent(name)}`, {
            method: 'PUT',
            body: formData
        });
        
        const data = await response.json();
        
        if (response.ok) {
            showToast(`Проект "${name}" успешно обновлен!`, 'success');
            bootstrap.Modal.getInstance(document.getElementById('updateIconProjectModal')).hide();
            refreshIconsProjects();
        } else {
            showToast(`Ошибка: ${data.error || data.message || 'Неизвестная ошибка'}`, 'danger');
        }
    } catch (error) {
        showToast(`Ошибка: ${error.message}`, 'danger');
    }
}

// Удаление проекта
async function deleteIconProject(projectName) {
    if (!confirm(`Вы уверены, что хотите удалить проект "${projectName}"? Это действие необратимо.`)) {
        return;
    }
    
    try {
        const response = await fetch(`/api/icons/projects/${encodeURIComponent(projectName)}`, {
            method: 'DELETE'
        });
        
        const data = await response.json();
        
        if (response.ok) {
            showToast(`Проект "${projectName}" успешно удален!`, 'success');
            refreshIconsProjects();
        } else {
            showToast(`Ошибка: ${data.error || data.message || 'Неизвестная ошибка'}`, 'danger');
        }
    } catch (error) {
        showToast(`Ошибка: ${error.message}`, 'danger');
    }
}

// Просмотр проекта - показываем детальную информацию
async function viewIconProject(projectName) {
    try {
        const response = await fetch(`/api/icons/projects/${encodeURIComponent(projectName)}/info`);
        const data = await response.json();
        
        if (!response.ok) {
            showToast(`Ошибка: ${data.error || 'Не удалось загрузить информацию'}`, 'danger');
            return;
        }
        
        showProjectDetailsModal(projectName, data);
    } catch (error) {
        showToast(`Ошибка: ${error.message}`, 'danger');
    }
}

// Модальное окно с детальной информацией о проекте
async function showProjectDetailsModal(projectName, data) {
    const baseUrl = 'https://api.dreampartners.online/icons';
    
    // Получаем информацию о загруженных файлах
    let uploadedFiles = {};
    try {
        const filesResponse = await fetch(`/api/icons/projects/${encodeURIComponent(projectName)}/files`);
        if (filesResponse.ok) {
            const filesData = await filesResponse.json();
            uploadedFiles = filesData.files || {};
        }
    } catch (e) {
        console.error('Failed to load files info:', e);
    }
    
    // Генерируем HTML для всех типов иконок
    const iconTypes = [
        { title: 'Favicons', items: [
            { name: '16x16', url: `${baseUrl}/${projectName}/favicon/16`, size: 16, fileType: 'favicon-16' },
            { name: '32x32', url: `${baseUrl}/${projectName}/favicon/32`, size: 32, fileType: 'favicon-32' },
            { name: '48x48', url: `${baseUrl}/${projectName}/favicon/48`, size: 48, fileType: 'favicon-48' },
            { name: '64x64', url: `${baseUrl}/${projectName}/favicon/64`, size: 64, fileType: 'favicon-64' },
            { name: '128x128', url: `${baseUrl}/${projectName}/favicon/128`, size: 64, fileType: 'favicon-128' },
            { name: '256x256', url: `${baseUrl}/${projectName}/favicon/256`, size: 64, fileType: 'favicon-256' },
        ]},
        { title: 'Специальные иконки', items: [
            { name: 'Apple Touch Icon (180x180)', url: `${baseUrl}/${projectName}/apple-touch-icon.png`, size: 90, fileType: 'apple-touch-icon' },
            { name: 'Android Chrome 192', url: `${baseUrl}/${projectName}/android-chrome-192.png`, size: 96, fileType: 'android-chrome-192' },
            { name: 'Android Chrome 512', url: `${baseUrl}/${projectName}/android-chrome-512.png`, size: 96, fileType: 'android-chrome-512' },
        ]},
        { title: 'Open Graph & Twitter', items: [
            { name: 'OG Image (1200x630)', url: `${baseUrl}/${projectName}/og-image.png`, size: 120, rect: true, fileType: 'og-image' },
            { name: 'OG Square (1200x1200)', url: `${baseUrl}/${projectName}/og-square.png`, size: 120, fileType: 'og-square' },
            { name: 'Twitter Card (1200x600)', url: `${baseUrl}/${projectName}/twitter-card.png`, size: 120, rect: true, fileType: 'twitter-card' },
            { name: 'Twitter Summary (300x300)', url: `${baseUrl}/${projectName}/twitter-summary.png`, size: 120, fileType: 'twitter-summary' },
        ]}
    ];
    
    let sectionsHTML = '';
    iconTypes.forEach(section => {
        const itemsHTML = section.items.map(item => {
            const isUploaded = uploadedFiles[item.fileType]?.exists || false;
            const uploadBadge = isUploaded ? '<span class="badge bg-success position-absolute top-0 end-0 m-1" style="font-size: 0.6rem;">Загружен</span>' : '<span class="badge bg-secondary position-absolute top-0 end-0 m-1" style="font-size: 0.6rem;">Авто</span>';
            
            return `
            <div class="col-6 col-md-4 col-lg-3">
                <div class="card h-100 icon-card-hover" style="position: relative;">
                    ${uploadBadge}
                    <div class="card-body text-center p-2">
                        <div class="border rounded p-2 bg-light mb-2 position-relative" style="min-height: ${item.size + 20}px;">
                            <img src="${item.url}?t=${Date.now()}" alt="${item.name}" 
                                 style="max-width: 100%; max-height: ${item.size}px;"
                                 onerror="this.src='data:image/svg+xml,%3Csvg xmlns=%22http://www.w3.org/2000/svg%22 width=%22${item.size}%22 height=%22${item.size}%22%3E%3Crect fill=%22%23ddd%22 width=%22${item.size}%22 height=%22${item.size}%22/%3E%3Ctext x=%2250%25%22 y=%2250%25%22 text-anchor=%22middle%22 dy=%22.3em%22 fill=%22%23999%22 font-size=%2212%22%3EError%3C/text%3E%3C/svg%3E'">
                            <div class="icon-hover-overlay position-absolute top-0 start-0 w-100 h-100 d-flex align-items-center justify-content-center" style="background: rgba(0,0,0,0.7); opacity: 0; transition: opacity 0.2s;">
                                <input type="file" id="upload-${item.fileType}" accept="image/*" style="display: none;" onchange="uploadIconFile('${escapeHtml(projectName)}', '${item.fileType}', this)">
                                <button class="btn btn-sm btn-primary me-1" onclick="document.getElementById('upload-${item.fileType}').click()">
                                    <i class="bi bi-upload"></i>
                                </button>
                                ${isUploaded ? `<button class="btn btn-sm btn-danger" onclick="deleteIconFile('${escapeHtml(projectName)}', '${item.fileType}')">
                                    <i class="bi bi-trash"></i>
                                </button>` : ''}
                            </div>
                        </div>
                        <small class="text-muted d-block">${item.name}</small>
                        <a href="${item.url}" target="_blank" class="btn btn-sm btn-outline-primary mt-1">
                            <i class="bi bi-box-arrow-up-right"></i>
                        </a>
                    </div>
                </div>
            </div>
        `}).join('');
        
        sectionsHTML += `
            <div class="mb-4">
                <h6 class="fw-bold mb-3">${section.title}</h6>
                <div class="row g-2">${itemsHTML}</div>
            </div>
        `;
    });
    
    const modalHTML = `
        <div class="modal fade" id="projectDetailsModal" tabindex="-1">
            <div class="modal-dialog modal-xl">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">
                            <i class="bi bi-image"></i> ${escapeHtml(projectName)} - Все иконки
                        </h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body" style="max-height: 70vh; overflow-y: auto;">
                        <!-- SVG Source -->
                        <div class="alert alert-info mb-4">
                            <div class="d-flex justify-content-between align-items-center">
                                <div>
                                    <strong><i class="bi bi-file-earmark-code"></i> Исходный файл:</strong>
                                    <code>${data.svg?.path || 'logo.svg'}</code>
                                </div>
                                <a href="${baseUrl}/${projectName}/logo.svg" target="_blank" class="btn btn-sm btn-primary">
                                    <i class="bi bi-download"></i> Скачать SVG
                                </a>
                            </div>
                            ${data.svg?.last_modified ? `<small class="text-muted">Изменен: ${data.svg.last_modified}</small>` : ''}
                        </div>
                        
                        ${sectionsHTML}
                        
                        <!-- Cache Status -->
                        ${data.cache_status ? `
                        <div class="mt-4">
                            <h6 class="fw-bold mb-2">Статус кэша</h6>
                            <div class="small">
                                <span class="badge bg-success">${Object.values(data.cache_status).filter(s => s.cached && s.valid).length} в кэше</span>
                                <span class="badge bg-warning">${Object.values(data.cache_status).filter(s => s.cached && !s.valid).length} устарело</span>
                                <span class="badge bg-secondary">${Object.values(data.cache_status).filter(s => !s.cached).length} не создано</span>
                            </div>
                        </div>
                        ` : ''}
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Закрыть</button>
                        <button type="button" class="btn btn-warning" onclick="clearProjectCache('${escapeHtml(projectName)}')">
                            <i class="bi bi-trash"></i> Очистить кэш
                        </button>
                        <button type="button" class="btn btn-primary" onclick="showUpdateIconProjectModal('${escapeHtml(projectName)}'); bootstrap.Modal.getInstance(document.getElementById('projectDetailsModal')).hide();">
                            <i class="bi bi-pencil"></i> Обновить логотип
                        </button>
                    </div>
                </div>
            </div>
        </div>
    `;
    
    document.getElementById('modal-container').innerHTML = modalHTML;
    const modalElement = document.getElementById('projectDetailsModal');
    const modal = new bootstrap.Modal(modalElement);
    
    // Fix backdrop cleanup
    modalElement.addEventListener('hidden.bs.modal', function handler() {
        setTimeout(() => {
            document.querySelectorAll('.modal-backdrop').forEach(el => el.remove());
            document.body.classList.remove('modal-open');
            document.body.style.overflow = '';
            document.body.style.paddingRight = '';
        }, 10);
        modalElement.removeEventListener('hidden.bs.modal', handler);
    });
    
    // Allow backdrop click to close
    modalElement.addEventListener('click', function(e) {
        if (e.target === modalElement) {
            modal.hide();
        }
    });
    
    modal.show();
}

// Загрузка конкретного файла иконки
async function uploadIconFile(projectName, fileType, inputElement) {
    const file = inputElement.files[0];
    if (!file) return;
    
    const formData = new FormData();
    formData.append('file', file);
    
    try {
        const response = await fetch(`/api/icons/projects/${encodeURIComponent(projectName)}/files/${fileType}`, {
            method: 'POST',
            body: formData
        });
        
        const data = await response.json();
        
        if (response.ok) {
            showToast(`Файл ${fileType} успешно загружен!`, 'success');
            // Перезагружаем модальное окно
            const infoResponse = await fetch(`/api/icons/projects/${encodeURIComponent(projectName)}/info`);
            if (infoResponse.ok) {
                const infoData = await infoResponse.json();
                showProjectDetailsModal(projectName, infoData);
            }
        } else {
            showToast(`Ошибка: ${data.error || data.message || 'Неизвестная ошибка'}`, 'danger');
        }
    } catch (error) {
        showToast(`Ошибка: ${error.message}`, 'danger');
    }
    
    // Очищаем input
    inputElement.value = '';
}

// Удаление конкретного файла иконки
async function deleteIconFile(projectName, fileType) {
    if (!confirm(`Удалить загруженный файл ${fileType}? После удаления будет использоваться автоматически сгенерированная версия из SVG.`)) {
        return;
    }
    
    try {
        const response = await fetch(`/api/icons/projects/${encodeURIComponent(projectName)}/files/${fileType}`, {
            method: 'DELETE'
        });
        
        const data = await response.json();
        
        if (response.ok) {
            showToast(`Файл ${fileType} успешно удален!`, 'success');
            // Перезагружаем модальное окно
            const infoResponse = await fetch(`/api/icons/projects/${encodeURIComponent(projectName)}/info`);
            if (infoResponse.ok) {
                const infoData = await infoResponse.json();
                showProjectDetailsModal(projectName, infoData);
            }
        } else {
            showToast(`Ошибка: ${data.error || data.message || 'Неизвестная ошибка'}`, 'danger');
        }
    } catch (error) {
        showToast(`Ошибка: ${error.message}`, 'danger');
    }
}

// Очистка кэша проекта
async function clearProjectCache(projectName) {
    if (!confirm(`Очистить кэш для проекта "${projectName}"? Иконки будут пересозданы при следующем запросе.`)) {
        return;
    }
    
    try {
        const response = await fetch(`/api/icons/projects/${encodeURIComponent(projectName)}/cache`, {
            method: 'DELETE'
        });
        
        const data = await response.json();
        
        if (response.ok) {
            showToast(`Кэш проекта "${projectName}" очищен! Удалено файлов: ${data.deleted_files || 0}`, 'success');
            // Перезагружаем модальное окно для обновления информации
            const infoResponse = await fetch(`/api/icons/projects/${encodeURIComponent(projectName)}/info`);
            if (infoResponse.ok) {
                const infoData = await infoResponse.json();
                showProjectDetailsModal(projectName, infoData);
            }
        } else {
            showToast(`Ошибка: ${data.error || data.message || 'Не удалось очистить кэш'}`, 'danger');
        }
    } catch (error) {
        showToast(`Ошибка: ${error.message}`, 'danger');
    }
}

// Утилиты
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Инициализация при переключении на секцию микросервисов
document.addEventListener('DOMContentLoaded', function() {
    // Слушаем переключение секций
    document.querySelectorAll('[data-section="microservices"]').forEach(link => {
        link.addEventListener('click', function() {
            setTimeout(() => refreshIconsProjects(), 100);
        });
    });
});
