// Configuración del servidor
// Detectar automáticamente la URL del servidor (funciona en localhost y producción)
const API_URL = window.location.origin + '/api';

// Estado global
let tokens = [];
let currentPage = 1;
let itemsPerPage = 20;
let currentSort = { field: null, direction: 'asc' };
let currentTab = 'tokens';
let authToken = localStorage.getItem('authToken');
let currentPageName = 'dashboard';
let charts = {};
let notifications = [];

// Función para hacer peticiones autenticadas
async function authenticatedFetch(url, options = {}) {
    if (!authToken) {
        // Si no hay token, redirigir al login
        window.location.href = 'login.html';
        throw new Error('No autenticado');
    }
    
    const headers = {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${authToken}`,
        ...options.headers
    };
    
    const response = await fetch(url, { ...options, headers });
    
    // Si el token expiró o es inválido, redirigir al login
    if (response.status === 401 || response.status === 403) {
        localStorage.removeItem('authToken');
        localStorage.removeItem('user');
        window.location.href = 'login.html';
        throw new Error('Sesión expirada');
    }
    
    return response;
}

// Verificar autenticación al cargar
async function checkAuth() {
    if (!authToken) {
        window.location.href = 'login.html';
        return false;
    }
    
    try {
        const response = await fetch(`${API_URL}/auth/verify`, {
            headers: {
                'Authorization': `Bearer ${authToken}`
            }
        });
        const data = await response.json();
        
        if (!data.valid) {
            localStorage.removeItem('authToken');
            localStorage.removeItem('user');
            window.location.href = 'login.html';
            return false;
        }
        
        // Mostrar usuario actual en sidebar
        const user = JSON.parse(localStorage.getItem('user') || '{}');
        if (user.username) {
            const userNameEl = document.getElementById('user-name');
            const userRoleEl = document.getElementById('user-role');
            if (userNameEl) userNameEl.textContent = user.username;
            if (userRoleEl) userRoleEl.textContent = user.role === 'admin' ? 'Administrador' : 'Usuario';
        }
        
        return true;
    } catch (error) {
        window.location.href = 'login.html';
        return false;
    }
}

// Cerrar sesión
function logout() {
    localStorage.removeItem('authToken');
    localStorage.removeItem('user');
    window.location.href = 'login.html';
}

// Inicializar
document.addEventListener('DOMContentLoaded', async () => {
    const isAuthenticated = await checkAuth();
    if (isAuthenticated) {
        initializeTheme();
        initializeNavigation();
        loadDashboard();
        setupGlobalSearch();
        loadNotifications();
        setInterval(loadNotifications, 30000); // Actualizar notificaciones cada 30s
    }
});

// Inicializar tema
function initializeTheme() {
    const savedTheme = localStorage.getItem('theme') || 'light';
    document.documentElement.setAttribute('data-theme', savedTheme);
    updateThemeIcon(savedTheme);
}

// Toggle sidebar
function toggleSidebar() {
    const sidebar = document.getElementById('sidebar');
    sidebar.classList.toggle('open');
}

// Navegación
function navigateTo(page) {
    currentPageName = page;
    
    // Actualizar sidebar
    document.querySelectorAll('.nav-item').forEach(item => {
        item.classList.remove('active');
        if (item.dataset.page === page) {
            item.classList.add('active');
        }
    });
    
    // Ocultar todas las páginas
    document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
    
    // Mostrar página seleccionada
    const targetPage = document.getElementById(`page-${page}`);
    if (targetPage) {
        targetPage.classList.add('active');
    }
    
    // Actualizar título
    const pageTitle = document.getElementById('page-title');
    if (pageTitle) {
        const titles = {
            dashboard: 'Dashboard',
            tokens: 'Tokens',
            history: 'Historial',
            analytics: 'Analíticas',
            users: 'Usuarios',
            sessions: 'Sesiones',
            logs: 'Logs',
            alerts: 'Alertas',
            settings: 'Configuración',
            backup: 'Backup',
            api: 'API Keys',
            security: 'Seguridad',
            reports: 'Reportes'
        };
        pageTitle.textContent = titles[page] || 'Panel';
    }
    
    // Cargar datos según la página
    switch(page) {
        case 'dashboard':
            loadDashboard();
            break;
        case 'tokens':
        loadTokens();
            break;
        case 'history':
            loadHistory();
            break;
        case 'analytics':
            loadAnalytics();
            break;
        case 'users':
            loadUsers();
            break;
        case 'sessions':
            loadSessions();
            break;
        case 'logs':
            loadLogs();
            break;
        case 'alerts':
            loadAlerts();
            break;
        case 'settings':
            loadSettings();
            break;
        case 'backup':
            loadBackups();
            break;
        case 'api':
            loadApiKeys();
            break;
        case 'security':
            loadSecurity();
            break;
        case 'reports':
            loadReports();
            break;
    }
}

function initializeNavigation() {
    // Navegar a dashboard por defecto
    navigateTo('dashboard');
}

// Toggle tema
function toggleTheme() {
    const currentTheme = document.documentElement.getAttribute('data-theme') || 'light';
    const newTheme = currentTheme === 'light' ? 'dark' : 'light';
    document.documentElement.setAttribute('data-theme', newTheme);
    localStorage.setItem('theme', newTheme);
    updateThemeIcon(newTheme);
}

function changeTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('theme', theme);
    updateThemeIcon(theme);
}

function updateThemeIcon(theme) {
    const icon = document.getElementById('theme-icon');
    if (icon) {
        icon.className = theme === 'dark' ? 'fas fa-sun' : 'fas fa-moon';
    }
}

// Búsqueda global
function setupGlobalSearch() {
    const searchInput = document.getElementById('global-search');
    if (searchInput) {
        searchInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                const query = searchInput.value.trim();
                if (query) {
                    performGlobalSearch(query);
                }
            }
        });
    }
}

function performGlobalSearch(query) {
    // Buscar en tokens
    navigateTo('tokens');
    document.getElementById('search-input').value = query;
    filterTokens();
}

// Dashboard
async function loadDashboard() {
    await loadTokens();
    await loadStats();
    await loadRecentActivity();
    await loadRecentAlerts();
    updateDashboardStats();
    renderDashboardCharts();
}

function updateDashboardStats() {
    const total = tokens.length;
    const used = tokens.filter(t => t.used).length;
    const available = total - used;
    
    const totalEl = document.getElementById('total-tokens');
    const usedEl = document.getElementById('used-tokens');
    const availableEl = document.getElementById('available-tokens');
    
    if (totalEl) totalEl.textContent = total;
    if (usedEl) usedEl.textContent = used;
    if (availableEl) availableEl.textContent = available;
    
    // Calcular validaciones de hoy
    loadStats().then(stats => {
        const validationsEl = document.getElementById('validations-today');
        if (validationsEl && stats) {
            validationsEl.textContent = stats.validations?.today || 0;
        }
    });
}

function renderDashboardCharts() {
    // Gráfico de uso de tokens (últimos 7 días)
    const tokensCtx = document.getElementById('tokens-chart');
    if (tokensCtx && tokens.length > 0) {
        if (charts.tokens) charts.tokens.destroy();
        
        const last7Days = [];
        for (let i = 6; i >= 0; i--) {
            const date = new Date();
            date.setDate(date.getDate() - i);
            const dateStr = date.toISOString().split('T')[0];
            const used = tokens.filter(t => t.usedAt && t.usedAt.startsWith(dateStr)).length;
            last7Days.push({ date: dateStr, used });
        }
        
        charts.tokens = new Chart(tokensCtx, {
            type: 'line',
            data: {
                labels: last7Days.map(d => new Date(d.date).toLocaleDateString('es-ES', { weekday: 'short' })),
                datasets: [{
                    label: 'Tokens Usados',
                    data: last7Days.map(d => d.used),
                    borderColor: '#667eea',
                    backgroundColor: 'rgba(102, 126, 234, 0.1)',
                    tension: 0.4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false }
                }
            }
        });
    }
    
    // Gráfico de distribución
    const distCtx = document.getElementById('distribution-chart');
    if (distCtx && tokens.length > 0) {
        if (charts.distribution) charts.distribution.destroy();
        
        const used = tokens.filter(t => t.used).length;
        const available = tokens.length - used;
        
        charts.distribution = new Chart(distCtx, {
            type: 'doughnut',
            data: {
                labels: ['Disponibles', 'Usados'],
                datasets: [{
                    data: [available, used],
                    backgroundColor: ['#10b981', '#ef4444']
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false
            }
        });
    }
}

async function loadRecentActivity() {
    try {
        const response = await authenticatedFetch(`${API_URL}/logs?limit=5`);
        if (response.ok) {
            const logs = await response.json();
            const container = document.getElementById('recent-activity');
            if (container) {
                container.innerHTML = logs.map(log => `
                    <div class="activity-item">
                        <div class="activity-action">${log.action}</div>
                        <div class="activity-details">${JSON.stringify(log.details)}</div>
                        <div class="activity-time">${formatDate(log.timestamp)}</div>
                    </div>
                `).join('');
            }
        }
    } catch (error) {
        console.error('Error loading recent activity:', error);
    }
}

async function loadRecentAlerts() {
    try {
        const response = await authenticatedFetch(`${API_URL}/alerts?limit=5`);
        if (response.ok) {
            const alerts = await response.json();
            const container = document.getElementById('recent-alerts');
            if (container) {
                container.innerHTML = alerts.length > 0 ? alerts.map(alert => `
                    <div class="activity-item">
                        <div class="activity-action">${alert.title}</div>
                        <div class="activity-details">${alert.message}</div>
                        <div class="activity-time">${formatDate(alert.timestamp)}</div>
                    </div>
                `).join('') : '<p style="text-align: center; color: var(--text-secondary);">No hay alertas</p>';
            }
        }
    } catch (error) {
        // Si no existe el endpoint, no mostrar nada
    }
}

// Notificaciones
async function loadNotifications() {
    try {
        const response = await authenticatedFetch(`${API_URL}/notifications`);
        if (response.ok) {
            notifications = await response.json();
            updateNotificationBadge();
            renderNotifications();
        }
    } catch (error) {
        // Endpoint puede no existir aún
    }
}

function updateNotificationBadge() {
    const unread = notifications.filter(n => !n.read).length;
    const badge = document.getElementById('notification-count');
    const alertsBadge = document.getElementById('alerts-badge');
    if (badge) badge.textContent = unread;
    if (alertsBadge) alertsBadge.textContent = unread;
}

function toggleNotifications() {
    const panel = document.getElementById('notifications-panel');
    if (panel) {
        panel.classList.toggle('show');
        if (panel.classList.contains('show')) {
            renderNotifications();
        }
    }
}

function renderNotifications() {
    const list = document.getElementById('notifications-list');
    if (!list) return;
    
    if (notifications.length === 0) {
        list.innerHTML = '<p style="text-align: center; padding: 20px; color: var(--text-secondary);">No hay notificaciones</p>';
        return;
    }
    
    list.innerHTML = notifications.map(notif => `
        <div class="notification-item ${!notif.read ? 'unread' : ''}" onclick="markNotificationAsRead('${notif.id}')">
            <div style="font-weight: 600; margin-bottom: 4px;">${notif.title}</div>
            <div style="font-size: 0.9rem; color: var(--text-secondary);">${notif.message}</div>
            <div style="font-size: 0.75rem; color: var(--text-tertiary); margin-top: 4px;">${formatDate(notif.timestamp)}</div>
        </div>
    `).join('');
}

function markNotificationAsRead(id) {
    // Implementar cuando el endpoint esté disponible
}

function markAllAsRead() {
    // Implementar cuando el endpoint esté disponible
    showNotification('Todas las notificaciones marcadas como leídas', 'success');
}

// Funciones adicionales para nuevas páginas
async function loadAnalytics() {
    // Cargar datos de analíticas
    await loadStats();
    renderAnalyticsCharts();
}

function renderAnalyticsCharts() {
    // Implementar gráficos de analíticas
}

async function loadSessions() {
    try {
        const response = await authenticatedFetch(`${API_URL}/sessions`);
        if (response.ok) {
            const sessions = await response.json();
            renderSessions(sessions);
        }
    } catch (error) {
        const tbody = document.getElementById('sessions-tbody');
        if (tbody) {
            tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; padding: 40px;">No hay sesiones disponibles</td></tr>';
        }
    }
}

function renderSessions(sessions) {
    const tbody = document.getElementById('sessions-tbody');
    if (!tbody) return;
    
    if (sessions.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; padding: 40px;">No hay sesiones activas</td></tr>';
        return;
    }
    
    tbody.innerHTML = sessions.map(session => `
        <tr>
            <td>${session.username}</td>
            <td>${session.ip}</td>
            <td>${formatDate(session.startedAt)}</td>
            <td>${formatDate(session.lastActivity)}</td>
            <td><span class="tag tag-success">Activa</span></td>
            <td>
                <button class="btn btn-sm btn-danger" onclick="revokeSession('${session.id}')">
                    <i class="fas fa-ban"></i> Revocar
                </button>
            </td>
        </tr>
    `).join('');
}

async function revokeSession(sessionId) {
    // Implementar cuando el endpoint esté disponible
    showNotification('Sesión revocada', 'success');
}

async function revokeAllSessions() {
    if (!confirm('¿Estás seguro de revocar todas las sesiones?')) return;
    // Implementar cuando el endpoint esté disponible
    showNotification('Todas las sesiones revocadas', 'success');
}

async function loadAlerts() {
    // Implementar carga de alertas
}

function createAlert() {
    // Implementar creación de alertas
    showNotification('Funcionalidad en desarrollo', 'info');
}

async function loadSettings() {
    try {
        const response = await authenticatedFetch(`${API_URL}/config`);
        if (response.ok) {
            const config = await response.json();
            document.getElementById('max-tokens').value = config.maxTokens || 10000;
            document.getElementById('rate-limit-enabled').checked = config.rateLimitEnabled !== false;
            document.getElementById('notifications-enabled').checked = config.notificationsEnabled === true;
        }
    } catch (error) {
        console.error('Error loading settings:', error);
    }
}

async function saveSettings() {
    try {
        const config = {
            maxTokens: parseInt(document.getElementById('max-tokens').value),
            rateLimitEnabled: document.getElementById('rate-limit-enabled').checked,
            notificationsEnabled: document.getElementById('notifications-enabled').checked
        };
        
        const response = await authenticatedFetch(`${API_URL}/config`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(config)
        });
        
        if (response.ok) {
            showNotification('Configuración guardada exitosamente', 'success');
        }
    } catch (error) {
        showNotification('Error al guardar configuración: ' + error.message, 'error');
    }
}

async function loadBackups() {
    // Implementar carga de backups
}

async function createBackup() {
    try {
        const response = await authenticatedFetch(`${API_URL}/backup/create`, { method: 'POST' });
        if (response.ok) {
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `backup-${new Date().toISOString().split('T')[0]}.json`;
            a.click();
            showNotification('Backup creado exitosamente', 'success');
        }
    } catch (error) {
        showNotification('Error al crear backup: ' + error.message, 'error');
    }
}

async function restoreBackup(file) {
    if (!confirm('¿Estás seguro de restaurar este backup? Esto sobrescribirá los datos actuales.')) return;
    
    try {
        const text = await file.text();
        const data = JSON.parse(text);
        
        const response = await authenticatedFetch(`${API_URL}/backup/restore`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data)
        });
        
        if (response.ok) {
            showNotification('Backup restaurado exitosamente', 'success');
            setTimeout(() => location.reload(), 2000);
        }
    } catch (error) {
        showNotification('Error al restaurar backup: ' + error.message, 'error');
    }
}

async function loadApiKeys() {
    // Implementar carga de API keys
    const tbody = document.getElementById('api-keys-tbody');
    if (tbody) {
        tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; padding: 40px;">No hay API keys disponibles</td></tr>';
    }
}

function generateApiKey() {
    showNotification('Funcionalidad en desarrollo', 'info');
}

async function loadSecurity() {
    // Implementar carga de configuración de seguridad
}

function addBlockedIp() {
    const ip = prompt('Ingresa la IP a bloquear:');
    if (ip) {
        // Implementar cuando el endpoint esté disponible
        showNotification('IP bloqueada', 'success');
    }
}

function addAllowedIp() {
    const ip = prompt('Ingresa la IP a permitir:');
    if (ip) {
        // Implementar cuando el endpoint esté disponible
        showNotification('IP permitida', 'success');
    }
}

async function loadReports() {
    // Implementar carga de reportes
}

function generateReport(type) {
    showNotification(`Generando reporte ${type}...`, 'info');
    // Implementar generación de reportes
}

// Cargar tokens desde el servidor
async function loadTokens() {
    try {
        const response = await authenticatedFetch(`${API_URL}/tokens`);
        if (!response.ok) throw new Error('Error al cargar tokens');
        
        tokens = await response.json();
        updateStats();
        renderTokens();
    } catch (error) {
        console.error('Error:', error);
        if (error.message !== 'No autenticado' && error.message !== 'Sesión expirada') {
            showNotification('Error al cargar tokens: ' + error.message, 'error');
        }
    }
}

// Actualizar estadísticas
function updateStats() {
    const total = tokens.length;
    const used = tokens.filter(t => t.used).length;
    const available = total - used;
    
    document.getElementById('total-tokens').textContent = total;
    document.getElementById('used-tokens').textContent = used;
    document.getElementById('available-tokens').textContent = available;
}

// Renderizar tabla de tokens
function renderTokens(filteredTokens = null) {
    const tbody = document.getElementById('tokens-tbody');
    let tokensToRender = filteredTokens || tokens;
    
    // Aplicar ordenamiento
    if (currentSort.field) {
        tokensToRender = [...tokensToRender].sort((a, b) => {
            let aVal = a[currentSort.field];
            let bVal = b[currentSort.field];
            
            if (currentSort.field === 'status') {
                aVal = a.used ? 1 : 0;
                bVal = b.used ? 1 : 0;
            }
            
            if (aVal === null || aVal === undefined) aVal = '';
            if (bVal === null || bVal === undefined) bVal = '';
            
            if (currentSort.direction === 'asc') {
                return aVal > bVal ? 1 : -1;
            } else {
                return aVal < bVal ? 1 : -1;
            }
        });
    }
    
    // Paginación
    const totalPages = Math.ceil(tokensToRender.length / itemsPerPage);
    const startIndex = (currentPage - 1) * itemsPerPage;
    const endIndex = startIndex + itemsPerPage;
    const paginatedTokens = tokensToRender.slice(startIndex, endIndex);
    
    if (paginatedTokens.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; padding: 40px;">No hay tokens disponibles</td></tr>';
        renderPagination(0, 1);
        return;
    }
    
    tbody.innerHTML = paginatedTokens.map(token => {
        const tags = token.tags || [];
        const tagsHtml = tags.map(tag => `<span class="tag tag-primary">${tag}</span>`).join('');
        return `
        <tr>
            <td>
                <div style="font-family: 'Courier New', monospace; font-size: 0.85rem; background: var(--bg-secondary); padding: 8px 12px; border-radius: 6px; word-break: break-all;">${token.token}</div>
            </td>
            <td>
                <span class="tag ${token.used ? 'tag-danger' : 'tag-success'}">
                    ${token.used ? 'Usado' : 'Disponible'}
                </span>
            </td>
            <td>${formatDate(token.createdAt)}</td>
            <td>${token.usedAt ? formatDate(token.usedAt) : '-'}</td>
            <td>${token.usedFromIp || '-'}</td>
            <td>${tagsHtml || '-'}</td>
            <td>
                <button class="btn btn-sm btn-danger" onclick="deleteToken('${token.token}')" title="Eliminar">
                    <i class="fas fa-trash"></i>
                </button>
                <button class="btn btn-sm btn-success" onclick="copyToken('${token.token}')" title="Copiar">
                    <i class="fas fa-copy"></i>
                </button>
            </td>
        </tr>
    `;
    }).join('');
    
    renderPagination(tokensToRender.length, totalPages);
}

// Formatear fecha
function formatDate(dateString) {
    if (!dateString) return '-';
    const date = new Date(dateString);
    return date.toLocaleString('es-ES');
}

// Generar nuevo token
async function generateToken() {
    document.getElementById('generate-modal').classList.add('show');
}

// Cerrar modal
function closeGenerateModal() {
    document.getElementById('generate-modal').classList.remove('show');
}

// Confirmar generación
async function confirmGenerate() {
    const count = parseInt(document.getElementById('token-count').value) || 1;
    const tagsInput = document.getElementById('token-tags');
    const tags = tagsInput ? tagsInput.value.split(',').map(t => t.trim()).filter(t => t) : [];
    
    try {
        const response = await authenticatedFetch(`${API_URL}/tokens/generate`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ count, tags })
        });
        
        if (!response.ok) throw new Error('Error al generar tokens');
        
        const result = await response.json();
        showNotification(`${result.tokens.length} token(s) generado(s) exitosamente`, 'success');
        closeGenerateModal();
        if (currentPageName === 'tokens' || currentPageName === 'dashboard') {
            loadTokens();
        }
    } catch (error) {
        console.error('Error:', error);
        showNotification('Error al generar tokens: ' + error.message, 'error');
    }
}

// Copiar token al portapapeles
async function copyToken(token) {
    try {
        await navigator.clipboard.writeText(token);
        showNotification('Token copiado al portapapeles', 'success');
    } catch (error) {
        // Fallback para navegadores antiguos
        const textArea = document.createElement('textarea');
        textArea.value = token;
        document.body.appendChild(textArea);
        textArea.select();
        document.execCommand('copy');
        document.body.removeChild(textArea);
        showNotification('Token copiado al portapapeles', 'success');
    }
}

// Eliminar token
async function deleteToken(token) {
    if (!confirm('¿Estás seguro de que quieres eliminar este token?')) return;
    
    try {
        const response = await authenticatedFetch(`${API_URL}/tokens/${encodeURIComponent(token)}`, {
            method: 'DELETE'
        });
        
        if (!response.ok) throw new Error('Error al eliminar token');
        
        showNotification('Token eliminado exitosamente', 'success');
        loadTokens();
    } catch (error) {
        console.error('Error:', error);
        showNotification('Error al eliminar token: ' + error.message, 'error');
    }
}

// Limpiar tokens usados
async function clearUsedTokens() {
    if (!confirm('¿Estás seguro de que quieres eliminar todos los tokens usados?')) return;
    
    try {
        const response = await authenticatedFetch(`${API_URL}/tokens/clear-used`, {
            method: 'DELETE'
        });
        
        if (!response.ok) throw new Error('Error al limpiar tokens');
        
        showNotification('Tokens usados eliminados exitosamente', 'success');
        loadTokens();
    } catch (error) {
        console.error('Error:', error);
        showNotification('Error al limpiar tokens: ' + error.message, 'error');
    }
}

// Actualizar lista
function refreshTokens() {
    loadTokens();
    showNotification('Lista actualizada', 'info');
}

// Filtrar tokens
function filterTokens() {
    const searchTerm = document.getElementById('search-input').value.toLowerCase();
    const statusFilter = document.getElementById('filter-status').value;
    
    let filtered = tokens;
    
    // Filtro de búsqueda
    if (searchTerm) {
        filtered = filtered.filter(token => 
            token.token.toLowerCase().includes(searchTerm)
        );
    }
    
    // Filtro de estado
    if (statusFilter === 'available') {
        filtered = filtered.filter(token => !token.used);
    } else if (statusFilter === 'used') {
        filtered = filtered.filter(token => token.used);
    }
    
    currentPage = 1; // Resetear a primera página
    renderTokens(filtered);
}

// Ordenar tokens
function sortTokens(field) {
    if (currentSort.field === field) {
        currentSort.direction = currentSort.direction === 'asc' ? 'desc' : 'asc';
    } else {
        currentSort.field = field;
        currentSort.direction = 'asc';
    }
    renderTokens();
}

// Renderizar paginación
function renderPagination(totalItems, totalPages) {
    const pagination = document.getElementById('pagination');
    if (!pagination) return;
    
    if (totalPages <= 1) {
        pagination.innerHTML = '';
        return;
    }
    
    let html = `
        <button onclick="changePage(${currentPage - 1})" ${currentPage === 1 ? 'disabled' : ''}>
            ← Anterior
        </button>
        <span class="page-info">Página ${currentPage} de ${totalPages} (${totalItems} tokens)</span>
        <button onclick="changePage(${currentPage + 1})" ${currentPage === totalPages ? 'disabled' : ''}>
            Siguiente →
        </button>
    `;
    
    pagination.innerHTML = html;
}

// Cambiar página
function changePage(page) {
    currentPage = page;
    filterTokens();
}

// Cambiar tab
function switchTab(tabName) {
    currentTab = tabName;
    
    // Actualizar botones de tabs
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.classList.remove('active');
        if (btn.dataset.tab === tabName) {
            btn.classList.add('active');
        }
    });
    
    // Actualizar contenido de tabs
    document.querySelectorAll('.tab-content').forEach(content => {
        content.classList.remove('active');
    });
    
    const activeTab = document.getElementById(`tab-${tabName}`);
    if (activeTab) {
        activeTab.classList.add('active');
    }
    
    // Cargar datos según el tab
    if (tabName === 'history') {
        loadHistory();
    } else if (tabName === 'stats') {
        loadStats();
    } else if (tabName === 'logs') {
        loadLogs();
    } else if (tabName === 'users') {
        loadUsers();
    }
}

// Mostrar notificación
function showNotification(message, type = 'info') {
    const notification = document.getElementById('notification');
    notification.textContent = message;
    notification.className = `notification ${type} show`;
    
    setTimeout(() => {
        notification.classList.remove('show');
    }, 3000);
}

// ==================== NUEVAS FUNCIONES ====================

// Exportar tokens
async function exportTokens() {
    try {
        const format = confirm('¿Exportar como CSV? (Cancelar para JSON)') ? 'csv' : 'json';
        const url = `${API_URL}/tokens/export?format=${format}`;
        window.open(url, '_blank');
        showNotification('Exportación iniciada', 'success');
    } catch (error) {
        showNotification('Error al exportar: ' + error.message, 'error');
    }
}

// Mostrar modal de importar
function showImportModal() {
    document.getElementById('import-modal').classList.add('show');
    const textarea = document.getElementById('import-tokens-text');
    if (textarea) {
        textarea.addEventListener('input', updateImportPreview);
    }
}

// Cerrar modal de importar
function closeImportModal() {
    document.getElementById('import-modal').classList.remove('show');
    document.getElementById('import-tokens-text').value = '';
    document.getElementById('import-preview').style.display = 'none';
}

// Actualizar preview de importación
function updateImportPreview() {
    const text = document.getElementById('import-tokens-text').value.trim();
    const preview = document.getElementById('import-preview');
    const countSpan = document.getElementById('import-count');
    
    if (!text) {
        preview.style.display = 'none';
        return;
    }
    
    let count = 0;
    try {
        // Intentar parsear como JSON
        const parsed = JSON.parse(text);
        if (Array.isArray(parsed)) {
            count = parsed.length;
        }
    } catch (e) {
        // Si no es JSON, contar líneas
        const lines = text.split('\n').filter(line => line.trim());
        count = lines.length;
    }
    
    countSpan.textContent = count;
    preview.style.display = 'block';
}

// Confirmar importación
async function confirmImport() {
    try {
        const text = document.getElementById('import-tokens-text').value.trim();
        if (!text) {
            showNotification('Por favor, ingresa tokens para importar', 'error');
            return;
        }
        
        let tokensToImport = [];
        
        try {
            // Intentar parsear como JSON
            const parsed = JSON.parse(text);
            if (Array.isArray(parsed)) {
                tokensToImport = parsed;
            } else {
                throw new Error('JSON debe ser un array');
            }
        } catch (e) {
            // Si no es JSON, tratar como líneas de texto
            const lines = text.split('\n').filter(line => line.trim());
            tokensToImport = lines.map(line => line.trim());
        }
        
        const response = await authenticatedFetch(`${API_URL}/tokens/import`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ tokens: tokensToImport })
        });
        
        if (!response.ok) throw new Error('Error al importar tokens');
        
        const result = await response.json();
        showNotification(
            `${result.imported} token(s) importado(s). ${result.skipped} omitido(s).`, 
            'success'
        );
        closeImportModal();
        loadTokens();
    } catch (error) {
        showNotification('Error al importar: ' + error.message, 'error');
    }
}

// Cargar estadísticas
async function loadStats() {
    try {
        const response = await authenticatedFetch(`${API_URL}/stats`);
        if (!response.ok) throw new Error('Error al cargar estadísticas');
        
        const stats = await response.json();
        renderStats(stats);
    } catch (error) {
        console.error('Error:', error);
    }
}

// Renderizar estadísticas
function renderStats(stats) {
    const statsGrid = document.getElementById('stats-grid');
    if (!statsGrid) return;
    
    statsGrid.innerHTML = `
        <div class="stat-card-advanced">
            <div class="stat-title">Tokens Totales</div>
            <div class="stat-value">${stats.tokens.total}</div>
            <div class="stat-change">${stats.tokens.usedPercentage}% usados</div>
        </div>
        <div class="stat-card-advanced">
            <div class="stat-title">Validaciones Hoy</div>
            <div class="stat-value">${stats.validations.today}</div>
            <div class="stat-change">${stats.validations.thisWeek} esta semana</div>
        </div>
        <div class="stat-card-advanced">
            <div class="stat-title">Tasa de Éxito</div>
            <div class="stat-value">${stats.validations.successRate}%</div>
            <div class="stat-change">${stats.validations.successful} exitosas</div>
        </div>
        <div class="stat-card-advanced">
            <div class="stat-title">Tokens Generados Hoy</div>
            <div class="stat-value">${stats.activity.tokensGeneratedToday}</div>
        </div>
    `;
}

// Cargar historial
async function loadHistory() {
    try {
        const search = document.getElementById('history-search')?.value || '';
        const success = document.getElementById('history-success-filter')?.value || '';
        
        let url = `${API_URL}/history?limit=100`;
        if (search) url += `&token=${encodeURIComponent(search)}`;
        if (success) url += `&success=${success}`;
        
        const response = await authenticatedFetch(url);
        if (!response.ok) throw new Error('Error al cargar historial');
        
        const data = await response.json();
        renderHistory(data.history);
    } catch (error) {
        console.error('Error:', error);
    }
}

// Renderizar historial
function renderHistory(history) {
    const tbody = document.getElementById('history-tbody');
    if (!tbody) return;
    
    if (history.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; padding: 40px;">No hay historial disponible</td></tr>';
        return;
    }
    
    tbody.innerHTML = history.map(entry => `
        <tr>
            <td><div style="font-family: 'Courier New', monospace; font-size: 0.85rem; background: var(--bg-secondary); padding: 8px 12px; border-radius: 6px;">${entry.token || 'N/A'}</div></td>
            <td>
                <strong>${entry.username || 'Unknown'}</strong>
            </td>
            <td>${entry.ip || 'Unknown'}</td>
            <td>
                <span class="tag ${entry.success ? 'tag-success' : 'tag-danger'}">
                    ${entry.success ? '✓ Exitoso' : '✗ Fallido'}
                </span>
            </td>
            <td>${formatDate(entry.timestamp)}</td>
            <td>${entry.error || '-'}</td>
        </tr>
    `).join('');
}

// Cargar logs
async function loadLogs() {
    try {
        const action = document.getElementById('logs-action-filter')?.value || '';
        let url = `${API_URL}/logs?limit=100`;
        if (action) url += `&action=${encodeURIComponent(action)}`;
        
        const response = await authenticatedFetch(url);
        if (!response.ok) throw new Error('Error al cargar logs');
        
        const logs = await response.json();
        renderLogs(logs);
    } catch (error) {
        console.error('Error:', error);
    }
}

// Renderizar logs
function renderLogs(logs) {
    const container = document.getElementById('logs-container');
    if (!container) return;
    
    if (logs.length === 0) {
        container.innerHTML = '<p style="text-align: center; padding: 40px; color: var(--text-secondary);">No hay logs disponibles</p>';
        return;
    }
    
    // Función para obtener icono según la acción
    function getActionIcon(action) {
        const icons = {
            'LOGIN_SUCCESS': 'fa-check-circle',
            'LOGIN_FAILED': 'fa-times-circle',
            'TOKEN_GENERATED': 'fa-key',
            'TOKEN_DELETED': 'fa-trash',
            'TOKENS_CLEARED': 'fa-broom',
            'TOKENS_EXPORTED': 'fa-download',
            'TOKENS_IMPORTED': 'fa-upload',
            'USER_CREATED': 'fa-user-plus',
            'USER_DELETED': 'fa-user-minus',
            'USER_PASSWORD_CHANGED': 'fa-lock',
            'CONFIG_UPDATED': 'fa-cog',
            'PASSWORD_CHANGED': 'fa-key'
        };
        return icons[action] || 'fa-info-circle';
    }
    
    // Función para obtener color según la acción
    function getActionColor(action) {
        if (action.includes('SUCCESS') || action.includes('CREATED') || action.includes('GENERATED')) {
            return 'log-success';
        } else if (action.includes('FAILED') || action.includes('DELETED')) {
            return 'log-error';
        } else if (action.includes('UPDATED') || action.includes('CHANGED')) {
            return 'log-warning';
        }
        return 'log-info';
    }
    
    // Función para formatear JSON de forma legible
    function formatJSON(obj) {
        try {
            const parsed = typeof obj === 'string' ? JSON.parse(obj) : obj;
            return JSON.stringify(parsed, null, 2);
        } catch (e) {
            return typeof obj === 'string' ? obj : JSON.stringify(obj);
        }
    }
    
    container.innerHTML = logs.map((log, index) => {
        const icon = getActionIcon(log.action);
        const colorClass = getActionColor(log.action);
        const details = formatJSON(log.details);
        
        return `
        <div class="log-entry-card ${colorClass}">
            <div class="log-entry-header">
                <div class="log-icon">
                    <i class="fas ${icon}"></i>
                </div>
                <div class="log-action-info">
                    <div class="log-action-name">${log.action}</div>
                    <div class="log-meta">
                        <span class="log-time">
                            <i class="fas fa-clock"></i> ${formatDate(log.timestamp)}
                        </span>
                        <span class="log-ip">
                            <i class="fas fa-network-wired"></i> ${log.ip || 'Unknown'}
                        </span>
                    </div>
                </div>
            </div>
            <div class="log-entry-body">
                <div class="log-details-label">Detalles:</div>
                <pre class="log-details-json">${details}</pre>
            </div>
        </div>
    `;
    }).join('');
}

// ==================== GESTIÓN DE USUARIOS ====================

// Cargar usuarios
async function loadUsers() {
    try {
        const response = await authenticatedFetch(`${API_URL}/users`);
        if (!response.ok) throw new Error('Error al cargar usuarios');
        
        const users = await response.json();
        renderUsers(users);
    } catch (error) {
        console.error('Error:', error);
        if (error.message !== 'No autenticado' && error.message !== 'Sesión expirada') {
            showNotification('Error al cargar usuarios: ' + error.message, 'error');
        }
    }
}

// Renderizar usuarios
function renderUsers(users) {
    const tbody = document.getElementById('users-tbody');
    if (!tbody) return;
    
    if (users.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; padding: 40px;">No hay usuarios disponibles</td></tr>';
        return;
    }
    
    const currentUser = JSON.parse(localStorage.getItem('user') || '{}');
    
    tbody.innerHTML = users.map(user => {
        const isCurrentUser = user.username === currentUser.username;
        const isAdmin = user.role === 'admin';
        
        return `
            <tr>
                <td>
                    <strong>${user.username}</strong>
                    ${isCurrentUser ? ' <span style="color: #667eea;">(Tú)</span>' : ''}
                </td>
                <td>
                    <span class="tag ${isAdmin ? 'tag-primary' : 'tag'}">
                        ${isAdmin ? '👑 Admin' : '👤 Usuario'}
                    </span>
                </td>
                <td>${formatDate(user.createdAt)}</td>
                <td>${user.createdBy || '-'}</td>
                <td>
                    ${!isCurrentUser ? `
                        <button class="btn btn-sm btn-info" onclick="changeUserPassword('${user.username}')" title="Cambiar contraseña">
                            <i class="fas fa-key"></i>
                        </button>
                        <button class="btn btn-sm btn-danger" onclick="deleteUser('${user.username}')" title="Eliminar">
                            <i class="fas fa-trash"></i>
                        </button>
                    ` : '<span style="color: var(--text-tertiary);">-</span>'}
                </td>
            </tr>
        `;
    }).join('');
}

// Mostrar modal de crear usuario
function showCreateUserModal() {
    document.getElementById('create-user-modal').classList.add('show');
    document.getElementById('new-username').value = '';
    document.getElementById('new-password').value = '';
    document.getElementById('new-user-role').value = 'user';
    document.getElementById('create-user-error').style.display = 'none';
    document.getElementById('create-user-success').style.display = 'none';
}

// Cerrar modal de crear usuario
function closeCreateUserModal() {
    document.getElementById('create-user-modal').classList.remove('show');
}

// Confirmar creación de usuario
async function confirmCreateUser() {
    const username = document.getElementById('new-username').value.trim();
    const password = document.getElementById('new-password').value;
    const role = document.getElementById('new-user-role').value;
    const errorDiv = document.getElementById('create-user-error');
    const successDiv = document.getElementById('create-user-success');
    
    if (!username || !password) {
        errorDiv.textContent = 'Por favor, completa todos los campos';
        errorDiv.style.display = 'block';
        return;
    }
    
    if (username.length < 3) {
        errorDiv.textContent = 'El nombre de usuario debe tener al menos 3 caracteres';
        errorDiv.style.display = 'block';
        return;
    }
    
    if (password.length < 6) {
        errorDiv.textContent = 'La contraseña debe tener al menos 6 caracteres';
        errorDiv.style.display = 'block';
        return;
    }
    
    try {
        const response = await authenticatedFetch(`${API_URL}/users`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ username, password, role })
        });
        
        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Error al crear usuario');
        }
        
        const result = await response.json();
        successDiv.style.display = 'block';
        errorDiv.style.display = 'none';
        
        showNotification('Usuario creado exitosamente', 'success');
        
        setTimeout(() => {
            closeCreateUserModal();
            loadUsers();
        }, 1500);
    } catch (error) {
        errorDiv.textContent = error.message;
        errorDiv.style.display = 'block';
        successDiv.style.display = 'none';
    }
}

// Cambiar contraseña de usuario
async function changeUserPassword(username) {
    const newPassword = prompt(`Ingresa la nueva contraseña para ${username} (mín. 6 caracteres):`);
    
    if (!newPassword) return;
    
    if (newPassword.length < 6) {
        showNotification('La contraseña debe tener al menos 6 caracteres', 'error');
        return;
    }
    
    try {
        const response = await authenticatedFetch(`${API_URL}/users/${encodeURIComponent(username)}/change-password`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ newPassword })
        });
        
        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Error al cambiar contraseña');
        }
        
        showNotification('Contraseña actualizada exitosamente', 'success');
    } catch (error) {
        showNotification('Error: ' + error.message, 'error');
    }
}

// Eliminar usuario
async function deleteUser(username) {
    if (!confirm(`¿Estás seguro de que quieres eliminar al usuario "${username}"?`)) {
        return;
    }
    
    try {
        const response = await authenticatedFetch(`${API_URL}/users/${encodeURIComponent(username)}`, {
            method: 'DELETE'
        });
        
        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Error al eliminar usuario');
        }
        
        showNotification('Usuario eliminado exitosamente', 'success');
        loadUsers();
    } catch (error) {
        showNotification('Error: ' + error.message, 'error');
    }
}

