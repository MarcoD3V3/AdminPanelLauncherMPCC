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

// Notificaciones (usando alertas)
async function loadNotifications() {
    try {
        const response = await authenticatedFetch(`${API_URL}/alerts`);
        if (response.ok) {
            notifications = await response.json();
            updateNotificationBadge();
            renderNotifications();
        }
    } catch (error) {
        // Si falla, usar array vacío
        notifications = [];
        updateNotificationBadge();
    }
}

function updateNotificationBadge() {
    const unread = notifications.length; // Todas las alertas no leídas
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
            <div style="font-weight: 600; margin-bottom: 4px;">${notif.title || 'Alerta'}</div>
            <div style="font-size: 0.9rem; color: var(--text-secondary);">${notif.message}</div>
            <div style="font-size: 0.75rem; color: var(--text-tertiary); margin-top: 4px;">${formatDate(notif.createdAt || notif.timestamp)}</div>
        </div>
    `).join('');
}

async function markNotificationAsRead(id) {
    try {
        const response = await authenticatedFetch(`${API_URL}/alerts/${id}/read`, {
            method: 'POST'
        });
        if (response.ok) {
            loadNotifications();
        }
    } catch (error) {
        console.error('Error marking notification as read:', error);
    }
}

async function markAllAsRead() {
    try {
        for (const notif of notifications) {
            await markNotificationAsRead(notif.id);
        }
        showNotification('Todas las notificaciones marcadas como leídas', 'success');
        loadNotifications();
    } catch (error) {
        showNotification('Error al marcar notificaciones', 'error');
    }
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
        } else {
            throw new Error('Error al cargar sesiones');
        }
    } catch (error) {
        console.error('Error loading sessions:', error);
        const tbody = document.getElementById('sessions-tbody');
        if (tbody) {
            tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; padding: 40px; color: var(--text-secondary);">No hay sesiones activas</td></tr>';
        }
    }
}

function renderSessions(sessions) {
    const tbody = document.getElementById('sessions-tbody');
    if (!tbody) return;
    
    if (sessions.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; padding: 40px; color: var(--text-secondary);">No hay sesiones activas</td></tr>';
        return;
    }
    
    tbody.innerHTML = sessions.map(session => `
        <tr>
            <td><strong>${session.username}</strong></td>
            <td>${session.ip}</td>
            <td>${formatDate(session.startedAt)}</td>
            <td>${formatDate(session.lastActivity)}</td>
            <td><span class="tag tag-success">Activa</span></td>
            <td>
                <button class="btn btn-sm btn-primary" onclick="sendAlertToUser('${session.username}')" title="Enviar alerta">
                    <i class="fas fa-bell"></i>
                </button>
                <button class="btn btn-sm btn-danger" onclick="revokeSession('${session.id}')" title="Revocar sesión">
                    <i class="fas fa-ban"></i>
                </button>
            </td>
        </tr>
    `).join('');
}

async function revokeSession(sessionId) {
    if (!confirm('¿Estás seguro de revocar esta sesión?')) return;
    
    try {
        const response = await authenticatedFetch(`${API_URL}/sessions/${sessionId}`, {
            method: 'DELETE'
        });
        
        if (response.ok) {
            showNotification('Sesión revocada exitosamente', 'success');
            loadSessions();
        } else {
            throw new Error('Error al revocar sesión');
        }
    } catch (error) {
        showNotification('Error al revocar sesión: ' + error.message, 'error');
    }
}

async function revokeAllSessions() {
    if (!confirm('¿Estás seguro de revocar todas las sesiones? Esto cerrará la sesión de todos los usuarios.')) return;
    
    try {
        const response = await authenticatedFetch(`${API_URL}/sessions`, {
            method: 'DELETE'
        });
        
        if (response.ok) {
            showNotification('Todas las sesiones revocadas exitosamente', 'success');
            loadSessions();
        } else {
            throw new Error('Error al revocar sesiones');
        }
    } catch (error) {
        showNotification('Error al revocar sesiones: ' + error.message, 'error');
    }
}

async function loadAlerts() {
    try {
        const response = await authenticatedFetch(`${API_URL}/alerts/all`);
        if (response.ok) {
            const alerts = await response.json();
            renderAlerts(alerts);
        }
    } catch (error) {
        console.error('Error loading alerts:', error);
        const container = document.getElementById('alerts-container');
        if (container) {
            container.innerHTML = '<p style="text-align: center; padding: 40px; color: var(--text-secondary);">No hay alertas disponibles</p>';
        }
    }
}

// Función para obtener el icono según la categoría
function getCategoryIcon(category) {
    const icons = {
        'alert': 'fa-bell',
        'maintenance': 'fa-tools',
        'update': 'fa-download',
        'event': 'fa-calendar-star',
        'reward': 'fa-gift',
        'restriction': 'fa-ban',
        'config': 'fa-cog',
        'achievement': 'fa-trophy',
        'promotion': 'fa-tag',
        'reminder': 'fa-clock',
        'command': 'fa-terminal'
    };
    return icons[category] || 'fa-bell';
}

// Función para obtener el nombre de la categoría
function getCategoryName(category) {
    const names = {
        'alert': 'Alerta General',
        'maintenance': 'Mantenimiento',
        'update': 'Actualización',
        'event': 'Evento Especial',
        'reward': 'Recompensa',
        'restriction': 'Restricción',
        'config': 'Configuración',
        'achievement': 'Logro',
        'promotion': 'Promoción',
        'reminder': 'Recordatorio',
        'command': 'Comando'
    };
    return names[category] || 'Alerta';
}

// Función para formatear metadata visualmente en el modal de detalles
function formatMetadataVisual(metadata, category) {
    if (!metadata || Object.keys(metadata).length === 0) {
        return '<div class="metadata-empty"><i class="fas fa-info-circle"></i> No hay metadata adicional</div>';
    }
    
    const fieldConfig = {
        'priority': { icon: 'fa-flag', label: 'Prioridad', type: 'badge' },
        'startDate': { icon: 'fa-calendar-plus', label: 'Fecha de Inicio', type: 'date' },
        'endDate': { icon: 'fa-calendar-check', label: 'Fecha de Fin', type: 'date' },
        'serverStatus': { icon: 'fa-server', label: 'Estado del Servidor', type: 'status' },
        'version': { icon: 'fa-code-branch', label: 'Versión', type: 'text' },
        'forceUpdate': { icon: 'fa-exclamation-triangle', label: 'Actualización Forzada', type: 'boolean' },
        'downloadUrl': { icon: 'fa-link', label: 'URL de Descarga', type: 'link' },
        'eventDate': { icon: 'fa-calendar', label: 'Fecha del Evento', type: 'date' },
        'duration': { icon: 'fa-hourglass-half', label: 'Duración', type: 'text' },
        'eventType': { icon: 'fa-star', label: 'Tipo de Evento', type: 'text' },
        'rewardType': { icon: 'fa-gift', label: 'Tipo de Recompensa', type: 'text' },
        'rewardValue': { icon: 'fa-coins', label: 'Valor de Recompensa', type: 'value' },
        'rewardCode': { icon: 'fa-ticket-alt', label: 'Código de Recompensa', type: 'code' },
        'restrictionType': { icon: 'fa-ban', label: 'Tipo de Restricción', type: 'text' },
        'reason': { icon: 'fa-comment', label: 'Razón', type: 'text' },
        'serverIp': { icon: 'fa-network-wired', label: 'IP del Servidor', type: 'text' },
        'serverPort': { icon: 'fa-plug', label: 'Puerto del Servidor', type: 'text' },
        'mcVersion': { icon: 'fa-cube', label: 'Versión de Minecraft', type: 'text' },
        'autoApply': { icon: 'fa-magic', label: 'Aplicar Automáticamente', type: 'boolean' },
        'achievementName': { icon: 'fa-trophy', label: 'Nombre del Logro', type: 'text' },
        'level': { icon: 'fa-level-up-alt', label: 'Nivel', type: 'number' },
        'points': { icon: 'fa-star', label: 'Puntos', type: 'number' },
        'promoType': { icon: 'fa-tag', label: 'Tipo de Promoción', type: 'text' },
        'promoCode': { icon: 'fa-ticket-alt', label: 'Código Promocional', type: 'code' },
        'discount': { icon: 'fa-percent', label: 'Descuento', type: 'percent' },
        'expiresAt': { icon: 'fa-calendar-times', label: 'Expira', type: 'date' },
        'reminderDate': { icon: 'fa-bell', label: 'Fecha de Recordatorio', type: 'date' },
        'reminderType': { icon: 'fa-list', label: 'Tipo de Recordatorio', type: 'text' },
        'command': { icon: 'fa-terminal', label: 'Comando', type: 'code' },
        'params': { icon: 'fa-cogs', label: 'Parámetros', type: 'json' }
    };
    
    let html = '<div class="metadata-visual-container">';
    
    // Ordenar campos según importancia
    const orderedKeys = Object.keys(metadata).sort((a, b) => {
        const priority = ['priority', 'version', 'rewardCode', 'promoCode', 'command'];
        const aIndex = priority.indexOf(a);
        const bIndex = priority.indexOf(b);
        if (aIndex !== -1 && bIndex !== -1) return aIndex - bIndex;
        if (aIndex !== -1) return -1;
        if (bIndex !== -1) return 1;
        return a.localeCompare(b);
    });
    
    orderedKeys.forEach(key => {
        const value = metadata[key];
        const config = fieldConfig[key] || { icon: 'fa-circle', label: key, type: 'text' };
        
        let displayValue = '';
        let valueClass = 'metadata-value';
        
        switch(config.type) {
            case 'badge':
                const priorityLabels = { 'low': 'Baja', 'normal': 'Normal', 'high': 'Alta', 'urgent': 'Urgente' };
                const priorityClass = value === 'urgent' ? 'badge-urgent' : 
                                     value === 'high' ? 'badge-high' : 
                                     value === 'low' ? 'badge-low' : 'badge-normal';
                displayValue = `<span class="metadata-badge ${priorityClass}">${priorityLabels[value] || value}</span>`;
                break;
            case 'boolean':
                displayValue = value ? 
                    '<span class="metadata-badge badge-success"><i class="fas fa-check"></i> Sí</span>' : 
                    '<span class="metadata-badge badge-error"><i class="fas fa-times"></i> No</span>';
                break;
            case 'date':
                displayValue = `<span class="metadata-date">${formatDate(value)}</span>`;
                break;
            case 'link':
                displayValue = `<a href="${value}" target="_blank" class="metadata-link"><i class="fas fa-external-link-alt"></i> ${value}</a>`;
                break;
            case 'code':
                displayValue = `<span class="metadata-code">${value}</span>`;
                break;
            case 'value':
                displayValue = `<span class="metadata-value-highlight">${value}</span>`;
                break;
            case 'percent':
                displayValue = `<span class="metadata-percent">${value}%</span>`;
                break;
            case 'number':
                displayValue = `<span class="metadata-number">${value}</span>`;
                break;
            case 'status':
                const statusLabels = { 'online': 'En Línea', 'offline': 'Desconectado', 'maintenance': 'Mantenimiento' };
                const statusClass = value === 'online' ? 'badge-success' : 
                                   value === 'offline' ? 'badge-error' : 'badge-warning';
                displayValue = `<span class="metadata-badge ${statusClass}">${statusLabels[value] || value}</span>`;
                break;
            case 'json':
                displayValue = `<pre class="metadata-json">${JSON.stringify(value, null, 2)}</pre>`;
                break;
            default:
                displayValue = `<span class="metadata-text">${value}</span>`;
        }
        
        html += `
            <div class="metadata-field">
                <div class="metadata-label">
                    <i class="fas ${config.icon}"></i>
                    <span>${config.label}</span>
                </div>
                <div class="metadata-content">
                    ${displayValue}
                </div>
            </div>
        `;
    });
    
    html += '</div>';
    return html;
}

// Función para formatear metadata según la categoría
function formatAlertMetadata(alert) {
    if (!alert.metadata) return '';
    
    const meta = alert.metadata;
    let html = '<div class="alert-metadata">';
    
    switch(alert.category) {
        case 'maintenance':
            if (meta.startDate) html += `<div><i class="fas fa-calendar"></i> Inicio: ${formatDate(meta.startDate)}</div>`;
            if (meta.endDate) html += `<div><i class="fas fa-calendar-check"></i> Fin: ${formatDate(meta.endDate)}</div>`;
            if (meta.serverStatus) html += `<div><i class="fas fa-server"></i> Estado: ${meta.serverStatus}</div>`;
            break;
        case 'update':
            if (meta.version) html += `<div><i class="fas fa-code-branch"></i> Versión: ${meta.version}</div>`;
            if (meta.forceUpdate) html += `<div><i class="fas fa-exclamation-triangle"></i> Actualización Forzada</div>`;
            if (meta.downloadUrl) html += `<div><i class="fas fa-link"></i> <a href="${meta.downloadUrl}" target="_blank">Descargar</a></div>`;
            break;
        case 'event':
            if (meta.eventDate) html += `<div><i class="fas fa-calendar"></i> Fecha: ${formatDate(meta.eventDate)}</div>`;
            if (meta.duration) html += `<div><i class="fas fa-hourglass-half"></i> Duración: ${meta.duration}h</div>`;
            if (meta.eventType) html += `<div><i class="fas fa-star"></i> Tipo: ${meta.eventType}</div>`;
            break;
        case 'reward':
            if (meta.rewardType) html += `<div><i class="fas fa-gift"></i> Tipo: ${meta.rewardType}</div>`;
            if (meta.rewardValue) html += `<div><i class="fas fa-coins"></i> Valor: ${meta.rewardValue}</div>`;
            if (meta.rewardCode) html += `<div><i class="fas fa-ticket-alt"></i> Código: <strong>${meta.rewardCode}</strong></div>`;
            break;
        case 'restriction':
            if (meta.restrictionType) html += `<div><i class="fas fa-shield-alt"></i> Tipo: ${meta.restrictionType}</div>`;
            if (meta.duration !== undefined) html += `<div><i class="fas fa-clock"></i> Duración: ${meta.duration === 0 ? 'Permanente' : meta.duration + ' días'}</div>`;
            if (meta.reason) html += `<div><i class="fas fa-info-circle"></i> Razón: ${meta.reason}</div>`;
            break;
        case 'config':
            if (meta.serverIp) html += `<div><i class="fas fa-network-wired"></i> IP: ${meta.serverIp}</div>`;
            if (meta.serverPort) html += `<div><i class="fas fa-plug"></i> Puerto: ${meta.serverPort}</div>`;
            if (meta.mcVersion) html += `<div><i class="fas fa-cube"></i> Versión MC: ${meta.mcVersion}</div>`;
            if (meta.autoApply) html += `<div><i class="fas fa-magic"></i> Aplicación Automática</div>`;
            break;
        case 'achievement':
            if (meta.achievementName) html += `<div><i class="fas fa-trophy"></i> Logro: ${meta.achievementName}</div>`;
            if (meta.level) html += `<div><i class="fas fa-level-up-alt"></i> ${meta.level}</div>`;
            if (meta.points) html += `<div><i class="fas fa-star"></i> Puntos: ${meta.points}</div>`;
            break;
        case 'promotion':
            if (meta.promoType) html += `<div><i class="fas fa-tag"></i> Tipo: ${meta.promoType}</div>`;
            if (meta.promoCode) html += `<div><i class="fas fa-ticket-alt"></i> Código: <strong>${meta.promoCode}</strong></div>`;
            if (meta.discount) html += `<div><i class="fas fa-percent"></i> Descuento: ${meta.discount}%</div>`;
            if (meta.expiresAt) html += `<div><i class="fas fa-calendar-times"></i> Expira: ${formatDate(meta.expiresAt)}</div>`;
            break;
        case 'reminder':
            if (meta.reminderDate) html += `<div><i class="fas fa-clock"></i> Recordatorio: ${formatDate(meta.reminderDate)}</div>`;
            if (meta.reminderType) html += `<div><i class="fas fa-bell"></i> Tipo: ${meta.reminderType}</div>`;
            break;
        case 'command':
            if (meta.command) html += `<div><i class="fas fa-terminal"></i> Comando: ${meta.command}</div>`;
            if (meta.params) html += `<div><i class="fas fa-code"></i> Parámetros: ${JSON.stringify(meta.params)}</div>`;
            break;
    }
    
    if (meta.priority && meta.priority !== 'normal') {
        html += `<div><i class="fas fa-exclamation-circle"></i> Prioridad: ${meta.priority}</div>`;
    }
    
    html += '</div>';
    return html;
}

function renderAlerts(alerts) {
    const container = document.getElementById('alerts-container');
    if (!container) return;
    
    // Verificar si hay mantenimiento activo
    const hasActiveMaintenance = alerts.some(alert => 
        alert.category === 'maintenance' && 
        alert.metadata && 
        
        (alert.metadata.serverStatus === 'maintenance' || alert.metadata.serverStatus === 'offline')
    );
    
    // Mostrar/ocultar botón de desactivar mantenimiento
    const disableMaintenanceBtn = document.getElementById('disable-maintenance-btn');
    if (disableMaintenanceBtn) {
        disableMaintenanceBtn.style.display = hasActiveMaintenance ? 'inline-flex' : 'none';
    }
    
    if (alerts.length === 0) {
        container.innerHTML = '<p style="text-align: center; padding: 40px; color: var(--text-secondary);">No hay alertas</p>';
        return;
    }
    
    // Ordenar por fecha (más recientes primero)
    alerts.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
    
    // Guardar alertas en variable global para acceso desde el modal
    window.currentAlerts = alerts;
    
    container.innerHTML = alerts.map(alert => {
        const categoryIcon = getCategoryIcon(alert.category || 'alert');
        const categoryName = getCategoryName(alert.category || 'alert');
        const metadata = formatAlertMetadata(alert);
        
        return `
        <div class="alert-card alert-${alert.type}" onclick="showAlertDetails('${alert.id}')" style="cursor: pointer;">
            <div class="alert-header">
                <div class="alert-title-section">
                    <i class="fas ${categoryIcon}"></i>
                    <h4>${alert.title}</h4>
                    <span class="alert-category-badge">${categoryName}</span>
                </div>
                <div class="alert-meta">
                    <span><i class="fas fa-user"></i> ${alert.targetUser || 'Todos los usuarios'}</span>
                    <span><i class="fas fa-clock"></i> ${formatDate(alert.createdAt)}</span>
                </div>
            </div>
            <div class="alert-body">
                <p>${alert.message}</p>
                ${metadata}
            </div>
            <div class="alert-actions" onclick="event.stopPropagation()">
                <button class="btn btn-sm btn-danger" onclick="deleteAlert('${alert.id}')">
                    <i class="fas fa-trash"></i> Eliminar
                </button>
            </div>
        </div>
    `;
    }).join('');
}

// Desactivar modo mantenimiento
async function disableMaintenanceMode() {
    if (!confirm('¿Estás seguro de que quieres desactivar el modo mantenimiento? Esto permitirá que los usuarios usen el launcher nuevamente.')) {
        return;
    }
    
    try {
        const response = await authenticatedFetch(`${API_URL}/maintenance/disable`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        });
        
        if (response.ok) {
            const result = await response.json();
            showNotification(result.message || 'Modo mantenimiento desactivado exitosamente', 'success');
            loadAlerts(); // Recargar alertas para actualizar la vista
        } else {
            const error = await response.json();
            throw new Error(error.error || 'Error al desactivar mantenimiento');
        }
    } catch (error) {
        console.error('Error:', error);
        showNotification('Error al desactivar mantenimiento: ' + error.message, 'error');
    }
}

function showCreateAlertModal() {
    document.getElementById('create-alert-modal').classList.add('show');
    document.getElementById('alert-title').value = '';
    document.getElementById('alert-message').value = '';
    document.getElementById('alert-target-user').value = '';
    document.getElementById('alert-type').value = 'info';
    document.getElementById('alert-category').value = 'alert';
    document.getElementById('alert-priority').value = 'normal';
    document.getElementById('create-alert-error').style.display = 'none';
    updateAlertFields();
}

// Actualizar campos según la categoría seleccionada
function updateAlertFields() {
    const category = document.getElementById('alert-category').value;
    const metadataFields = document.getElementById('alert-metadata-fields');
    
    let fieldsHTML = '';
    
    switch(category) {
        case 'maintenance':
            fieldsHTML = `
                <label>Fecha/Hora de Inicio:</label>
                <input type="datetime-local" id="metadata-startDate">
                <label>Fecha/Hora de Fin (opcional):</label>
                <input type="datetime-local" id="metadata-endDate">
                <label>Estado del Servidor:</label>
                <select id="metadata-serverStatus">
                    <option value="offline">Offline</option>
                    <option value="maintenance">En Mantenimiento</option>
                    <option value="online">Online</option>
                </select>
            `;
            break;
        case 'update':
            fieldsHTML = `
                <label>Versión del Launcher:</label>
                <input type="text" id="metadata-version" placeholder="Ej: 1.2.0">
                <label>Forzar Actualización:</label>
                <select id="metadata-forceUpdate">
                    <option value="false">No</option>
                    <option value="true">Sí</option>
                </select>
                <label>URL de Descarga (opcional):</label>
                <input type="url" id="metadata-downloadUrl" placeholder="https://...">
            `;
            break;
        case 'event':
            fieldsHTML = `
                <label>Fecha/Hora del Evento:</label>
                <input type="datetime-local" id="metadata-eventDate">
                <label>Duración (horas):</label>
                <input type="number" id="metadata-duration" placeholder="2" min="1">
                <label>Tipo de Evento:</label>
                <select id="metadata-eventType">
                    <option value="tournament">Torneo</option>
                    <option value="special">Especial</option>
                    <option value="seasonal">Temporal</option>
                </select>
            `;
            break;
        case 'reward':
            fieldsHTML = `
                <label>Tipo de Recompensa:</label>
                <select id="metadata-rewardType">
                    <option value="daily">Diaria</option>
                    <option value="bonus">Bono</option>
                    <option value="code">Código</option>
                </select>
                <label>Valor/Cantidad:</label>
                <input type="text" id="metadata-rewardValue" placeholder="Ej: 100 monedas, XP x2">
                <label>Código de Canje (si aplica):</label>
                <input type="text" id="metadata-rewardCode" placeholder="CÓDIGO123">
            `;
            break;
        case 'restriction':
            fieldsHTML = `
                <label>Tipo de Restricción:</label>
                <select id="metadata-restrictionType">
                    <option value="ban">Ban</option>
                    <option value="suspension">Suspensión</option>
                    <option value="warning">Advertencia</option>
                </select>
                <label>Duración (días, 0 = permanente):</label>
                <input type="number" id="metadata-duration" placeholder="0" min="0">
                <label>Razón:</label>
                <textarea id="metadata-reason" rows="2" placeholder="Razón de la restricción"></textarea>
            `;
            break;
        case 'config':
            fieldsHTML = `
                <label>IP del Servidor:</label>
                <input type="text" id="metadata-serverIp" placeholder="192.168.1.1">
                <label>Puerto:</label>
                <input type="number" id="metadata-serverPort" placeholder="25565">
                <label>Versión de Minecraft:</label>
                <input type="text" id="metadata-mcVersion" placeholder="1.20.1">
                <label>Aplicar Automáticamente:</label>
                <select id="metadata-autoApply">
                    <option value="false">No</option>
                    <option value="true">Sí</option>
                </select>
            `;
            break;
        case 'achievement':
            fieldsHTML = `
                <label>Nombre del Logro:</label>
                <input type="text" id="metadata-achievementName" placeholder="Primer Paso">
                <label>Nivel/Progreso:</label>
                <input type="text" id="metadata-level" placeholder="Nivel 5">
                <label>Puntos:</label>
                <input type="number" id="metadata-points" placeholder="100" min="0">
            `;
            break;
        case 'promotion':
            fieldsHTML = `
                <label>Tipo de Promoción:</label>
                <select id="metadata-promoType">
                    <option value="discount">Descuento</option>
                    <option value="code">Código Promocional</option>
                    <option value="offer">Oferta Especial</option>
                </select>
                <label>Código Promocional:</label>
                <input type="text" id="metadata-promoCode" placeholder="PROMO2025">
                <label>Descuento (%):</label>
                <input type="number" id="metadata-discount" placeholder="20" min="0" max="100">
                <label>Fecha de Expiración:</label>
                <input type="datetime-local" id="metadata-expiresAt">
            `;
            break;
        case 'reminder':
            fieldsHTML = `
                <label>Fecha/Hora del Recordatorio:</label>
                <input type="datetime-local" id="metadata-reminderDate">
                <label>Tipo:</label>
                <select id="metadata-reminderType">
                    <option value="event">Evento Próximo</option>
                    <option value="task">Tarea Pendiente</option>
                    <option value="friend">Amigo Conectado</option>
                </select>
            `;
            break;
        case 'command':
            fieldsHTML = `
                <label>Comando a Ejecutar:</label>
                <select id="metadata-command">
                    <option value="update">Forzar Actualización</option>
                    <option value="restart">Reiniciar Launcher</option>
                    <option value="config">Cambiar Configuración</option>
                    <option value="clear">Limpiar Caché</option>
                </select>
                <label>Parámetros (JSON, opcional):</label>
                <textarea id="metadata-params" rows="3" placeholder='{"key": "value"}'></textarea>
            `;
            break;
        default:
            fieldsHTML = '';
    }
    
    metadataFields.innerHTML = fieldsHTML;
}

function closeCreateAlertModal() {
    document.getElementById('create-alert-modal').classList.remove('show');
}

function confirmCreateAlert() {
    const title = document.getElementById('alert-title').value.trim();
    const message = document.getElementById('alert-message').value.trim();
    const targetUser = document.getElementById('alert-target-user').value.trim() || null;
    const type = document.getElementById('alert-type').value;
    const category = document.getElementById('alert-category').value;
    const priority = document.getElementById('alert-priority').value;
    const errorDiv = document.getElementById('create-alert-error');
    
    if (!title || !message) {
        errorDiv.textContent = 'Por favor, completa título y mensaje';
        errorDiv.style.display = 'block';
        return;
    }
    
    // Recopilar metadata según la categoría
    const metadata = { priority };
    
    // Agregar campos específicos según la categoría
    switch(category) {
        case 'maintenance':
            const startDate = document.getElementById('metadata-startDate')?.value;
            const endDate = document.getElementById('metadata-endDate')?.value;
            const serverStatus = document.getElementById('metadata-serverStatus')?.value;
            if (startDate) metadata.startDate = new Date(startDate).toISOString();
            if (endDate) metadata.endDate = new Date(endDate).toISOString();
            if (serverStatus) metadata.serverStatus = serverStatus;
            break;
        case 'update':
            const version = document.getElementById('metadata-version')?.value;
            const forceUpdate = document.getElementById('metadata-forceUpdate')?.value === 'true';
            const downloadUrl = document.getElementById('metadata-downloadUrl')?.value;
            if (version) metadata.version = version;
            metadata.forceUpdate = forceUpdate;
            if (downloadUrl) metadata.downloadUrl = downloadUrl;
            break;
        case 'event':
            const eventDate = document.getElementById('metadata-eventDate')?.value;
            const duration = document.getElementById('metadata-duration')?.value;
            const eventType = document.getElementById('metadata-eventType')?.value;
            if (eventDate) metadata.eventDate = new Date(eventDate).toISOString();
            if (duration) metadata.duration = parseInt(duration);
            if (eventType) metadata.eventType = eventType;
            break;
        case 'reward':
            const rewardType = document.getElementById('metadata-rewardType')?.value;
            const rewardValue = document.getElementById('metadata-rewardValue')?.value;
            const rewardCode = document.getElementById('metadata-rewardCode')?.value;
            if (rewardType) metadata.rewardType = rewardType;
            if (rewardValue) metadata.rewardValue = rewardValue;
            if (rewardCode) metadata.rewardCode = rewardCode;
            break;
        case 'restriction':
            const restrictionType = document.getElementById('metadata-restrictionType')?.value;
            const restrictionDuration = document.getElementById('metadata-duration')?.value;
            const reason = document.getElementById('metadata-reason')?.value;
            if (restrictionType) metadata.restrictionType = restrictionType;
            if (restrictionDuration) metadata.duration = parseInt(restrictionDuration);
            if (reason) metadata.reason = reason;
            break;
        case 'config':
            const serverIp = document.getElementById('metadata-serverIp')?.value;
            const serverPort = document.getElementById('metadata-serverPort')?.value;
            const mcVersion = document.getElementById('metadata-mcVersion')?.value;
            const autoApply = document.getElementById('metadata-autoApply')?.value === 'true';
            if (serverIp) metadata.serverIp = serverIp;
            if (serverPort) metadata.serverPort = parseInt(serverPort);
            if (mcVersion) metadata.mcVersion = mcVersion;
            metadata.autoApply = autoApply;
            break;
        case 'achievement':
            const achievementName = document.getElementById('metadata-achievementName')?.value;
            const level = document.getElementById('metadata-level')?.value;
            const points = document.getElementById('metadata-points')?.value;
            if (achievementName) metadata.achievementName = achievementName;
            if (level) metadata.level = level;
            if (points) metadata.points = parseInt(points);
            break;
        case 'promotion':
            const promoType = document.getElementById('metadata-promoType')?.value;
            const promoCode = document.getElementById('metadata-promoCode')?.value;
            const discount = document.getElementById('metadata-discount')?.value;
            const expiresAt = document.getElementById('metadata-expiresAt')?.value;
            if (promoType) metadata.promoType = promoType;
            if (promoCode) metadata.promoCode = promoCode;
            if (discount) metadata.discount = parseInt(discount);
            if (expiresAt) metadata.expiresAt = new Date(expiresAt).toISOString();
            break;
        case 'reminder':
            const reminderDate = document.getElementById('metadata-reminderDate')?.value;
            const reminderType = document.getElementById('metadata-reminderType')?.value;
            if (reminderDate) metadata.reminderDate = new Date(reminderDate).toISOString();
            if (reminderType) metadata.reminderType = reminderType;
            break;
        case 'command':
            const command = document.getElementById('metadata-command')?.value;
            const params = document.getElementById('metadata-params')?.value;
            if (command) metadata.command = command;
            if (params) {
                try {
                    metadata.params = JSON.parse(params);
                } catch (e) {
                    errorDiv.textContent = 'Error en formato JSON de parámetros';
                    errorDiv.style.display = 'block';
                    return;
                }
            }
            break;
    }
    
    sendAlert(title, message, targetUser, type, category, metadata);
    closeCreateAlertModal();
}

function sendAlertToUser(username) {
    showCreateAlertModal();
    document.getElementById('alert-target-user').value = username;
}

function showSendAlertToSessionModal() {
    showCreateAlertModal();
}

async function sendAlert(title, message, targetUser, type = 'info', category = 'alert', metadata = {}) {
    try {
        const response = await authenticatedFetch(`${API_URL}/alerts`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ title, message, targetUser, type, category, metadata })
        });
        
        if (response.ok) {
            showNotification('Notificación enviada exitosamente', 'success');
            loadAlerts();
        } else {
            throw new Error('Error al enviar notificación');
        }
    } catch (error) {
        showNotification('Error al enviar notificación: ' + error.message, 'error');
    }
}

// Mostrar detalles completos de una alerta
function showAlertDetails(alertId) {
    if (!window.currentAlerts) {
        showNotification('Error: No se encontraron alertas', 'error');
        return;
    }
    
    const alert = window.currentAlerts.find(a => a.id === alertId);
    if (!alert) {
        showNotification('Error: Alerta no encontrada', 'error');
        return;
    }
    
    const modal = document.getElementById('alert-details-modal');
    if (!modal) {
        showNotification('Error: Modal no encontrado', 'error');
        return;
    }
    
    // Llenar el modal con los datos de la alerta
    document.getElementById('alert-details-id').textContent = alert.id;
    document.getElementById('alert-details-title').textContent = alert.title;
    document.getElementById('alert-details-message').textContent = alert.message;
    document.getElementById('alert-details-category').textContent = getCategoryName(alert.category || 'alert');
    document.getElementById('alert-details-category').innerHTML = `<i class="fas ${getCategoryIcon(alert.category || 'alert')}"></i> ${getCategoryName(alert.category || 'alert')}`;
    document.getElementById('alert-details-type').textContent = alert.type;
    document.getElementById('alert-details-priority').textContent = alert.metadata?.priority || 'normal';
    document.getElementById('alert-details-target').textContent = alert.targetUser || 'Todos los usuarios';
    document.getElementById('alert-details-created').textContent = formatDate(alert.createdAt);
    document.getElementById('alert-details-expires').textContent = alert.expiresAt ? formatDate(alert.expiresAt) : 'No expira';
    document.getElementById('alert-details-read').textContent = alert.read ? 'Sí' : 'No';
    document.getElementById('alert-details-readBy').textContent = alert.readBy && alert.readBy.length > 0 ? alert.readBy.join(', ') : 'Ninguno';
    
    // Mostrar metadata completa con formato visual
    const metadataContainer = document.getElementById('alert-details-metadata');
    if (alert.metadata && Object.keys(alert.metadata).length > 0) {
        metadataContainer.innerHTML = formatMetadataVisual(alert.metadata, alert.category);
    } else {
        metadataContainer.innerHTML = '<div class="metadata-empty"><i class="fas fa-info-circle"></i> No hay metadata adicional</div>';
    }
    
    // Mostrar el modal
    modal.classList.add('show');
}

// Cerrar modal de detalles
function closeAlertDetailsModal() {
    const modal = document.getElementById('alert-details-modal');
    if (modal) {
        modal.classList.remove('show');
    }
}

// Cerrar modal al hacer clic fuera de él o con ESC
document.addEventListener('DOMContentLoaded', function() {
    const modal = document.getElementById('alert-details-modal');
    if (modal) {
        // Cerrar al hacer clic fuera del modal
        modal.addEventListener('click', function(e) {
            if (e.target === modal) {
                closeAlertDetailsModal();
            }
        });
        
        // Cerrar con tecla ESC
        document.addEventListener('keydown', function(e) {
            if (e.key === 'Escape' && modal.classList.contains('show')) {
                closeAlertDetailsModal();
            }
        });
    }
});

async function deleteAlert(alertId) {
    if (!confirm('¿Estás seguro de eliminar esta alerta?')) return;
    
    try {
        const response = await authenticatedFetch(`${API_URL}/alerts/${alertId}`, {
            method: 'DELETE'
        });
        
        if (response.ok) {
            showNotification('Alerta eliminada exitosamente', 'success');
            loadAlerts();
            closeAlertDetailsModal(); // Cerrar el modal si está abierto
        } else {
            throw new Error('Error al eliminar alerta');
        }
    } catch (error) {
        showNotification('Error al eliminar alerta: ' + error.message, 'error');
    }
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
        
        if (!response.ok) {
            // Intentar leer el mensaje de error del servidor
            let errorMessage = 'Error al generar tokens';
            try {
                const errorData = await response.json();
                errorMessage = errorData.error || errorMessage;
            } catch (e) {
                // Si no se puede parsear el JSON, usar mensaje según el código de estado
                if (response.status === 429) {
                    errorMessage = 'Demasiadas peticiones. Por favor, espera un momento antes de intentar nuevamente.';
                } else if (response.status === 500) {
                    errorMessage = 'Error interno del servidor. Por favor, intenta más tarde.';
                } else if (response.status === 503) {
                    errorMessage = 'Servicio temporalmente no disponible. Por favor, intenta más tarde.';
                } else {
                    errorMessage = `Error al generar tokens (${response.status})`;
                }
            }
            throw new Error(errorMessage);
        }
        
        const result = await response.json();
        showNotification(`${result.tokens.length} token(s) generado(s) exitosamente`, 'success');
        closeGenerateModal();
        if (currentPageName === 'tokens' || currentPageName === 'dashboard') {
        loadTokens();
        }
    } catch (error) {
        console.error('Error:', error);
        // Manejar diferentes tipos de errores
        let errorMsg;
        if (error.name === 'TypeError' && error.message.includes('fetch')) {
            errorMsg = 'Error de conexión. Verifica tu conexión a internet e intenta nuevamente.';
        } else if (error.message.includes('Error al generar tokens')) {
            errorMsg = error.message; // Ya tiene el mensaje completo
        } else if (error.message === 'Failed to fetch' || error.message.includes('NetworkError')) {
            errorMsg = 'Error de red. El servidor no está disponible. Por favor, intenta más tarde.';
        } else {
            errorMsg = `Error al generar tokens: ${error.message}`;
        }
        showNotification(errorMsg, 'error');
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

