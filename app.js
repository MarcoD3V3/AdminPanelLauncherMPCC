// Configuración del servidor
// Detectar automáticamente la URL del servidor (funciona en localhost y producción)
const API_URL = window.location.origin + '/api';

// Estado global
let tokens = [];
let currentPage = 1;
let itemsPerPage = 20;
let currentSort = { field: null, direction: 'asc' };
let currentTab = 'tokens';

// Inicializar
document.addEventListener('DOMContentLoaded', () => {
    loadTokens();
    loadStats();
    // Cargar historial y logs cuando se cambie de tab
});

// Cargar tokens desde el servidor
async function loadTokens() {
    try {
        const response = await fetch(`${API_URL}/tokens`);
        if (!response.ok) throw new Error('Error al cargar tokens');
        
        tokens = await response.json();
        updateStats();
        renderTokens();
    } catch (error) {
        console.error('Error:', error);
        showNotification('Error al cargar tokens: ' + error.message, 'error');
        // Cargar desde localStorage como fallback
        const savedTokens = localStorage.getItem('tokens');
        if (savedTokens) {
            tokens = JSON.parse(savedTokens);
            updateStats();
            renderTokens();
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
    
    tbody.innerHTML = paginatedTokens.map(token => `
        <tr>
            <td>
                <div class="token-code">${token.token}</div>
            </td>
            <td>
                <span class="status-badge ${token.used ? 'status-used' : 'status-available'}">
                    ${token.used ? 'Usado' : 'Disponible'}
                </span>
            </td>
            <td>${formatDate(token.createdAt)}</td>
            <td>${token.usedAt ? formatDate(token.usedAt) : '-'}</td>
            <td>${token.usedFromIp || '-'}</td>
            <td>
                <button class="action-btn btn-danger" onclick="deleteToken('${token.token}')" title="Eliminar">
                    🗑️
                </button>
                <button class="action-btn btn-success" onclick="copyToken('${token.token}')" title="Copiar">
                    📋
                </button>
            </td>
        </tr>
    `).join('');
    
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
    
    try {
        const response = await fetch(`${API_URL}/tokens/generate`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ count })
        });
        
        if (!response.ok) throw new Error('Error al generar tokens');
        
        const result = await response.json();
        showNotification(`${result.tokens.length} token(s) generado(s) exitosamente`, 'success');
        closeGenerateModal();
        loadTokens();
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
        const response = await fetch(`${API_URL}/tokens/${encodeURIComponent(token)}`, {
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
        const response = await fetch(`${API_URL}/tokens/clear-used`, {
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
        
        const response = await fetch(`${API_URL}/tokens/import`, {
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
        const response = await fetch(`${API_URL}/stats`);
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
        
        const response = await fetch(url);
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
        tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; padding: 40px;">No hay historial disponible</td></tr>';
        return;
    }
    
    tbody.innerHTML = history.map(entry => `
        <tr>
            <td><div class="token-code">${entry.token || 'N/A'}</div></td>
            <td>${entry.ip || 'Unknown'}</td>
            <td>
                <span class="status-badge ${entry.success ? 'status-available' : 'status-used'}">
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
        
        const response = await fetch(url);
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
        container.innerHTML = '<p style="text-align: center; padding: 40px;">No hay logs disponibles</p>';
        return;
    }
    
    container.innerHTML = logs.map(log => `
        <div class="log-entry">
            <div class="log-action">${log.action}</div>
            <div class="log-details">${JSON.stringify(log.details)}</div>
            <div class="log-timestamp">${formatDate(log.timestamp)} | IP: ${log.ip || 'Unknown'}</div>
        </div>
    `).join('');
}

