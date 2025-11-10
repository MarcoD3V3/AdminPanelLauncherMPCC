// Configuración del servidor
const API_URL = 'http://localhost:3000/api'; // Cambia esto por la URL de tu servidor

// Estado global
let tokens = [];

// Inicializar
document.addEventListener('DOMContentLoaded', () => {
    loadTokens();
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
    const tokensToRender = filteredTokens || tokens;
    
    if (tokensToRender.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; padding: 40px;">No hay tokens disponibles</td></tr>';
        return;
    }
    
    tbody.innerHTML = tokensToRender.map(token => `
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
    const filtered = tokens.filter(token => 
        token.token.toLowerCase().includes(searchTerm)
    );
    renderTokens(filtered);
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

