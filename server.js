const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const fs = require('fs').promises;
const fsSync = require('fs'); // Para operaciones síncronas (necesario para JWT_SECRET)
const path = require('path');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const TOKENS_FILE = path.join(__dirname, 'tokens.json');
const HISTORY_FILE = path.join(__dirname, 'validation_history.json');
const LOGS_FILE = path.join(__dirname, 'activity_logs.json');
const CONFIG_FILE = path.join(__dirname, 'config.json');
const USERS_FILE = path.join(__dirname, 'users.json');
const JWT_SECRET_FILE = path.join(__dirname, '.jwt_secret');

// Cargar o generar JWT_SECRET de forma persistente
function loadOrCreateJWTSecret() {
    try {
        // Intentar cargar desde archivo
        if (fsSync.existsSync(JWT_SECRET_FILE)) {
            const secret = fsSync.readFileSync(JWT_SECRET_FILE, 'utf-8').trim();
            if (secret && secret.length > 0) {
                return secret;
            }
        }
        
        // Si no existe o está vacío, generar uno nuevo
        const secret = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');
        
        // Guardar en archivo para persistencia
        fsSync.writeFileSync(JWT_SECRET_FILE, secret, 'utf-8');
        console.log('✅ JWT Secret generado y guardado');
        
        return secret;
    } catch (error) {
        console.error('Error al cargar/crear JWT_SECRET:', error);
        // Fallback a variable de entorno o generar uno nuevo
        return process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');
    }
}

const JWT_SECRET = loadOrCreateJWTSecret();

// Middleware de seguridad
app.use(helmet({
    contentSecurityPolicy: false // Permitir scripts inline para el panel
}));
app.use(cors());
app.use(express.json());

// Rate limiting para validación de tokens (más permisivo para el launcher)
const validateLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minuto
    max: 100, // 100 peticiones por minuto
    message: 'Demasiadas peticiones, intenta más tarde'
});

// Rate limiting para API del panel (más restrictivo)
const apiLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minuto
    max: 30, // 30 peticiones por minuto
    message: 'Demasiadas peticiones, intenta más tarde'
});

// Cargar tokens desde archivo
async function loadTokens() {
    try {
        const data = await fs.readFile(TOKENS_FILE, 'utf-8');
        return JSON.parse(data);
    } catch (error) {
        // Si el archivo no existe, crear uno vacío
        await saveTokens([]);
        return [];
    }
}

// Guardar tokens en archivo
async function saveTokens(tokens) {
    await fs.writeFile(TOKENS_FILE, JSON.stringify(tokens, null, 2));
}

// Cargar historial de validaciones
async function loadHistory() {
    try {
        const data = await fs.readFile(HISTORY_FILE, 'utf-8');
        return JSON.parse(data);
    } catch (error) {
        await saveHistory([]);
        return [];
    }
}

// Guardar historial de validaciones
async function saveHistory(history) {
    await fs.writeFile(HISTORY_FILE, JSON.stringify(history, null, 2));
}

// Agregar entrada al historial
async function addToHistory(token, ip, userAgent, success, error = null, username = null) {
    try {
        const history = await loadHistory();
        history.push({
            token: token,
            ip: ip,
            userAgent: userAgent || 'Unknown',
            success: success,
            error: error,
            username: username || 'Unknown',
            timestamp: new Date().toISOString()
        });
        // Mantener solo los últimos 1000 registros
        if (history.length > 1000) {
            history.splice(0, history.length - 1000);
        }
        await saveHistory(history);
    } catch (error) {
        console.error('Error al guardar historial:', error);
    }
}

// Cargar logs de actividad
async function loadLogs() {
    try {
        const data = await fs.readFile(LOGS_FILE, 'utf-8');
        return JSON.parse(data);
    } catch (error) {
        await saveLogs([]);
        return [];
    }
}

// Guardar logs de actividad
async function saveLogs(logs) {
    await fs.writeFile(LOGS_FILE, JSON.stringify(logs, null, 2));
}

// Agregar log de actividad
async function addLog(action, details, ip = null) {
    try {
        const logs = await loadLogs();
        logs.push({
            action: action,
            details: details,
            ip: ip,
            timestamp: new Date().toISOString()
        });
        // Mantener solo los últimos 500 logs
        if (logs.length > 500) {
            logs.splice(0, logs.length - 500);
        }
        await saveLogs(logs);
    } catch (error) {
        console.error('Error al guardar log:', error);
    }
}

// Cargar configuración
async function loadConfig() {
    try {
        const data = await fs.readFile(CONFIG_FILE, 'utf-8');
        return JSON.parse(data);
    } catch (error) {
        const defaultConfig = {
            maxTokens: 10000,
            rateLimitEnabled: true,
            notificationsEnabled: false
        };
        await saveConfig(defaultConfig);
        return defaultConfig;
    }
}

// Guardar configuración
async function saveConfig(config) {
    await fs.writeFile(CONFIG_FILE, JSON.stringify(config, null, 2));
}

// Obtener IP del cliente
function getClientIp(req) {
    return req.headers['x-forwarded-for']?.split(',')[0] || 
           req.headers['x-real-ip'] || 
           req.connection.remoteAddress || 
           req.socket.remoteAddress ||
           'Unknown';
}

// Generar token único
function generateToken() {
    return crypto.randomBytes(32).toString('hex').toUpperCase();
}

// ==================== SISTEMA DE USUARIOS ====================

// Cargar usuarios
async function loadUsers() {
    try {
        const data = await fs.readFile(USERS_FILE, 'utf-8');
        return JSON.parse(data);
    } catch (error) {
        // Si no existe, crear usuario por defecto
        const defaultUsers = [{
            username: 'admin',
            password: await bcrypt.hash('admin123', 10), // Contraseña por defecto
            createdAt: new Date().toISOString(),
            role: 'admin'
        }];
        await saveUsers(defaultUsers);
        console.log('⚠️ Usuario por defecto creado: admin / admin123');
        return defaultUsers;
    }
}

// Guardar usuarios
async function saveUsers(users) {
    await fs.writeFile(USERS_FILE, JSON.stringify(users, null, 2));
}

// Verificar credenciales
async function verifyCredentials(username, password) {
    const users = await loadUsers();
    const user = users.find(u => u.username === username);
    
    if (!user) {
        return null;
    }
    
    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) {
        return null;
    }
    
    return { username: user.username, role: user.role || 'user' };
}

// Middleware de autenticación JWT
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN
    
    if (!token) {
        return res.status(401).json({ error: 'Token de acceso requerido' });
    }
    
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Token inválido o expirado' });
        }
        req.user = user;
        next();
    });
}

// Middleware opcional (para rutas que pueden funcionar con o sin auth)
function optionalAuth(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (token) {
        jwt.verify(token, JWT_SECRET, (err, user) => {
            if (!err) {
                req.user = user;
            }
        });
    }
    next();
}

// ==================== RUTAS DE AUTENTICACIÓN ====================

// Login (para panel y launcher)
app.post('/api/auth/login', apiLimiter, async (req, res) => {
    try {
        const { username, password } = req.body;
        const ip = getClientIp(req);
        
        if (!username || !password) {
            return res.status(400).json({ error: 'Usuario y contraseña requeridos' });
        }
        
        const user = await verifyCredentials(username, password);
        
        if (!user) {
            await addLog('LOGIN_FAILED', { username, ip }, ip);
            return res.status(401).json({ error: 'Credenciales inválidas' });
        }
        
        // Generar JWT
        const token = jwt.sign(
            { username: user.username, role: user.role },
            JWT_SECRET,
            { expiresIn: '7d' } // Token válido por 7 días
        );
        
        await addLog('LOGIN_SUCCESS', { username: user.username, ip }, ip);
        
        res.json({
            success: true,
            token: token,
            user: {
                username: user.username,
                role: user.role
            }
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Verificar token
app.get('/api/auth/verify', optionalAuth, async (req, res) => {
    if (req.user) {
        res.json({ valid: true, user: req.user });
    } else {
        res.json({ valid: false });
    }
});

// Cambiar contraseña (requiere autenticación)
app.post('/api/auth/change-password', authenticateToken, apiLimiter, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;
        const username = req.user.username;
        const ip = getClientIp(req);
        
        if (!currentPassword || !newPassword) {
            return res.status(400).json({ error: 'Contraseña actual y nueva requeridas' });
        }
        
        const users = await loadUsers();
        const user = users.find(u => u.username === username);
        
        if (!user) {
            return res.status(404).json({ error: 'Usuario no encontrado' });
        }
        
        const isValid = await bcrypt.compare(currentPassword, user.password);
        if (!isValid) {
            return res.status(401).json({ error: 'Contraseña actual incorrecta' });
        }
        
        user.password = await bcrypt.hash(newPassword, 10);
        await saveUsers(users);
        
        await addLog('PASSWORD_CHANGED', { username }, ip);
        
        res.json({ success: true, message: 'Contraseña actualizada exitosamente' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Crear nuevo usuario (requiere autenticación y rol admin)
app.post('/api/users', authenticateToken, apiLimiter, async (req, res) => {
    try {
        // Solo admins pueden crear usuarios
        if (req.user.role !== 'admin') {
            return res.status(403).json({ error: 'Solo los administradores pueden crear usuarios' });
        }
        
        const { username, password, role = 'user' } = req.body;
        const ip = getClientIp(req);
        
        if (!username || !password) {
            return res.status(400).json({ error: 'Usuario y contraseña requeridos' });
        }
        
        if (username.length < 3) {
            return res.status(400).json({ error: 'El nombre de usuario debe tener al menos 3 caracteres' });
        }
        
        if (password.length < 6) {
            return res.status(400).json({ error: 'La contraseña debe tener al menos 6 caracteres' });
        }
        
        const validRoles = ['admin', 'user'];
        if (!validRoles.includes(role)) {
            return res.status(400).json({ error: 'Rol inválido. Roles válidos: admin, user' });
        }
        
        const users = await loadUsers();
        
        // Verificar que el usuario no exista
        if (users.find(u => u.username === username)) {
            return res.status(400).json({ error: 'El usuario ya existe' });
        }
        
        // Crear nuevo usuario
        const newUser = {
            username: username,
            password: await bcrypt.hash(password, 10),
            role: role,
            createdAt: new Date().toISOString(),
            createdBy: req.user.username
        };
        
        users.push(newUser);
        await saveUsers(users);
        
        await addLog('USER_CREATED', { username, role, createdBy: req.user.username }, ip);
        
        res.json({
            success: true,
            message: 'Usuario creado exitosamente',
            user: {
                username: newUser.username,
                role: newUser.role,
                createdAt: newUser.createdAt
            }
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Obtener todos los usuarios (requiere autenticación y rol admin)
app.get('/api/users', authenticateToken, apiLimiter, async (req, res) => {
    try {
        // Solo admins pueden ver usuarios
        if (req.user.role !== 'admin') {
            return res.status(403).json({ error: 'Solo los administradores pueden ver usuarios' });
        }
        
        const users = await loadUsers();
        
        // No devolver las contraseñas
        const safeUsers = users.map(u => ({
            username: u.username,
            role: u.role || 'user',
            createdAt: u.createdAt,
            createdBy: u.createdBy
        }));
        
        res.json(safeUsers);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Eliminar usuario (requiere autenticación y rol admin)
app.delete('/api/users/:username', authenticateToken, apiLimiter, async (req, res) => {
    try {
        // Solo admins pueden eliminar usuarios
        if (req.user.role !== 'admin') {
            return res.status(403).json({ error: 'Solo los administradores pueden eliminar usuarios' });
        }
        
        const { username } = req.params;
        const ip = getClientIp(req);
        
        // No permitir eliminar el propio usuario
        if (username === req.user.username) {
            return res.status(400).json({ error: 'No puedes eliminar tu propio usuario' });
        }
        
        const users = await loadUsers();
        const userIndex = users.findIndex(u => u.username === username);
        
        if (userIndex === -1) {
            return res.status(404).json({ error: 'Usuario no encontrado' });
        }
        
        users.splice(userIndex, 1);
        await saveUsers(users);
        
        await addLog('USER_DELETED', { username, deletedBy: req.user.username }, ip);
        
        res.json({ success: true, message: 'Usuario eliminado exitosamente' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Cambiar contraseña de otro usuario (requiere autenticación y rol admin)
app.post('/api/users/:username/change-password', authenticateToken, apiLimiter, async (req, res) => {
    try {
        // Solo admins pueden cambiar contraseñas de otros usuarios
        if (req.user.role !== 'admin') {
            return res.status(403).json({ error: 'Solo los administradores pueden cambiar contraseñas' });
        }
        
        const { username } = req.params;
        const { newPassword } = req.body;
        const ip = getClientIp(req);
        
        if (!newPassword) {
            return res.status(400).json({ error: 'Nueva contraseña requerida' });
        }
        
        if (newPassword.length < 6) {
            return res.status(400).json({ error: 'La contraseña debe tener al menos 6 caracteres' });
        }
        
        const users = await loadUsers();
        const user = users.find(u => u.username === username);
        
        if (!user) {
            return res.status(404).json({ error: 'Usuario no encontrado' });
        }
        
        user.password = await bcrypt.hash(newPassword, 10);
        await saveUsers(users);
        
        await addLog('USER_PASSWORD_CHANGED', { username, changedBy: req.user.username }, ip);
        
        res.json({ success: true, message: 'Contraseña actualizada exitosamente' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ==================== RUTAS ====================

// Obtener todos los tokens (requiere autenticación)
app.get('/api/tokens', authenticateToken, apiLimiter, async (req, res) => {
    try {
        const tokens = await loadTokens();
        res.json(tokens);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Generar nuevos tokens (requiere autenticación)
app.post('/api/tokens/generate', authenticateToken, apiLimiter, async (req, res) => {
    try {
        const { count = 1 } = req.body;
        const ip = getClientIp(req);
        const config = await loadConfig();
        
        // Validar límite
        if (count > 100) {
            return res.status(400).json({ error: 'No se pueden generar más de 100 tokens a la vez' });
        }
        
        const tokens = await loadTokens();
        if (tokens.length + count > config.maxTokens) {
            return res.status(400).json({ 
                error: `Límite de tokens alcanzado. Máximo: ${config.maxTokens}` 
            });
        }
        
        const newTokens = [];
        for (let i = 0; i < count; i++) {
            const token = generateToken();
            newTokens.push({
                token: token,
                used: false,
                createdAt: new Date().toISOString(),
                usedAt: null,
                createdBy: ip
            });
        }
        
        tokens.push(...newTokens);
        await saveTokens(tokens);
        
        // Registrar en logs
        await addLog('TOKEN_GENERATED', { count, tokens: newTokens.map(t => t.token) }, ip);
        
        res.json({ 
            success: true, 
            tokens: newTokens,
            message: `${count} token(s) generado(s) exitosamente`
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Validar token (usado por el launcher - requiere autenticación)
app.post('/api/validate-token', authenticateToken, validateLimiter, async (req, res) => {
    try {
        const { token } = req.body;
        const ip = getClientIp(req);
        const userAgent = req.headers['user-agent'] || 'Unknown';
        
        // Obtener usuario del token JWT
        const username = req.user ? req.user.username : 'Unknown';
        
        if (!token) {
            await addToHistory(token, ip, userAgent, false, 'Token no proporcionado', username);
            return res.status(400).json({
                valid: false,
                success: false,
                error: 'Token no proporcionado'
            });
        }
        
        const tokens = await loadTokens();
        const tokenRecord = tokens.find(t => t.token === token);
        
        if (!tokenRecord) {
            await addToHistory(token, ip, userAgent, false, 'Token no encontrado', username);
            return res.status(400).json({
                valid: false,
                success: false,
                error: 'Token no encontrado'
            });
        }
        
        if (tokenRecord.used) {
            await addToHistory(token, ip, userAgent, false, 'Token ya ha sido usado', username);
            return res.status(400).json({
                valid: false,
                success: false,
                error: 'Token ya ha sido usado'
            });
        }
        
        // Marcar como usado
        tokenRecord.used = true;
        tokenRecord.usedAt = new Date().toISOString();
        tokenRecord.usedFromIp = ip;
        tokenRecord.validatedBy = username;
        await saveTokens(tokens);
        
        // Registrar en historial (con información del usuario)
        await addToHistory(token, ip, userAgent, true, null, username);
        
        res.json({
            valid: true,
            success: true,
            message: 'Token válido'
        });
    } catch (error) {
        const ip = getClientIp(req);
        const userAgent = req.headers['user-agent'] || 'Unknown';
        const username = req.user ? req.user.username : 'Unknown';
        await addToHistory(req.body.token || 'N/A', ip, userAgent, false, error.message, username);
        res.status(500).json({
            valid: false,
            success: false,
            error: error.message
        });
    }
});

// Eliminar un token (requiere autenticación)
app.delete('/api/tokens/:token', authenticateToken, apiLimiter, async (req, res) => {
    try {
        const { token } = req.params;
        const ip = getClientIp(req);
        const tokens = await loadTokens();
        const filtered = tokens.filter(t => t.token !== token);
        
        if (filtered.length === tokens.length) {
            return res.status(404).json({ error: 'Token no encontrado' });
        }
        
        await saveTokens(filtered);
        
        // Registrar en logs
        await addLog('TOKEN_DELETED', { token }, ip);
        
        res.json({ success: true, message: 'Token eliminado exitosamente' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Limpiar tokens usados (requiere autenticación)
app.delete('/api/tokens/clear-used', authenticateToken, apiLimiter, async (req, res) => {
    try {
        const ip = getClientIp(req);
        const tokens = await loadTokens();
        const available = tokens.filter(t => !t.used);
        const deletedCount = tokens.length - available.length;
        
        await saveTokens(available);
        
        // Registrar en logs
        await addLog('TOKENS_CLEARED', { deleted: deletedCount }, ip);
        
        res.json({ 
            success: true, 
            message: 'Tokens usados eliminados exitosamente',
            deleted: deletedCount
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ==================== NUEVOS ENDPOINTS ====================

// Obtener estadísticas (requiere autenticación)
app.get('/api/stats', authenticateToken, apiLimiter, async (req, res) => {
    try {
        const tokens = await loadTokens();
        const history = await loadHistory();
        
        const total = tokens.length;
        const used = tokens.filter(t => t.used).length;
        const available = total - used;
        
        // Estadísticas de los últimos 7 días
        const sevenDaysAgo = new Date();
        sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);
        
        const recentHistory = history.filter(h => 
            new Date(h.timestamp) >= sevenDaysAgo
        );
        
        const validationsToday = history.filter(h => {
            const today = new Date();
            const histDate = new Date(h.timestamp);
            return histDate.toDateString() === today.toDateString();
        }).length;
        
        const validationsThisWeek = recentHistory.length;
        const successfulValidations = recentHistory.filter(h => h.success).length;
        const failedValidations = recentHistory.filter(h => !h.success).length;
        
        // Tokens generados hoy
        const tokensToday = tokens.filter(t => {
            const today = new Date();
            const tokenDate = new Date(t.createdAt);
            return tokenDate.toDateString() === today.toDateString();
        }).length;
        
        res.json({
            tokens: {
                total,
                used,
                available,
                usedPercentage: total > 0 ? ((used / total) * 100).toFixed(2) : 0
            },
            validations: {
                today: validationsToday,
                thisWeek: validationsThisWeek,
                successful: successfulValidations,
                failed: failedValidations,
                successRate: validationsThisWeek > 0 
                    ? ((successfulValidations / validationsThisWeek) * 100).toFixed(2) 
                    : 0
            },
            activity: {
                tokensGeneratedToday: tokensToday
            }
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Obtener historial de validaciones (requiere autenticación)
app.get('/api/history', authenticateToken, apiLimiter, async (req, res) => {
    try {
        const { limit = 100, offset = 0, token, success } = req.query;
        let history = await loadHistory();
        
        // Filtros
        if (token) {
            history = history.filter(h => h.token.includes(token));
        }
        if (success !== undefined) {
            history = history.filter(h => h.success === (success === 'true'));
        }
        
        // Ordenar por fecha (más reciente primero)
        history.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
        
        // Paginación
        const total = history.length;
        const paginated = history.slice(parseInt(offset), parseInt(offset) + parseInt(limit));
        
        res.json({
            history: paginated,
            total,
            limit: parseInt(limit),
            offset: parseInt(offset)
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Exportar tokens (requiere autenticación)
app.get('/api/tokens/export', authenticateToken, apiLimiter, async (req, res) => {
    try {
        const { format = 'json' } = req.query;
        const tokens = await loadTokens();
        
        if (format === 'csv') {
            // Generar CSV
            const csvHeader = 'Token,Estado,Fecha Creación,Fecha Uso,IP de Uso\n';
            const csvRows = tokens.map(t => {
                const token = t.token;
                const estado = t.used ? 'Usado' : 'Disponible';
                const fechaCreacion = t.createdAt || '';
                const fechaUso = t.usedAt || '';
                const ipUso = t.usedFromIp || '';
                return `${token},${estado},${fechaCreacion},${fechaUso},${ipUso}`;
            }).join('\n');
            
            res.setHeader('Content-Type', 'text/csv');
            res.setHeader('Content-Disposition', 'attachment; filename=tokens.csv');
            res.send(csvHeader + csvRows);
        } else {
            // JSON por defecto
            res.setHeader('Content-Type', 'application/json');
            res.setHeader('Content-Disposition', 'attachment; filename=tokens.json');
            res.json(tokens);
        }
        
        await addLog('TOKENS_EXPORTED', { format, count: tokens.length }, getClientIp(req));
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Importar tokens (requiere autenticación)
app.post('/api/tokens/import', authenticateToken, apiLimiter, async (req, res) => {
    try {
        const { tokens: tokensToImport } = req.body;
        const ip = getClientIp(req);
        
        if (!Array.isArray(tokensToImport)) {
            return res.status(400).json({ error: 'Los tokens deben ser un array' });
        }
        
        const existingTokens = await loadTokens();
        const newTokens = [];
        const skipped = [];
        
        for (const tokenData of tokensToImport) {
            const token = typeof tokenData === 'string' ? tokenData : tokenData.token;
            
            // Verificar que no exista
            if (existingTokens.find(t => t.token === token)) {
                skipped.push(token);
                continue;
            }
            
            newTokens.push({
                token: token,
                used: typeof tokenData === 'object' ? (tokenData.used || false) : false,
                createdAt: typeof tokenData === 'object' ? (tokenData.createdAt || new Date().toISOString()) : new Date().toISOString(),
                usedAt: typeof tokenData === 'object' ? (tokenData.usedAt || null) : null,
                createdBy: ip
            });
        }
        
        existingTokens.push(...newTokens);
        await saveTokens(existingTokens);
        
        await addLog('TOKENS_IMPORTED', { 
            imported: newTokens.length, 
            skipped: skipped.length 
        }, ip);
        
        res.json({
            success: true,
            imported: newTokens.length,
            skipped: skipped.length,
            skippedTokens: skipped
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Obtener logs de actividad (requiere autenticación)
app.get('/api/logs', authenticateToken, apiLimiter, async (req, res) => {
    try {
        const { limit = 100, action } = req.query;
        let logs = await loadLogs();
        
        if (action) {
            logs = logs.filter(l => l.action === action);
        }
        
        // Ordenar por fecha (más reciente primero)
        logs.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
        
        // Limitar
        logs = logs.slice(0, parseInt(limit));
        
        res.json(logs);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Obtener configuración (requiere autenticación)
app.get('/api/config', authenticateToken, apiLimiter, async (req, res) => {
    try {
        const config = await loadConfig();
        res.json(config);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Actualizar configuración (requiere autenticación)
app.put('/api/config', authenticateToken, apiLimiter, async (req, res) => {
    try {
        const ip = getClientIp(req);
        const newConfig = req.body;
        const currentConfig = await loadConfig();
        
        const updatedConfig = { ...currentConfig, ...newConfig };
        await saveConfig(updatedConfig);
        
        await addLog('CONFIG_UPDATED', { changes: newConfig }, ip);
        
        res.json({ success: true, config: updatedConfig });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Servir archivos estáticos del panel
app.use(express.static(__dirname));

// Iniciar servidor
// Usar el puerto de la variable de entorno (para Railway, Render, Heroku, etc.)
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log(`🚀 Servidor de administración corriendo en puerto ${PORT}`);
    console.log(`📊 Panel de administración: http://localhost:${PORT}/index.html`);
    console.log(`🔗 Endpoint de validación: http://localhost:${PORT}/api/validate-token`);
});

