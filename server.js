const express = require('express');
const http = require('http');
const cors = require('cors');
const crypto = require('crypto');
const fs = require('fs').promises;
const fsSync = require('fs'); // Para operaciones síncronas (necesario para JWT_SECRET)
const path = require('path');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Server } = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
    cors: {
        origin: "*",
        methods: ["GET", "POST"],
        credentials: true
    },
    transports: ['websocket', 'polling'], // Asegurar compatibilidad con Railway/Heroku
    allowEIO3: true // Compatibilidad con versiones antiguas
});
const TOKENS_FILE = path.join(__dirname, 'tokens.json');
const HISTORY_FILE = path.join(__dirname, 'validation_history.json');
const LOGS_FILE = path.join(__dirname, 'activity_logs.json');
const CONFIG_FILE = path.join(__dirname, 'config.json');
const USERS_FILE = path.join(__dirname, 'users.json');
const SESSIONS_FILE = path.join(__dirname, 'sessions.json');
const ALERTS_FILE = path.join(__dirname, 'alerts.json');
const JWT_SECRET_FILE = path.join(__dirname, '.jwt_secret');

// Almacenamiento en memoria de sesiones activas (para acceso rápido)
let activeSessions = new Map();

// Almacenamiento de conexiones WebSocket activas (para chat)
let activeConnections = new Map(); // Map<socketId, {username, token, socket}>
let userMessages = new Map(); // Map<username, [{from, to, message, timestamp}]>

// Lock para evitar condiciones de carrera al escribir tokens
let tokensWriteLock = null;

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

// Configurar Express para confiar en proxies (necesario para Railway, Heroku, etc.)
// Esto permite que express-rate-limit identifique correctamente las IPs reales
app.set('trust proxy', true);

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
    message: 'Demasiadas peticiones, intenta más tarde',
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
        res.status(429).json({ 
            error: 'Demasiadas peticiones. Por favor, espera un momento antes de intentar nuevamente.' 
        });
    }
});

// Rate limiting para chat (más permisivo)
const chatLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minuto
    max: 100, // 100 peticiones por minuto (más permisivo para chat)
    message: 'Demasiadas peticiones, intenta más tarde'
});

// Función helper para cargar archivos JSON de forma segura
async function safeLoadJSON(filePath, defaultValue = [], saveFunction = null) {
    try {
        const data = await fs.readFile(filePath, 'utf-8');
        if (!data || data.trim() === '') {
            return defaultValue;
        }
        const parsed = JSON.parse(data);
        // Si el valor por defecto es un array, asegurar que el resultado también lo sea
        if (Array.isArray(defaultValue)) {
            return Array.isArray(parsed) ? parsed : defaultValue;
        }
        return parsed || defaultValue;
    } catch (error) {
        if (error.code === 'ENOENT') {
            // Archivo no existe, crear uno con valores por defecto
            if (saveFunction) {
                await saveFunction(defaultValue);
            }
        } else {
            console.error(`⚠️ Error al cargar ${path.basename(filePath)} (archivo corrupto?), creando nuevo:`, error.message);
            // Archivo corrupto, hacer backup y crear uno nuevo
            try {
                await fs.rename(filePath, filePath + '.backup.' + Date.now());
            } catch (e) {
                // Ignorar si no se puede renombrar
            }
            if (saveFunction) {
                await saveFunction(defaultValue);
            }
        }
        return defaultValue;
    }
}

// Cargar tokens desde archivo
async function loadTokens() {
    return await safeLoadJSON(TOKENS_FILE, [], saveTokens);
}

// Guardar tokens en archivo (con manejo de errores robusto y lock para evitar condiciones de carrera)
async function saveTokens(tokens) {
    // Esperar a que termine cualquier escritura en curso
    while (tokensWriteLock) {
        await tokensWriteLock;
    }
    
    // Crear un lock para esta operación
    let resolveLock;
    const lockPromise = new Promise(resolve => {
        resolveLock = resolve;
    });
    tokensWriteLock = lockPromise;
    
    try {
        const data = JSON.stringify(tokens, null, 2);
        await fs.writeFile(TOKENS_FILE, data, 'utf-8');
        // Verificar que se guardó correctamente
        const verify = await fs.readFile(TOKENS_FILE, 'utf-8');
        if (!verify) {
            throw new Error('Error al verificar guardado de tokens');
        }
    } catch (error) {
        console.error('❌ Error crítico al guardar tokens:', error);
        throw error; // Re-lanzar para que el llamador sepa que falló
    } finally {
        // Liberar el lock
        tokensWriteLock = null;
        if (resolveLock) resolveLock();
    }
}

// Cargar historial de validaciones
async function loadHistory() {
    return await safeLoadJSON(HISTORY_FILE, [], saveHistory);
}

// Guardar historial de validaciones (con manejo de errores robusto)
async function saveHistory(history) {
    try {
        const data = JSON.stringify(history, null, 2);
        await fs.writeFile(HISTORY_FILE, data, 'utf-8');
    } catch (error) {
        console.error('❌ Error crítico al guardar historial:', error);
        throw error;
    }
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
    return await safeLoadJSON(LOGS_FILE, [], saveLogs);
}

// Guardar logs de actividad (con manejo de errores robusto)
async function saveLogs(logs) {
    try {
        const data = JSON.stringify(logs, null, 2);
        await fs.writeFile(LOGS_FILE, data, 'utf-8');
    } catch (error) {
        console.error('❌ Error crítico al guardar logs:', error);
        throw error;
    }
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

// ==================== SISTEMA DE SESIONES ====================

// Cargar sesiones
async function loadSessions() {
    return await safeLoadJSON(SESSIONS_FILE, [], saveSessions);
}

// Guardar sesiones (con manejo de errores robusto)
async function saveSessions(sessions) {
    try {
        const data = JSON.stringify(sessions, null, 2);
        await fs.writeFile(SESSIONS_FILE, data, 'utf-8');
        // Actualizar mapa en memoria
        activeSessions.clear();
        sessions.forEach(session => {
            if (session.active) {
                activeSessions.set(session.token, session);
            }
        });
    } catch (error) {
        console.error('❌ Error crítico al guardar sesiones:', error);
        throw error;
    }
}

// Crear o actualizar sesión
async function createOrUpdateSession(username, token, ip, userAgent) {
    const sessions = await loadSessions();
    
    // Buscar sesión existente por token (sesión actual)
    let existingIndex = sessions.findIndex(s => s.token === token && s.active);
    
    // Si no existe por token, buscar por username (para actualizar sesión existente del mismo usuario)
    if (existingIndex === -1) {
        existingIndex = sessions.findIndex(s => s.username === username && s.active);
        
        // Si encontramos una sesión activa del mismo usuario, revocarla primero
        if (existingIndex >= 0) {
            sessions[existingIndex].active = false;
            sessions[existingIndex].revokedAt = new Date().toISOString();
            sessions[existingIndex].revokedReason = 'Nueva sesión iniciada';
        }
    }
    
    // Crear nueva sesión con el nuevo token
    const sessionData = {
        id: existingIndex >= 0 && sessions[existingIndex].token === token 
            ? sessions[existingIndex].id 
            : crypto.randomBytes(16).toString('hex'),
        username: username,
        token: token,
        ip: ip,
        userAgent: userAgent || 'Unknown',
        startedAt: existingIndex >= 0 && sessions[existingIndex].token === token
            ? sessions[existingIndex].startedAt 
            : new Date().toISOString(),
        lastActivity: new Date().toISOString(),
        active: true
    };
    
    // Si existe y es el mismo token, actualizar
    if (existingIndex >= 0 && sessions[existingIndex].token === token) {
        sessions[existingIndex] = sessionData;
    } else {
        // Agregar nueva sesión
        sessions.push(sessionData);
    }
    
    // Limpiar sesiones inactivas antiguas (más de 7 días sin actividad)
    const sevenDaysAgo = new Date();
    sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);
    
    const cleanedSessions = sessions.filter(s => {
        if (!s.active) {
            // Mantener sesiones revocadas solo por 1 día
            if (s.revokedAt) {
                const revokedDate = new Date(s.revokedAt);
                return revokedDate > sevenDaysAgo;
            }
            return false;
        }
        // Mantener sesiones activas
        return true;
    });
    
    await saveSessions(cleanedSessions);
    return sessionData;
}

// Revocar sesión
async function revokeSession(sessionId) {
    const sessions = await loadSessions();
    const sessionIndex = sessions.findIndex(s => s.id === sessionId);
    
    if (sessionIndex >= 0) {
        sessions[sessionIndex].active = false;
        sessions[sessionIndex].revokedAt = new Date().toISOString();
        await saveSessions(sessions);
        return true;
    }
    return false;
}

// Revocar todas las sesiones de un usuario
async function revokeAllUserSessions(username) {
    const sessions = await loadSessions();
    sessions.forEach(session => {
        if (session.username === username && session.active) {
            session.active = false;
            session.revokedAt = new Date().toISOString();
        }
    });
    await saveSessions(sessions);
}

// Revocar todas las sesiones
async function revokeAllSessions() {
    const sessions = await loadSessions();
    sessions.forEach(session => {
        if (session.active) {
            session.active = false;
            session.revokedAt = new Date().toISOString();
        }
    });
    await saveSessions(sessions);
}

// Actualizar última actividad de sesión
async function updateSessionActivity(token) {
    const sessions = await loadSessions();
    const session = sessions.find(s => s.token === token && s.active);
    if (session) {
        session.lastActivity = new Date().toISOString();
        await saveSessions(sessions);
    } else {
        // Si no se encuentra la sesión, puede que el token sea nuevo
        // Intentar decodificar el token para obtener el username
        try {
            const decoded = jwt.verify(token, JWT_SECRET);
            // Buscar sesión activa del usuario y actualizarla
            const userSession = sessions.find(s => s.username === decoded.username && s.active);
            if (userSession) {
                // Actualizar el token de la sesión existente
                userSession.token = token;
                userSession.lastActivity = new Date().toISOString();
                await saveSessions(sessions);
            }
        } catch (error) {
            // Token inválido, no hacer nada
        }
    }
}

// ==================== SISTEMA DE ALERTAS ====================

// Cargar alertas
async function loadAlerts() {
    return await safeLoadJSON(ALERTS_FILE, [], saveAlerts);
}

// Guardar alertas (con manejo de errores robusto)
async function saveAlerts(alerts) {
    try {
        const data = JSON.stringify(alerts, null, 2);
        await fs.writeFile(ALERTS_FILE, data, 'utf-8');
    } catch (error) {
        console.error('❌ Error crítico al guardar alertas:', error);
        throw error;
    }
}

// Crear alerta
async function createAlert(title, message, targetUser = null, type = 'info', category = 'alert', metadata = {}) {
    const alerts = await loadAlerts();
    const alert = {
        id: crypto.randomBytes(16).toString('hex'),
        title: title,
        message: message,
        targetUser: targetUser, // null = todos los usuarios
        type: type, // info, warning, error, success
        category: category, // alert, maintenance, update, event, reward, restriction, config, achievement, promotion, reminder, command
        metadata: metadata, // Datos adicionales según la categoría
        createdAt: new Date().toISOString(),
        expiresAt: metadata.expiresAt || null, // Fecha de expiración opcional
        priority: metadata.priority || 'normal', // low, normal, high, urgent
        read: false,
        readBy: []
    };
    alerts.push(alert);
    await saveAlerts(alerts);
    return alert;
}

// Marcar alerta como leída
async function markAlertAsRead(alertId, username) {
    const alerts = await loadAlerts();
    const alert = alerts.find(a => a.id === alertId);
    if (alert) {
        if (!alert.readBy.includes(username)) {
            alert.readBy.push(username);
        }
        if (alert.readBy.length > 0) {
            alert.read = true;
        }
        await saveAlerts(alerts);
    }
}

// Obtener alertas para un usuario
async function getUserAlerts(username) {
    const alerts = await loadAlerts();


    const now = new Date();
    
    // Filtrar alertas: globales o específicas del usuario, no leídas, y no expiradas
    return alerts.filter(a => {
        // Filtrar por usuario
        if (a.targetUser && a.targetUser !== username) return false;
        
        // Filtrar alertas ya leídas por este usuario
        if (a.readBy && a.readBy.includes(username)) return false;
        
        // Filtrar alertas expiradas
        if (a.expiresAt && new Date(a.expiresAt) < now) return false;
        
        return true;
    }).sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
}

// ==================== FUNCIONES HELPER PARA CREAR NOTIFICACIONES ====================

// Crear notificación de mantenimiento
async function createMaintenanceAlert(title, message, startDate, endDate, serverStatus, targetUser = null) {
    return await createAlert(
        title, 
        message, 
        targetUser, 
        'warning', 
        'maintenance', 
        { startDate, endDate, serverStatus, priority: 'high' }
    );
}

// Crear notificación de actualización
async function createUpdateAlert(title, message, version, forceUpdate = false, downloadUrl = null, targetUser = null) {
    return await createAlert(
        title, 
        message, 
        targetUser, 
        'info', 
        'update', 
        { version, forceUpdate, downloadUrl, priority: forceUpdate ? 'urgent' : 'high' }
    );
}

// Crear notificación de evento
async function createEventAlert(title, message, eventDate, duration, eventType, targetUser = null) {
    return await createAlert(
        title, 
        message, 
        targetUser, 
        'success', 
        'event', 
        { eventDate, duration, eventType, priority: 'normal' }
    );
}

// Crear notificación de recompensa
async function createRewardAlert(title, message, rewardType, rewardValue, rewardCode = null, targetUser = null) {
    return await createAlert(
        title, 
        message, 
        targetUser, 
        'success', 
        'reward', 
        { rewardType, rewardValue, rewardCode, priority: 'normal' }
    );
}

// Crear notificación de restricción
async function createRestrictionAlert(title, message, restrictionType, duration, reason, targetUser) {
    if (!targetUser) {
        throw new Error('Las restricciones deben ser para un usuario específico');
    }
    return await createAlert(
        title, 
        message, 
        targetUser, 
        'error', 
        'restriction', 
        { restrictionType, duration, reason, priority: 'high' }
    );
}

// Crear notificación de configuración
async function createConfigAlert(title, message, serverIp, serverPort, mcVersion, autoApply = false, targetUser = null) {
    return await createAlert(
        title, 
        message, 
        targetUser, 
        'info', 
        'config', 
        { serverIp, serverPort, mcVersion, autoApply, priority: 'high' }
    );
}

// Crear notificación de logro
async function createAchievementAlert(title, message, achievementName, level, points, targetUser) {
    return await createAlert(
        title, 
        message, 
        targetUser, 
        'success', 
        'achievement', 
        { achievementName, level, points, priority: 'normal' }
    );
}

// Crear notificación de promoción
async function createPromotionAlert(title, message, promoType, promoCode, discount, expiresAt, targetUser = null) {
    return await createAlert(
        title, 
        message, 
        targetUser, 
        'success', 
        'promotion', 
        { promoType, promoCode, discount, expiresAt, priority: 'normal' }
    );
}

// Crear notificación de recordatorio
async function createReminderAlert(title, message, reminderDate, reminderType, targetUser = null) {
    return await createAlert(
        title, 
        message, 
        targetUser, 
        'info', 
        'reminder', 
        { reminderDate, reminderType, priority: 'normal' }
    );
}

// Crear notificación de comando
async function createCommandAlert(title, message, command, params = {}, targetUser = null) {
    return await createAlert(
        title, 
        message, 
        targetUser, 
        'warning', 
        'command', 
        { command, params, priority: 'high' }
    );
}

// Cargar configuración
async function loadConfig() {
    const defaultConfig = {
        maxTokens: 10000,
        rateLimitEnabled: true,
        notificationsEnabled: false
    };
    return await safeLoadJSON(CONFIG_FILE, defaultConfig, saveConfig);
}

// Guardar configuración (con manejo de errores robusto)
async function saveConfig(config) {
    try {
        const data = JSON.stringify(config, null, 2);
        await fs.writeFile(CONFIG_FILE, data, 'utf-8');
    } catch (error) {
        console.error('❌ Error crítico al guardar configuración:', error);
        throw error;
    }
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
        if (!data || data.trim() === '') {
            throw new Error('Archivo vacío');
        }
        const parsed = JSON.parse(data);
        if (!Array.isArray(parsed) || parsed.length === 0) {
            throw new Error('Array vacío o inválido');
        }
        return parsed;
    } catch (error) {
        // Si no existe o está corrupto, crear usuario por defecto
        if (error.code === 'ENOENT' || error.message.includes('corrupto') || error.message.includes('vacío') || error.message.includes('inválido')) {
            if (error.code !== 'ENOENT') {
                console.error('⚠️ Error al cargar usuarios (archivo corrupto?), creando nuevo:', error.message);
                // Hacer backup del archivo corrupto
                try {
                    await fs.rename(USERS_FILE, USERS_FILE + '.backup.' + Date.now());
                } catch (e) {
                    // Ignorar si no se puede renombrar
                }
            }
            // Crear usuario por defecto
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
        throw error; // Re-lanzar otros errores
    }
}

// Guardar usuarios (con manejo de errores robusto)
async function saveUsers(users) {
    try {
        const data = JSON.stringify(users, null, 2);
        await fs.writeFile(USERS_FILE, data, 'utf-8');
    } catch (error) {
        console.error('❌ Error crítico al guardar usuarios:', error);
        throw error;
    }
}

// Verificar credenciales
async function verifyCredentials(username, password) {
    // Limpiar espacios en blanco
    const cleanUsername = (username || '').trim();
    const cleanPassword = (password || '').trim();
    
    if (!cleanUsername || !cleanPassword) {
        console.log('⚠️ Credenciales vacías después de trim');
        return null;
    }
    
    const users = await loadUsers();
    
    // Buscar usuario (case-insensitive para mayor flexibilidad)
    const user = users.find(u => u.username && u.username.trim().toLowerCase() === cleanUsername.toLowerCase());
    
    if (!user) {
        console.log(`⚠️ Usuario no encontrado: "${cleanUsername}" (buscado en: ${users.map(u => u.username).join(', ')})`);
        return null;
    }
    
    // Verificar que el usuario tenga contraseña
    if (!user.password) {
        console.log(`⚠️ Usuario "${user.username}" no tiene contraseña guardada`);
        return null;
    }
    
    // Comparar contraseña
    const isValid = await bcrypt.compare(cleanPassword, user.password);
    
    if (!isValid) {
        console.log(`⚠️ Contraseña incorrecta para usuario: "${user.username}"`);
        // Log adicional para debug (solo en desarrollo)
        if (process.env.NODE_ENV === 'development') {
            console.log(`   - Contraseña recibida (longitud): ${cleanPassword.length}`);
            console.log(`   - Hash guardado (prefijo): ${user.password.substring(0, 10)}...`);
        }
        return null;
    }
    
    console.log(`✅ Login exitoso para usuario: "${user.username}"`);
    return { username: user.username, role: user.role || 'user' };
}

// Middleware de autenticación JWT
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN
    
    if (!token) {
        console.log('❌ API: Token no proporcionado en header Authorization');
        return res.status(401).json({ error: 'Token de acceso requerido' });
    }
    
    console.log('🔍 API: Verificando token (primeros 20 chars):', token.substring(0, 20) + '...');
    
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            console.log('❌ API: Error al verificar token:', err.message);
            console.log('❌ API: Tipo de error:', err.name);
            if (err.name === 'TokenExpiredError') {
                console.log('❌ API: Token expirado en:', err.expiredAt);
            }
            return res.status(403).json({ error: 'Token inválido o expirado' });
        }
        console.log('✅ API: Token válido para usuario:', user.username);
        req.user = user;
        req.token = token;
        // Actualizar última actividad de la sesión
        updateSessionActivity(token).catch(console.error);
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
        
        // Limpiar espacios en blanco
        const cleanUsername = (username || '').trim();
        const cleanPassword = (password || '').trim();
        
        if (!cleanUsername || !cleanPassword) {
            return res.status(400).json({ error: 'Usuario y contraseña requeridos' });
        }
        
        const user = await verifyCredentials(cleanUsername, cleanPassword);
        
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
        
        // Crear o actualizar sesión
        const userAgent = req.headers['user-agent'] || 'Unknown';
        await createOrUpdateSession(user.username, token, ip, userAgent);
        
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
        
        // Limpiar espacios en blanco
        const cleanUsername = (username || '').trim();
        const cleanPassword = (password || '').trim();
        
        if (!cleanUsername || !cleanPassword) {
            return res.status(400).json({ error: 'Usuario y contraseña requeridos' });
        }
        
        if (cleanUsername.length < 3) {
            return res.status(400).json({ error: 'El nombre de usuario debe tener al menos 3 caracteres' });
        }
        
        if (cleanPassword.length < 6) {
            return res.status(400).json({ error: 'La contraseña debe tener al menos 6 caracteres' });
        }
        
        const validRoles = ['admin', 'user'];
        if (!validRoles.includes(role)) {
            return res.status(400).json({ error: 'Rol inválido. Roles válidos: admin, user' });
        }
        
        const users = await loadUsers();
        
        // Verificar que el usuario no exista (case-insensitive)
        if (users.find(u => u.username && u.username.trim().toLowerCase() === cleanUsername.toLowerCase())) {
            return res.status(400).json({ error: 'El usuario ya existe' });
        }
        
        // Crear nuevo usuario
        const newUser = {
            username: cleanUsername,
            password: await bcrypt.hash(cleanPassword, 10),
            role: role,
            createdAt: new Date().toISOString(),
            createdBy: req.user.username
        };
        
        users.push(newUser);
        await saveUsers(users);
        
        await addLog('USER_CREATED', { username: cleanUsername, role, createdBy: req.user.username }, ip);
        
        console.log(`✅ Usuario creado: "${cleanUsername}" con rol "${role}"`);
        
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

// ==================== ENDPOINTS DE SESIONES ====================

// Obtener todas las sesiones activas (requiere autenticación y rol admin)
app.get('/api/sessions', authenticateToken, apiLimiter, async (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ error: 'Solo los administradores pueden ver sesiones' });
        }
        
        const sessions = await loadSessions();
        
        // Filtrar solo sesiones activas y limpiar duplicados
        // Si un usuario tiene múltiples sesiones activas, mantener solo la más reciente
        const activeSessions = sessions.filter(s => s.active);
        
        // Agrupar por usuario y mantener solo la sesión más reciente de cada uno
        const sessionsByUser = new Map();
        activeSessions.forEach(session => {
            const existing = sessionsByUser.get(session.username);
            if (!existing || new Date(session.lastActivity) > new Date(existing.lastActivity)) {
                sessionsByUser.set(session.username, session);
            }
        });
        
        // Convertir a array y ordenar por última actividad (más reciente primero)
        const uniqueSessions = Array.from(sessionsByUser.values())
            .sort((a, b) => new Date(b.lastActivity) - new Date(a.lastActivity));
        
        res.json(uniqueSessions);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Revocar una sesión específica (requiere autenticación y rol admin)
app.delete('/api/sessions/:sessionId', authenticateToken, apiLimiter, async (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ error: 'Solo los administradores pueden revocar sesiones' });
        }
        
        const { sessionId } = req.params;
        const ip = getClientIp(req);
        
        const success = await revokeSession(sessionId);
        if (success) {
            await addLog('SESSION_REVOKED', { sessionId, revokedBy: req.user.username }, ip);
            res.json({ success: true, message: 'Sesión revocada exitosamente' });
        } else {
            res.status(404).json({ error: 'Sesión no encontrada' });
        }
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Revocar todas las sesiones (requiere autenticación y rol admin)
app.delete('/api/sessions', authenticateToken, apiLimiter, async (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ error: 'Solo los administradores pueden revocar sesiones' });
        }
        
        const ip = getClientIp(req);
        await revokeAllSessions();
        await addLog('ALL_SESSIONS_REVOKED', { revokedBy: req.user.username }, ip);
        res.json({ success: true, message: 'Todas las sesiones revocadas exitosamente' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Obtener alertas del usuario actual
app.get('/api/alerts', authenticateToken, apiLimiter, async (req, res) => {
    try {
        const username = req.user.username;
        const alerts = await getUserAlerts(username);
        res.json(alerts);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Obtener todas las alertas (requiere autenticación y rol admin)
app.get('/api/alerts/all', authenticateToken, apiLimiter, async (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ error: 'Solo los administradores pueden ver todas las alertas' });
        }
        
        const alerts = await loadAlerts();
        res.json(alerts.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt)));
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Crear alerta (requiere autenticación y rol admin)
app.post('/api/alerts', authenticateToken, apiLimiter, async (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ error: 'Solo los administradores pueden crear alertas' });
        }
        
        const { title, message, targetUser, type = 'info', category = 'alert', metadata = {} } = req.body;
        const ip = getClientIp(req);
        
        if (!title || !message) {
            return res.status(400).json({ error: 'Título y mensaje requeridos' });
        }
        
        const alert = await createAlert(title, message, targetUser || null, type, category, metadata);
        await addLog('ALERT_CREATED', { 
            alertId: alert.id, 
            title, 
            category,
            targetUser: targetUser || 'all',
            createdBy: req.user.username 
        }, ip);
        
        res.json({ success: true, alert });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Marcar alerta como leída
app.post('/api/alerts/:alertId/read', authenticateToken, apiLimiter, async (req, res) => {
    try {
        const { alertId } = req.params;
        const username = req.user.username;
        
        await markAlertAsRead(alertId, username);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Eliminar alerta (requiere autenticación y rol admin)
app.delete('/api/alerts/:alertId', authenticateToken, apiLimiter, async (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ error: 'Solo los administradores pueden eliminar alertas' });
        }
        
        const { alertId } = req.params;
        const alerts = await loadAlerts();
        const filtered = alerts.filter(a => a.id !== alertId);
        await saveAlerts(filtered);
        
        await addLog('ALERT_DELETED', { alertId, deletedBy: req.user.username }, getClientIp(req));
        res.json({ success: true, message: 'Alerta eliminada exitosamente' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Desactivar modo mantenimiento (requiere autenticación y rol admin)
app.post('/api/maintenance/disable', authenticateToken, apiLimiter, async (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ error: 'Solo los administradores pueden desactivar mantenimiento' });
        }
        
        const ip = getClientIp(req);
        const alerts = await loadAlerts();
        
        // Buscar y actualizar todas las alertas de mantenimiento activas
        let updated = false;
        const updatedAlerts = alerts.map(alert => {
            if (alert.category === 'maintenance' && alert.metadata && alert.metadata.serverStatus) {
                // Cambiar estado a "online" y agregar fecha de fin si no existe
                alert.metadata.serverStatus = 'online';
                if (!alert.metadata.endDate) {
                    alert.metadata.endDate = new Date().toISOString();
                }
                updated = true;
            }
            return alert;
        });
        
        if (updated) {
            await saveAlerts(updatedAlerts);
            await addLog('MAINTENANCE_DISABLED', { disabledBy: req.user.username }, ip);
            res.json({ success: true, message: 'Modo mantenimiento desactivado exitosamente' });
        } else {
            res.json({ success: true, message: 'No hay mantenimiento activo para desactivar' });
        }
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ==================== SISTEMA DE CHAT ====================

// Endpoint para obtener usuarios activos
app.get('/api/chat/active-users', authenticateToken, chatLimiter, async (req, res) => {
    try {
        const currentUsername = req.user.username;
        const activeUsers = [];
        
        // Obtener usuarios de conexiones WebSocket activas
        activeConnections.forEach((conn, socketId) => {
            if (conn.username !== currentUsername) {
                activeUsers.push({
                    username: conn.username,
                    socketId: socketId
                });
            }
        });
        
        // También incluir usuarios de sesiones activas que no tienen conexión WebSocket
        const sessions = await loadSessions();
        const sessionUsers = new Set();
        sessions.forEach(session => {
            if (session.active && session.username !== currentUsername) {
                sessionUsers.add(session.username);
            }
        });
        
        // Agregar usuarios de sesiones que no están en conexiones WebSocket
        sessionUsers.forEach(username => {
            const alreadyInList = activeUsers.some(u => u.username === username);
            if (!alreadyInList) {
                activeUsers.push({
                    username: username,
                    socketId: null // No tiene conexión WebSocket activa
                });
            }
        });
        
        res.json({ success: true, users: activeUsers });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Endpoint para obtener mensajes de un usuario
app.get('/api/chat/messages/:username', authenticateToken, chatLimiter, async (req, res) => {
    try {
        const currentUsername = req.user.username;
        const targetUsername = req.params.username;
        
        const messages = userMessages.get(currentUsername) || [];
        const conversationMessages = messages.filter(msg => 
            (msg.from === targetUsername && msg.to === currentUsername) ||
            (msg.from === currentUsername && msg.to === targetUsername)
        );
        
        res.json({ success: true, messages: conversationMessages });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// WebSocket handlers para chat
io.on('connection', (socket) => {
    console.log(`🔌 Nueva conexión WebSocket: ${socket.id}`);
    
    // Autenticar conexión
    socket.on('authenticate', async (data) => {
        try {
            const { token } = data;
            if (!token) {
                console.log('❌ WebSocket: Token no proporcionado');
                socket.emit('error', { message: 'Token requerido' });
                return;
            }
            
            // Verificar token
            jwt.verify(token, JWT_SECRET, (err, user) => {
                if (err) {
                    console.log('❌ WebSocket: Error al verificar token:', err.message);
                    socket.emit('error', { message: `Token inválido: ${err.message}` });
                    return;
                }
                
                console.log(`✅ WebSocket: Token válido para usuario: ${user.username}`);
                
                // Guardar conexión
                activeConnections.set(socket.id, {
                    username: user.username,
                    token: token,
                    socket: socket
                });
                
                socket.emit('authenticated', { username: user.username });
                
                // Notificar a otros usuarios que este usuario está en línea
                io.emit('user-online', { username: user.username });
                
                console.log(`✅ Usuario autenticado en WebSocket: ${user.username}`);
            });
        } catch (error) {
            console.error('❌ WebSocket: Error en authenticate:', error);
            socket.emit('error', { message: error.message });
        }
    });
    
    // Enviar mensaje privado
    socket.on('private-message', async (data) => {
        try {
            const connection = activeConnections.get(socket.id);
            if (!connection) {
                socket.emit('error', { message: 'No autenticado' });
                return;
            }
            
            const { to, message } = data;
            if (!to || !message) {
                socket.emit('error', { message: 'Destinatario y mensaje requeridos' });
                return;
            }
            
            const from = connection.username;
            const timestamp = new Date().toISOString();
            
            const messageData = {
                from,
                to,
                message,
                timestamp
            };
            
            // Guardar mensaje para ambos usuarios
            if (!userMessages.has(from)) {
                userMessages.set(from, []);
            }
            if (!userMessages.has(to)) {
                userMessages.set(to, []);
            }
            
            userMessages.get(from).push(messageData);
            userMessages.get(to).push(messageData);
            
            // Enviar mensaje al destinatario si está conectado
            let sent = false;
            activeConnections.forEach((conn, socketId) => {
                if (conn.username === to) {
                    console.log(`📤 Enviando mensaje de ${from} a ${to} (socket: ${socketId})`);
                    conn.socket.emit('private-message', messageData);
                    sent = true;
                }
            });
            
            // También enviar el mensaje de vuelta al remitente para confirmación
            // Esto asegura que el mensaje se muestre correctamente en ambos lados
            socket.emit('private-message', messageData);
            
            // Confirmar al remitente
            socket.emit('message-sent', { ...messageData, delivered: sent });
            
            console.log(`✅ Mensaje de ${from} a ${to} ${sent ? 'entregado' : 'guardado (destinatario offline)'}`);
            
            // Si el destinatario no está conectado, el mensaje se guardará y se entregará cuando se conecte
        } catch (error) {
            socket.emit('error', { message: error.message });
        }
    });
    
    // Obtener usuarios activos
    socket.on('get-active-users', () => {
        const connection = activeConnections.get(socket.id);
        if (!connection) {
            socket.emit('error', { message: 'No autenticado' });
            return;
        }
        
        const currentUsername = connection.username;
        const activeUsers = [];
        
        activeConnections.forEach((conn, socketId) => {
            if (conn.username !== currentUsername) {
                activeUsers.push({
                    username: conn.username,
                    socketId: socketId
                });
            }
        });
        
        socket.emit('active-users', { users: activeUsers });
    });
    
    // Desconexión
    socket.on('disconnect', () => {
        const connection = activeConnections.get(socket.id);
        if (connection) {
            const username = connection.username;
            activeConnections.delete(socket.id);
            
            // Notificar a otros usuarios que este usuario se desconectó
            io.emit('user-offline', { username });
            
            console.log(`🔌 Usuario desconectado: ${username}`);
        }
    });
});

// ==================== INICIALIZACIÓN DEL SERVIDOR ====================

// Función para inicializar y cargar todos los datos al inicio
async function initializeServer() {
    try {
        console.log('📦 Inicializando servidor y cargando datos...');
        
        // Cargar todos los datos para verificar que los archivos existen
        const tokens = await loadTokens();
        const history = await loadHistory();
        const logs = await loadLogs();
        const sessions = await loadSessions();
        const alerts = await loadAlerts();
        const config = await loadConfig();
        const users = await loadUsers();
        
        // Mostrar estadísticas de datos cargados
        console.log(`✅ Tokens cargados: ${tokens.length}`);
        console.log(`✅ Historial cargado: ${history.length} registros`);
        console.log(`✅ Logs cargados: ${logs.length} entradas`);
        console.log(`✅ Sesiones cargadas: ${sessions.length} (${sessions.filter(s => s.active).length} activas)`);
        console.log(`✅ Alertas cargadas: ${alerts.length}`);
        console.log(`✅ Usuarios cargados: ${users.length}`);
        console.log(`✅ Configuración cargada`);
        
        // Cargar sesiones activas en memoria
        sessions.forEach(session => {
            if (session.active) {
                activeSessions.set(session.token, session);
            }
        });
        
        console.log('✅ Todos los datos han sido cargados correctamente');
        console.log('💾 Los datos se guardan automáticamente en cada operación');
        
    } catch (error) {
        console.error('❌ Error al inicializar servidor:', error);
        // No lanzar el error, permitir que el servidor inicie de todas formas
        // pero con datos vacíos
    }
}

// Servir archivos estáticos del panel
app.use(express.static(__dirname));

// Iniciar servidor
// Usar el puerto de la variable de entorno (para Railway, Render, Heroku, etc.)
const PORT = process.env.PORT || 3000;

// Inicializar datos antes de iniciar el servidor
initializeServer().then(() => {
    server.listen(PORT, () => {
        console.log(`🚀 Servidor de administración corriendo en puerto ${PORT}`);
        console.log(`📊 Panel de administración: http://localhost:${PORT}/index.html`);
        console.log(`🔗 Endpoint de validación: http://localhost:${PORT}/api/validate-token`);
        console.log(`💬 Sistema de chat WebSocket activo`);
        console.log('💾 Sistema de persistencia activo - Todos los cambios se guardan automáticamente');
    });
}).catch(error => {
    console.error('❌ Error crítico al inicializar:', error);
    // Iniciar servidor de todas formas
    server.listen(PORT, () => {
        console.log(`🚀 Servidor de administración corriendo en puerto ${PORT} (con advertencias)`);
        console.log(`📊 Panel de administración: http://localhost:${PORT}/index.html`);
        console.log(`💬 Sistema de chat WebSocket activo`);
    });
});

