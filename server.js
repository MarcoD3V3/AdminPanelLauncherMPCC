const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const fs = require('fs').promises;
const path = require('path');

const app = express();
const TOKENS_FILE = path.join(__dirname, 'tokens.json');

// Middleware
app.use(cors());
app.use(express.json());

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

// Generar token único
function generateToken() {
    return crypto.randomBytes(32).toString('hex').toUpperCase();
}

// ==================== RUTAS ====================

// Obtener todos los tokens
app.get('/api/tokens', async (req, res) => {
    try {
        const tokens = await loadTokens();
        res.json(tokens);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Generar nuevos tokens
app.post('/api/tokens/generate', async (req, res) => {
    try {
        const { count = 1 } = req.body;
        const tokens = await loadTokens();
        
        const newTokens = [];
        for (let i = 0; i < count; i++) {
            const token = generateToken();
            newTokens.push({
                token: token,
                used: false,
                createdAt: new Date().toISOString(),
                usedAt: null
            });
        }
        
        tokens.push(...newTokens);
        await saveTokens(tokens);
        
        res.json({ 
            success: true, 
            tokens: newTokens,
            message: `${count} token(s) generado(s) exitosamente`
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Validar token (usado por el launcher)
app.post('/api/validate-token', async (req, res) => {
    try {
        const { token } = req.body;
        
        if (!token) {
            return res.status(400).json({
                valid: false,
                success: false,
                error: 'Token no proporcionado'
            });
        }
        
        const tokens = await loadTokens();
        const tokenRecord = tokens.find(t => t.token === token);
        
        if (!tokenRecord) {
            return res.status(400).json({
                valid: false,
                success: false,
                error: 'Token no encontrado'
            });
        }
        
        if (tokenRecord.used) {
            return res.status(400).json({
                valid: false,
                success: false,
                error: 'Token ya ha sido usado'
            });
        }
        
        // Marcar como usado
        tokenRecord.used = true;
        tokenRecord.usedAt = new Date().toISOString();
        await saveTokens(tokens);
        
        res.json({
            valid: true,
            success: true,
            message: 'Token válido'
        });
    } catch (error) {
        res.status(500).json({
            valid: false,
            success: false,
            error: error.message
        });
    }
});

// Eliminar un token
app.delete('/api/tokens/:token', async (req, res) => {
    try {
        const { token } = req.params;
        const tokens = await loadTokens();
        const filtered = tokens.filter(t => t.token !== token);
        
        if (filtered.length === tokens.length) {
            return res.status(404).json({ error: 'Token no encontrado' });
        }
        
        await saveTokens(filtered);
        res.json({ success: true, message: 'Token eliminado exitosamente' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Limpiar tokens usados
app.delete('/api/tokens/clear-used', async (req, res) => {
    try {
        const tokens = await loadTokens();
        const available = tokens.filter(t => !t.used);
        await saveTokens(available);
        
        res.json({ 
            success: true, 
            message: 'Tokens usados eliminados exitosamente',
            deleted: tokens.length - available.length
        });
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

