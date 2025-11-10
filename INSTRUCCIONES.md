# 📖 Instrucciones Rápidas - Panel de Administración

## 🚀 Inicio Rápido

### 1. Instalar dependencias
```bash
cd admin_panel
npm install
```

### 2. Iniciar el servidor
```bash
npm start
```

### 3. Abrir el panel
Abre tu navegador en: **http://localhost:3000/index.html**

## 📝 Cómo usar el panel

### Generar Tokens
1. Haz clic en "➕ Generar Nuevo Token"
2. Elige cuántos tokens quieres generar (1-100)
3. Haz clic en "Generar"
4. Los tokens aparecerán en la tabla

### Ver Tokens
- La tabla muestra todos los tokens
- **Verde** = Disponible (no usado)
- **Rojo** = Usado

### Copiar Token
- Haz clic en el botón 📋 junto al token
- Se copiará al portapapeles

### Eliminar Token
- Haz clic en el botón 🗑️ junto al token
- Confirma la eliminación

### Buscar Token
- Usa el campo de búsqueda para filtrar tokens

## 🔗 Conectar con el Launcher

### Opción 1: Servidor Local (Desarrollo)
En `main.js` del launcher:
```javascript
let TOKEN_VALIDATION_SERVER = 'http://localhost:3000/api/validate-token';
```

### Opción 2: Servidor Remoto (Producción)
1. Sube el panel a tu servidor (Heroku, Railway, VPS, etc.)
2. En `main.js` del launcher:
```javascript
let TOKEN_VALIDATION_SERVER = 'https://tu-servidor.com/api/validate-token';
```

## 🌐 Desplegar en Internet

### Opción A: Heroku (Gratis)
1. Crea cuenta en Heroku
2. Instala Heroku CLI
3. En la carpeta `admin_panel`:
```bash
heroku create tu-panel-tokens
git init
git add .
git commit -m "Initial commit"
git push heroku main
```

### Opción B: Railway (Gratis)
1. Crea cuenta en Railway
2. Conecta tu repositorio
3. Railway detectará automáticamente Node.js y lo desplegará

### Opción C: VPS (Servidor propio)
1. Sube los archivos a tu servidor
2. Instala Node.js
3. Instala PM2: `npm install -g pm2`
4. Inicia: `pm2 start server.js`
5. Configura nginx o similar como proxy reverso

## 🔒 Seguridad (Importante para Producción)

El panel actual NO tiene autenticación. Para producción, agrega:

1. **Login básico** - Agrega usuario/contraseña
2. **HTTPS** - Usa SSL/TLS
3. **Rate Limiting** - Limita peticiones por IP
4. **Base de datos** - Usa MongoDB/PostgreSQL en lugar de archivo JSON

## 📊 Estructura de Datos

Los tokens se guardan en `tokens.json`:
```json
[
  {
    "token": "ABC123...",
    "used": false,
    "createdAt": "2025-11-10T01:00:00.000Z",
    "usedAt": null
  }
]
```

## 🆘 Solución de Problemas

### El servidor no inicia
- Verifica que el puerto 3000 no esté en uso
- Cambia el puerto en `server.js` si es necesario

### No se cargan los tokens
- Verifica que `tokens.json` exista
- Revisa la consola del navegador (F12)

### El launcher no valida tokens
- Verifica que la URL en `main.js` sea correcta
- Asegúrate de que el servidor esté corriendo
- Revisa los logs del servidor

## 💡 Próximos Pasos

1. ✅ Panel básico funcionando
2. 🔄 Agregar autenticación
3. 🔄 Migrar a base de datos
4. 🔄 Agregar más estadísticas
5. 🔄 Exportar tokens a CSV/Excel

