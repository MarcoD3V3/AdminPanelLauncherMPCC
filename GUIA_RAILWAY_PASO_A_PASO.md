# 🚂 Guía Paso a Paso: Desplegar en Railway

## 📋 Paso 1: Preparar el código

### Opción A: Con GitHub (Recomendado)

1. **Crea un repositorio en GitHub:**
   - Ve a https://github.com/new
   - Nombre: `token-admin-panel` (o el que quieras)
   - Crea el repositorio

2. **Sube los archivos:**
   ```bash
   cd admin_panel
   git init
   git add .
   git commit -m "Initial commit"
   git branch -M main
   git remote add origin https://github.com/TU_USUARIO/token-admin-panel.git
   git push -u origin main
   ```

### Opción B: Sin GitHub (Empty Project)

1. En Railway, selecciona **"Empty Project"**
2. Luego subirás los archivos manualmente

---

## 🚀 Paso 2: En Railway

### Si elegiste "GitHub Repository":

1. **Conecta GitHub:**
   - Click en "GitHub Repository"
   - Autoriza Railway a acceder a tu GitHub
   - Selecciona tu repositorio `token-admin-panel`

2. **Railway detectará automáticamente:**
   - Node.js
   - El archivo `package.json`
   - Configurará todo automáticamente

3. **Espera el deploy:**
   - Railway empezará a construir tu proyecto
   - Verás logs en tiempo real
   - Tardará 2-3 minutos

### Si elegiste "Empty Project":

1. **Crea el proyecto vacío**
2. **Agrega servicio:**
   - Click en "Add Service"
   - Selecciona "GitHub Repo" o "Local Directory"
3. **Configura manualmente:**
   - Build Command: `npm install`
   - Start Command: `node server.js`

---

## 🔗 Paso 3: Obtener tu URL

Una vez termine el deploy:

1. **Railway te dará una URL:**
   - Algo como: `https://tu-panel-production.up.railway.app`
   - O puedes crear un dominio personalizado

2. **Copia esta URL** - la necesitarás

---

## ⚙️ Paso 4: Configurar el Launcher

En `main.js` del launcher, cambia:

```javascript
let TOKEN_VALIDATION_SERVER = 'https://tu-panel-production.up.railway.app/api/validate-token';
```

**Reemplaza** `tu-panel-production.up.railway.app` con tu URL real.

---

## ✅ Paso 5: Verificar que funciona

1. **Abre el panel:**
   - Ve a: `https://tu-url.up.railway.app/index.html`
   - Deberías ver el panel de administración

2. **Prueba el endpoint:**
   - Ve a: `https://tu-url.up.railway.app/api/tokens`
   - Deberías ver `[]` (array vacío si no hay tokens)

3. **Genera un token:**
   - En el panel, genera un token
   - Pruébalo en el launcher

---

## 🎯 Configuración Adicional (Opcional)

### Agregar dominio personalizado:

1. En Railway, ve a tu proyecto
2. Click en "Settings"
3. "Domains" → "Add Domain"
4. Ingresa tu dominio
5. Configura el DNS según las instrucciones

### Variables de entorno:

Si necesitas cambiar algo, en Railway:
1. Settings → Variables
2. Agrega variables si es necesario
3. (Para este panel, no necesitas ninguna)

---

## 🆘 Solución de Problemas

### El deploy falla:
- Verifica que `package.json` esté correcto
- Revisa los logs en Railway
- Asegúrate de que `server.js` esté en la raíz

### No se conecta el launcher:
- Verifica que la URL sea correcta
- Asegúrate de usar `https://` (no `http://`)
- Verifica que el endpoint sea `/api/validate-token`

### El panel no carga:
- Verifica que el archivo `index.html` esté en la carpeta
- Revisa la consola del navegador (F12)

---

## 📝 Checklist Final

- [ ] Código subido a GitHub (o Railway)
- [ ] Proyecto creado en Railway
- [ ] Deploy completado exitosamente
- [ ] URL copiada
- [ ] URL configurada en `main.js` del launcher
- [ ] Panel accesible en el navegador
- [ ] Token generado y probado

---

## 🎉 ¡Listo!

Tu panel está en producción. Ahora puedes:
- Generar tokens desde cualquier lugar
- El launcher validará tokens contra tu servidor
- Todo funciona con HTTPS automático

