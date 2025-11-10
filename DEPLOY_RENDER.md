# 🎨 Desplegar Panel en Render (GRATIS)

## Paso 1: Crear cuenta
1. Ve a https://render.com
2. Crea cuenta con GitHub

## Paso 2: Crear nuevo servicio
1. Click en "New +" → "Web Service"
2. Conecta tu repositorio de GitHub
3. O sube los archivos manualmente

## Paso 3: Configurar
- **Name:** token-admin-panel (o el que quieras)
- **Environment:** Node
- **Build Command:** `npm install`
- **Start Command:** `node server.js`
- **Plan:** Free

## Paso 4: Variables de entorno
- `PORT` = 10000 (Render usa este puerto por defecto)

O modifica `server.js` para usar:
```javascript
const PORT = process.env.PORT || 3000;
```

## Paso 5: Desplegar
1. Click en "Create Web Service"
2. Espera a que termine el deploy (2-3 minutos)

## Paso 6: Obtener URL
Render te dará una URL como: `https://token-admin-panel.onrender.com`

## Paso 7: Configurar el launcher
En `main.js` del launcher:
```javascript
let TOKEN_VALIDATION_SERVER = 'https://token-admin-panel.onrender.com/api/validate-token';
```

## ✅ Ventajas
- ✅ Gratis
- ✅ HTTPS automático
- ✅ Auto-deploy desde GitHub
- ⚠️ Puede tardar 30-60 segundos en "despertar" si está inactivo

## ⚠️ Desventajas
- El servicio free se "duerme" después de 15 minutos sin uso
- Primera petición puede tardar 30-60 segundos

