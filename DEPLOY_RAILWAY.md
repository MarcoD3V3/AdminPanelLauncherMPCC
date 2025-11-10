# 🚂 Desplegar Panel en Railway (GRATIS)

## Paso 1: Crear cuenta
1. Ve a https://railway.app
2. Crea cuenta con GitHub (recomendado) o email

## Paso 2: Crear nuevo proyecto
1. Click en "New Project"
2. Selecciona "Deploy from GitHub repo" (si tienes el código en GitHub)
   O "Empty Project" si vas a subir manualmente

## Paso 3: Configurar
1. Si usas "Empty Project":
   - Click en "Add Service" → "GitHub Repo"
   - Selecciona tu repositorio con el panel

2. Railway detectará automáticamente Node.js

## Paso 4: Variables de entorno (opcional)
Si necesitas cambiar el puerto, agrega:
- `PORT` = (Railway lo asigna automáticamente)

## Paso 5: Obtener URL
1. Railway te dará una URL como: `https://tu-panel.up.railway.app`
2. Copia esta URL

## Paso 6: Configurar el launcher
En `main.js` del launcher, cambia:
```javascript
let TOKEN_VALIDATION_SERVER = 'https://tu-panel.up.railway.app/api/validate-token';
```

## ✅ Ventajas
- ✅ Gratis (500 horas/mes)
- ✅ HTTPS automático
- ✅ Fácil de usar
- ✅ Auto-deploy desde GitHub

## 📝 Nota
Railway puede poner el proyecto en "sleep" si no hay tráfico. Para evitar esto:
- Usa el plan de pago ($5/mes)
- O usa otro servicio como Render

