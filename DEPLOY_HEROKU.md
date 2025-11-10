# 🟣 Desplegar Panel en Heroku (GRATIS - Limitado)

## ⚠️ Nota Importante
Heroku eliminó su plan gratuito en 2022. Ahora el plan más barato es $5/mes.
Si buscas gratis, usa Railway o Render.

## Si aún quieres usar Heroku:

### Paso 1: Instalar Heroku CLI
Descarga desde: https://devcenter.heroku.com/articles/heroku-cli

### Paso 2: Login
```bash
heroku login
```

### Paso 3: Crear app
```bash
cd admin_panel
heroku create tu-panel-tokens
```

### Paso 4: Desplegar
```bash
git init
git add .
git commit -m "Initial commit"
git push heroku main
```

### Paso 5: Obtener URL
```bash
heroku open
```

## Configurar el launcher
```javascript
let TOKEN_VALIDATION_SERVER = 'https://tu-panel-tokens.herokuapp.com/api/validate-token';
```

## 💰 Costo
- Plan más barato: $5/mes
- No recomendado si buscas gratis

