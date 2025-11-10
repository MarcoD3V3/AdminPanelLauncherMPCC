# 🖥️ Desplegar Panel en VPS (Servidor Propio)

## Opciones de VPS Baratos

### 1. DigitalOcean ($4-6/mes)
- https://www.digitalocean.com
- Muy confiable
- $4/mes para el plan básico

### 2. Vultr ($2.50-6/mes)
- https://www.vultr.com
- Muy barato
- $2.50/mes para el plan más básico

### 3. Linode ($5/mes)
- https://www.linode.com
- Buena opción intermedia

## Pasos para desplegar en VPS

### 1. Conectar al servidor
```bash
ssh root@tu-servidor-ip
```

### 2. Instalar Node.js
```bash
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs
```

### 3. Subir archivos
```bash
# Opción A: Con git
git clone tu-repositorio
cd admin_panel

# Opción B: Con scp (desde tu PC)
scp -r admin_panel/* root@tu-servidor-ip:/var/www/panel
```

### 4. Instalar dependencias
```bash
cd admin_panel
npm install
```

### 5. Instalar PM2 (para mantener el servidor corriendo)
```bash
npm install -g pm2
pm2 start server.js
pm2 save
pm2 startup
```

### 6. Configurar Nginx (opcional, para HTTPS)
```bash
sudo apt install nginx
# Configurar nginx para proxy reverso
```

### 7. Configurar dominio (opcional)
- Compra un dominio (Namecheap, GoDaddy, etc.)
- Apunta el DNS a tu IP del VPS
- Configura SSL con Let's Encrypt (gratis)

## Configurar el launcher
```javascript
let TOKEN_VALIDATION_SERVER = 'http://tu-ip:3000/api/validate-token';
// O con dominio:
let TOKEN_VALIDATION_SERVER = 'https://tudominio.com/api/validate-token';
```

## ✅ Ventajas
- ✅ Control total
- ✅ No se "duerme"
- ✅ Más barato a largo plazo
- ✅ Puedes instalar lo que quieras

## ⚠️ Desventajas
- Requiere conocimientos técnicos
- Tienes que mantener el servidor
- Necesitas configurar seguridad

