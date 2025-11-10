# 🚀 Panel de Administración - Versión React

Panel de administración de tokens migrado completamente a React.

## 📁 Estructura del Proyecto

```
admin_panel/
├── public/
│   └── index.html          # HTML base
├── src/
│   ├── components/         # Componentes React
│   │   ├── Header.js
│   │   ├── Stats.js
│   │   ├── Actions.js
│   │   ├── TokenTable.js
│   │   ├── GenerateTokenModal.js
│   │   └── Notification.js
│   ├── context/
│   │   └── TokenContext.js # Context API para estado global
│   ├── App.js              # Componente principal
│   ├── App.css
│   ├── index.js            # Punto de entrada
│   └── index.css
├── server.js               # Backend Express (sin cambios)
├── package.json
└── README_REACT.md
```

## 🚀 Instalación y Desarrollo

### Instalar dependencias:
```bash
npm install
```

### Modo desarrollo (frontend + backend):
```bash
npm run dev
```

Esto iniciará:
- React en http://localhost:3000
- Backend API en http://localhost:3001

### Solo frontend:
```bash
npm start
```

### Solo backend:
```bash
npm run server
```

## 🏗️ Build para Producción

### Compilar React:
```bash
npm run build
```

Esto crea la carpeta `build/` con los archivos optimizados.

### En Railway:
Railway automáticamente:
1. Detecta que es React
2. Ejecuta `npm install`
3. Ejecuta `npm run build`
4. El servidor sirve los archivos desde `build/`

## 🎯 Características

- ✅ **React 18** con hooks modernos
- ✅ **Context API** para estado global
- ✅ **Componentes funcionales** con hooks
- ✅ **CSS modular** por componente
- ✅ **Responsive design**
- ✅ **Mismo diseño** que la versión anterior
- ✅ **Toda la funcionalidad** mantenida

## 📦 Componentes

### Header
- Título y subtítulo del panel

### Stats
- Muestra estadísticas: Total, Usados, Disponibles
- Se actualiza automáticamente

### Actions
- Botones de acción: Generar, Actualizar, Limpiar
- Maneja el modal de generación

### TokenTable
- Tabla de tokens con búsqueda
- Acciones: Eliminar, Copiar
- Estados: Disponible/Usado

### GenerateTokenModal
- Modal para generar tokens
- Validación de cantidad (1-100)

### Notification
- Sistema de notificaciones
- Tipos: success, error, info

## 🔧 Context API

El `TokenContext` maneja:
- Estado de tokens
- Funciones CRUD
- Notificaciones
- Estadísticas calculadas

## 🌐 Desplegar en Railway

1. **Sube el código a GitHub**
2. **En Railway:**
   - New Project → GitHub Repo
   - Selecciona tu repositorio
   - Railway detecta React automáticamente
3. **Railway ejecutará:**
   - `npm install`
   - `npm run build`
   - `node server.js` (servirá los archivos de build)

## ⚙️ Configuración del Servidor

El `server.js` está configurado para:
- En **producción**: Servir archivos de `build/`
- En **desarrollo**: Servir archivos estáticos normales
- API siempre disponible en `/api/*`

## 🆚 Diferencias con versión anterior

| Aspecto | Versión Anterior | Versión React |
|---------|-----------------|---------------|
| Framework | Vanilla JS | React 18 |
| Estado | Variables globales | Context API |
| Componentes | Funciones | Componentes React |
| Build | No necesario | `npm run build` |
| Organización | Un archivo grande | Múltiples componentes |

## 🐛 Solución de Problemas

### El build falla:
```bash
# Limpia y reinstala
rm -rf node_modules build
npm install
npm run build
```

### El servidor no sirve React:
- Verifica que `build/` existe
- Verifica que `NODE_ENV=production`
- Revisa los logs del servidor

### CORS errors:
- El servidor ya tiene CORS configurado
- Verifica que la URL de la API sea correcta

## 📝 Notas

- El backend (`server.js`) no cambió
- La API sigue siendo la misma
- Compatible con la versión anterior del launcher
- Listo para Railway sin configuración extra

