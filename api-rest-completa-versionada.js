// api-rest-completa-versionada.js
const express = require('express');
const crypto = require('crypto');
const app = express();
app.use(express.json());

// ============================================
// CONFIGURACIÓN Y ALMACENAMIENTO
// ============================================

const JWT_SECRET = 'mi-secreto-super-seguro-2024';
const JWT_EXPIRATION = '24h';

// Base de datos simulada
let productos = [
  { id: 1, nombre: 'Laptop', precio: 1000, categoria: 'Electrónica', stock: 5, activo: true },
  { id: 2, nombre: 'Mouse', precio: 25, categoria: 'Accesorios', stock: 10, activo: true },
  { id: 3, nombre: 'Teclado', precio: 75, categoria: 'Accesorios', stock: 8, activo: true }
];

let siguienteId = 4;

// Usuarios simulados (en producción usar base de datos con bcrypt)
const usuarios = [
  { id: 1, username: 'admin', password: 'admin123', role: 'admin' },
  { id: 2, username: 'user', password: 'user123', role: 'user' }
];

// Almacenamiento de webhooks
let webhooks = [];
let webhookIdCounter = 1;

// Almacenamiento de logs
let logs = [];

// Rate limiting storage
const rateLimitMap = new Map();

// ============================================
// UTILIDADES JWT
// ============================================

function base64UrlEncode(str) {
  return Buffer.from(str)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

function base64UrlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  return Buffer.from(str, 'base64').toString();
}

function createJWT(payload) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const now = Math.floor(Date.now() / 1000);
  
  const tokenPayload = {
    ...payload,
    iat: now,
    exp: now + 86400 // 24 horas
  };

  const encodedHeader = base64UrlEncode(JSON.stringify(header));
  const encodedPayload = base64UrlEncode(JSON.stringify(tokenPayload));
  const signatureInput = `${encodedHeader}.${encodedPayload}`;
  
  const signature = crypto
    .createHmac('sha256', JWT_SECRET)
    .update(signatureInput)
    .digest('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');

  return `${encodedHeader}.${encodedPayload}.${signature}`;
}

function verifyJWT(token) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;

    const [encodedHeader, encodedPayload, signature] = parts;
    const signatureInput = `${encodedHeader}.${encodedPayload}`;
    
    const expectedSignature = crypto
      .createHmac('sha256', JWT_SECRET)
      .update(signatureInput)
      .digest('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');

    if (signature !== expectedSignature) return null;

    const payload = JSON.parse(base64UrlDecode(encodedPayload));
    
    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) {
      return null; // Token expirado
    }

    return payload;
  } catch (error) {
    return null;
  }
}

// ============================================
// SISTEMA DE LOGGING
// ============================================

function log(level, message, metadata = {}) {
  const logEntry = {
    timestamp: new Date().toISOString(),
    level,
    message,
    ...metadata
  };
  
  logs.push(logEntry);
  
  // Mantener solo los últimos 1000 logs
  if (logs.length > 1000) {
    logs = logs.slice(-1000);
  }

  // Imprimir en consola con colores
  const colors = {
    info: '\x1b[36m',
    warn: '\x1b[33m',
    error: '\x1b[31m',
    success: '\x1b[32m'
  };
  const reset = '\x1b[0m';
  console.log(`${colors[level] || ''}[${level.toUpperCase()}] ${message}${reset}`, metadata);
}

// ============================================
// SISTEMA DE WEBHOOKS
// ============================================

async function triggerWebhooks(event, data) {
  const activeWebhooks = webhooks.filter(w => w.events.includes(event) && w.active);
  
  log('info', `Disparando ${activeWebhooks.length} webhooks para evento: ${event}`);

  for (const webhook of activeWebhooks) {
    try {
      const payload = {
        event,
        timestamp: new Date().toISOString(),
        data
      };

      // En un entorno real, usarías fetch o axios
      log('success', `Webhook disparado: ${webhook.url}`, { event, webhookId: webhook.id });
      
      // Simular envío exitoso
      webhook.lastTriggered = new Date().toISOString();
      webhook.deliveryCount = (webhook.deliveryCount || 0) + 1;
      
    } catch (error) {
      log('error', `Error al disparar webhook ${webhook.id}`, { error: error.message });
    }
  }
}

// ============================================
// MIDDLEWARES
// ============================================

// Middleware de logging de requests
app.use((req, res, next) => {
  const start = Date.now();
  
  res.on('finish', () => {
    const duration = Date.now() - start;
    log('info', `${req.method} ${req.path}`, {
      method: req.method,
      path: req.path,
      statusCode: res.statusCode,
      duration: `${duration}ms`,
      ip: req.ip,
      userAgent: req.get('user-agent')
    });
  });
  
  next();
});

// Middleware de autenticación JWT
function authenticateJWT(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    log('warn', 'Intento de acceso sin token', { path: req.path });
    return res.status(401).json({ error: 'Token no proporcionado' });
  }

  const token = authHeader.substring(7);
  const payload = verifyJWT(token);

  if (!payload) {
    log('warn', 'Token inválido o expirado', { path: req.path });
    return res.status(403).json({ error: 'Token inválido o expirado' });
  }

  req.user = payload;
  next();
}

// Middleware opcional de autenticación (permite acceso sin token)
function optionalAuth(req, res, next) {
  const authHeader = req.headers.authorization;

  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.substring(7);
    const payload = verifyJWT(token);
    if (payload) {
      req.user = payload;
    }
  }

  next();
}

// Middleware de verificación de rol
function requireRole(role) {
  return (req, res, next) => {
    if (!req.user || req.user.role !== role) {
      log('warn', 'Acceso denegado por rol insuficiente', { 
        user: req.user?.username, 
        requiredRole: role,
        path: req.path 
      });
      return res.status(403).json({ error: 'Permisos insuficientes' });
    }
    next();
  };
}

// Middleware de rate limiting
function rateLimiter(options = {}) {
  const windowMs = options.windowMs || 60000; // 1 minuto por defecto
  const maxRequests = options.maxRequests || 100;

  return (req, res, next) => {
    const identifier = req.user?.id || req.ip;
    const now = Date.now();
    
    if (!rateLimitMap.has(identifier)) {
      rateLimitMap.set(identifier, { count: 1, resetTime: now + windowMs });
      return next();
    }

    const userData = rateLimitMap.get(identifier);

    if (now > userData.resetTime) {
      userData.count = 1;
      userData.resetTime = now + windowMs;
      return next();
    }

    if (userData.count >= maxRequests) {
      const resetIn = Math.ceil((userData.resetTime - now) / 1000);
      log('warn', 'Rate limit excedido', { identifier, path: req.path });
      
      res.set('X-RateLimit-Limit', maxRequests);
      res.set('X-RateLimit-Remaining', 0);
      res.set('X-RateLimit-Reset', userData.resetTime);
      
      return res.status(429).json({
        error: 'Demasiadas solicitudes',
        message: `Límite de ${maxRequests} peticiones por minuto excedido`,
        resetIn: `${resetIn} segundos`
      });
    }

    userData.count++;
    
    res.set('X-RateLimit-Limit', maxRequests);
    res.set('X-RateLimit-Remaining', maxRequests - userData.count);
    res.set('X-RateLimit-Reset', userData.resetTime);
    
    next();
  };
}

// Middleware de content negotiation
app.use((req, res, next) => {
  const accept = req.headers.accept || '';
  const format = req.query.format;

  if (format === 'xml' || accept.includes('application/xml') || accept.includes('text/xml')) {
    req.requestedFormat = 'xml';
  } else if (format === 'html' || accept.includes('text/html')) {
    req.requestedFormat = 'html';
  } else {
    req.requestedFormat = 'json';
  }

  next();
});

// ============================================
// FUNCIONES HELPER
// ============================================

function objectToXML(obj, rootName = 'response') {
  function toXML(data, name) {
    if (data === null || data === undefined) return '';

    if (typeof data === 'object' && !Array.isArray(data)) {
      const children = Object.entries(data)
        .map(([key, value]) => toXML(value, key))
        .join('');
      return `<${name}>${children}</${name}>`;
    }

    if (Array.isArray(data)) {
      const items = data.map((item) => toXML(item, 'item')).join('');
      return `<${name}>${items}</${name}>`;
    }

    return `<${name}>${data}</${name}>`;
  }

  return `<?xml version="1.0" encoding="UTF-8"?>\n${toXML(obj, rootName)}`;
}

function sendResponse(res, data, statusCode = 200, format = 'json') {
  res.status(statusCode);

  switch (format) {
    case 'xml':
      res.set('Content-Type', 'application/xml');
      return res.send(objectToXML(data));

    case 'html':
      res.set('Content-Type', 'text/html');
      if (typeof data === 'string') {
        return res.send(data);
      }
      return res.send(`<pre>${JSON.stringify(data, null, 2)}</pre>`);

    default:
      return res.json(data);
  }
}

// ============================================
// RUTAS DE AUTENTICACIÓN
// ============================================

app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username y password requeridos' });
  }

  const usuario = usuarios.find(u => u.username === username && u.password === password);

  if (!usuario) {
    log('warn', 'Intento de login fallido', { username });
    return res.status(401).json({ error: 'Credenciales inválidas' });
  }

  const token = createJWT({
    id: usuario.id,
    username: usuario.username,
    role: usuario.role
  });

  log('success', 'Login exitoso', { username, role: usuario.role });

  res.json({
    success: true,
    message: 'Login exitoso',
    token,
    user: {
      id: usuario.id,
      username: usuario.username,
      role: usuario.role
    }
  });
});

app.get('/api/auth/me', authenticateJWT, (req, res) => {
  res.json({
    success: true,
    user: req.user
  });
});

// ============================================
// RUTAS DE WEBHOOKS
// ============================================

app.post('/api/webhooks', authenticateJWT, requireRole('admin'), (req, res) => {
  const { url, events, description } = req.body;

  if (!url || !events || !Array.isArray(events)) {
    return res.status(400).json({
      error: 'URL y events (array) son requeridos'
    });
  }

  const validEvents = ['producto.creado', 'producto.actualizado', 'producto.eliminado'];
  const invalidEvents = events.filter(e => !validEvents.includes(e));

  if (invalidEvents.length > 0) {
    return res.status(400).json({
      error: 'Eventos inválidos',
      invalidEvents,
      validEvents
    });
  }

  const webhook = {
    id: webhookIdCounter++,
    url,
    events,
    description: description || '',
    active: true,
    createdAt: new Date().toISOString(),
    createdBy: req.user.username,
    deliveryCount: 0
  };

  webhooks.push(webhook);
  log('success', 'Webhook registrado', { webhookId: webhook.id, url, events });

  res.status(201).json({
    success: true,
    message: 'Webhook registrado exitosamente',
    data: webhook
  });
});

app.get('/api/webhooks', authenticateJWT, requireRole('admin'), (req, res) => {
  res.json({
    success: true,
    data: webhooks,
    total: webhooks.length
  });
});

app.delete('/api/webhooks/:id', authenticateJWT, requireRole('admin'), (req, res) => {
  const id = parseInt(req.params.id);
  const index = webhooks.findIndex(w => w.id === id);

  if (index === -1) {
    return res.status(404).json({ error: 'Webhook no encontrado' });
  }

  const deleted = webhooks.splice(index, 1)[0];
  log('info', 'Webhook eliminado', { webhookId: id });

  res.json({
    success: true,
    message: 'Webhook eliminado',
    data: deleted
  });
});

// ============================================
// RUTAS DE LOGS
// ============================================

app.get('/api/logs', authenticateJWT, requireRole('admin'), (req, res) => {
  const { level, limit = 100 } = req.query;
  
  let filteredLogs = logs;
  
  if (level) {
    filteredLogs = filteredLogs.filter(l => l.level === level);
  }

  const limitNum = parseInt(limit);
  const recentLogs = filteredLogs.slice(-limitNum);

  res.json({
    success: true,
    data: recentLogs,
    total: logs.length,
    filtered: filteredLogs.length,
    showing: recentLogs.length
  });
});

// ============================================
// CREAR ROUTERS VERSIONADOS
// ============================================

function createVersionedRouter(version) {
  const router = express.Router();

  router.use((req, res, next) => {
    req.apiVersion = version;
    res.set('API-Version', version);
    next();
  });

  return router;
}

const v1Router = createVersionedRouter('v1');
const v2Router = createVersionedRouter('v2');

// ============================================
// API V1 - BÁSICA
// ============================================

v1Router.get('/productos', rateLimiter({ maxRequests: 50 }), optionalAuth, (req, res) => {
  const { categoria } = req.query;
  let resultados = productos;

  if (categoria) {
    resultados = resultados.filter(p => p.categoria === categoria);
  }

  sendResponse(res, {
    productos: resultados.map(p => ({
      id: p.id,
      nombre: p.nombre,
      precio: p.precio
    }))
  }, 200, req.requestedFormat);
});

v1Router.get('/productos/:id', rateLimiter({ maxRequests: 100 }), optionalAuth, (req, res) => {
  const id = parseInt(req.params.id);
  const producto = productos.find(p => p.id === id);

  if (!producto) {
    return sendResponse(res, { error: 'Producto no encontrado' }, 404, req.requestedFormat);
  }

  sendResponse(res, {
    id: producto.id,
    nombre: producto.nombre,
    precio: producto.precio
  }, 200, req.requestedFormat);
});

v1Router.post('/productos', authenticateJWT, rateLimiter({ maxRequests: 20 }), (req, res) => {
  const { nombre, precio } = req.body;

  if (!nombre || !precio) {
    return sendResponse(res, { error: 'Nombre y precio requeridos' }, 400, req.requestedFormat);
  }

  const nuevoProducto = {
    id: siguienteId++,
    nombre,
    precio: parseFloat(precio),
    categoria: 'General',
    stock: 0,
    activo: true
  };

  productos.push(nuevoProducto);
  
  triggerWebhooks('producto.creado', nuevoProducto);
  
  sendResponse(res, { mensaje: 'Producto creado', producto: nuevoProducto }, 201, req.requestedFormat);
});

// ============================================
// API V2 - AVANZADA CON TODAS LAS FUNCIONALIDADES
// ============================================

v2Router.get('/productos', rateLimiter({ maxRequests: 100 }), optionalAuth, (req, res) => {
  const {
    categoria,
    precio_min,
    precio_max,
    activo,
    pagina = 1,
    limite = 10,
    ordenar
  } = req.query;

  let resultados = [...productos];

  if (categoria) {
    resultados = resultados.filter(p => p.categoria === categoria);
  }

  if (precio_min) {
    resultados = resultados.filter(p => p.precio >= parseFloat(precio_min));
  }

  if (precio_max) {
    resultados = resultados.filter(p => p.precio <= parseFloat(precio_max));
  }

  if (activo !== undefined) {
    resultados = resultados.filter(p => p.activo === (activo === 'true'));
  }

  if (ordenar) {
    switch (ordenar) {
      case 'precio_asc':
        resultados.sort((a, b) => a.precio - b.precio);
        break;
      case 'precio_desc':
        resultados.sort((a, b) => b.precio - a.precio);
        break;
      case 'nombre':
        resultados.sort((a, b) => a.nombre.localeCompare(b.nombre));
        break;
    }
  }

  const paginaNum = parseInt(pagina);
  const limiteNum = parseInt(limite);
  const inicio = (paginaNum - 1) * limiteNum;
  const paginados = resultados.slice(inicio, inicio + limiteNum);

  const respuesta = {
    success: true,
    data: paginados,
    meta: {
      total: resultados.length,
      pagina: paginaNum,
      limite: limiteNum,
      paginasTotal: Math.ceil(resultados.length / limiteNum)
    }
  };

  sendResponse(res, respuesta, 200, req.requestedFormat);
});

v2Router.get('/productos/:id', rateLimiter({ maxRequests: 100 }), optionalAuth, (req, res) => {
  const id = parseInt(req.params.id);
  const producto = productos.find(p => p.id === id);

  if (!producto) {
    return sendResponse(res, { error: 'Producto no encontrado' }, 404, req.requestedFormat);
  }

  sendResponse(res, {
    success: true,
    data: producto
  }, 200, req.requestedFormat);
});

v2Router.post('/productos', authenticateJWT, rateLimiter({ maxRequests: 30 }), (req, res) => {
  const { nombre, precio, categoria, stock } = req.body;

  if (!nombre || !precio) {
    return sendResponse(res, {
      error: 'Nombre y precio son requeridos',
      camposRequeridos: ['nombre', 'precio']
    }, 400, req.requestedFormat);
  }

  if (precio <= 0) {
    return sendResponse(res, { error: 'El precio debe ser mayor a 0' }, 400, req.requestedFormat);
  }

  const nuevoProducto = {
    id: siguienteId++,
    nombre: nombre.trim(),
    precio: parseFloat(precio),
    categoria: categoria || 'General',
    stock: parseInt(stock) || 0,
    activo: true,
    fechaCreacion: new Date().toISOString(),
    creadoPor: req.user.username
  };

  productos.push(nuevoProducto);
  
  log('success', 'Producto creado', { productoId: nuevoProducto.id, usuario: req.user.username });
  triggerWebhooks('producto.creado', nuevoProducto);

  sendResponse(res, {
    success: true,
    message: 'Producto creado exitosamente',
    data: nuevoProducto
  }, 201, req.requestedFormat);
});

v2Router.put('/productos/:id', authenticateJWT, rateLimiter({ maxRequests: 30 }), (req, res) => {
  const id = parseInt(req.params.id);
  const indice = productos.findIndex(p => p.id === id);

  if (indice === -1) {
    return sendResponse(res, { error: 'Producto no encontrado' }, 404, req.requestedFormat);
  }

  const { nombre, precio, categoria, stock, activo } = req.body;

  if (!nombre || !precio) {
    return sendResponse(res, { error: 'Nombre y precio son requeridos' }, 400, req.requestedFormat);
  }

  const productoAnterior = { ...productos[indice] };

  productos[indice] = {
    ...productos[indice],
    nombre: nombre.trim(),
    precio: parseFloat(precio),
    categoria: categoria || productos[indice].categoria,
    stock: parseInt(stock) || productos[indice].stock,
    activo: activo !== undefined ? activo : productos[indice].activo,
    fechaActualizacion: new Date().toISOString(),
    actualizadoPor: req.user.username
  };

  log('success', 'Producto actualizado', { 
    productoId: id, 
    usuario: req.user.username,
    cambios: { anterior: productoAnterior, nuevo: productos[indice] }
  });
  
  triggerWebhooks('producto.actualizado', {
    anterior: productoAnterior,
    nuevo: productos[indice]
  });

  sendResponse(res, {
    success: true,
    message: 'Producto actualizado',
    data: productos[indice]
  }, 200, req.requestedFormat);
});

v2Router.patch('/productos/:id', authenticateJWT, rateLimiter({ maxRequests: 30 }), (req, res) => {
  const id = parseInt(req.params.id);
  const indice = productos.findIndex(p => p.id === id);

  if (indice === -1) {
    return sendResponse(res, { error: 'Producto no encontrado' }, 404, req.requestedFormat);
  }

  const camposPermitidos = ['nombre', 'precio', 'categoria', 'stock', 'activo'];
  const actualizaciones = {};

  Object.keys(req.body).forEach(key => {
    if (camposPermitidos.includes(key)) {
      actualizaciones[key] = req.body[key];
    }
  });

  if (Object.keys(actualizaciones).length === 0) {
    return sendResponse(res, { error: 'No hay campos válidos para actualizar' }, 400, req.requestedFormat);
  }

  const productoAnterior = { ...productos[indice] };

  productos[indice] = {
    ...productos[indice],
    ...actualizaciones,
    fechaActualizacion: new Date().toISOString(),
    actualizadoPor: req.user.username
  };

  log('success', 'Producto parcialmente actualizado', { 
    productoId: id, 
    usuario: req.user.username,
    campos: Object.keys(actualizaciones)
  });

  triggerWebhooks('producto.actualizado', {
    anterior: productoAnterior,
    nuevo: productos[indice]
  });

  sendResponse(res, {
    success: true,
    message: 'Producto actualizado parcialmente',
    data: productos[indice]
  }, 200, req.requestedFormat);
});

v2Router.delete('/productos/:id', authenticateJWT, requireRole('admin'), rateLimiter({ maxRequests: 20 }), (req, res) => {
  const id = parseInt(req.params.id);
  const indice = productos.findIndex(p => p.id === id);

  if (indice === -1) {
    return sendResponse(res, { error: 'Producto no encontrado' }, 404, req.requestedFormat);
  }

  const productoEliminado = productos.splice(indice, 1)[0];

  log('warn', 'Producto eliminado', { 
    productoId: id, 
    usuario: req.user.username,
    producto: productoEliminado
  });

  triggerWebhooks('producto.eliminado', productoEliminado);

  sendResponse(res, {
    success: true,
    message: 'Producto eliminado',
    data: productoEliminado
  }, 200, req.requestedFormat);
});

// ============================================
// MONTAR VERSIONES
// ============================================

app.use('/api/v1', v1Router);
app.use('/api/v2', v2Router);
app.use('/api', v2Router);

// ============================================
// DOCUMENTACIÓN OPENAPI
// ============================================

app.get('/api/openapi.json', (req, res) => {
  const openApiSpec = {
    openapi: '3.0.0',
    info: {
      title: 'API REST Completa con Versionado',
      version: '2.0.0',
      description: 'API completa con autenticación JWT, rate limiting, logging y webhooks',
      contact: {
        name: 'API Support',
        email: 'soporte@api.com'
      }
    },
    servers: [
      {
        url: `http://localhost:${PORT}/api/v2`,
        description: 'Servidor de desarrollo - API v2'
      },
      {
        url: `http://localhost:${PORT}/api/v1`,
        description: 'Servidor de desarrollo - API v1 (deprecated)'
      }
    ],
    components: {
      securitySchemes: {
        bearerAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT'
        }
      },
      schemas: {
        Producto: {
          type: 'object',
          properties: {
            id: { type: 'integer' },
            nombre: { type: 'string' },
            precio: { type: 'number' },
            categoria: { type: 'string' },
            stock: { type: 'integer' },
            activo: { type: 'boolean' },
            fechaCreacion: { type: 'string', format: 'date-time' },
            fechaActualizacion: { type: 'string', format: 'date-time' }
          }
        },
        Error: {
          type: 'object',
          properties: {
            error: { type: 'string' },
            message: { type: 'string' }
          }
        }
      }
    },
    paths: {
      '/auth/login': {
        post: {
          tags: ['Autenticación'],
          summary: 'Iniciar sesión',
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    username: { type: 'string', example: 'admin' },
                    password: { type: 'string', example: 'admin123' }
                  }
                }
              }
            }
          },
          responses: {
            200: {
              description: 'Login exitoso',
              content: {
                'application/json': {
                  schema: {
                    type: 'object',
                    properties: {
                      success: { type: 'boolean' },
                      token: { type: 'string' },
                      user: { type: 'object' }
                    }
                  }
                }
              }
            }
          }
        }
      },
      '/productos': {
        get: {
          tags: ['Productos'],
          summary: 'Listar productos',
          parameters: [
            { name: 'categoria', in: 'query', schema: { type: 'string' } },
            { name: 'precio_min', in: 'query', schema: { type: 'number' } },
            { name: 'precio_max', in: 'query', schema: { type: 'number' } },
            { name: 'pagina', in: 'query', schema: { type: 'integer' } },
            { name: 'limite', in: 'query', schema: { type: 'integer' } },
            { name: 'ordenar', in: 'query', schema: { type: 'string', enum: ['precio_asc', 'precio_desc', 'nombre'] } }
          ],
          responses: {
            200: {
              description: 'Lista de productos',
              content: {
                'application/json': {
                  schema: {
                    type: 'object',
                    properties: {
                      success: { type: 'boolean' },
                      data: {
                        type: 'array',
                        items: { $ref: '#/components/schemas/Producto' }
                      },
                      meta: { type: 'object' }
                    }
                  }
                }
              }
            }
          }
        },
        post: {
          tags: ['Productos'],
          summary: 'Crear producto',
          security: [{ bearerAuth: [] }],
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['nombre', 'precio'],
                  properties: {
                    nombre: { type: 'string' },
                    precio: { type: 'number' },
                    categoria: { type: 'string' },
                    stock: { type: 'integer' }
                  }
                }
              }
            }
          },
          responses: {
            201: { description: 'Producto creado' },
            401: { description: 'No autenticado' }
          }
        }
      },
      '/webhooks': {
        get: {
          tags: ['Webhooks'],
          summary: 'Listar webhooks',
          security: [{ bearerAuth: [] }],
          responses: {
            200: { description: 'Lista de webhooks' }
          }
        },
        post: {
          tags: ['Webhooks'],
          summary: 'Registrar webhook',
          security: [{ bearerAuth: [] }],
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    url: { type: 'string' },
                    events: { 
                      type: 'array',
                      items: { 
                        type: 'string',
                        enum: ['producto.creado', 'producto.actualizado', 'producto.eliminado']
                      }
                    },
                    description: { type: 'string' }
                  }
                }
              }
            }
          },
          responses: {
            201: { description: 'Webhook registrado' }
          }
        }
      },
      '/logs': {
        get: {
          tags: ['Logs'],
          summary: 'Obtener logs del sistema',
          security: [{ bearerAuth: [] }],
          parameters: [
            { name: 'level', in: 'query', schema: { type: 'string', enum: ['info', 'warn', 'error', 'success'] } },
            { name: 'limit', in: 'query', schema: { type: 'integer' } }
          ],
          responses: {
            200: { description: 'Logs del sistema' }
          }
        }
      }
    },
    tags: [
      { name: 'Autenticación', description: 'Endpoints de autenticación JWT' },
      { name: 'Productos', description: 'Gestión de productos' },
      { name: 'Webhooks', description: 'Sistema de notificaciones webhook' },
      { name: 'Logs', description: 'Logs del sistema' }
    ]
  };

  res.json(openApiSpec);
});

// ============================================
// INFORMACIÓN DE VERSIONES
// ============================================

app.get('/api/versions', (req, res) => {
  sendResponse(res, {
    versions: {
      v1: {
        status: 'deprecated',
        description: 'Versión básica, funcionalidad limitada',
        deprecatedAt: '2024-01-01',
        features: ['CRUD básico', 'Rate limiting bajo', 'Autenticación opcional']
      },
      v2: {
        status: 'current',
        description: 'Versión completa con todas las funcionalidades',
        releasedAt: '2024-06-01',
        features: [
          'CRUD completo',
          'Autenticación JWT obligatoria (escritura)',
          'Rate limiting configurable',
          'Logging completo',
          'Sistema de webhooks',
          'Filtros y paginación avanzada',
          'PATCH para actualizaciones parciales'
        ]
      }
    },
    current: 'v2',
    supportedFormats: ['json', 'xml', 'html'],
    authentication: 'JWT Bearer Token',
    documentation: {
      openapi: '/api/openapi.json',
      swagger: '/api/docs',
      v1: '/api/v1',
      v2: '/api/v2'
    }
  }, 200, req.requestedFormat);
});

// ============================================
// PÁGINA DE INICIO CON DOCUMENTACIÓN
// ============================================

app.get('/', (req, res) => {
  const html = `
    <!DOCTYPE html>
    <html>
    <head>
      <title>API REST Completa</title>
      <meta charset="UTF-8">
      <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
          font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
          color: #333;
          line-height: 1.6;
        }
        .container {
          max-width: 1200px;
          margin: 0 auto;
          padding: 20px;
        }
        .header {
          background: white;
          padding: 30px;
          border-radius: 10px;
          box-shadow: 0 10px 30px rgba(0,0,0,0.2);
          margin-bottom: 20px;
          text-align: center;
        }
        h1 { color: #667eea; font-size: 2.5em; margin-bottom: 10px; }
        .subtitle { color: #666; font-size: 1.2em; }
        .grid {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
          gap: 20px;
          margin-bottom: 20px;
        }
        .card {
          background: white;
          padding: 25px;
          border-radius: 10px;
          box-shadow: 0 5px 15px rgba(0,0,0,0.1);
          transition: transform 0.3s;
        }
        .card:hover { transform: translateY(-5px); box-shadow: 0 10px 25px rgba(0,0,0,0.2); }
        .card h2 {
          color: #667eea;
          margin-bottom: 15px;
          font-size: 1.5em;
          display: flex;
          align-items: center;
          gap: 10px;
        }
        .icon { font-size: 1.5em; }
        .feature-list {
          list-style: none;
          padding-left: 0;
        }
        .feature-list li {
          padding: 8px 0;
          border-bottom: 1px solid #f0f0f0;
        }
        .feature-list li:last-child { border-bottom: none; }
        .feature-list li:before {
          content: "✓";
          color: #28a745;
          font-weight: bold;
          margin-right: 10px;
        }
        code {
          background: #f8f9fa;
          padding: 3px 8px;
          border-radius: 4px;
          font-family: 'Courier New', monospace;
          color: #e83e8c;
          font-size: 0.9em;
        }
        .endpoint {
          background: #f8f9fa;
          padding: 15px;
          border-radius: 5px;
          margin: 10px 0;
          border-left: 4px solid #667eea;
        }
        .method {
          display: inline-block;
          padding: 3px 8px;
          border-radius: 3px;
          font-weight: bold;
          margin-right: 10px;
          font-size: 0.85em;
        }
        .get { background: #28a745; color: white; }
        .post { background: #007bff; color: white; }
        .put { background: #ffc107; color: #333; }
        .delete { background: #dc3545; color: white; }
        .badge {
          display: inline-block;
          padding: 3px 8px;
          border-radius: 12px;
          font-size: 0.8em;
          font-weight: bold;
          margin: 2px;
        }
        .badge-success { background: #d4edda; color: #155724; }
        .badge-warning { background: #fff3cd; color: #856404; }
        .badge-info { background: #d1ecf1; color: #0c5460; }
        .credentials {
          background: #fff3cd;
          padding: 15px;
          border-radius: 5px;
          border-left: 4px solid #ffc107;
          margin: 15px 0;
        }
        .stats {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
          gap: 15px;
          margin-top: 20px;
        }
        .stat {
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
          color: white;
          padding: 20px;
          border-radius: 8px;
          text-align: center;
        }
        .stat-value {
          font-size: 2em;
          font-weight: bold;
          display: block;
        }
        .stat-label {
          font-size: 0.9em;
          opacity: 0.9;
        }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <h1>🚀 API REST Completa</h1>
          <p class="subtitle">Con JWT, Rate Limiting, Logging, Webhooks y OpenAPI</p>
          <div class="stats">
            <div class="stat">
              <span class="stat-value">${productos.length}</span>
              <span class="stat-label">Productos</span>
            </div>
            <div class="stat">
              <span class="stat-value">${webhooks.length}</span>
              <span class="stat-label">Webhooks</span>
            </div>
            <div class="stat">
              <span class="stat-value">${logs.length}</span>
              <span class="stat-label">Logs</span>
            </div>
          </div>
        </div>

        <div class="grid">
          <div class="card">
            <h2><span class="icon">🔐</span> Autenticación</h2>
            <div class="credentials">
              <strong>Credenciales de prueba:</strong><br>
              Admin: <code>admin / admin123</code><br>
              Usuario: <code>user / user123</code>
            </div>
            <div class="endpoint">
              <span class="method post">POST</span>
              <code>/api/auth/login</code>
            </div>
            <p>La API usa JWT (JSON Web Tokens) para autenticación. El token expira en 24 horas.</p>
          </div>

          <div class="card">
            <h2><span class="icon">⚡</span> Rate Limiting</h2>
            <ul class="feature-list">
              <li>Lectura: 100 req/min</li>
              <li>Escritura: 30 req/min</li>
              <li>Admin: 20 req/min</li>
              <li>Headers informativos</li>
            </ul>
            <p><small>Se incluyen headers X-RateLimit-* en cada respuesta.</small></p>
          </div>

          <div class="card">
            <h2><span class="icon">📝</span> Logging</h2>
            <div class="endpoint">
              <span class="method get">GET</span>
              <code>/api/logs</code>
              <span class="badge badge-warning">Admin</span>
            </div>
            <p>Sistema completo de logging con niveles: info, warn, error, success. Todos los eventos quedan registrados.</p>
          </div>

          <div class="card">
            <h2><span class="icon">🔔</span> Webhooks</h2>
            <div class="endpoint">
              <span class="method post">POST</span>
              <code>/api/webhooks</code>
              <span class="badge badge-warning">Admin</span>
            </div>
            <p><strong>Eventos disponibles:</strong></p>
            <ul class="feature-list">
              <li>producto.creado</li>
              <li>producto.actualizado</li>
              <li>producto.eliminado</li>
            </ul>
          </div>

          <div class="card">
            <h2><span class="icon">📚</span> Documentación</h2>
            <div class="endpoint">
              <span class="method get">GET</span>
              <code>/api/openapi.json</code>
            </div>
            <div class="endpoint">
              <span class="method get">GET</span>
              <code>/api/versions</code>
            </div>
            <p>Especificación OpenAPI 3.0 completa con todos los endpoints documentados.</p>
          </div>

          <div class="card">
            <h2><span class="icon">🎯</span> Versionado</h2>
            <div>
              <span class="badge badge-warning">v1</span> Básica (deprecated)<br>
              <span class="badge badge-success">v2</span> Completa (current)
            </div>
            <div class="endpoint" style="margin-top: 10px;">
              <code>/api/v1/productos</code><br>
              <code>/api/v2/productos</code><br>
              <code>/api/productos</code> → v2
            </div>
          </div>
        </div>

        <div class="card">
          <h2><span class="icon">🛠️</span> Endpoints Principales (v2)</h2>
          
          <div class="endpoint">
            <span class="method get">GET</span>
            <code>/api/productos</code>
            <span class="badge badge-info">Público</span>
            <p style="margin-top: 10px;">Parámetros: categoria, precio_min, precio_max, activo, pagina, limite, ordenar</p>
          </div>

          <div class="endpoint">
            <span class="method get">GET</span>
            <code>/api/productos/:id</code>
            <span class="badge badge-info">Público</span>
          </div>

          <div class="endpoint">
            <span class="method post">POST</span>
            <code>/api/productos</code>
            <span class="badge badge-success">Autenticado</span>
            <p style="margin-top: 10px;">Body: { nombre, precio, categoria?, stock? }</p>
          </div>

          <div class="endpoint">
            <span class="method put">PUT</span>
            <code>/api/productos/:id</code>
            <span class="badge badge-success">Autenticado</span>
            <p style="margin-top: 10px;">Actualización completa del producto</p>
          </div>

          <div class="endpoint">
            <span class="method put">PATCH</span>
            <code>/api/productos/:id</code>
            <span class="badge badge-success">Autenticado</span>
            <p style="margin-top: 10px;">Actualización parcial del producto</p>
          </div>

          <div class="endpoint">
            <span class="method delete">DELETE</span>
            <code>/api/productos/:id</code>
            <span class="badge badge-warning">Admin</span>
          </div>
        </div>

        <div class="card">
          <h2><span class="icon">🌐</span> Formatos de Respuesta</h2>
          <ul class="feature-list">
            <li><strong>JSON</strong> (por defecto): <code>Accept: application/json</code></li>
            <li><strong>XML</strong>: <code>Accept: application/xml</code> o <code>?format=xml</code></li>
            <li><strong>HTML</strong>: <code>Accept: text/html</code> o <code>?format=html</code></li>
          </ul>
        </div>

        <div class="card">
          <h2><span class="icon">💡</span> Ejemplo de Uso con cURL</h2>
          <div style="background: #2d2d2d; color: #f8f8f2; padding: 15px; border-radius: 5px; overflow-x: auto;">
            <pre style="margin: 0; font-family: 'Courier New', monospace; font-size: 0.9em;">
# 1. Login
curl -X POST http://localhost:${PORT}/api/auth/login \\
  -H "Content-Type: application/json" \\
  -d '{"username":"admin","password":"admin123"}'

# 2. Usar el token (reemplazar YOUR_TOKEN)
curl http://localhost:${PORT}/api/productos \\
  -H "Authorization: Bearer YOUR_TOKEN"

# 3. Crear producto
curl -X POST http://localhost:${PORT}/api/productos \\
  -H "Authorization: Bearer YOUR_TOKEN" \\
  -H "Content-Type: application/json" \\
  -d '{"nombre":"Tablet","precio":500,"categoria":"Electrónica"}'

# 4. Registrar webhook
curl -X POST http://localhost:${PORT}/api/webhooks \\
  -H "Authorization: Bearer YOUR_TOKEN" \\
  -H "Content-Type: application/json" \\
  -d '{"url":"https://mi-servidor.com/webhook","events":["producto.creado"]}'

# 5. Ver logs
curl http://localhost:${PORT}/api/logs?level=info \\
  -H "Authorization: Bearer YOUR_TOKEN"
            </pre>
          </div>
        </div>
      </div>
    </body>
    </html>
  `;

  res.send(html);
});

// ============================================
// MANEJO DE ERRORES
// ============================================

app.use((error, req, res, next) => {
  log('error', 'Error en el servidor', { error: error.message, stack: error.stack });
  
  sendResponse(res, {
    error: 'Error interno del servidor',
    message: process.env.NODE_ENV === 'development' ? error.message : undefined
  }, 500, req.requestedFormat);
});

// 404
app.use((req, res) => {
  sendResponse(res, {
    error: 'Ruta no encontrada',
    metodo: req.method,
    ruta: req.url,
    sugerencia: 'Visita / para ver la documentación'
  }, 404, req.requestedFormat);
});

// ============================================
// INICIAR SERVIDOR
// ============================================

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log('\n' + '='.repeat(60));
  console.log('🚀 API REST COMPLETA INICIADA');
  console.log('='.repeat(60));
  console.log(`📡 Servidor: http://localhost:${PORT}`);
  console.log(`📖 Documentación: http://localhost:${PORT}`);
  console.log(`📋 OpenAPI: http://localhost:${PORT}/api/openapi.json`);
  console.log(`🔄 Versiones: /api/versions`);
  console.log('='.repeat(60));
  console.log('\n✨ CARACTERÍSTICAS:');
  console.log('  • 🔐 Autenticación JWT');
  console.log('  • ⚡ Rate Limiting configurable');
  console.log('  • 📝 Logging completo de operaciones');
  console.log('  • 🔔 Sistema de Webhooks');
  console.log('  • 📚 Documentación OpenAPI 3.0');
  console.log('  • 🎯 Versionado de API (v1, v2)');
  console.log('  • 🌐 Múltiples formatos (JSON, XML, HTML)');
  console.log('\n👤 CREDENCIALES DE PRUEBA:');
  console.log('  Admin: admin / admin123');
  console.log('  User:  user / user123');
  console.log('='.repeat(60) + '\n');
});

// Graceful shutdown
process.on('SIGINT', () => {
  console.log('\n\n' + '='.repeat(60));
  console.log('👋 Cerrando servidor gracefully...');
  console.log(`📊 Estadísticas finales:`);
  console.log(`   • Productos: ${productos.length}`);
  console.log(`   • Webhooks registrados: ${webhooks.length}`);
  console.log(`   • Logs generados: ${logs.length}`);
  console.log('='.repeat(60) + '\n');
  process.exit(0);
});