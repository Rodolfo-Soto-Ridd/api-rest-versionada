# 1. Login y obtener token
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}'

# Respuesta: {"success":true,"token":"eyJ...","user":{...}}

# 2. Usar el token para crear un producto
curl -X POST http://localhost:3000/api/productos \
  -H "Authorization: Bearer TU_TOKEN_AQUI" \
  -H "Content-Type: application/json" \
  -d '{"nombre":"Tablet","precio":500,"categoria":"Electrónica","stock":15}'

# 3. Listar productos con filtros
curl "http://localhost:3000/api/productos?categoria=Electrónica&precio_min=100&ordenar=precio_asc"

# 4. Registrar un webhook
curl -X POST http://localhost:3000/api/webhooks \
  -H "Authorization: Bearer TU_TOKEN_AQUI" \
  -H "Content-Type: application/json" \
  -d '{"url":"https://mi-servidor.com/webhook","events":["producto.creado","producto.actualizado"],"description":"Notificaciones de productos"}'

# 5. Ver logs (solo admin)
curl http://localhost:3000/api/logs?level=info&limit=50 \
  -H "Authorization: Bearer TU_TOKEN_AQUI"