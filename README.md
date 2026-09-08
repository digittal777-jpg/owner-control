# Owner Control POS

Panel central para controlar clientes POS, pagos, salud y validaciones sin mezclarlo con el admin local del negocio.

## Arranque local

```bash
cd C:\Users\Monitor\Desktop\proyectos\owner-control
npm install
npm start
```

Por defecto abre en:

```txt
http://localhost:3200
```

Si no configuras `OWNER_CONTROL_TOKEN` y arrancas solo en local sin HTTPS forzado ni dominio remoto, el servidor genera un token temporal y lo imprime en consola.

En produccion o cualquier despliegue endurecido configura siempre:

```txt
OWNER_CONTROL_TOKEN=un-token-largo
OWNER_CONTROL_DB_PATH=/ruta/privada/owner-control.sqlite
OWNER_CONTROL_PORT=3200
OWNER_CONTROL_REQUIRE_CLIENT_SIGNATURE=true
```

Si quieres HTTPS directo sin depender del host, agrega certificado y llave PEM por ruta o base64:

```txt
OWNER_CONTROL_FORCE_HTTPS=true
OWNER_CONTROL_PUBLIC_ORIGIN=https://owner-control.tudominio.com
OWNER_CONTROL_HTTPS_CERT_PATH=certs/owner-control-cert.pem
OWNER_CONTROL_HTTPS_KEY_PATH=certs/owner-control-key.pem
OWNER_CONTROL_HTTP_REDIRECT_PORT=80
```

Tambien acepta:

- `OWNER_CONTROL_HTTPS_CERT_B64`
- `OWNER_CONTROL_HTTPS_KEY_B64`
- `OWNER_CONTROL_HTTPS_CA_PATH`
- `OWNER_CONTROL_HTTPS_CA_B64`

Cuando cargas certificado y llave, `OWNER_CONTROL_PORT` pasa a ser el puerto HTTPS real del servicio.

Si el TLS termina en un proxy o balanceador, deja `OWNER_CONTROL_FORCE_HTTPS=true` y configura `OWNER_CONTROL_TRUST_PROXY` con las subredes o aliases confiables para aceptar `X-Forwarded-Proto`.
No uses `true` ni numeros de hops: owner-control debe confiar solo en proxies, IPs o CIDRs explicitos para no abrir spoof de headers o bypass de rate limits.

Con HTTPS forzado, owner-control exige por defecto firmas HMAC en la API cliente POS aunque olvides `OWNER_CONTROL_REQUIRE_CLIENT_SIGNATURE`.

## Runtime administrado desde el panel

El propio panel owner ahora puede guardar su runtime endurecido en la SQLite privada de `owner-control`, incluyendo:

- `OWNER_CONTROL_PUBLIC_ORIGIN`
- `OWNER_CONTROL_FORCE_HTTPS`
- `OWNER_CONTROL_HTTPS_CERT_*`
- `OWNER_CONTROL_HTTP_REDIRECT_PORT`
- `OWNER_CONTROL_TRUST_PROXY`
- `OWNER_CONTROL_HSTS_MAX_AGE_SECONDS`
- `OWNER_CONTROL_REQUIRE_CLIENT_SIGNATURE`
- `OWNER_CONTROL_RATE_LIMIT_*`
- `OWNER_CONTROL_CLIENT_SIGNATURE_NONCE_LIMIT`
- `OWNER_CONTROL_HEALTH_REPORT_RETENTION_LIMIT`
- `OWNER_CONTROL_VALIDATION_REPORT_RETENTION_LIMIT`

Eso reduce la dependencia de Railway u otro host para la capa HTTPS diaria. Cuando guardas uno de esos cambios, el panel lo marca como `reinicio pendiente` porque el proceso Node debe reiniciar para volver a leer certificado, token, proxy y limites.

`OWNER_CONTROL_DB_PATH`, `NODE_ENV` y cualquier `PORT` impuesto por el host siguen siendo decisiones de arranque del entorno.

## Modelo de permisos

- `OWNER_CONTROL_TOKEN`: abre el panel central y permite crear clientes, registrar pagos y rotar API keys. Ya no existe un token por defecto conocido para arranques endurecidos.
- `X-Client-Slug` + `Authorization: Bearer <apiKey>`: credenciales de cada POS para sincronizar su estado.
- El `POS_BOOTSTRAP_TOKEN` no se usa aqui. Ese token debe quedar solo para instalacion inicial del POS.

## API owner

```txt
GET    /api/owner/clients
POST   /api/owner/clients
GET    /api/owner/clients/:slug
PATCH  /api/owner/clients/:slug/subscription
POST   /api/owner/clients/:slug/payments
POST   /api/owner/clients/:slug/rotate-key
```

Header:

```txt
X-Owner-Control-Token: <OWNER_CONTROL_TOKEN>
```

## API cliente POS

```txt
GET  /api/client/subscription
POST /api/client/health
POST /api/client/validation-report
```

Headers:

```txt
X-Client-Slug: cremeria-rincon
Authorization: Bearer pos_xxxxx
X-Client-Timestamp: 2026-07-05T18:30:00.000Z
X-Client-Nonce: nonce-unico
X-Client-Signature: sha256=<firma-hmac>
```

## Integracion POS actual

El POS local ya incluye el sincronizador contra owner-control. El flujo esperado es:

1. Consulta `/api/client/subscription` para reflejar plan, estado y runtime administrado.
2. Envia `/api/client/health` con el semaforo operativo actual.
3. Envia `/api/client/validation-report` desde el flujo de `validate:client`.

Para que funcione, el runtime del POS cliente debe tener `CONTROL_API_URL`, `CONTROL_CLIENT_SLUG` y `CONTROL_CLIENT_SECRET`. Si HTTPS esta forzado, las llamadas cliente usan firma HMAC con timestamp y nonce.

## Retencion y limites

Owner-control conserva limites en memoria para rate limit y nonces HMAC, y poda reportes historicos por cliente para evitar crecimiento indefinido:

```txt
OWNER_CONTROL_RATE_LIMIT_BUCKET_LIMIT=5000
OWNER_CONTROL_CLIENT_SIGNATURE_NONCE_LIMIT=5000
OWNER_CONTROL_HEALTH_REPORT_RETENTION_LIMIT=200
OWNER_CONTROL_VALIDATION_REPORT_RETENTION_LIMIT=200
```

Para podar reportes historicos que ya existian antes de activar la retencion, ejecuta primero dry-run:

```bash
npm run maintenance:prune-reports
```

Si el conteo es correcto, aplica la poda:

```bash
npm run maintenance:prune-reports -- --apply
```

## Pruebas

```bash
npm test
```

El smoke test local levanta la app con una SQLite temporal y valida `/api/health`.
