const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const proxyaddr = require("proxy-addr");

const Database = require("better-sqlite3");

const VALID_SUBSCRIPTION_STATUSES = new Set(["trial", "active", "overdue", "suspended", "cancelled"]);
const VALID_HEALTH_STATUSES = new Set(["ok", "risk", "critical", "unknown"]);
const VALID_VALIDATION_STATUSES = new Set(["ok", "warning", "failed", "unknown"]);
const VALID_CONFIG_SYNC_STATUSES = new Set(["unknown", "pending", "applied", "failed", "stale"]);
const VALID_RUNTIME_KEY = /^[A-Z][A-Z0-9_]*$/;
const SECRET_KEY_PATTERN = /(SECRET|TOKEN|PASSWORD|ACCESS_KEY|API_KEY|CLIENT_SECRET)/i;
const PAIRING_RUNTIME_KEYS = new Set(["CONTROL_API_URL", "CONTROL_CLIENT_SLUG", "CONTROL_CLIENT_SECRET"]);
const HTTPS_RUNTIME_URL_KEYS = new Set([
  "CONTROL_API_URL",
  "POS_PUBLIC_ORIGIN",
  "RESEND_API_URL",
  "TELEGRAM_API_BASE_URL",
]);
const HTTPS_RUNTIME_URL_LIST_KEYS = new Set([
  "POS_ALLOWED_ORIGINS",
]);
const HTTPS_OR_FILE_RUNTIME_URL_KEYS = new Set([
  "BACKUP_BUCKET_ENDPOINT",
]);
const PEM_BASE64_RUNTIME_KEYS = new Set([
  "POS_HTTPS_CERT_B64",
  "POS_HTTPS_KEY_B64",
  "POS_HTTPS_CA_B64",
]);
const TRUST_PROXY_RUNTIME_KEYS = new Set([
  "POS_TRUST_PROXY",
]);
const RUNTIME_VARIABLE_DEFINITIONS = [
  { key: "PORT", group: "Host", label: "Puerto POS", description: "Puerto HTTP local. El host puede tener prioridad.", placeholder: "3100" },
  { key: "NODE_ENV", group: "Host", label: "Modo Node", description: "production, development o test.", placeholder: "production", type: "select", options: ["", "production", "development", "test"] },
  { key: "POS_DB_PATH", group: "POS", label: "Base SQLite", description: "Ruta de la base SQLite del cliente.", placeholder: "data/retail-base-pos.sqlite" },
  { key: "POS_WORKBOOK_PATH", group: "POS", label: "Excel base", description: "Catalogo usado al sembrar o reimportar.", placeholder: "catalogos/cremeria-base.xlsx" },
  { key: "POS_TIMEZONE", group: "POS", label: "Zona horaria", description: "Zona operativa para cortes y reportes.", placeholder: "America/Mexico_City" },
  { key: "POS_EXPORT_LOOKBACK_DAYS", group: "POS", label: "Dias exportables", description: "Ventana maxima para exportaciones.", placeholder: "14" },
  { key: "POS_DB_INSTALL_BACKUP", group: "POS", label: "Backup antes de instalar DB", description: "Crea respaldo local antes de instalar base.", placeholder: "false", type: "select", options: ["", "true", "false"] },
  { key: "POS_PUBLIC_ORIGIN", group: "Red", label: "URL publica", description: "Origen publico esperado del POS.", placeholder: "https://cliente.ejemplo.com" },
  { key: "POS_ALLOWED_ORIGINS", group: "Red", label: "Origenes permitidos", description: "Lista separada por comas para CORS.", placeholder: "https://cliente.ejemplo.com,http://localhost:3100" },
  { key: "POS_SECURE_COOKIES", group: "Seguridad", label: "Cookies seguras", description: "Usa true en HTTPS y false en local.", placeholder: "true", type: "select", options: ["", "true", "false"] },
  { key: "POS_FORCE_HTTPS", group: "Seguridad", label: "Forzar HTTPS POS", description: "Redirige o bloquea HTTP fuera de localhost.", placeholder: "true", type: "select", options: ["", "true", "false"] },
  { key: "POS_HTTPS_CERT_PATH", group: "Seguridad", label: "Certificado HTTPS", description: "Ruta local al certificado PEM si el mismo proceso Node termina TLS.", placeholder: "certs/pos-cert.pem" },
  { key: "POS_HTTPS_KEY_PATH", group: "Seguridad", label: "Llave HTTPS", description: "Ruta local a la llave privada PEM del certificado HTTPS.", placeholder: "certs/pos-key.pem" },
  { key: "POS_HTTPS_CA_PATH", group: "Seguridad", label: "CA HTTPS", description: "Ruta opcional a la cadena PEM intermedia o CA.", placeholder: "certs/pos-ca.pem" },
  { key: "POS_HTTPS_CERT_B64", group: "Seguridad", label: "Certificado HTTPS b64", description: "Certificado PEM codificado en base64 para administrarlo desde owner-control.", placeholder: "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t..." },
  { key: "POS_HTTPS_KEY_B64", group: "Seguridad", label: "Llave HTTPS b64", description: "Llave privada PEM codificada en base64. Guardala como secreto.", placeholder: "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0t...", secret: true },
  { key: "POS_HTTPS_CA_B64", group: "Seguridad", label: "CA HTTPS b64", description: "Cadena PEM intermedia o CA codificada en base64.", placeholder: "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t..." },
  { key: "POS_HTTP_REDIRECT_PORT", group: "Seguridad", label: "Puerto HTTP redirect", description: "Puerto opcional para redirigir HTTP a HTTPS cuando el POS termina TLS directo.", placeholder: "80" },
  { key: "POS_TRUST_PROXY", group: "Seguridad", label: "Proxy confiable", description: "Subred o aliases confiables para aceptar X-Forwarded-Proto detras de TLS. Usa lista explicita, no true. Ejemplo: loopback,linklocal,uniquelocal", placeholder: "loopback,linklocal,uniquelocal" },
  { key: "POS_HSTS_MAX_AGE_SECONDS", group: "Seguridad", label: "HSTS segundos", description: "Tiempo para recordar HTTPS en navegadores.", placeholder: "31536000" },
  { key: "POS_BOOTSTRAP_TOKEN", group: "Seguridad", label: "Token bootstrap", description: "Token para setup inicial.", placeholder: "token-largo-privado", secret: true },
  { key: "POS_ADMIN_MAX_FAILED_LOGINS", group: "Seguridad", label: "Intentos admin", description: "Intentos fallidos antes de bloqueo.", placeholder: "5" },
  { key: "POS_CASHIER_SESSION_TTL_MS", group: "Seguridad", label: "TTL sesion cajero", description: "Milisegundos que dura una sesion de cajero antes de requerir nuevo login.", placeholder: "604800000" },
  { key: "POS_ADMIN_LOGIN_WINDOW_MS", group: "Seguridad", label: "Ventana login admin", description: "Milisegundos de ventana de intentos.", placeholder: "900000" },
  { key: "POS_ADMIN_LOGIN_LOCK_MS", group: "Seguridad", label: "Bloqueo login admin", description: "Milisegundos de bloqueo.", placeholder: "900000" },
  { key: "CONTROL_API_URL", group: "Owner-control", label: "URL owner-control", description: "API central. Usa HTTPS fuera de localhost.", placeholder: "https://owner-control.ejemplo.com" },
  { key: "CONTROL_REQUIRE_HTTPS", group: "Owner-control", label: "Compatibilidad HTTPS central", description: "Compatibilidad legacy. El POS sigue exigiendo HTTPS fuera de localhost aunque este valor se ponga en false.", placeholder: "true", type: "select", options: ["", "true", "false"] },
  { key: "CONTROL_CLIENT_SLUG", group: "Owner-control", label: "Slug cliente", description: "Identificador del cliente.", placeholder: "cremeria-rincon" },
  { key: "CONTROL_CLIENT_SECRET", group: "Owner-control", label: "API key cliente", description: "Secreto cliente. La sync activa conserva el emparejamiento local.", placeholder: "pos_...", secret: true },
  { key: "RAILWAY_COST_SAVER_MODE", group: "Compatibilidad", label: "Ahorro Railway", description: "Activa defaults de bajo consumo en Railway, incluyendo polling saliente apagado salvo configuracion explicita.", placeholder: "true", type: "select", options: ["", "true", "false"] },
  { key: "CONTROL_CONFIG_POLL_MS", group: "Owner-control", label: "Polling config", description: "Milisegundos entre consultas automaticas. Usa 0 en Railway para permitir sleep serverless.", placeholder: "0 en Railway, 30000 local" },
  { key: "CONTROL_SYNC_TIMEOUT_MS", group: "Owner-control", label: "Timeout sync", description: "Tiempo maximo de llamadas al owner-control.", placeholder: "8000" },
  { key: "CONTROL_CONFIG_SYNC_MAX_AGE_MS", group: "Owner-control", label: "Edad cache config", description: "Edad maxima de cache central.", placeholder: "15000" },
  { key: "TELEGRAM_BOT_TOKEN", group: "Telegram", label: "Bot token", description: "Token privado del bot.", placeholder: "123456:ABC...", secret: true },
  { key: "TELEGRAM_CHAT_IDS", group: "Telegram", label: "Chats destino", description: "IDs separados por comas.", placeholder: "-1001234567890,123456" },
  { key: "TELEGRAM_API_BASE_URL", group: "Telegram", label: "API Telegram", description: "Base URL de Telegram o proxy.", placeholder: "https://api.telegram.org" },
  { key: "BACKUP_ENABLED", group: "Backups", label: "Backups activos", description: "Activa respaldo externo.", placeholder: "false", type: "select", options: ["", "true", "false"] },
  { key: "BACKUP_BUCKET_ENDPOINT", group: "Backups", label: "Endpoint bucket", description: "Endpoint compatible S3.", placeholder: "https://..." },
  { key: "BACKUP_BUCKET_NAME", group: "Backups", label: "Bucket", description: "Nombre del bucket.", placeholder: "pos-backups" },
  { key: "BACKUP_BUCKET_REGION", group: "Backups", label: "Region bucket", description: "Region S3 o auto.", placeholder: "auto" },
  { key: "BACKUP_ACCESS_KEY_ID", group: "Backups", label: "Access key", description: "Llave de acceso.", placeholder: "access-key", secret: true },
  { key: "BACKUP_SECRET_ACCESS_KEY", group: "Backups", label: "Secret key", description: "Secreto de acceso.", placeholder: "secret-key", secret: true },
  { key: "BACKUP_PREFIX", group: "Backups", label: "Prefijo", description: "Prefijo remoto del cliente.", placeholder: "clientes/cremeria-rincon" },
  { key: "BACKUP_RETENTION_DAILY", group: "Backups", label: "Retencion diaria", description: "Respaldos diarios a conservar.", placeholder: "14" },
  { key: "BACKUP_RETENTION_WEEKLY", group: "Backups", label: "Retencion semanal", description: "Respaldos semanales a conservar.", placeholder: "8" },
  { key: "BACKUP_RETENTION_MONTHLY", group: "Backups", label: "Retencion mensual", description: "Respaldos mensuales a conservar.", placeholder: "12" },
  { key: "BACKUP_NOTIFY_TO", group: "Backups", label: "Avisos backup", description: "Correos separados por comas.", placeholder: "owner@cliente.com" },
  { key: "BACKUP_SYNC_REPORT_STALE_HOURS", group: "Backups", label: "Horas stale backup", description: "Horas sin reporte antes de riesgo.", placeholder: "36" },
  { key: "BACKUP_LOCAL_STAGING_KEEP", group: "Backups", label: "Staging local", description: "Temporales locales a conservar.", placeholder: "2" },
  { key: "RESEND_API_KEY", group: "Correo", label: "Resend API key", description: "Llave privada de correo.", placeholder: "re_...", secret: true },
  { key: "RESEND_API_URL", group: "Correo", label: "Resend API URL", description: "Endpoint de envio de correos.", placeholder: "https://api.resend.com/emails" },
  { key: "RAILWAY_PUBLIC_DOMAIN", group: "Compatibilidad", label: "Dominio Railway", description: "Compatibilidad; ya no debe ser fuente unica.", placeholder: "cliente.up.railway.app" },
  { key: "RAILWAY_STATIC_URL", group: "Compatibilidad", label: "URL estatica Railway", description: "Compatibilidad; ya no debe ser fuente unica.", placeholder: "cliente.up.railway.app" },
].map((definition) => ({
  ...definition,
  restartRequired: true,
  secret: Boolean(definition.secret || SECRET_KEY_PATTERN.test(definition.key)),
  options: Array.isArray(definition.options) ? definition.options : [],
}));
const EDITABLE_RUNTIME_KEYS = new Set(RUNTIME_VARIABLE_DEFINITIONS.map((item) => item.key));
const OWNER_RUNTIME_VARIABLE_DEFINITIONS = [
  { key: "OWNER_CONTROL_TOKEN", group: "Seguridad", label: "Token owner-control", description: "Token privado para abrir el panel central. Requiere reinicio para aplicar el nuevo valor.", placeholder: "owner_...", secret: true },
  { key: "OWNER_CONTROL_PORT", group: "Host", label: "Puerto owner-control", description: "Puerto local del servicio cuando el host no impone PORT.", placeholder: "3200" },
  { key: "OWNER_CONTROL_PUBLIC_ORIGIN", group: "Red", label: "URL publica owner-control", description: "Origen publico esperado del panel central. Usa HTTPS fuera de localhost.", placeholder: "https://owner-control.ejemplo.com" },
  { key: "OWNER_CONTROL_FORCE_HTTPS", group: "Seguridad", label: "Forzar HTTPS owner-control", description: "Bloquea o redirige HTTP fuera de localhost para no exponer el panel central.", placeholder: "true", type: "select", options: ["", "true", "false"] },
  { key: "OWNER_CONTROL_HTTPS_CERT_PATH", group: "Seguridad", label: "Certificado HTTPS", description: "Ruta local al certificado PEM si owner-control termina TLS directo.", placeholder: "certs/owner-control-cert.pem" },
  { key: "OWNER_CONTROL_HTTPS_KEY_PATH", group: "Seguridad", label: "Llave HTTPS", description: "Ruta local a la llave privada PEM del certificado HTTPS.", placeholder: "certs/owner-control-key.pem" },
  { key: "OWNER_CONTROL_HTTPS_CA_PATH", group: "Seguridad", label: "CA HTTPS", description: "Ruta opcional a la cadena PEM intermedia o CA.", placeholder: "certs/owner-control-ca.pem" },
  { key: "OWNER_CONTROL_HTTPS_CERT_B64", group: "Seguridad", label: "Certificado HTTPS b64", description: "Certificado PEM codificado en base64 para administrarlo desde el propio panel.", placeholder: "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t..." },
  { key: "OWNER_CONTROL_HTTPS_KEY_B64", group: "Seguridad", label: "Llave HTTPS b64", description: "Llave privada PEM codificada en base64.", placeholder: "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0t...", secret: true },
  { key: "OWNER_CONTROL_HTTPS_CA_B64", group: "Seguridad", label: "CA HTTPS b64", description: "Cadena PEM intermedia o CA codificada en base64.", placeholder: "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t..." },
  { key: "OWNER_CONTROL_HTTP_REDIRECT_PORT", group: "Seguridad", label: "Puerto HTTP redirect", description: "Puerto opcional para redirigir HTTP plano a HTTPS cuando owner-control termina TLS directo.", placeholder: "80" },
  { key: "OWNER_CONTROL_TRUST_PROXY", group: "Seguridad", label: "Proxy confiable owner-control", description: "Subred o aliases confiables para aceptar X-Forwarded-Proto detras de TLS. Usa lista explicita, no true.", placeholder: "loopback,linklocal,uniquelocal" },
  { key: "OWNER_CONTROL_HSTS_MAX_AGE_SECONDS", group: "Seguridad", label: "HSTS segundos", description: "Tiempo para recordar HTTPS en navegadores.", placeholder: "31536000" },
  { key: "OWNER_CONTROL_REQUIRE_CLIENT_SIGNATURE", group: "API cliente", label: "Firma HMAC cliente", description: "Exige firma HMAC en la API cliente del POS.", placeholder: "true", type: "select", options: ["", "true", "false"] },
  { key: "OWNER_CONTROL_CLIENT_SIGNATURE_WINDOW_MS", group: "API cliente", label: "Ventana firma ms", description: "Tiempo valido para firmas cliente.", placeholder: "300000" },
  { key: "OWNER_CONTROL_RATE_LIMIT_WINDOW_MS", group: "API cliente", label: "Ventana rate limit ms", description: "Ventana de tiempo para el rate limit de owner-control.", placeholder: "60000" },
  { key: "OWNER_CONTROL_RATE_LIMIT_MAX", group: "API cliente", label: "Maximo rate limit", description: "Solicitudes permitidas por ventana antes de responder 429.", placeholder: "600" },
  { key: "OWNER_CONTROL_RATE_LIMIT_BUCKET_LIMIT", group: "API cliente", label: "Buckets rate limit", description: "Maximo de buckets IP/ruta conservados en memoria.", placeholder: "5000" },
  { key: "OWNER_CONTROL_CLIENT_SIGNATURE_NONCE_LIMIT", group: "API cliente", label: "Nonces firma", description: "Maximo de nonces HMAC recientes conservados en memoria.", placeholder: "5000" },
  { key: "OWNER_CONTROL_HEALTH_REPORT_RETENTION_LIMIT", group: "Retencion", label: "Health reports", description: "Reportes de salud recientes a conservar por cliente.", placeholder: "200" },
  { key: "OWNER_CONTROL_VALIDATION_REPORT_RETENTION_LIMIT", group: "Retencion", label: "Validation reports", description: "Reportes de validacion recientes a conservar por cliente.", placeholder: "200" },
].map((definition) => ({
  ...definition,
  restartRequired: true,
  secret: Boolean(definition.secret || SECRET_KEY_PATTERN.test(definition.key)),
  options: Array.isArray(definition.options) ? definition.options : [],
}));
const EDITABLE_OWNER_RUNTIME_KEYS = new Set(OWNER_RUNTIME_VARIABLE_DEFINITIONS.map((item) => item.key));
const OWNER_HTTPS_RUNTIME_URL_KEYS = new Set([
  "OWNER_CONTROL_PUBLIC_ORIGIN",
]);
const OWNER_PEM_BASE64_RUNTIME_KEYS = new Set([
  "OWNER_CONTROL_HTTPS_CERT_B64",
  "OWNER_CONTROL_HTTPS_KEY_B64",
  "OWNER_CONTROL_HTTPS_CA_B64",
]);
const OWNER_TRUST_PROXY_RUNTIME_KEYS = new Set([
  "OWNER_CONTROL_TRUST_PROXY",
]);
const OWNER_AVAILABLE_MODULES = [
  {
    code: "merchandise_requests",
    label: "Solicitudes de mercaderia",
    description: "Permite que el negocio capture y administre solicitudes internas de compra.",
  },
  {
    code: "weighted_audit",
    label: "Auditoria de pesado",
    description: "Habilita la auditoria para productos vendidos por kilo.",
  },
];
const OWNER_ADMIN_SECTIONS = [
  {
    code: "daily_flow",
    label: "Flujo diario",
    description: "Reimportar catalogo e importacion rapida.",
  },
  {
    code: "backups",
    label: "Respaldos e instalaciones",
    description: "Exportar Excel, descargar o instalar bases y workbooks.",
  },
  {
    code: "merchandise_requests",
    label: "Solicitudes de mercaderia",
    description: "Vista y aprobacion de solicitudes en admin.",
  },
  {
    code: "weighted_audit",
    label: "Auditoria de pesado",
    description: "Panel para auditar productos por kilo.",
  },
  {
    code: "inventory",
    label: "Inventario y productos",
    description: "Alta manual de productos y control editable de inventario.",
  },
  {
    code: "branches",
    label: "Sucursales",
    description: "Alta y edicion de sucursales.",
  },
  {
    code: "cashiers",
    label: "Cajeros y contrasenas",
    description: "Creacion y administracion de accesos de cajero.",
  },
  {
    code: "business_config",
    label: "Configuracion base",
    description: "Perfil del negocio, modulos, categorias, unidades y atributos.",
  },
  {
    code: "audit_log",
    label: "Bitacora admin",
    description: "Historial de cambios y acciones administrativas.",
  },
  {
    code: "support_tools",
    label: "Diagnostico y soporte",
    description: "Panel dev, metricas y herramientas de soporte.",
  },
  {
    code: "quick_edit",
    label: "Edicion rapida",
    description: "Edicion de ventas, cortes y movimientos.",
  },
];
const DEFAULT_ENABLED_MODULES = ["weighted_audit", "merchandise_requests"];
const DEFAULT_ADMIN_CAPABILITIES = OWNER_ADMIN_SECTIONS.map((item) => item.code);

function createHttpError(message, statusCode = 400) {
  const error = new Error(message);
  error.statusCode = statusCode;
  return error;
}

function nowIso() {
  return new Date().toISOString();
}

function normalizeSlug(value) {
  const slug = String(value || "")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .replace(/-{2,}/g, "-");
  if (!slug) {
    throw createHttpError("Captura un slug de cliente valido.", 400);
  }
  return slug;
}

function normalizeText(value, maxLength, fallback = "") {
  const text = String(value ?? fallback).trim();
  return text.slice(0, maxLength);
}

function normalizeConfigCode(value, maxLength = 64) {
  return String(value || "")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9_:-]+/g, "_")
    .replace(/^_+|_+$/g, "")
    .slice(0, maxLength);
}

function cloneDefinitions(items) {
  return items.map((item) => ({ ...item }));
}

function normalizeConfigList(input, definitions, fallback = []) {
  if (!Array.isArray(input)) {
    return fallback.slice();
  }
  const allowed = new Set(definitions.map((item) => item.code));
  return [...new Set(
    input
      .map((item) => normalizeConfigCode(item, 64))
      .filter((item) => item && allowed.has(item)),
  )];
}

function parseConfigList(value, definitions, fallback = []) {
  return normalizeConfigList(safeJsonParse(value, fallback), definitions, fallback);
}

function sameConfigList(left, right) {
  const leftList = Array.isArray(left) ? left.slice().sort() : [];
  const rightList = Array.isArray(right) ? right.slice().sort() : [];
  return leftList.length === rightList.length && leftList.every((item, index) => item === rightList[index]);
}

function cloneRuntimeVariableDefinitions() {
  return RUNTIME_VARIABLE_DEFINITIONS.map((item) => ({
    ...item,
    options: Array.isArray(item.options) ? item.options.slice() : [],
  }));
}

function cloneOwnerRuntimeVariableDefinitions() {
  return OWNER_RUNTIME_VARIABLE_DEFINITIONS.map((item) => ({
    ...item,
    options: Array.isArray(item.options) ? item.options.slice() : [],
  }));
}

function normalizeRuntimeValues(input) {
  const source = input && typeof input === "object" && !Array.isArray(input)
    ? input.env && typeof input.env === "object" && !Array.isArray(input.env)
      ? input.env
      : input.values && typeof input.values === "object" && !Array.isArray(input.values)
        ? input.values
        : input
    : {};

  return Object.entries(source).reduce((result, [key, value]) => {
    const safeKey = String(key || "").trim();
    if (!VALID_RUNTIME_KEY.test(safeKey) || !EDITABLE_RUNTIME_KEYS.has(safeKey) || value == null) {
      return result;
    }
    result[safeKey] = Array.isArray(value) ? value.join(",") : String(value).trim();
    return result;
  }, {});
}

function normalizeOwnerRuntimeValues(input) {
  const source = input && typeof input === "object" && !Array.isArray(input)
    ? input.env && typeof input.env === "object" && !Array.isArray(input.env)
      ? input.env
      : input.values && typeof input.values === "object" && !Array.isArray(input.values)
        ? input.values
        : input
    : {};

  return Object.entries(source).reduce((result, [key, value]) => {
    const safeKey = String(key || "").trim();
    if (!VALID_RUNTIME_KEY.test(safeKey) || !EDITABLE_OWNER_RUNTIME_KEYS.has(safeKey) || value == null) {
      return result;
    }
    result[safeKey] = Array.isArray(value) ? value.join(",") : String(value).trim();
    return result;
  }, {});
}

function normalizeRuntimeHostname(hostname) {
  return String(hostname || "")
    .trim()
    .toLowerCase()
    .replace(/^\[/, "")
    .replace(/\]$/, "");
}

function isLoopbackRuntimeHost(hostname) {
  const host = normalizeRuntimeHostname(hostname);
  return host === "localhost"
    || host.endsWith(".localhost")
    || host === "::1"
    || host === "0.0.0.0"
    || host.startsWith("127.");
}

function validateRuntimeUrlValue(key, rawValue, options = {}) {
  const value = String(rawValue || "").trim();
  if (!value) {
    return;
  }

  let parsed = null;
  try {
    parsed = new URL(value);
  } catch (_error) {
    throw createHttpError(`${key} no es una URL valida.`, 400);
  }

  const allowedProtocols = new Set(options.allowFileProtocol ? ["https:", "http:", "file:"] : ["https:", "http:"]);
  if (!allowedProtocols.has(parsed.protocol)) {
    throw createHttpError(`${key} usa un protocolo no soportado.`, 400);
  }

  if (parsed.protocol === "file:") {
    return;
  }

  if (parsed.protocol !== "https:" && !isLoopbackRuntimeHost(parsed.hostname)) {
    throw createHttpError(`${key} debe usar HTTPS fuera de localhost para no exponer secretos o sesiones.`, 400);
  }
}

function parseTrustProxySetting(rawValue) {
  const text = String(rawValue ?? "").trim();
  if (!text) {
    return false;
  }

  const lowerText = text.toLowerCase();
  if (["false", "no", "off"].includes(lowerText)) {
    return false;
  }
  if (lowerText === "true") {
    return true;
  }
  if (/^\d+$/.test(text)) {
    return Number(text);
  }

  return text
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function validateTrustProxyValue(key, rawValue) {
  const value = String(rawValue ?? "").trim();
  if (!value) {
    return;
  }

  const setting = parseTrustProxySetting(value);
  if (setting === false) {
    return;
  }
  if (setting === true || typeof setting === "number") {
    throw createHttpError(`${key} debe listar proxies confiables explicitos; no uses true ni numero de hops.`, 400);
  }

  try {
    proxyaddr.compile(setting);
  } catch (_error) {
    throw createHttpError(`${key} no es una lista valida de proxies confiables.`, 400);
  }
}

function validatePemBase64Value(key, rawValue) {
  const compactValue = String(rawValue ?? "").trim().replace(/\s+/g, "");
  if (!compactValue) {
    return;
  }
  if (!/^[A-Za-z0-9+/=]+$/.test(compactValue) || compactValue.length % 4 === 1) {
    throw createHttpError(`${key} debe ser base64 valido.`, 400);
  }

  const decodedValue = Buffer.from(compactValue, "base64").toString("utf8").trim();
  if (!decodedValue.includes("-----BEGIN")) {
    throw createHttpError(`${key} debe contener un PEM codificado en base64.`, 400);
  }
}

function hasConfiguredRuntimeValue(values, key) {
  return Object.prototype.hasOwnProperty.call(values, key)
    && String(values[key] ?? "").trim() !== "";
}

function isTruthyRuntimeOption(value) {
  return ["1", "true", "yes", "on"].includes(String(value ?? "").trim().toLowerCase());
}

function validateRuntimeConfigCombination(values) {
  const hasHttpsCert = hasConfiguredRuntimeValue(values, "POS_HTTPS_CERT_PATH")
    || hasConfiguredRuntimeValue(values, "POS_HTTPS_CERT_B64");
  const hasHttpsKey = hasConfiguredRuntimeValue(values, "POS_HTTPS_KEY_PATH")
    || hasConfiguredRuntimeValue(values, "POS_HTTPS_KEY_B64");
  const hasHttpsCa = hasConfiguredRuntimeValue(values, "POS_HTTPS_CA_PATH")
    || hasConfiguredRuntimeValue(values, "POS_HTTPS_CA_B64");
  const redirectPortText = String(values.POS_HTTP_REDIRECT_PORT ?? "").trim();
  const redirectPort = redirectPortText ? Number(redirectPortText) : 0;
  const portText = String(values.PORT ?? process.env.PORT ?? "3100").trim();
  const port = portText ? Number(portText) : 3100;

  if ((hasHttpsCert || hasHttpsKey || hasHttpsCa) && !(hasHttpsCert && hasHttpsKey)) {
    throw createHttpError("POS_HTTPS_CERT_* y POS_HTTPS_KEY_* deben configurarse juntos para habilitar HTTPS directo.", 400);
  }
  if (redirectPortText) {
    if (!Number.isInteger(redirectPort) || redirectPort < 0) {
      throw createHttpError("POS_HTTP_REDIRECT_PORT debe ser un entero igual o mayor a 0.", 400);
    }
    if (redirectPort > 0 && !(hasHttpsCert && hasHttpsKey)) {
      throw createHttpError("POS_HTTP_REDIRECT_PORT requiere configurar certificado y llave HTTPS del POS.", 400);
    }
    if (redirectPort > 0 && Number.isInteger(port) && port > 0 && redirectPort === port) {
      throw createHttpError("POS_HTTP_REDIRECT_PORT no puede usar el mismo puerto que PORT.", 400);
    }
  }
}

function validateRuntimeValue(key, rawValue) {
  if (PEM_BASE64_RUNTIME_KEYS.has(key)) {
    validatePemBase64Value(key, rawValue);
    return;
  }
  if (TRUST_PROXY_RUNTIME_KEYS.has(key)) {
    validateTrustProxyValue(key, rawValue);
    return;
  }
  if (HTTPS_RUNTIME_URL_KEYS.has(key)) {
    validateRuntimeUrlValue(key, rawValue);
    return;
  }
  if (HTTPS_OR_FILE_RUNTIME_URL_KEYS.has(key)) {
    validateRuntimeUrlValue(key, rawValue, { allowFileProtocol: true });
    return;
  }
  if (HTTPS_RUNTIME_URL_LIST_KEYS.has(key)) {
    String(rawValue || "")
      .split(",")
      .map((value) => value.trim())
      .filter(Boolean)
      .forEach((value) => {
        validateRuntimeUrlValue(key, value);
      });
  }
}

function validateIntegerRuntimeValue(key, rawValue, minimum = 0) {
  const value = String(rawValue ?? "").trim();
  if (!value) {
    return;
  }
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < minimum) {
    throw createHttpError(`${key} debe ser un entero igual o mayor a ${minimum}.`, 400);
  }
}

function validateOwnerRuntimeConfigCombination(values) {
  const hasHttpsCert = hasConfiguredRuntimeValue(values, "OWNER_CONTROL_HTTPS_CERT_PATH")
    || hasConfiguredRuntimeValue(values, "OWNER_CONTROL_HTTPS_CERT_B64");
  const hasHttpsKey = hasConfiguredRuntimeValue(values, "OWNER_CONTROL_HTTPS_KEY_PATH")
    || hasConfiguredRuntimeValue(values, "OWNER_CONTROL_HTTPS_KEY_B64");
  const hasHttpsCa = hasConfiguredRuntimeValue(values, "OWNER_CONTROL_HTTPS_CA_PATH")
    || hasConfiguredRuntimeValue(values, "OWNER_CONTROL_HTTPS_CA_B64");
  const redirectPortText = String(values.OWNER_CONTROL_HTTP_REDIRECT_PORT ?? "").trim();
  const redirectPort = redirectPortText ? Number(redirectPortText) : 0;
  const portText = String(values.OWNER_CONTROL_PORT ?? process.env.OWNER_CONTROL_PORT ?? process.env.PORT ?? "3200").trim();
  const port = portText ? Number(portText) : 3200;

  if ((hasHttpsCert || hasHttpsKey || hasHttpsCa) && !(hasHttpsCert && hasHttpsKey)) {
    throw createHttpError("OWNER_CONTROL_HTTPS_CERT_* y OWNER_CONTROL_HTTPS_KEY_* deben configurarse juntos para habilitar HTTPS directo.", 400);
  }
  if (redirectPortText) {
    if (!Number.isInteger(redirectPort) || redirectPort < 0) {
      throw createHttpError("OWNER_CONTROL_HTTP_REDIRECT_PORT debe ser un entero igual o mayor a 0.", 400);
    }
    if (redirectPort > 0 && !(hasHttpsCert && hasHttpsKey)) {
      throw createHttpError("OWNER_CONTROL_HTTP_REDIRECT_PORT requiere configurar certificado y llave HTTPS de owner-control.", 400);
    }
    if (redirectPort > 0 && Number.isInteger(port) && port > 0 && redirectPort === port) {
      throw createHttpError("OWNER_CONTROL_HTTP_REDIRECT_PORT no puede usar el mismo puerto que OWNER_CONTROL_PORT.", 400);
    }
  }
}

function validateOwnerRuntimeValue(key, rawValue) {
  if (OWNER_PEM_BASE64_RUNTIME_KEYS.has(key)) {
    validatePemBase64Value(key, rawValue);
    return;
  }
  if (OWNER_TRUST_PROXY_RUNTIME_KEYS.has(key)) {
    validateTrustProxyValue(key, rawValue);
    return;
  }
  if (OWNER_HTTPS_RUNTIME_URL_KEYS.has(key)) {
    validateRuntimeUrlValue(key, rawValue);
    return;
  }
  if (key === "OWNER_CONTROL_TOKEN") {
    const value = String(rawValue ?? "").trim();
    if (!value) {
      return;
    }
    if (value === "dev-owner-token" || value.length < 24) {
      throw createHttpError("OWNER_CONTROL_TOKEN debe ser un secreto largo y no puede usar el valor por defecto.", 400);
    }
    return;
  }
  if (key === "OWNER_CONTROL_PORT") {
    validateIntegerRuntimeValue(key, rawValue, 1);
    return;
  }
  if (key === "OWNER_CONTROL_HTTP_REDIRECT_PORT" || key === "OWNER_CONTROL_HSTS_MAX_AGE_SECONDS") {
    validateIntegerRuntimeValue(key, rawValue, 0);
    return;
  }
  if (key === "OWNER_CONTROL_CLIENT_SIGNATURE_WINDOW_MS") {
    validateIntegerRuntimeValue(key, rawValue, 60000);
    return;
  }
  if (key === "OWNER_CONTROL_RATE_LIMIT_WINDOW_MS") {
    validateIntegerRuntimeValue(key, rawValue, 1000);
    return;
  }
  if (key === "OWNER_CONTROL_RATE_LIMIT_MAX") {
    validateIntegerRuntimeValue(key, rawValue, 20);
  }
}

function validateClientBaseUrl(rawValue) {
  const value = String(rawValue || "").trim();
  if (!value) {
    return "";
  }

  let parsed = null;
  try {
    parsed = new URL(value);
  } catch (_error) {
    throw createHttpError("La URL publica del cliente no es valida.", 400);
  }

  if (!["http:", "https:"].includes(parsed.protocol)) {
    throw createHttpError("La URL publica del cliente debe iniciar con http:// o https://.", 400);
  }

  if (parsed.protocol !== "https:" && !isLoopbackRuntimeHost(parsed.hostname)) {
    throw createHttpError("La URL publica del cliente debe usar HTTPS fuera de localhost.", 400);
  }

  return parsed.toString().replace(/\/+$/g, "");
}

function parseRuntimeValues(value) {
  return normalizeRuntimeValues(safeJsonParse(value, {}));
}

function normalizeRuntimeKeyList(input) {
  return [...new Set((Array.isArray(input) ? input : [])
    .map((item) => String(item || "").trim())
    .filter((item) => EDITABLE_RUNTIME_KEYS.has(item)))]
    .sort();
}

function normalizeOwnerRuntimeKeyList(input) {
  return [...new Set((Array.isArray(input) ? input : [])
    .map((item) => String(item || "").trim())
    .filter((item) => EDITABLE_OWNER_RUNTIME_KEYS.has(item)))]
    .sort();
}

function sameRuntimeKeyList(left, right) {
  const leftList = normalizeRuntimeKeyList(left);
  const rightList = normalizeRuntimeKeyList(right);
  return leftList.length === rightList.length && leftList.every((item, index) => item === rightList[index]);
}

function diffRuntimeValueKeys(currentValues, bootValues, allowedKeys) {
  const keys = new Set([
    ...Object.keys(currentValues || {}),
    ...Object.keys(bootValues || {}),
  ]);
  return [...keys]
    .filter((key) => !allowedKeys || allowedKeys.has(key))
    .filter((key) => String(currentValues?.[key] ?? "").trim() !== String(bootValues?.[key] ?? "").trim())
    .sort();
}

function getClientRuntimeSyncValues(rowOrValues) {
  const values = rowOrValues && Object.prototype.hasOwnProperty.call(rowOrValues, "runtime_config_json")
    ? parseRuntimeValues(rowOrValues.runtime_config_json)
    : normalizeRuntimeValues(rowOrValues);
  return Object.keys(values)
    .sort()
    .reduce((result, key) => {
      if (!PAIRING_RUNTIME_KEYS.has(key)) {
        result[key] = values[key];
      }
      return result;
    }, {});
}

function stableRuntimeJson(values) {
  const normalized = normalizeRuntimeValues(values);
  const sorted = Object.keys(normalized)
    .sort()
    .reduce((result, key) => {
      result[key] = normalized[key];
      return result;
    }, {});
  return JSON.stringify(sorted);
}

function parseOwnerRuntimeValues(value) {
  return normalizeOwnerRuntimeValues(safeJsonParse(value, {}));
}

function stableOwnerRuntimeJson(values) {
  const normalized = normalizeOwnerRuntimeValues(values);
  const sorted = Object.keys(normalized)
    .sort()
    .reduce((result, key) => {
      result[key] = normalized[key];
      return result;
    }, {});
  return JSON.stringify(sorted);
}

function hashOwnerRuntimeValues(values) {
  return crypto.createHash("sha256").update(stableOwnerRuntimeJson(values), "utf8").digest("hex");
}

function hashRuntimeValues(values) {
  return crypto.createHash("sha256").update(stableRuntimeJson(values), "utf8").digest("hex");
}

function buildClientRuntimeConfig(row, options = {}) {
  const values = parseRuntimeValues(row.runtime_config_json);
  const syncValues = getClientRuntimeSyncValues(values);
  const keys = Object.keys(values).sort();
  const syncKeys = Object.keys(syncValues).sort();
  const appliedKeys = normalizeRuntimeKeyList(safeJsonParse(row.latest_runtime_sync_keys_json, []));
  const runtimeUpdatedAt = row.runtime_config_updated_at || row.updated_at || null;
  const syncedAt = row.latest_runtime_sync_at || null;
  const expectedHash = hashRuntimeValues(syncValues);
  const appliedHash = String(row.latest_runtime_sync_hash || "");
  const runtimeValuesInSync = Boolean(
    syncedAt
    && (!runtimeUpdatedAt || syncedAt >= runtimeUpdatedAt)
    && sameRuntimeKeyList(syncKeys, appliedKeys)
    && expectedHash === appliedHash,
  );
  const latestAuthenticatedAt = row.latest_authenticated_at || null;
  const pairingChangedAt = row.api_key_rotated_at || row.created_at || null;
  const pairingInSync = Boolean(
    !pairingChangedAt
    || (latestAuthenticatedAt && latestAuthenticatedAt >= pairingChangedAt),
  );
  let syncStatus = normalizeStatus(row.latest_runtime_sync_status, VALID_CONFIG_SYNC_STATUSES, "unknown");
  if (!pairingInSync) {
    syncStatus = "pending";
  } else if (syncStatus === "applied" && !runtimeValuesInSync) {
    syncStatus = "stale";
  }
  const syncMessage = !pairingInSync
    ? latestAuthenticatedAt
      ? "API key rotada en owner-control. Actualiza CONTROL_CLIENT_SECRET en el POS para reactivar la sincronizacion."
      : "Esperando que el POS se conecte por primera vez con la API key actual."
    : row.latest_runtime_sync_message || "";

  const payload = {
    updatedAt: runtimeUpdatedAt,
    keys,
    managedKeys: syncKeys,
    variables: cloneRuntimeVariableDefinitions().map((definition) => {
      const hasStoredValue = Object.prototype.hasOwnProperty.call(values, definition.key)
        && String(values[definition.key] ?? "").trim() !== "";
      const isSecret = Boolean(definition.secret);
      return {
        ...definition,
        value: !isSecret ? String(values[definition.key] || "") : "",
        hasStoredValue,
        maskedValue: isSecret && hasStoredValue ? "********" : "",
        managedByClientSync: !PAIRING_RUNTIME_KEYS.has(definition.key),
      };
    }),
    sync: {
      status: syncStatus,
      inSync: runtimeValuesInSync && pairingInSync,
      syncedAt,
      message: syncMessage,
      keys: appliedKeys,
      pairingInSync,
      pairingChangedAt,
      latestAuthenticatedAt,
    },
  };
  if (options.includeValues) {
    payload.values = syncValues;
    payload.runtimeHash = expectedHash;
  }
  return payload;
}

function safeIso(value, fallback = nowIso()) {
  if (!value) {
    return fallback;
  }
  const date = new Date(value);
  return Number.isFinite(date.getTime()) ? date.toISOString() : fallback;
}

function normalizeHealthIssueSignature(items) {
  return (Array.isArray(items) ? items : []).map((item) => ({
    code: String(item?.code || ""),
    severity: String(item?.severity || ""),
    message: String(item?.message || item?.title || ""),
  }));
}

function buildHealthReportSignature(status, reasons, actions) {
  return JSON.stringify({
    status: String(status || "unknown"),
    reasons: normalizeHealthIssueSignature(reasons),
    actions: normalizeHealthIssueSignature(actions),
  });
}

function normalizeMoney(value, fallback = 0) {
  const amount = Number(value ?? fallback);
  if (!Number.isFinite(amount) || amount < 0) {
    throw createHttpError("El monto no es valido.", 400);
  }
  return Math.round(amount * 100) / 100;
}

function normalizeDateKey(value, fieldName, fallback = null) {
  if (value == null || value === "") {
    return fallback;
  }
  const text = String(value).trim();
  if (!/^\d{4}-\d{2}-\d{2}$/.test(text)) {
    throw createHttpError(`${fieldName} debe tener formato YYYY-MM-DD.`, 400);
  }
  const date = new Date(`${text}T00:00:00.000Z`);
  if (!Number.isFinite(date.getTime()) || date.toISOString().slice(0, 10) !== text) {
    throw createHttpError(`${fieldName} no es una fecha real.`, 400);
  }
  return text;
}

function shiftDateKey(dateKey, days) {
  const date = new Date(`${dateKey}T00:00:00.000Z`);
  date.setUTCDate(date.getUTCDate() + Number(days || 0));
  return date.toISOString().slice(0, 10);
}

function generateApiKey() {
  return `pos_${crypto.randomBytes(32).toString("base64url")}`;
}

function hashApiKey(apiKey) {
  return crypto.createHash("sha256").update(String(apiKey || ""), "utf8").digest("hex");
}

function safeEqualHash(left, right) {
  const leftBuffer = Buffer.from(String(left || ""), "hex");
  const rightBuffer = Buffer.from(String(right || ""), "hex");
  return leftBuffer.length === rightBuffer.length && crypto.timingSafeEqual(leftBuffer, rightBuffer);
}

function safeJsonParse(value, fallback) {
  if (!value) {
    return fallback;
  }
  try {
    return JSON.parse(value);
  } catch (_error) {
    return fallback;
  }
}

function normalizeStatus(value, allowed, fallback) {
  const status = String(value || fallback).trim().toLowerCase();
  return allowed.has(status) ? status : fallback;
}

function buildClientConfig(row) {
  const enabledModules = parseConfigList(row.enabled_modules_json, OWNER_AVAILABLE_MODULES, DEFAULT_ENABLED_MODULES);
  const adminCapabilities = parseConfigList(row.admin_capabilities_json, OWNER_ADMIN_SECTIONS, DEFAULT_ADMIN_CAPABILITIES);
  const appliedModules = parseConfigList(row.latest_config_sync_modules_json, OWNER_AVAILABLE_MODULES, []);
  const appliedAdminCapabilities = parseConfigList(row.latest_config_sync_capabilities_json, OWNER_ADMIN_SECTIONS, []);
  const configUpdatedAt = row.config_updated_at || row.updated_at || null;
  const syncedAt = row.latest_config_sync_at || null;
  const inSync = Boolean(
    syncedAt
    && (!configUpdatedAt || syncedAt >= configUpdatedAt)
    && sameConfigList(enabledModules, appliedModules)
    && sameConfigList(adminCapabilities, appliedAdminCapabilities),
  );
  let syncStatus = normalizeStatus(row.latest_config_sync_status, VALID_CONFIG_SYNC_STATUSES, "unknown");
  if (syncStatus === "applied" && !inSync) {
    syncStatus = "stale";
  }

  return {
    enabledModules,
    adminCapabilities,
    updatedAt: configUpdatedAt,
    sync: {
      status: syncStatus,
      inSync,
      syncedAt,
      message: row.latest_config_sync_message || "",
      enabledModules: appliedModules,
      adminCapabilities: appliedAdminCapabilities,
    },
  };
}

function mapClient(row) {
  if (!row) {
    return null;
  }
  return {
    id: row.id,
    slug: row.slug,
    businessName: row.business_name,
    baseUrl: row.base_url || "",
    healthStatus: row.health_status || "unknown",
    latestHealthAt: row.latest_health_at || null,
    latestValidationAt: row.latest_validation_at || null,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    subscription: {
      status: row.status,
      planCode: row.plan_code,
      monthlyAmount: Number(row.monthly_amount || 0),
      currencyCode: row.currency_code || "MXN",
      currentPeriodStart: row.current_period_start || null,
      currentPeriodEnd: row.current_period_end || null,
      gracePeriodUntil: row.grace_period_until || null,
      lastPaymentAt: row.last_payment_at || null,
    },
    config: buildClientConfig(row),
    runtimeConfig: buildClientRuntimeConfig(row),
  };
}

function mapPayment(row) {
  return {
    id: row.id,
    slug: row.client_slug,
    amount: Number(row.amount || 0),
    paymentMethod: row.payment_method || "",
    periodStart: row.period_start || null,
    periodEnd: row.period_end || null,
    paidAt: row.paid_at,
    notes: row.notes || "",
    createdAt: row.created_at,
  };
}

function mapHealthReport(row) {
  return {
    id: row.id,
    slug: row.client_slug,
    status: row.status || "unknown",
    reasons: safeJsonParse(row.reasons_json, []),
    actions: safeJsonParse(row.actions_json, []),
    metrics: safeJsonParse(row.metrics_json, {}),
    reportedAt: row.reported_at,
    receivedAt: row.received_at,
  };
}

function mapValidationReport(row) {
  return {
    id: row.id,
    slug: row.client_slug,
    status: row.status || "unknown",
    url: row.url || "",
    checks: safeJsonParse(row.checks_json, []),
    summary: safeJsonParse(row.summary_json, {}),
    reportedAt: row.reported_at,
    receivedAt: row.received_at,
  };
}

function initializeSchema(db) {
  db.exec(`
    PRAGMA foreign_keys = ON;

    CREATE TABLE IF NOT EXISTS clients (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      slug TEXT NOT NULL UNIQUE,
      business_name TEXT NOT NULL,
      base_url TEXT NOT NULL DEFAULT '',
      status TEXT NOT NULL DEFAULT 'trial',
      plan_code TEXT NOT NULL DEFAULT 'beta',
      monthly_amount REAL NOT NULL DEFAULT 0,
      currency_code TEXT NOT NULL DEFAULT 'MXN',
      current_period_start TEXT,
      current_period_end TEXT,
      grace_period_until TEXT,
      last_payment_at TEXT,
      api_key_hash TEXT NOT NULL,
      api_key_rotated_at TEXT NOT NULL,
      health_status TEXT NOT NULL DEFAULT 'unknown',
      latest_health_at TEXT,
      latest_validation_at TEXT,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS payments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      client_slug TEXT NOT NULL,
      amount REAL NOT NULL,
      payment_method TEXT NOT NULL DEFAULT '',
      period_start TEXT NOT NULL,
      period_end TEXT NOT NULL,
      paid_at TEXT NOT NULL,
      notes TEXT NOT NULL DEFAULT '',
      created_at TEXT NOT NULL,
      FOREIGN KEY (client_slug) REFERENCES clients(slug) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS health_reports (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      client_slug TEXT NOT NULL,
      status TEXT NOT NULL,
      reasons_json TEXT NOT NULL DEFAULT '[]',
      actions_json TEXT NOT NULL DEFAULT '[]',
      metrics_json TEXT NOT NULL DEFAULT '{}',
      reported_at TEXT NOT NULL,
      received_at TEXT NOT NULL,
      FOREIGN KEY (client_slug) REFERENCES clients(slug) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS validation_reports (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      client_slug TEXT NOT NULL,
      status TEXT NOT NULL,
      url TEXT NOT NULL DEFAULT '',
      checks_json TEXT NOT NULL DEFAULT '[]',
      summary_json TEXT NOT NULL DEFAULT '{}',
      reported_at TEXT NOT NULL,
      received_at TEXT NOT NULL,
      FOREIGN KEY (client_slug) REFERENCES clients(slug) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS owner_runtime_state (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      runtime_config_json TEXT NOT NULL DEFAULT '{}',
      updated_at TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_payments_client_created ON payments(client_slug, created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_health_reports_client_received ON health_reports(client_slug, received_at DESC);
    CREATE INDEX IF NOT EXISTS idx_validation_reports_client_received ON validation_reports(client_slug, received_at DESC);
  `);
  db.prepare(`
    INSERT OR IGNORE INTO owner_runtime_state (id, runtime_config_json, updated_at)
    VALUES (1, '{}', NULL)
  `).run();
  ensureColumn(
    db,
    "clients",
    "enabled_modules_json",
    `enabled_modules_json TEXT NOT NULL DEFAULT '${JSON.stringify(DEFAULT_ENABLED_MODULES)}'`,
  );
  ensureColumn(
    db,
    "clients",
    "admin_capabilities_json",
    `admin_capabilities_json TEXT NOT NULL DEFAULT '${JSON.stringify(DEFAULT_ADMIN_CAPABILITIES)}'`,
  );
  ensureColumn(db, "clients", "config_updated_at", "config_updated_at TEXT");
  ensureColumn(db, "clients", "latest_config_sync_at", "latest_config_sync_at TEXT");
  ensureColumn(db, "clients", "latest_config_sync_status", "latest_config_sync_status TEXT NOT NULL DEFAULT 'unknown'");
  ensureColumn(db, "clients", "latest_config_sync_message", "latest_config_sync_message TEXT NOT NULL DEFAULT ''");
  ensureColumn(db, "clients", "latest_config_sync_modules_json", "latest_config_sync_modules_json TEXT NOT NULL DEFAULT '[]'");
  ensureColumn(db, "clients", "latest_config_sync_capabilities_json", "latest_config_sync_capabilities_json TEXT NOT NULL DEFAULT '[]'");
  ensureColumn(db, "clients", "runtime_config_json", "runtime_config_json TEXT NOT NULL DEFAULT '{}'");
  ensureColumn(db, "clients", "runtime_config_updated_at", "runtime_config_updated_at TEXT");
  ensureColumn(db, "clients", "latest_runtime_sync_at", "latest_runtime_sync_at TEXT");
  ensureColumn(db, "clients", "latest_runtime_sync_status", "latest_runtime_sync_status TEXT NOT NULL DEFAULT 'unknown'");
  ensureColumn(db, "clients", "latest_runtime_sync_message", "latest_runtime_sync_message TEXT NOT NULL DEFAULT ''");
  ensureColumn(db, "clients", "latest_runtime_sync_keys_json", "latest_runtime_sync_keys_json TEXT NOT NULL DEFAULT '[]'");
  ensureColumn(db, "clients", "latest_runtime_sync_hash", "latest_runtime_sync_hash TEXT NOT NULL DEFAULT ''");
  ensureColumn(db, "clients", "latest_authenticated_at", "latest_authenticated_at TEXT");
  db.prepare(`
    UPDATE clients
    SET config_updated_at = COALESCE(config_updated_at, updated_at, created_at)
    WHERE config_updated_at IS NULL OR config_updated_at = ''
  `).run();
  db.prepare(`
    UPDATE clients
    SET runtime_config_updated_at = COALESCE(runtime_config_updated_at, updated_at, created_at)
    WHERE runtime_config_updated_at IS NULL OR runtime_config_updated_at = ''
  `).run();
}

function ensureColumn(db, tableName, columnName, columnDdl) {
  const columns = db.prepare(`PRAGMA table_info(${tableName})`).all();
  if (!columns.some((column) => column.name === columnName)) {
    db.exec(`ALTER TABLE ${tableName} ADD COLUMN ${columnDdl}`);
  }
}

function createControlStore(options = {}) {
  const dbPath = options.dbPath || path.resolve(__dirname, "..", "data", "owner-control.sqlite");
  fs.mkdirSync(path.dirname(dbPath), { recursive: true });
  const db = new Database(dbPath);
  db.pragma("journal_mode = WAL");
  db.pragma("synchronous = NORMAL");
  initializeSchema(db);
  const healthReportRetentionLimit = Math.max(
    1,
    Number(options.healthReportRetentionLimit || process.env.OWNER_CONTROL_HEALTH_REPORT_RETENTION_LIMIT || 200),
  );
  const validationReportRetentionLimit = Math.max(
    1,
    Number(options.validationReportRetentionLimit || process.env.OWNER_CONTROL_VALIDATION_REPORT_RETENTION_LIMIT || 200),
  );

  function getClientRow(slug) {
    const safeSlug = normalizeSlug(slug);
    return db.prepare("SELECT * FROM clients WHERE slug = ?").get(safeSlug);
  }

  function requireClientRow(slug) {
    const row = getClientRow(slug);
    if (!row) {
      throw createHttpError("Cliente no encontrado.", 404);
    }
    return row;
  }

  function getOwnerRuntimeRow() {
    return db.prepare("SELECT runtime_config_json, updated_at FROM owner_runtime_state WHERE id = 1").get();
  }

  function pruneHealthReports(slug) {
    db.prepare(`
      DELETE FROM health_reports
      WHERE client_slug = ?
        AND id NOT IN (
          SELECT id
          FROM health_reports
          WHERE client_slug = ?
          ORDER BY received_at DESC, id DESC
          LIMIT ?
        )
    `).run(slug, slug, healthReportRetentionLimit);
  }

  function pruneValidationReports(slug) {
    db.prepare(`
      DELETE FROM validation_reports
      WHERE client_slug = ?
        AND id NOT IN (
          SELECT id
          FROM validation_reports
          WHERE client_slug = ?
          ORDER BY received_at DESC, id DESC
          LIMIT ?
        )
    `).run(slug, slug, validationReportRetentionLimit);
  }

  function buildOwnerRuntimeConfig(row = getOwnerRuntimeRow(), options = {}) {
    const values = parseOwnerRuntimeValues(row?.runtime_config_json);
    const keys = Object.keys(values).sort();
    const bootValues = normalizeOwnerRuntimeValues(options.bootValues || {});
    const fallbackValues = normalizeOwnerRuntimeValues(options.fallbackValues || {});
    const effectiveNextValues = normalizeOwnerRuntimeValues({
      ...fallbackValues,
      ...values,
    });
    if (!hasConfiguredRuntimeValue(effectiveNextValues, "OWNER_CONTROL_REQUIRE_CLIENT_SIGNATURE")) {
      const defaultRequireClientSignature = isTruthyRuntimeOption(effectiveNextValues.OWNER_CONTROL_FORCE_HTTPS)
        || Boolean(options.isProductionRuntime);
      effectiveNextValues.OWNER_CONTROL_REQUIRE_CLIENT_SIGNATURE = defaultRequireClientSignature ? "true" : "false";
    }
    const pendingKeys = diffRuntimeValueKeys(effectiveNextValues, bootValues, EDITABLE_OWNER_RUNTIME_KEYS);
    const restartRequired = pendingKeys.length > 0;

    return {
      updatedAt: row?.updated_at || null,
      keys,
      pendingKeys,
      restartRequired,
      runtimeHash: hashOwnerRuntimeValues(values),
      bootRuntimeHash: hashOwnerRuntimeValues(bootValues),
      message: restartRequired
        ? "Hay cambios runtime guardados en owner-control. Reinicia el proceso Node para aplicar HTTPS, token, proxy o limites nuevos."
        : "Sin cambios runtime pendientes en owner-control.",
      variables: cloneOwnerRuntimeVariableDefinitions().map((definition) => {
        const hasStoredValue = Object.prototype.hasOwnProperty.call(values, definition.key)
          && String(values[definition.key] ?? "").trim() !== "";
        const isSecret = Boolean(definition.secret);
      return {
        ...definition,
        value: !isSecret ? String(values[definition.key] || "") : "",
        hasStoredValue,
        maskedValue: isSecret && hasStoredValue ? "********" : "",
        pendingRestart: pendingKeys.includes(definition.key),
        managedHint: "aplica al reiniciar owner-control",
      };
    }),
  };
}

  function listClients() {
    return db.prepare(`
      SELECT *
      FROM clients
      ORDER BY
        CASE status
          WHEN 'overdue' THEN 1
          WHEN 'suspended' THEN 2
          WHEN 'trial' THEN 3
          WHEN 'active' THEN 4
          ELSE 5
        END,
        business_name COLLATE NOCASE ASC
    `).all().map(mapClient);
  }

  function getClientDetail(slug) {
    const row = requireClientRow(slug);
    const safeSlug = row.slug;
    return {
      client: mapClient(row),
      availableModules: cloneDefinitions(OWNER_AVAILABLE_MODULES),
      adminSections: cloneDefinitions(OWNER_ADMIN_SECTIONS),
      runtimeVariables: cloneRuntimeVariableDefinitions(),
      payments: listClientPayments(safeSlug, 20),
      healthReports: db.prepare(`
        SELECT *
        FROM health_reports
        WHERE client_slug = ?
        ORDER BY received_at DESC, id DESC
        LIMIT 10
      `).all(safeSlug).map(mapHealthReport),
      validationReports: db.prepare(`
        SELECT *
        FROM validation_reports
        WHERE client_slug = ?
        ORDER BY received_at DESC, id DESC
        LIMIT 10
      `).all(safeSlug).map(mapValidationReport),
    };
  }

  function getOwnerRuntimeValues() {
    return parseOwnerRuntimeValues(getOwnerRuntimeRow()?.runtime_config_json);
  }

  function getOwnerRuntimeConfig(options = {}) {
    return {
      runtimeConfig: buildOwnerRuntimeConfig(getOwnerRuntimeRow(), options),
      runtimeVariables: cloneOwnerRuntimeVariableDefinitions(),
    };
  }

  function listClientPayments(slug, limit = 12) {
    const row = requireClientRow(slug);
    const safeLimit = Math.max(1, Math.min(50, Number(limit || 12)));
    return db.prepare(`
      SELECT *
      FROM payments
      WHERE client_slug = ?
      ORDER BY paid_at DESC, id DESC
      LIMIT ?
    `).all(row.slug, safeLimit).map(mapPayment);
  }

  function getClientConfig(slug) {
    const row = requireClientRow(slug);
    const client = mapClient(row);
    return {
      client: {
        slug: client.slug,
        businessName: client.businessName,
      },
      config: client.config,
      availableModules: cloneDefinitions(OWNER_AVAILABLE_MODULES),
      adminSections: cloneDefinitions(OWNER_ADMIN_SECTIONS),
    };
  }

  function updateClientConfig(slug, payload = {}) {
    const row = requireClientRow(slug);
    const current = mapClient(row).config;
    const enabledModules = Object.prototype.hasOwnProperty.call(payload, "enabledModules")
      ? normalizeConfigList(payload.enabledModules, OWNER_AVAILABLE_MODULES, current.enabledModules)
      : current.enabledModules;
    const adminCapabilities = Object.prototype.hasOwnProperty.call(payload, "adminCapabilities")
      ? normalizeConfigList(payload.adminCapabilities, OWNER_ADMIN_SECTIONS, current.adminCapabilities)
      : current.adminCapabilities;
    const now = nowIso();

    db.prepare(`
      UPDATE clients
      SET
        enabled_modules_json = ?,
        admin_capabilities_json = ?,
        config_updated_at = ?,
        latest_config_sync_status = 'pending',
        latest_config_sync_message = 'Esperando que el POS aplique la configuracion central.',
        updated_at = ?
      WHERE slug = ?
    `).run(JSON.stringify(enabledModules), JSON.stringify(adminCapabilities), now, now, row.slug);

    return getClientConfig(row.slug);
  }

  function recordClientConfigSync(client, payload = {}) {
    const row = requireClientRow(client.slug);
    const status = normalizeStatus(payload.status, VALID_CONFIG_SYNC_STATUSES, "applied");
    const enabledModules = normalizeConfigList(payload.enabledModules, OWNER_AVAILABLE_MODULES, []);
    const adminCapabilities = normalizeConfigList(payload.adminCapabilities, OWNER_ADMIN_SECTIONS, []);
    const message = normalizeText(payload.message ?? "", 500);
    const reportedAt = safeIso(payload.reportedAt);
    const now = nowIso();

    db.prepare(`
      UPDATE clients
      SET
        latest_config_sync_at = ?,
        latest_config_sync_status = ?,
        latest_config_sync_message = ?,
        latest_config_sync_modules_json = ?,
        latest_config_sync_capabilities_json = ?,
        updated_at = ?
      WHERE slug = ?
    `).run(
      reportedAt,
      status,
      message,
      JSON.stringify(enabledModules),
      JSON.stringify(adminCapabilities),
      now,
      row.slug,
    );

    const updatedClient = mapClient(requireClientRow(row.slug));
    return {
      client: updatedClient,
      configSync: updatedClient.config.sync,
    };
  }

  function getClientRuntimeConfig(slug, options = {}) {
    const row = requireClientRow(slug);
    const client = mapClient(row);
    return {
      client: {
        slug: client.slug,
        businessName: client.businessName,
      },
      runtimeConfig: buildClientRuntimeConfig(row, options),
      runtimeVariables: cloneRuntimeVariableDefinitions(),
    };
  }

  function updateClientRuntimeConfig(slug, payload = {}) {
    const row = requireClientRow(slug);
    const currentValues = parseRuntimeValues(row.runtime_config_json);
    const incomingValues = normalizeRuntimeValues(payload);
    const clearKeys = normalizeRuntimeKeyList(payload.clearKeys);
    const nextValues = { ...currentValues };
    const updatedKeys = [];
    const clearedKeys = [];

    Object.entries(incomingValues).forEach(([key, value]) => {
      const normalizedValue = String(value ?? "").trim();
      const isSecret = SECRET_KEY_PATTERN.test(key);
      if (!normalizedValue && isSecret && currentValues[key]) {
        return;
      }
      if (!normalizedValue) {
        if (Object.prototype.hasOwnProperty.call(nextValues, key)) {
          delete nextValues[key];
          clearedKeys.push(key);
        }
        return;
      }
      validateRuntimeValue(key, normalizedValue);
      if (nextValues[key] !== normalizedValue) {
        nextValues[key] = normalizedValue;
        updatedKeys.push(key);
      }
    });

    clearKeys.forEach((key) => {
      if (Object.prototype.hasOwnProperty.call(nextValues, key)) {
        delete nextValues[key];
        clearedKeys.push(key);
      }
    });

    validateRuntimeConfigCombination(nextValues);
    const changed = updatedKeys.length > 0 || clearedKeys.length > 0;
    const now = nowIso();
    db.prepare(`
      UPDATE clients
      SET
        runtime_config_json = ?,
        runtime_config_updated_at = ?,
        latest_runtime_sync_status = ?,
        latest_runtime_sync_message = ?,
        updated_at = ?
      WHERE slug = ?
    `).run(
      stableRuntimeJson(nextValues),
      changed ? now : row.runtime_config_updated_at || now,
      changed ? "pending" : row.latest_runtime_sync_status || "unknown",
      changed
        ? "Esperando que el POS sincronice variables runtime desde owner-control."
        : row.latest_runtime_sync_message || "",
      now,
      row.slug,
    );

    return {
      ...getClientRuntimeConfig(row.slug),
      updatedKeys: [...new Set(updatedKeys)].sort(),
      clearedKeys: [...new Set(clearedKeys)].sort(),
    };
  }

  function updateOwnerRuntimeConfig(payload = {}, options = {}) {
    const row = getOwnerRuntimeRow();
    const currentValues = parseOwnerRuntimeValues(row?.runtime_config_json);
    const incomingValues = normalizeOwnerRuntimeValues(payload);
    const clearKeys = normalizeOwnerRuntimeKeyList(payload.clearKeys);
    const nextValues = { ...currentValues };
    const updatedKeys = [];
    const clearedKeys = [];

    Object.entries(incomingValues).forEach(([key, value]) => {
      const normalizedValue = String(value ?? "").trim();
      const isSecret = SECRET_KEY_PATTERN.test(key);
      if (!normalizedValue && isSecret && currentValues[key]) {
        return;
      }
      if (!normalizedValue) {
        if (Object.prototype.hasOwnProperty.call(nextValues, key)) {
          delete nextValues[key];
          clearedKeys.push(key);
        }
        return;
      }
      validateOwnerRuntimeValue(key, normalizedValue);
      if (nextValues[key] !== normalizedValue) {
        nextValues[key] = normalizedValue;
        updatedKeys.push(key);
      }
    });

    clearKeys.forEach((key) => {
      if (Object.prototype.hasOwnProperty.call(nextValues, key)) {
        delete nextValues[key];
        clearedKeys.push(key);
      }
    });

    validateOwnerRuntimeConfigCombination(nextValues);
    const changed = updatedKeys.length > 0 || clearedKeys.length > 0;
    const now = nowIso();
    db.prepare(`
      UPDATE owner_runtime_state
      SET runtime_config_json = ?, updated_at = ?
      WHERE id = 1
    `).run(
      stableOwnerRuntimeJson(nextValues),
      changed ? now : row?.updated_at || now,
    );

    return {
      ...getOwnerRuntimeConfig(options),
      updatedKeys: [...new Set(updatedKeys)].sort(),
      clearedKeys: [...new Set(clearedKeys)].sort(),
    };
  }

  function recordClientRuntimeConfigSync(client, payload = {}) {
    const row = requireClientRow(client.slug);
    const status = normalizeStatus(payload.status, VALID_CONFIG_SYNC_STATUSES, "applied");
    const keys = normalizeRuntimeKeyList(payload.keys || payload.appliedKeys || payload.runtimeKeys);
    const runtimeHash = normalizeText(payload.runtimeHash ?? payload.hash ?? "", 128);
    const message = normalizeText(payload.message ?? "", 500);
    const reportedAt = safeIso(payload.reportedAt);
    const now = nowIso();

    db.prepare(`
      UPDATE clients
      SET
        latest_runtime_sync_at = ?,
        latest_runtime_sync_status = ?,
        latest_runtime_sync_message = ?,
        latest_runtime_sync_keys_json = ?,
        latest_runtime_sync_hash = ?,
        updated_at = ?
      WHERE slug = ?
    `).run(
      reportedAt,
      status,
      message,
      JSON.stringify(keys),
      runtimeHash,
      now,
      row.slug,
    );

    const updatedRow = requireClientRow(row.slug);
    return {
      client: mapClient(updatedRow),
      runtimeConfigSync: buildClientRuntimeConfig(updatedRow).sync,
    };
  }

  function createClient(payload = {}) {
    const slug = normalizeSlug(payload.slug);
    const businessName = normalizeText(payload.businessName ?? payload.business_name ?? slug, 120, slug);
    const baseUrl = validateClientBaseUrl(normalizeText(payload.baseUrl ?? payload.base_url ?? "", 300));
    const planCode = normalizeText(payload.planCode ?? payload.plan_code ?? "beta", 48, "beta") || "beta";
    const monthlyAmount = normalizeMoney(payload.monthlyAmount ?? payload.monthly_amount, 0);
    const status = normalizeStatus(payload.status, VALID_SUBSCRIPTION_STATUSES, "trial");
    const apiKey = generateApiKey();
    const now = nowIso();

    try {
      db.prepare(`
        INSERT INTO clients (
          slug,
          business_name,
          base_url,
          status,
          plan_code,
          monthly_amount,
          currency_code,
          enabled_modules_json,
          admin_capabilities_json,
          config_updated_at,
          latest_config_sync_status,
          latest_config_sync_message,
          api_key_hash,
          api_key_rotated_at,
          created_at,
          updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, 'MXN', ?, ?, ?, 'pending', 'Esperando primera sincronizacion POS.', ?, ?, ?, ?)
      `).run(
        slug,
        businessName,
        baseUrl,
        status,
        planCode,
        monthlyAmount,
        JSON.stringify(DEFAULT_ENABLED_MODULES),
        JSON.stringify(DEFAULT_ADMIN_CAPABILITIES),
        now,
        hashApiKey(apiKey),
        now,
        now,
        now,
      );
    } catch (error) {
      if (String(error.message || "").includes("UNIQUE")) {
        throw createHttpError("Ya existe un cliente con ese slug.", 409);
      }
      throw error;
    }

    return {
      client: mapClient(requireClientRow(slug)),
      apiKey,
    };
  }

  function rotateClientKey(slug) {
    const row = requireClientRow(slug);
    const apiKey = generateApiKey();
    const now = nowIso();
    db.prepare(`
      UPDATE clients
      SET api_key_hash = ?, api_key_rotated_at = ?, updated_at = ?
      WHERE slug = ?
    `).run(hashApiKey(apiKey), now, now, row.slug);
    return {
      client: mapClient(requireClientRow(row.slug)),
      apiKey,
    };
  }

  function authenticateClient(slug, apiKey) {
    const row = getClientRow(slug);
    if (!row) {
      throw createHttpError("Credenciales de cliente invalidas.", 403);
    }
    const candidateHash = hashApiKey(apiKey);
    if (!safeEqualHash(candidateHash, row.api_key_hash)) {
      throw createHttpError("Credenciales de cliente invalidas.", 403);
    }
    const latestAuthenticatedAt = String(row.latest_authenticated_at || "");
    const pairingChangedAt = String(row.api_key_rotated_at || row.created_at || "");
    if (!latestAuthenticatedAt || (pairingChangedAt && latestAuthenticatedAt < pairingChangedAt)) {
      db.prepare(`
        UPDATE clients
        SET latest_authenticated_at = ?
        WHERE slug = ?
      `).run(nowIso(), row.slug);
      return mapClient(requireClientRow(row.slug));
    }
    return mapClient(row);
  }

  function updateSubscription(slug, payload = {}) {
    const row = requireClientRow(slug);
    const status = payload.status == null
      ? row.status
      : normalizeStatus(payload.status, VALID_SUBSCRIPTION_STATUSES, row.status);
    const planCode = payload.planCode == null && payload.plan_code == null
      ? row.plan_code
      : normalizeText(payload.planCode ?? payload.plan_code, 48, row.plan_code) || row.plan_code;
    const monthlyAmount = payload.monthlyAmount == null && payload.monthly_amount == null
      ? Number(row.monthly_amount || 0)
      : normalizeMoney(payload.monthlyAmount ?? payload.monthly_amount, row.monthly_amount);
    const currentPeriodStart = normalizeDateKey(
      payload.currentPeriodStart ?? payload.current_period_start,
      "currentPeriodStart",
      row.current_period_start,
    );
    const currentPeriodEnd = normalizeDateKey(
      payload.currentPeriodEnd ?? payload.current_period_end,
      "currentPeriodEnd",
      row.current_period_end,
    );
    const gracePeriodUntil = normalizeDateKey(
      payload.gracePeriodUntil ?? payload.grace_period_until,
      "gracePeriodUntil",
      row.grace_period_until,
    );
    if (currentPeriodStart && currentPeriodEnd && currentPeriodStart > currentPeriodEnd) {
      throw createHttpError("El periodo de suscripcion no es valido.", 400);
    }

    const now = nowIso();
    db.prepare(`
      UPDATE clients
      SET
        status = ?,
        plan_code = ?,
        monthly_amount = ?,
        current_period_start = ?,
        current_period_end = ?,
        grace_period_until = ?,
        updated_at = ?
      WHERE slug = ?
    `).run(status, planCode, monthlyAmount, currentPeriodStart, currentPeriodEnd, gracePeriodUntil, now, row.slug);

    return mapClient(requireClientRow(row.slug));
  }

  function recordPayment(slug, payload = {}) {
    const row = requireClientRow(slug);
    const amount = normalizeMoney(payload.amount, row.monthly_amount || 0);
    if (amount <= 0) {
      throw createHttpError("El pago debe ser mayor a cero.", 400);
    }
    const today = nowIso().slice(0, 10);
    const periodStart = normalizeDateKey(payload.periodStart ?? payload.period_start, "periodStart", today);
    const periodEnd = normalizeDateKey(payload.periodEnd ?? payload.period_end, "periodEnd", shiftDateKey(periodStart, 30));
    if (periodStart > periodEnd) {
      throw createHttpError("El periodo del pago no es valido.", 400);
    }
    const paidAt = payload.paidAt ? new Date(payload.paidAt).toISOString() : nowIso();
    const paymentMethod = normalizeText(payload.paymentMethod ?? payload.payment_method ?? "Transferencia", 60, "Transferencia") || "Transferencia";
    const notes = normalizeText(payload.notes ?? "", 1000);
    const now = nowIso();

    const paymentId = db.transaction(() => {
      const result = db.prepare(`
        INSERT INTO payments (
          client_slug,
          amount,
          payment_method,
          period_start,
          period_end,
          paid_at,
          notes,
          created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `).run(row.slug, amount, paymentMethod, periodStart, periodEnd, paidAt, notes, now);

      db.prepare(`
        UPDATE clients
        SET
          status = 'active',
          monthly_amount = ?,
          current_period_start = ?,
          current_period_end = ?,
          grace_period_until = ?,
          last_payment_at = ?,
          updated_at = ?
        WHERE slug = ?
      `).run(amount, periodStart, periodEnd, shiftDateKey(periodEnd, 5), paidAt, now, row.slug);

      return Number(result.lastInsertRowid);
    })();

    return {
      payment: mapPayment(db.prepare("SELECT * FROM payments WHERE id = ?").get(paymentId)),
      client: mapClient(requireClientRow(row.slug)),
    };
  }

  function receiveHealthReport(client, payload = {}) {
    const slug = normalizeSlug(client.slug);
    const health = payload.health && typeof payload.health === "object" ? payload.health : payload;
    const semaphore = health.semaphore && typeof health.semaphore === "object" ? health.semaphore : health;
    const status = normalizeStatus(semaphore.status || health.status, VALID_HEALTH_STATUSES, "unknown");
    const reasons = Array.isArray(semaphore.reasons) ? semaphore.reasons : [];
    const actions = Array.isArray(semaphore.actions) ? semaphore.actions : [];
    const metrics = health.metrics && typeof health.metrics === "object" ? health.metrics : health;
    const reportedAt = payload.reportedAt ? new Date(payload.reportedAt).toISOString() : nowIso();
    const receivedAt = nowIso();
    const latestReport = db.prepare(`
      SELECT *
      FROM health_reports
      WHERE client_slug = ?
      ORDER BY received_at DESC, id DESC
      LIMIT 1
    `).get(slug);
    const incomingSignature = buildHealthReportSignature(status, reasons, actions);
    const latestSignature = latestReport
      ? buildHealthReportSignature(
          latestReport.status,
          safeJsonParse(latestReport.reasons_json, []),
          safeJsonParse(latestReport.actions_json, []),
        )
      : "";

    if (latestReport && latestSignature === incomingSignature) {
      db.transaction(() => {
        db.prepare(`
          UPDATE health_reports
          SET metrics_json = ?, reported_at = ?, received_at = ?
          WHERE id = ?
        `).run(JSON.stringify(metrics), reportedAt, receivedAt, latestReport.id);
        db.prepare(`
          UPDATE clients
          SET health_status = ?, latest_health_at = ?, updated_at = ?
          WHERE slug = ?
        `).run(status, receivedAt, receivedAt, slug);
        pruneHealthReports(slug);
      })();

      return {
        deduped: true,
        report: mapHealthReport(db.prepare("SELECT * FROM health_reports WHERE id = ?").get(latestReport.id)),
        client: mapClient(requireClientRow(slug)),
      };
    }

    const reportId = db.transaction(() => {
      const result = db.prepare(`
        INSERT INTO health_reports (
          client_slug,
          status,
          reasons_json,
          actions_json,
          metrics_json,
          reported_at,
          received_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
      `).run(
        slug,
        status,
        JSON.stringify(reasons),
        JSON.stringify(actions),
        JSON.stringify(metrics),
        reportedAt,
        receivedAt,
      );
      db.prepare(`
        UPDATE clients
        SET health_status = ?, latest_health_at = ?, updated_at = ?
        WHERE slug = ?
      `).run(status, receivedAt, receivedAt, slug);
      pruneHealthReports(slug);
      return Number(result.lastInsertRowid);
    })();

    return {
      report: mapHealthReport(db.prepare("SELECT * FROM health_reports WHERE id = ?").get(reportId)),
      client: mapClient(requireClientRow(slug)),
    };
  }

  function receiveValidationReport(client, payload = {}) {
    const slug = normalizeSlug(client.slug);
    const checks = Array.isArray(payload.checks) ? payload.checks : [];
    const failedChecks = checks.filter((check) => check && check.ok === false).length;
    const status = normalizeStatus(
      payload.status || (failedChecks > 0 ? "failed" : checks.length > 0 ? "ok" : "unknown"),
      VALID_VALIDATION_STATUSES,
      "unknown",
    );
    const summary = payload.summary && typeof payload.summary === "object"
      ? payload.summary
      : {
          checks: checks.length,
          failedChecks,
        };
    const url = normalizeText(payload.url ?? client.baseUrl ?? "", 300);
    const reportedAt = payload.reportedAt ? new Date(payload.reportedAt).toISOString() : nowIso();
    const receivedAt = nowIso();

    const reportId = db.transaction(() => {
      const result = db.prepare(`
        INSERT INTO validation_reports (
          client_slug,
          status,
          url,
          checks_json,
          summary_json,
          reported_at,
          received_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
      `).run(slug, status, url, JSON.stringify(checks), JSON.stringify(summary), reportedAt, receivedAt);
      db.prepare(`
        UPDATE clients
        SET latest_validation_at = ?, updated_at = ?
        WHERE slug = ?
      `).run(receivedAt, receivedAt, slug);
      pruneValidationReports(slug);
      return Number(result.lastInsertRowid);
    })();

    return {
      report: mapValidationReport(db.prepare("SELECT * FROM validation_reports WHERE id = ?").get(reportId)),
      client: mapClient(requireClientRow(slug)),
    };
  }

  function close() {
    db.close();
  }

  return {
    close,
    createClient,
    getClientConfig,
    getClientDetail,
    getClientRuntimeConfig,
    getOwnerRuntimeConfig,
    getOwnerRuntimeValues,
    listClients,
    listClientPayments,
    recordPayment,
    rotateClientKey,
    authenticateClient,
    recordClientConfigSync,
    recordClientRuntimeConfigSync,
    receiveHealthReport,
    receiveValidationReport,
    updateClientConfig,
    updateClientRuntimeConfig,
    updateOwnerRuntimeConfig,
    updateSubscription,
  };
}

module.exports = {
  DEFAULT_ADMIN_CAPABILITIES,
  DEFAULT_ENABLED_MODULES,
  OWNER_RUNTIME_VARIABLE_DEFINITIONS,
  RUNTIME_VARIABLE_DEFINITIONS,
  createControlStore,
  createHttpError,
};
