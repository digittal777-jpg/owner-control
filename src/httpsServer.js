const fs = require("node:fs");
const http = require("node:http");
const https = require("node:https");
const path = require("node:path");

function normalizeText(value) {
  return String(value || "").trim();
}

function hasValue(value) {
  return normalizeText(value) !== "";
}

function resolveFilePath(baseDir, filePath) {
  return path.isAbsolute(filePath)
    ? filePath
    : path.resolve(baseDir, filePath);
}

function decodePemBase64(value, label) {
  const compactValue = normalizeText(value).replace(/\s+/g, "");
  if (!compactValue) {
    return "";
  }
  if (!/^[A-Za-z0-9+/=]+$/.test(compactValue) || compactValue.length % 4 === 1) {
    throw new Error(`${label} no es base64 valido.`);
  }

  const decodedValue = Buffer.from(compactValue, "base64").toString("utf8").trim();
  if (!decodedValue.includes("-----BEGIN")) {
    throw new Error(`${label} debe contener un PEM codificado en base64.`);
  }

  return decodedValue;
}

function readPemValue({ baseDir, base64Value, filePath, label, optional = false }) {
  if (hasValue(base64Value)) {
    return {
      text: decodePemBase64(base64Value, label),
      source: `${label} (base64)`,
    };
  }

  if (hasValue(filePath)) {
    const resolvedPath = resolveFilePath(baseDir, filePath);
    let fileText = "";
    try {
      fileText = fs.readFileSync(resolvedPath, "utf8").trim();
    } catch (error) {
      throw new Error(`${label} no se pudo leer desde ${resolvedPath}: ${error.message}`);
    }
    if (!fileText.includes("-----BEGIN")) {
      throw new Error(`${label} debe apuntar a un archivo PEM valido.`);
    }
    return {
      text: fileText,
      source: resolvedPath,
    };
  }

  if (optional) {
    return { text: "", source: "" };
  }

  throw new Error(`${label} es requerido para habilitar HTTPS directo.`);
}

function loadHttpsCredentials(options = {}) {
  const values = [
    options.certBase64,
    options.certPath,
    options.keyBase64,
    options.keyPath,
    options.caBase64,
    options.caPath,
  ];
  const enabled = values.some(hasValue);
  if (!enabled) {
    return {
      enabled: false,
      tlsOptions: null,
      sources: [],
    };
  }

  const labelPrefix = normalizeText(options.label || "HTTPS");
  const baseDir = options.baseDir || process.cwd();
  const certificate = readPemValue({
    baseDir,
    base64Value: options.certBase64,
    filePath: options.certPath,
    label: `${labelPrefix} certificado`,
  });
  const privateKey = readPemValue({
    baseDir,
    base64Value: options.keyBase64,
    filePath: options.keyPath,
    label: `${labelPrefix} llave privada`,
  });
  const certificateAuthority = readPemValue({
    baseDir,
    base64Value: options.caBase64,
    filePath: options.caPath,
    label: `${labelPrefix} CA`,
    optional: true,
  });

  return {
    enabled: true,
    tlsOptions: {
      cert: certificate.text,
      key: privateKey.text,
      ca: certificateAuthority.text || undefined,
      minVersion: "TLSv1.2",
    },
    sources: [certificate.source, privateKey.source, certificateAuthority.source].filter(Boolean),
  };
}

function createPrimaryServer(app, httpsCredentials) {
  return httpsCredentials?.enabled
    ? https.createServer(httpsCredentials.tlsOptions, app)
    : http.createServer(app);
}

function buildFallbackHttpsOrigin(request, httpsPort) {
  const defaultHost = httpsPort === 443 ? "localhost" : `localhost:${httpsPort}`;
  const hostHeader = normalizeText(request?.headers?.host || defaultHost);
  try {
    const parsed = new URL(`http://${hostHeader}`);
    const hostname = parsed.hostname.includes(":")
      ? `[${parsed.hostname}]`
      : parsed.hostname;
    const portSegment = httpsPort === 443 ? "" : `:${httpsPort}`;
    return `https://${hostname}${portSegment}`;
  } catch (_error) {
    return `https://${defaultHost}`;
  }
}

function buildHttpsRedirectUrl(request, options = {}) {
  const publicOrigin = normalizeText(options.publicOrigin);
  const httpsPort = Math.max(1, Number(options.httpsPort) || 443);
  const targetOrigin = publicOrigin || buildFallbackHttpsOrigin(request, httpsPort);
  return new URL(request?.url || "/", targetOrigin).toString();
}

function createRedirectServer(options = {}) {
  return http.createServer((request, response) => {
    response.statusCode = 308;
    response.setHeader("Cache-Control", "no-store");
    response.setHeader("Location", buildHttpsRedirectUrl(request, options));
    response.end("Redirigiendo a HTTPS.");
  });
}

module.exports = {
  buildHttpsRedirectUrl,
  createPrimaryServer,
  createRedirectServer,
  loadHttpsCredentials,
};
