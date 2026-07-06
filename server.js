const crypto = require("node:crypto");
const path = require("node:path");

const { createApp } = require("./src/app");
const { createControlStore } = require("./src/store");
const {
  createPrimaryServer,
  createRedirectServer,
  loadHttpsCredentials,
} = require("./src/httpsServer");

const DB_PATH = process.env.OWNER_CONTROL_DB_PATH
  ? path.resolve(process.cwd(), process.env.OWNER_CONTROL_DB_PATH)
  : path.resolve(__dirname, "data", "owner-control.sqlite");
const NODE_ENV = String(process.env.NODE_ENV || "").trim().toLowerCase();
const store = createControlStore({ dbPath: DB_PATH });
const ownerRuntimeBootValues = store.getOwnerRuntimeValues();

function pickStoredRuntimeValue(key, fallback = "") {
  const storedValue = String(ownerRuntimeBootValues[key] || "").trim();
  return storedValue || String(fallback || "").trim();
}

function pickEnvironmentRuntimeValue(key, fallback = "") {
  const envValue = String(process.env[key] || "").trim();
  return envValue || String(fallback || "").trim();
}

const RUNTIME_PORT = Number(ownerRuntimeBootValues.OWNER_CONTROL_PORT || 0);
const PORT = Number(process.env.OWNER_CONTROL_PORT || process.env.PORT || RUNTIME_PORT || 3200);
const HTTPS_CERT_PATH = pickStoredRuntimeValue("OWNER_CONTROL_HTTPS_CERT_PATH", process.env.OWNER_CONTROL_HTTPS_CERT_PATH);
const HTTPS_KEY_PATH = pickStoredRuntimeValue("OWNER_CONTROL_HTTPS_KEY_PATH", process.env.OWNER_CONTROL_HTTPS_KEY_PATH);
const HTTPS_CA_PATH = pickStoredRuntimeValue("OWNER_CONTROL_HTTPS_CA_PATH", process.env.OWNER_CONTROL_HTTPS_CA_PATH);
const HTTPS_CERT_B64 = pickStoredRuntimeValue("OWNER_CONTROL_HTTPS_CERT_B64", process.env.OWNER_CONTROL_HTTPS_CERT_B64);
const HTTPS_KEY_B64 = pickStoredRuntimeValue("OWNER_CONTROL_HTTPS_KEY_B64", process.env.OWNER_CONTROL_HTTPS_KEY_B64);
const HTTPS_CA_B64 = pickStoredRuntimeValue("OWNER_CONTROL_HTTPS_CA_B64", process.env.OWNER_CONTROL_HTTPS_CA_B64);
const HTTP_REDIRECT_PORT = Math.max(
  0,
  Number(process.env.OWNER_CONTROL_HTTP_REDIRECT_PORT || ownerRuntimeBootValues.OWNER_CONTROL_HTTP_REDIRECT_PORT || 0),
);
const PUBLIC_ORIGIN = pickStoredRuntimeValue("OWNER_CONTROL_PUBLIC_ORIGIN", process.env.OWNER_CONTROL_PUBLIC_ORIGIN);
const TRUST_PROXY = pickStoredRuntimeValue("OWNER_CONTROL_TRUST_PROXY", process.env.OWNER_CONTROL_TRUST_PROXY);
const FORCE_HTTPS = readBooleanOption(
  pickStoredRuntimeValue("OWNER_CONTROL_FORCE_HTTPS", process.env.OWNER_CONTROL_FORCE_HTTPS),
  false,
);
const REQUIRE_CLIENT_SIGNATURE = readBooleanOption(
  pickStoredRuntimeValue("OWNER_CONTROL_REQUIRE_CLIENT_SIGNATURE", process.env.OWNER_CONTROL_REQUIRE_CLIENT_SIGNATURE),
  FORCE_HTTPS || NODE_ENV === "production",
);
const CLIENT_SIGNATURE_WINDOW_MS = Math.max(
  60_000,
  Number(
    pickStoredRuntimeValue(
      "OWNER_CONTROL_CLIENT_SIGNATURE_WINDOW_MS",
      process.env.OWNER_CONTROL_CLIENT_SIGNATURE_WINDOW_MS || 300_000,
    ),
  ),
);
const HSTS_MAX_AGE_SECONDS = Math.max(
  0,
  Number(
    pickStoredRuntimeValue(
      "OWNER_CONTROL_HSTS_MAX_AGE_SECONDS",
      process.env.OWNER_CONTROL_HSTS_MAX_AGE_SECONDS || 31_536_000,
    ),
  ),
);
const API_RATE_LIMIT_WINDOW_MS = Math.max(
  1000,
  Number(
    pickStoredRuntimeValue(
      "OWNER_CONTROL_RATE_LIMIT_WINDOW_MS",
      process.env.OWNER_CONTROL_RATE_LIMIT_WINDOW_MS || 60_000,
    ),
  ),
);
const API_RATE_LIMIT_MAX = Math.max(
  20,
  Number(
    pickStoredRuntimeValue(
      "OWNER_CONTROL_RATE_LIMIT_MAX",
      process.env.OWNER_CONTROL_RATE_LIMIT_MAX || 600,
    ),
  ),
);
function normalizeHostname(hostname) {
  return String(hostname || "").trim().toLowerCase().replace(/^\[/, "").replace(/\]$/, "");
}

function isLoopbackHost(hostname) {
  const host = normalizeHostname(hostname);
  return host === "localhost"
    || host.endsWith(".localhost")
    || host === "::1"
    || host === "0.0.0.0"
    || host.startsWith("127.");
}

function isRemotePublicOrigin(value) {
  const text = String(value || "").trim();
  if (!text) {
    return false;
  }
  try {
    const parsed = new URL(text);
    return !isLoopbackHost(parsed.hostname);
  } catch (_error) {
    return true;
  }
}

function createOwnerToken() {
  return `owner_${crypto.randomBytes(24).toString("base64url")}`;
}

function hasConfiguredTrustProxy(value) {
  const text = String(value || "").trim().toLowerCase();
  if (!text || ["false", "no", "off", "0"].includes(text)) {
    return false;
  }
  return true;
}

function resolveOwnerToken() {
  const rawToken = pickStoredRuntimeValue("OWNER_CONTROL_TOKEN", process.env.OWNER_CONTROL_TOKEN);
  const missingOrDefault = !rawToken || rawToken === "dev-owner-token";
  if (!missingOrDefault) {
    return {
      value: rawToken,
      generated: false,
    };
  }

  if (FORCE_HTTPS || isRemotePublicOrigin(PUBLIC_ORIGIN) || hasConfiguredTrustProxy(TRUST_PROXY) || NODE_ENV === "production") {
    throw new Error(
      "OWNER_CONTROL_TOKEN debe configurarse con un token largo antes de exponer owner-control con HTTPS, proxy o dominio remoto.",
    );
  }

  return {
    value: createOwnerToken(),
    generated: true,
  };
}

const {
  value: OWNER_TOKEN,
  generated: OWNER_TOKEN_GENERATED,
} = resolveOwnerToken();
const effectiveOwnerRuntimeFallbackValues = {
  OWNER_CONTROL_PORT: String(process.env.OWNER_CONTROL_PORT || process.env.PORT || 3200),
  OWNER_CONTROL_TOKEN: pickEnvironmentRuntimeValue("OWNER_CONTROL_TOKEN"),
  OWNER_CONTROL_PUBLIC_ORIGIN: pickEnvironmentRuntimeValue("OWNER_CONTROL_PUBLIC_ORIGIN"),
  OWNER_CONTROL_FORCE_HTTPS: readBooleanOption(process.env.OWNER_CONTROL_FORCE_HTTPS, false) ? "true" : "false",
  OWNER_CONTROL_HTTPS_CERT_PATH: pickEnvironmentRuntimeValue("OWNER_CONTROL_HTTPS_CERT_PATH"),
  OWNER_CONTROL_HTTPS_KEY_PATH: pickEnvironmentRuntimeValue("OWNER_CONTROL_HTTPS_KEY_PATH"),
  OWNER_CONTROL_HTTPS_CA_PATH: pickEnvironmentRuntimeValue("OWNER_CONTROL_HTTPS_CA_PATH"),
  OWNER_CONTROL_HTTPS_CERT_B64: pickEnvironmentRuntimeValue("OWNER_CONTROL_HTTPS_CERT_B64"),
  OWNER_CONTROL_HTTPS_KEY_B64: pickEnvironmentRuntimeValue("OWNER_CONTROL_HTTPS_KEY_B64"),
  OWNER_CONTROL_HTTPS_CA_B64: pickEnvironmentRuntimeValue("OWNER_CONTROL_HTTPS_CA_B64"),
  OWNER_CONTROL_HTTP_REDIRECT_PORT: String(process.env.OWNER_CONTROL_HTTP_REDIRECT_PORT || 0),
  OWNER_CONTROL_TRUST_PROXY: pickEnvironmentRuntimeValue("OWNER_CONTROL_TRUST_PROXY"),
  OWNER_CONTROL_HSTS_MAX_AGE_SECONDS: String(process.env.OWNER_CONTROL_HSTS_MAX_AGE_SECONDS || 31_536_000),
  OWNER_CONTROL_REQUIRE_CLIENT_SIGNATURE: pickEnvironmentRuntimeValue("OWNER_CONTROL_REQUIRE_CLIENT_SIGNATURE"),
  OWNER_CONTROL_CLIENT_SIGNATURE_WINDOW_MS: String(process.env.OWNER_CONTROL_CLIENT_SIGNATURE_WINDOW_MS || 300_000),
  OWNER_CONTROL_RATE_LIMIT_WINDOW_MS: String(process.env.OWNER_CONTROL_RATE_LIMIT_WINDOW_MS || 60_000),
  OWNER_CONTROL_RATE_LIMIT_MAX: String(process.env.OWNER_CONTROL_RATE_LIMIT_MAX || 600),
};
const effectiveOwnerRuntimeBootValues = {
  OWNER_CONTROL_PORT: String(PORT || ""),
  OWNER_CONTROL_TOKEN: OWNER_TOKEN_GENERATED ? "" : OWNER_TOKEN,
  OWNER_CONTROL_PUBLIC_ORIGIN: PUBLIC_ORIGIN,
  OWNER_CONTROL_FORCE_HTTPS: FORCE_HTTPS ? "true" : "false",
  OWNER_CONTROL_HTTPS_CERT_PATH: HTTPS_CERT_PATH,
  OWNER_CONTROL_HTTPS_KEY_PATH: HTTPS_KEY_PATH,
  OWNER_CONTROL_HTTPS_CA_PATH: HTTPS_CA_PATH,
  OWNER_CONTROL_HTTPS_CERT_B64: HTTPS_CERT_B64,
  OWNER_CONTROL_HTTPS_KEY_B64: HTTPS_KEY_B64,
  OWNER_CONTROL_HTTPS_CA_B64: HTTPS_CA_B64,
  OWNER_CONTROL_HTTP_REDIRECT_PORT: String(HTTP_REDIRECT_PORT || ""),
  OWNER_CONTROL_TRUST_PROXY: TRUST_PROXY,
  OWNER_CONTROL_HSTS_MAX_AGE_SECONDS: String(HSTS_MAX_AGE_SECONDS || ""),
  OWNER_CONTROL_REQUIRE_CLIENT_SIGNATURE: REQUIRE_CLIENT_SIGNATURE ? "true" : "false",
  OWNER_CONTROL_CLIENT_SIGNATURE_WINDOW_MS: String(CLIENT_SIGNATURE_WINDOW_MS || ""),
  OWNER_CONTROL_RATE_LIMIT_WINDOW_MS: String(API_RATE_LIMIT_WINDOW_MS || ""),
  OWNER_CONTROL_RATE_LIMIT_MAX: String(API_RATE_LIMIT_MAX || ""),
};

const app = createApp({
  dbPath: DB_PATH,
  store,
  ownerToken: OWNER_TOKEN,
  forceHttps: FORCE_HTTPS,
  publicOrigin: PUBLIC_ORIGIN,
  trustProxy: TRUST_PROXY,
  hstsMaxAgeSeconds: HSTS_MAX_AGE_SECONDS,
  requireClientSignature: REQUIRE_CLIENT_SIGNATURE,
  clientSignatureWindowMs: CLIENT_SIGNATURE_WINDOW_MS,
  apiRateLimitWindowMs: API_RATE_LIMIT_WINDOW_MS,
  apiRateLimitMax: API_RATE_LIMIT_MAX,
  ownerRuntimeBootValues: effectiveOwnerRuntimeBootValues,
  ownerRuntimeFallbackValues: effectiveOwnerRuntimeFallbackValues,
  ownerRuntimeIsProduction: NODE_ENV === "production",
});
const httpsCredentials = loadHttpsCredentials({
  label: "owner-control HTTPS",
  baseDir: __dirname,
  certBase64: HTTPS_CERT_B64,
  certPath: HTTPS_CERT_PATH,
  keyBase64: HTTPS_KEY_B64,
  keyPath: HTTPS_KEY_PATH,
  caBase64: HTTPS_CA_B64,
  caPath: HTTPS_CA_PATH,
});
if (HTTP_REDIRECT_PORT > 0 && !httpsCredentials.enabled) {
  throw new Error("OWNER_CONTROL_HTTP_REDIRECT_PORT requiere certificado y llave HTTPS de owner-control.");
}
if (HTTP_REDIRECT_PORT > 0 && HTTP_REDIRECT_PORT === PORT) {
  throw new Error("OWNER_CONTROL_HTTP_REDIRECT_PORT no puede usar el mismo puerto que OWNER_CONTROL_PORT.");
}
const server = createPrimaryServer(app, httpsCredentials);
const redirectServer = httpsCredentials.enabled && HTTP_REDIRECT_PORT > 0
  ? createRedirectServer({
    publicOrigin: PUBLIC_ORIGIN,
    httpsPort: PORT,
  })
  : null;

server.listen(PORT, () => {
  const protocol = httpsCredentials.enabled ? "https" : "http";
  console.log(`Owner control listo en ${protocol}://localhost:${PORT}`);
  console.log(`Base owner-control: ${DB_PATH}`);
  if (httpsCredentials.enabled && httpsCredentials.sources.length > 0) {
    console.log(`HTTPS directo owner-control activo con ${httpsCredentials.sources.join(", ")}`);
  }
  if (redirectServer) {
    redirectServer.listen(HTTP_REDIRECT_PORT, () => {
      console.log(`Redireccion HTTP owner-control activa en http://localhost:${HTTP_REDIRECT_PORT}`);
    });
  }
  if (OWNER_TOKEN_GENERATED) {
    console.warn("OWNER_CONTROL_TOKEN no estaba configurado para este arranque local.");
    console.warn(`Token owner-control temporal solo para esta sesion: ${OWNER_TOKEN}`);
  }
  if (FORCE_HTTPS && !httpsCredentials.enabled && !TRUST_PROXY) {
    console.warn("OWNER_CONTROL_FORCE_HTTPS esta activo pero owner-control no termina TLS ni confia en un proxy HTTPS.");
  }
});

function readBooleanOption(value, fallback = false) {
  const text = String(value ?? "").trim().toLowerCase();
  if (!text) {
    return fallback;
  }
  return ["1", "true", "yes", "on"].includes(text);
}

module.exports = {
  app,
  server,
  redirectServer,
  httpsEnabled: httpsCredentials.enabled,
};
