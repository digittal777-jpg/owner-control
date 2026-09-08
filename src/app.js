const crypto = require("node:crypto");
const express = require("express");
const path = require("node:path");
const proxyaddr = require("proxy-addr");

const { createControlStore } = require("./store");
function buildOwnerControlContentSecurityPolicy(forceHttps) {
  const directives = [
    "default-src 'self'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'self'",
    "object-src 'none'",
    "script-src 'self'",
    "style-src 'self'",
    "img-src 'self' data:",
    "connect-src 'self'",
    "worker-src 'self' blob:",
  ];
  if (forceHttps) {
    directives.push("upgrade-insecure-requests");
    directives.push("block-all-mixed-content");
  }
  return directives.join("; ");
}

function safeEqualText(left, right) {
  const leftBuffer = Buffer.from(String(left || ""), "utf8");
  const rightBuffer = Buffer.from(String(right || ""), "utf8");
  return leftBuffer.length === rightBuffer.length && crypto.timingSafeEqual(leftBuffer, rightBuffer);
}

function getBearerToken(request) {
  const authorization = String(request.headers.authorization || "");
  if (authorization.toLowerCase().startsWith("bearer ")) {
    return authorization.slice(7).trim();
  }
  return "";
}

function getOwnerTokenFromRequest(request) {
  return String(request.headers["x-owner-control-token"] || "").trim() || getBearerToken(request);
}

function getClientSecretFromRequest(request) {
  return String(request.headers["x-client-secret"] || "").trim() || getBearerToken(request);
}

function isEnabled(value) {
  return ["1", "true", "yes", "on"].includes(String(value || "").trim().toLowerCase());
}

function readBooleanOption(value, fallback = false) {
  const text = String(value ?? "").trim();
  if (!text) {
    return fallback;
  }
  return isEnabled(text);
}

function isProductionRuntime() {
  return String(process.env.NODE_ENV || "").trim().toLowerCase() === "production";
}

function getFirstForwardedProto(request) {
  return String(request.headers["x-forwarded-proto"] || "")
    .split(",")
    .map((value) => value.trim().toLowerCase())
    .find(Boolean) || "";
}

function parseTrustProxySetting(value) {
  const text = String(value ?? "").trim();
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

function createTrustProxyMatcher(setting) {
  if (setting === false || setting === 0) {
    return () => false;
  }
  if (setting === true || typeof setting === "number") {
    throw new Error("usa true o hops numericos; captura proxies o CIDRs explicitos.");
  }
  const compiled = proxyaddr.compile(setting);
  return (address) => {
    if (!address) {
      return false;
    }
    return compiled(address, 0);
  };
}

function resolveTrustProxyConfiguration(rawValue, label = "OWNER_CONTROL_TRUST_PROXY") {
  const setting = parseTrustProxySetting(rawValue);
  try {
    return {
      trustProxySetting: setting,
      isTrustedProxyAddress: createTrustProxyMatcher(setting),
    };
  } catch (error) {
    console.warn(`${label} invalido; se desactiva trust proxy. ${error.message}`);
    return {
      trustProxySetting: false,
      isTrustedProxyAddress: () => false,
    };
  }
}

function normalizeNetworkValue(value) {
  return String(value || "")
    .trim()
    .toLowerCase()
    .replace(/^\[/, "")
    .replace(/\]$/, "")
    .replace(/^::ffff:/, "");
}

function isLoopbackAddress(address) {
  const normalizedAddress = normalizeNetworkValue(address);
  return normalizedAddress === "::1"
    || normalizedAddress === "localhost"
    || normalizedAddress.startsWith("127.");
}

function isLoopbackRequest(request) {
  return isLoopbackAddress(request.socket?.remoteAddress)
    || isLoopbackAddress(request.socket?.localAddress);
}

function isTrustedProxyRequest(request, isTrustedProxyAddress) {
  const remoteAddress = String(request.socket?.remoteAddress || request.connection?.remoteAddress || "").trim();
  return Boolean(remoteAddress) && isTrustedProxyAddress(remoteAddress);
}

function isHttpsRequest(request, isTrustedProxyAddress) {
  if (request.secure || request.socket?.encrypted) {
    return true;
  }
  return isTrustedProxyRequest(request, isTrustedProxyAddress) && getFirstForwardedProto(request) === "https";
}

function getConfiguredHttpsOrigin(originValue) {
  const value = String(originValue || "").trim();
  if (!value) {
    return "";
  }
  try {
    const parsed = new URL(value);
    return parsed.protocol === "https:" ? parsed.origin : "";
  } catch (_error) {
    return "";
  }
}

function buildHttpsRedirectUrl(request, publicOrigin) {
  if (!publicOrigin) {
    return "";
  }
  return new URL(request.originalUrl || request.url || "/", publicOrigin).toString();
}

function isRailwayHealthcheckRequest(request) {
  const hostname = String(request.headers.host || "")
    .trim()
    .toLowerCase()
    .replace(/:\d+$/, "");
  return ["GET", "HEAD"].includes(request.method)
    && request.path === "/api/health"
    && hostname === "healthcheck.railway.app";
}

function createApp(options = {}) {
  const app = express();
  const store = options.store || createControlStore({ dbPath: options.dbPath });
  const ownerRuntimeBootValues = options.ownerRuntimeBootValues && typeof options.ownerRuntimeBootValues === "object"
    ? options.ownerRuntimeBootValues
    : {};
  const ownerRuntimeFallbackValues = options.ownerRuntimeFallbackValues && typeof options.ownerRuntimeFallbackValues === "object"
    ? options.ownerRuntimeFallbackValues
    : {};
  const ownerRuntimeIsProduction = options.ownerRuntimeIsProduction === undefined
    ? isProductionRuntime()
    : Boolean(options.ownerRuntimeIsProduction);
  const ownerTokenSource = Object.prototype.hasOwnProperty.call(options, "ownerToken")
    ? options.ownerToken
    : process.env.OWNER_CONTROL_TOKEN;
  const ownerToken = String(ownerTokenSource || "").trim();
  const forceHttps = options.forceHttps === undefined
    ? readBooleanOption(process.env.OWNER_CONTROL_FORCE_HTTPS, isProductionRuntime())
    : Boolean(options.forceHttps);
  const requireClientSignature = options.requireClientSignature === undefined
    ? readBooleanOption(process.env.OWNER_CONTROL_REQUIRE_CLIENT_SIGNATURE, forceHttps || isProductionRuntime())
    : Boolean(options.requireClientSignature);
  const clientSignatureWindowMs = Math.max(
    60_000,
    Number(options.clientSignatureWindowMs || process.env.OWNER_CONTROL_CLIENT_SIGNATURE_WINDOW_MS || 300_000),
  );
  const hstsMaxAgeSeconds = Math.max(0, Number(options.hstsMaxAgeSeconds || process.env.OWNER_CONTROL_HSTS_MAX_AGE_SECONDS || 31_536_000));
  const trustProxyValue = options.trustProxy === undefined
    ? parseTrustProxySetting(process.env.OWNER_CONTROL_TRUST_PROXY)
    : parseTrustProxySetting(options.trustProxy);
  const {
    trustProxySetting,
    isTrustedProxyAddress,
  } = resolveTrustProxyConfiguration(trustProxyValue);
  const publicOrigin = getConfiguredHttpsOrigin(options.publicOrigin || process.env.OWNER_CONTROL_PUBLIC_ORIGIN || "");
  const apiRateLimitWindowMs = Math.max(1000, Number(options.apiRateLimitWindowMs || process.env.OWNER_CONTROL_RATE_LIMIT_WINDOW_MS || 60_000));
  const apiRateLimitMax = Math.max(20, Number(options.apiRateLimitMax || process.env.OWNER_CONTROL_RATE_LIMIT_MAX || 600));
  const apiRateLimitBucketLimit = Math.max(
    1,
    Number(options.apiRateLimitBucketLimit || process.env.OWNER_CONTROL_RATE_LIMIT_BUCKET_LIMIT || 5000),
  );
  const clientSignatureNonceLimit = Math.max(
    1,
    Number(options.clientSignatureNonceLimit || process.env.OWNER_CONTROL_CLIENT_SIGNATURE_NONCE_LIMIT || 5000),
  );
  const rateLimitBuckets = new Map();
  const clientSignatureNonces = new Map();
  const ownerControlContentSecurityPolicy = buildOwnerControlContentSecurityPolicy(forceHttps);

  app.locals.controlStore = store;
  app.locals.ownerToken = ownerToken;
  app.locals.forceHttps = forceHttps;
  app.locals.publicOrigin = publicOrigin;
  app.locals.requireClientSignature = requireClientSignature;
  app.locals.ownerRuntimeBootValues = ownerRuntimeBootValues;
  app.locals.ownerRuntimeFallbackValues = ownerRuntimeFallbackValues;
  app.locals.ownerRuntimeIsProduction = ownerRuntimeIsProduction;
  app.locals.rateLimitBuckets = rateLimitBuckets;
  app.locals.clientSignatureNonces = clientSignatureNonces;

  app.disable("x-powered-by");
  app.set("trust proxy", trustProxySetting);
  app.use((request, response, next) => {
    response.setHeader("X-Content-Type-Options", "nosniff");
    response.setHeader("X-Frame-Options", "SAMEORIGIN");
    response.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
    response.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
    response.setHeader("Content-Security-Policy", ownerControlContentSecurityPolicy);
    response.setHeader("Cross-Origin-Opener-Policy", "same-origin");
    response.setHeader("Cross-Origin-Resource-Policy", "same-origin");
    response.setHeader("Origin-Agent-Cluster", "?1");
    response.setHeader("X-Permitted-Cross-Domain-Policies", "none");
    if (isHttpsRequest(request, isTrustedProxyAddress) && hstsMaxAgeSeconds > 0) {
      response.setHeader("Strict-Transport-Security", `max-age=${hstsMaxAgeSeconds}`);
    }
    if (
      forceHttps
      && !isRailwayHealthcheckRequest(request)
      && !isHttpsRequest(request, isTrustedProxyAddress)
      && !isLoopbackRequest(request)
    ) {
      response.setHeader("Cache-Control", "no-store");
      const redirectUrl = ["GET", "HEAD"].includes(String(request.method || "GET").toUpperCase()) && !request.path.startsWith("/api/")
        ? buildHttpsRedirectUrl(request, publicOrigin)
        : "";
      if (redirectUrl) {
        response.redirect(308, redirectUrl);
        return;
      }
      response.status(426).json({ message: "HTTPS requerido. Owner-control no acepta HTTP fuera de localhost." });
      return;
    }
    if (request.path.startsWith("/api/")) {
      response.setHeader("Cache-Control", "no-store");
    }
    next();
  });
  function pruneRateLimitBuckets(now = Date.now()) {
    for (const [key, bucket] of rateLimitBuckets.entries()) {
      if (!bucket || now - bucket.startedAt >= apiRateLimitWindowMs) {
        rateLimitBuckets.delete(key);
      }
    }

    if (rateLimitBuckets.size <= apiRateLimitBucketLimit) {
      return;
    }

    [...rateLimitBuckets.entries()]
      .sort((left, right) => Number(left[1]?.startedAt || 0) - Number(right[1]?.startedAt || 0))
      .slice(0, rateLimitBuckets.size - apiRateLimitBucketLimit)
      .forEach(([key]) => {
        rateLimitBuckets.delete(key);
      });
  }

  app.use((request, response, next) => {
    if (!request.path.startsWith("/api/")) {
      next();
      return;
    }
    const now = Date.now();
    pruneRateLimitBuckets(now);
    const key = `${request.ip || request.socket?.remoteAddress || "unknown"}:${request.path.split("/").slice(0, 4).join("/")}`;
    const bucket = rateLimitBuckets.get(key);
    if (!bucket || now - bucket.startedAt >= apiRateLimitWindowMs) {
      rateLimitBuckets.set(key, { startedAt: now, count: 1 });
      pruneRateLimitBuckets(now);
      next();
      return;
    }
    bucket.count += 1;
    if (bucket.count > apiRateLimitMax) {
      response.status(429).json({ message: "Demasiadas solicitudes al owner-control." });
      return;
    }
    next();
  });
  app.use(express.json({
    limit: "1mb",
    verify(request, _response, buffer) {
      request.rawBody = Buffer.from(buffer || "");
    },
  }));
  app.use(express.static(path.resolve(__dirname, "..", "public"), {
    index: false,
    setHeaders(response, filePath) {
      if (path.basename(filePath).toLowerCase() === "index.html") {
        response.setHeader("Cache-Control", "no-store");
      }
    },
  }));

  function pruneClientSignatureNonces(now = Date.now(), targetSize = clientSignatureNonceLimit) {
    for (const [key, expiresAt] of clientSignatureNonces.entries()) {
      if (expiresAt <= now) {
        clientSignatureNonces.delete(key);
      }
    }

    if (clientSignatureNonces.size <= targetSize) {
      return;
    }

    [...clientSignatureNonces.entries()]
      .sort((left, right) => Number(left[1] || 0) - Number(right[1] || 0))
      .slice(0, clientSignatureNonces.size - targetSize)
      .forEach(([key]) => {
        clientSignatureNonces.delete(key);
      });
  }

  function requireValidClientSignature(request, response, slug, secret) {
    if (!requireClientSignature) {
      return true;
    }

    const timestamp = String(request.headers["x-client-timestamp"] || "").trim();
    const nonce = String(request.headers["x-client-nonce"] || "").trim();
    const signature = String(request.headers["x-client-signature"] || "").trim().replace(/^sha256=/i, "");
    const timestampMs = Date.parse(timestamp);
    const now = Date.now();
    if (!timestamp || !nonce || !signature || !Number.isFinite(timestampMs)) {
      response.status(401).json({ message: "Firma cliente requerida." });
      return false;
    }
    if (Math.abs(now - timestampMs) > clientSignatureWindowMs) {
      response.status(401).json({ message: "Firma cliente expirada." });
      return false;
    }
    pruneClientSignatureNonces(now, clientSignatureNonceLimit - 1);
    const nonceKey = `${slug}:${nonce}`;
    if (clientSignatureNonces.has(nonceKey)) {
      response.status(409).json({ message: "Nonce cliente repetido." });
      return false;
    }
    const rawBody = request.rawBody ? request.rawBody.toString("utf8") : "";
    const payload = [
      String(request.method || "GET").toUpperCase(),
      String(request.originalUrl || request.url || ""),
      timestamp,
      nonce,
      rawBody,
    ].join("\n");
    const expected = crypto.createHmac("sha256", secret).update(payload).digest("hex");
    if (!safeEqualText(signature, expected)) {
      response.status(401).json({ message: "Firma cliente invalida." });
      return false;
    }
    clientSignatureNonces.set(nonceKey, now + clientSignatureWindowMs);
    pruneClientSignatureNonces(now);
    return true;
  }

  function requireOwner(request, response, next) {
    const token = getOwnerTokenFromRequest(request);
    if (!token || !ownerToken || !safeEqualText(token, ownerToken)) {
      response.status(401).json({ message: "Necesitas token owner central." });
      return;
    }
    next();
  }

  function requireClient(request, response, next) {
    try {
      const slug = String(request.headers["x-client-slug"] || request.query.slug || "").trim();
      const secret = getClientSecretFromRequest(request);
      if (!slug || !secret) {
        response.status(401).json({ message: "Necesitas credenciales de cliente." });
        return;
      }
      if (!requireValidClientSignature(request, response, slug, secret)) {
        return;
      }
      request.controlClient = store.authenticateClient(slug, secret);
      next();
    } catch (error) {
      next(error);
    }
  }

  app.get("/api/health", (_request, response) => {
    response.json({
      ok: true,
      service: "owner-control",
      generatedAt: new Date().toISOString(),
    });
  });

  app.get("/api/owner/clients", requireOwner, (_request, response, next) => {
    try {
      response.json({
        clients: store.listClients(),
        generatedAt: new Date().toISOString(),
      });
    } catch (error) {
      next(error);
    }
  });

  app.get("/api/owner/runtime-config", requireOwner, (_request, response, next) => {
    try {
      response.json({
        ...store.getOwnerRuntimeConfig({
          bootValues: app.locals.ownerRuntimeBootValues,
          fallbackValues: app.locals.ownerRuntimeFallbackValues,
          isProductionRuntime: app.locals.ownerRuntimeIsProduction,
        }),
        generatedAt: new Date().toISOString(),
      });
    } catch (error) {
      next(error);
    }
  });

  app.patch("/api/owner/runtime-config", requireOwner, (request, response, next) => {
    try {
      response.json({
        ...store.updateOwnerRuntimeConfig(request.body || {}, {
          bootValues: app.locals.ownerRuntimeBootValues,
          fallbackValues: app.locals.ownerRuntimeFallbackValues,
          isProductionRuntime: app.locals.ownerRuntimeIsProduction,
        }),
        generatedAt: new Date().toISOString(),
      });
    } catch (error) {
      next(error);
    }
  });

  app.post("/api/owner/clients", requireOwner, (request, response, next) => {
    try {
      response.status(201).json({
        ...store.createClient(request.body || {}),
        generatedAt: new Date().toISOString(),
      });
    } catch (error) {
      next(error);
    }
  });

  app.get("/api/owner/clients/:slug", requireOwner, (request, response, next) => {
    try {
      response.json({
        ...store.getClientDetail(request.params.slug),
        generatedAt: new Date().toISOString(),
      });
    } catch (error) {
      next(error);
    }
  });

  app.patch("/api/owner/clients/:slug/config", requireOwner, (request, response, next) => {
    try {
      response.json({
        ...store.updateClientConfig(request.params.slug, request.body || {}),
        generatedAt: new Date().toISOString(),
      });
    } catch (error) {
      next(error);
    }
  });

  app.get("/api/owner/clients/:slug/runtime-config", requireOwner, (request, response, next) => {
    try {
      response.json({
        ...store.getClientRuntimeConfig(request.params.slug),
        generatedAt: new Date().toISOString(),
      });
    } catch (error) {
      next(error);
    }
  });

  app.patch("/api/owner/clients/:slug/runtime-config", requireOwner, (request, response, next) => {
    try {
      response.json({
        ...store.updateClientRuntimeConfig(request.params.slug, request.body || {}),
        generatedAt: new Date().toISOString(),
      });
    } catch (error) {
      next(error);
    }
  });

  app.patch("/api/owner/clients/:slug/subscription", requireOwner, (request, response, next) => {
    try {
      response.json({
        client: store.updateSubscription(request.params.slug, request.body || {}),
        generatedAt: new Date().toISOString(),
      });
    } catch (error) {
      next(error);
    }
  });

  app.post("/api/owner/clients/:slug/payments", requireOwner, (request, response, next) => {
    try {
      response.status(201).json({
        ...store.recordPayment(request.params.slug, request.body || {}),
        generatedAt: new Date().toISOString(),
      });
    } catch (error) {
      next(error);
    }
  });

  app.post("/api/owner/clients/:slug/rotate-key", requireOwner, (request, response, next) => {
    try {
      response.json({
        ...store.rotateClientKey(request.params.slug, request.body || {}),
        generatedAt: new Date().toISOString(),
      });
    } catch (error) {
      next(error);
    }
  });

  app.get("/api/client/subscription", requireClient, (request, response) => {
    response.json({
      client: {
        slug: request.controlClient.slug,
        businessName: request.controlClient.businessName,
      },
      subscription: request.controlClient.subscription,
      payments: store.listClientPayments(request.controlClient.slug, 12),
      generatedAt: new Date().toISOString(),
    });
  });

  app.get("/api/client/config", requireClient, (request, response, next) => {
    try {
      response.json({
        ...store.getClientConfig(request.controlClient.slug),
        generatedAt: new Date().toISOString(),
      });
    } catch (error) {
      next(error);
    }
  });

  app.get("/api/client/runtime-config", requireClient, (request, response, next) => {
    try {
      response.json({
        ...store.getClientRuntimeConfig(request.controlClient.slug, { includeValues: true }),
        generatedAt: new Date().toISOString(),
      });
    } catch (error) {
      next(error);
    }
  });

  app.post("/api/client/config-sync", requireClient, (request, response, next) => {
    try {
      response.status(202).json({
        ...store.recordClientConfigSync(request.controlClient, request.body || {}),
        generatedAt: new Date().toISOString(),
      });
    } catch (error) {
      next(error);
    }
  });

  app.post("/api/client/runtime-config-sync", requireClient, (request, response, next) => {
    try {
      response.status(202).json({
        ...store.recordClientRuntimeConfigSync(request.controlClient, request.body || {}),
        generatedAt: new Date().toISOString(),
      });
    } catch (error) {
      next(error);
    }
  });

  app.post("/api/client/health", requireClient, (request, response, next) => {
    try {
      response.status(202).json({
        ...store.receiveHealthReport(request.controlClient, request.body || {}),
        generatedAt: new Date().toISOString(),
      });
    } catch (error) {
      next(error);
    }
  });

  app.post("/api/client/validation-report", requireClient, (request, response, next) => {
    try {
      response.status(202).json({
        ...store.receiveValidationReport(request.controlClient, request.body || {}),
        generatedAt: new Date().toISOString(),
      });
    } catch (error) {
      next(error);
    }
  });

  app.use((request, response) => {
    if (request.path.startsWith("/api/")) {
      response.status(404).json({ message: "Endpoint owner-control no encontrado." });
      return;
    }
    response.setHeader("Cache-Control", "no-store");
    response.sendFile(path.resolve(__dirname, "..", "public", "index.html"));
  });

  app.use((error, _request, response, _next) => {
    const statusCode = Number(error.statusCode || error.status || 500);
    response.status(statusCode >= 400 && statusCode < 600 ? statusCode : 500).json({
      message: error.message || "Error interno owner-control.",
    });
  });

  return app;
}

module.exports = {
  createApp,
};
