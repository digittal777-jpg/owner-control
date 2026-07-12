const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");
const { test } = require("node:test");

const Database = require("better-sqlite3");

const { createApp } = require("../src/app");
const { createControlStore } = require("../src/store");

async function startServer(t, appOptions = {}) {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "owner-control-client-flow-"));
  const dbPath = path.join(tempDir, "owner-control.sqlite");
  const { storeOptions, ...safeAppOptions } = appOptions;
  const store = safeAppOptions.store || (storeOptions ? createControlStore({
    dbPath,
    ...storeOptions,
  }) : null);
  const app = createApp({
    dbPath,
    ownerToken: "test-owner-token",
    requireClientSignature: true,
    ...(store ? { store } : {}),
    ...safeAppOptions,
  });
  const server = http.createServer(app);

  t.after(async () => {
    await new Promise((resolve) => server.close(resolve));
    app.locals.controlStore.close();
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();
  return {
    app,
    baseUrl: `http://127.0.0.1:${port}`,
  };
}

async function json(baseUrl, pathname, options = {}) {
  const response = await fetch(`${baseUrl}${pathname}`, {
    method: options.method || "GET",
    headers: {
      ...(options.headers || {}),
    },
    body: options.body,
  });
  const text = await response.text();
  let body = null;
  try {
    body = text ? JSON.parse(text) : null;
  } catch (_error) {
    body = text;
  }
  return {
    status: response.status,
    body,
  };
}

function ownerHeaders() {
  return {
    "Content-Type": "application/json",
    "X-Owner-Control-Token": "test-owner-token",
  };
}

function clientHeaders(slug, apiKey) {
  return {
    "Content-Type": "application/json",
    "X-Client-Slug": slug,
    Authorization: `Bearer ${apiKey}`,
  };
}

function signedClientHeaders(slug, apiKey, method, pathname, body = "") {
  const timestamp = new Date().toISOString();
  const nonce = crypto.randomBytes(12).toString("hex");
  const payload = [
    String(method || "GET").toUpperCase(),
    pathname,
    timestamp,
    nonce,
    String(body || ""),
  ].join("\n");
  return {
    ...clientHeaders(slug, apiKey),
    "X-Client-Timestamp": timestamp,
    "X-Client-Nonce": nonce,
    "X-Client-Signature": crypto.createHmac("sha256", apiKey).update(payload).digest("hex"),
  };
}

function readStoredRuntimeJson(dbPath, slug) {
  const db = new Database(dbPath, { readonly: true });
  try {
    return String(db.prepare("SELECT runtime_config_json FROM clients WHERE slug = ?").get(slug)?.runtime_config_json || "");
  } finally {
    db.close();
  }
}

async function createClient(baseUrl, slug = "cremeria-rincon") {
  const response = await json(baseUrl, "/api/owner/clients", {
    method: "POST",
    headers: ownerHeaders(),
    body: JSON.stringify({
      slug,
      businessName: "Cremeria Rincon",
      baseUrl: "http://localhost:3100",
      planCode: "pro",
      monthlyAmount: 1299,
    }),
  });
  assert.equal(response.status, 201);
  return response.body;
}

test("owner-control accepts a POS-like signed client lifecycle and rejects replay or tampering", async (t) => {
  const server = await startServer(t);
  const slug = "cremeria-rincon";
  const created = await createClient(server.baseUrl, slug);
  const apiKey = created.apiKey;

  const unsigned = await json(server.baseUrl, "/api/client/subscription", {
    headers: clientHeaders(slug, apiKey),
  });
  assert.equal(unsigned.status, 401);
  assert.match(String(unsigned.body?.message || ""), /Firma cliente requerida/i);

  const subscription = await json(server.baseUrl, "/api/client/subscription", {
    headers: signedClientHeaders(slug, apiKey, "GET", "/api/client/subscription"),
  });
  assert.equal(subscription.status, 200);
  assert.equal(subscription.body.subscription.status, "trial");

  const configUpdate = await json(server.baseUrl, `/api/owner/clients/${slug}/config`, {
    method: "PATCH",
    headers: ownerHeaders(),
    body: JSON.stringify({
      enabledModules: ["weighted_audit", "unknown_module"],
      adminCapabilities: ["daily_flow", "support_tools", "unknown_capability"],
    }),
  });
  assert.equal(configUpdate.status, 200);
  assert.deepEqual(configUpdate.body.config.enabledModules, ["weighted_audit"]);
  assert.deepEqual(configUpdate.body.config.adminCapabilities, ["daily_flow", "support_tools"]);

  const clientConfig = await json(server.baseUrl, "/api/client/config", {
    headers: signedClientHeaders(slug, apiKey, "GET", "/api/client/config"),
  });
  assert.equal(clientConfig.status, 200);
  assert.deepEqual(clientConfig.body.config.enabledModules, ["weighted_audit"]);
  assert.deepEqual(clientConfig.body.config.adminCapabilities, ["daily_flow", "support_tools"]);

  const configSyncBody = JSON.stringify({
    status: "applied",
    enabledModules: clientConfig.body.config.enabledModules,
    adminCapabilities: clientConfig.body.config.adminCapabilities,
    message: "Configuracion aplicada por POS de prueba.",
  });
  const configSync = await json(server.baseUrl, "/api/client/config-sync", {
    method: "POST",
    headers: signedClientHeaders(slug, apiKey, "POST", "/api/client/config-sync", configSyncBody),
    body: configSyncBody,
  });
  assert.equal(configSync.status, 202);
  assert.equal(configSync.body.configSync.status, "applied");
  assert.equal(configSync.body.configSync.inSync, true);

  const invalidPairingUpdate = await json(server.baseUrl, `/api/owner/clients/${slug}/runtime-config`, {
    method: "PATCH",
    headers: ownerHeaders(),
    body: JSON.stringify({
      values: {
        CONTROL_API_URL: "https://owner-control.example",
        CONTROL_CLIENT_SECRET: "pos_plaintext_should_not_be_stored",
      },
    }),
  });
  assert.equal(invalidPairingUpdate.status, 400);
  assert.match(String(invalidPairingUpdate.body?.message || ""), /entorno del servicio POS.*Variables de Railway/i);

  const runtimeUpdate = await json(server.baseUrl, `/api/owner/clients/${slug}/runtime-config`, {
    method: "PATCH",
    headers: ownerHeaders(),
    body: JSON.stringify({
      values: {
        POS_PUBLIC_ORIGIN: "https://cremeria.example",
        POS_ALLOWED_ORIGINS: "https://cremeria.example,http://localhost:3100",
        POS_CASHIER_SESSION_TTL_MS: "43200000",
        POS_BOOTSTRAP_TOKEN: "bootstrap-test-value",
        RAILWAY_COST_SAVER_MODE: "true",
      },
    }),
  });
  assert.equal(runtimeUpdate.status, 200);
  assert.equal(runtimeUpdate.body.runtimeConfig.sync.status, "pending");

  const ownerRuntimeRead = await json(server.baseUrl, `/api/owner/clients/${slug}/runtime-config`, {
    headers: ownerHeaders(),
  });
  assert.equal(ownerRuntimeRead.status, 200);
  const bootstrapVariable = ownerRuntimeRead.body.runtimeConfig.variables.find((variable) => variable.key === "POS_BOOTSTRAP_TOKEN");
  const railwaySaverVariable = ownerRuntimeRead.body.runtimeConfig.variables.find((variable) => variable.key === "RAILWAY_COST_SAVER_MODE");
  assert.equal(ownerRuntimeRead.body.runtimeConfig.variables.some((variable) => variable.key === "CONTROL_CLIENT_SECRET"), false);
  assert.equal(bootstrapVariable.hasStoredValue, true);
  assert.equal(bootstrapVariable.maskedValue, "********");
  assert.equal(bootstrapVariable.value, "");
  assert.equal(railwaySaverVariable.value, "true");

  const clientRuntime = await json(server.baseUrl, "/api/client/runtime-config", {
    headers: signedClientHeaders(slug, apiKey, "GET", "/api/client/runtime-config"),
  });
  assert.equal(clientRuntime.status, 200);
  assert.equal(clientRuntime.body.runtimeConfig.values.POS_PUBLIC_ORIGIN, "https://cremeria.example");
  assert.equal(clientRuntime.body.runtimeConfig.values.POS_CASHIER_SESSION_TTL_MS, "43200000");
  assert.equal(clientRuntime.body.runtimeConfig.values.POS_BOOTSTRAP_TOKEN, "bootstrap-test-value");
  assert.equal(clientRuntime.body.runtimeConfig.values.RAILWAY_COST_SAVER_MODE, "true");
  assert.equal(clientRuntime.body.runtimeConfig.values.CONTROL_CLIENT_SECRET, undefined);
  assert.match(clientRuntime.body.runtimeConfig.runtimeHash, /^[a-f0-9]{64}$/);

  const expectedRuntimeSyncBody = JSON.stringify({
    status: "applied",
    keys: Object.keys(clientRuntime.body.runtimeConfig.values),
    runtimeHash: clientRuntime.body.runtimeConfig.runtimeHash,
  });
  const tamperedRuntimeSync = await json(server.baseUrl, "/api/client/runtime-config-sync", {
    method: "POST",
    headers: signedClientHeaders(slug, apiKey, "POST", "/api/client/runtime-config-sync", expectedRuntimeSyncBody),
    body: JSON.stringify({
      status: "applied",
      keys: ["POS_PUBLIC_ORIGIN"],
      runtimeHash: clientRuntime.body.runtimeConfig.runtimeHash,
    }),
  });
  assert.equal(tamperedRuntimeSync.status, 401);
  assert.match(String(tamperedRuntimeSync.body?.message || ""), /Firma cliente invalida/i);

  const runtimeSync = await json(server.baseUrl, "/api/client/runtime-config-sync", {
    method: "POST",
    headers: signedClientHeaders(slug, apiKey, "POST", "/api/client/runtime-config-sync", expectedRuntimeSyncBody),
    body: expectedRuntimeSyncBody,
  });
  assert.equal(runtimeSync.status, 202);
  assert.equal(runtimeSync.body.runtimeConfigSync.status, "applied");
  assert.equal(runtimeSync.body.runtimeConfigSync.inSync, true);

  const healthBody = JSON.stringify({
    semaphore: {
      status: "risk",
      reasons: [{ title: "Backup pendiente" }],
      actions: [{ title: "Revisar respaldo" }],
    },
    metrics: {
      pendingSync: 0,
    },
  });
  const healthHeaders = signedClientHeaders(slug, apiKey, "POST", "/api/client/health", healthBody);
  const health = await json(server.baseUrl, "/api/client/health", {
    method: "POST",
    headers: healthHeaders,
    body: healthBody,
  });
  assert.equal(health.status, 202);
  assert.equal(health.body.report.status, "risk");
  assert.equal(health.body.client.healthStatus, "risk");

  const replay = await json(server.baseUrl, "/api/client/health", {
    method: "POST",
    headers: healthHeaders,
    body: healthBody,
  });
  assert.equal(replay.status, 409);
  assert.match(String(replay.body?.message || ""), /Nonce cliente repetido/i);

  const validationBody = JSON.stringify({
    url: "http://localhost:3100",
    checks: [
      { name: "/api/health", ok: true },
      { name: "/administracion", ok: true },
    ],
  });
  const validation = await json(server.baseUrl, "/api/client/validation-report", {
    method: "POST",
    headers: signedClientHeaders(slug, apiKey, "POST", "/api/client/validation-report", validationBody),
    body: validationBody,
  });
  assert.equal(validation.status, 202);
  assert.equal(validation.body.report.status, "ok");

  const detail = await json(server.baseUrl, `/api/owner/clients/${slug}`, {
    headers: ownerHeaders(),
  });
  assert.equal(detail.status, 200);
  assert.equal(detail.body.client.config.sync.status, "applied");
  assert.equal(detail.body.client.config.sync.inSync, true);
  assert.equal(detail.body.client.runtimeConfig.sync.status, "applied");
  assert.equal(detail.body.client.runtimeConfig.sync.inSync, true);
  assert.equal(detail.body.client.healthStatus, "risk");
  assert.equal(detail.body.healthReports.length, 1);
  assert.equal(detail.body.validationReports.length, 1);
  assert.equal(detail.body.validationReports[0].status, "ok");
});

test("owner-control scrubs legacy plaintext pairing values from client runtime storage", () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "owner-control-pairing-scrub-"));
  const dbPath = path.join(tempDir, "owner-control.sqlite");
  const legacySecret = "pos_legacy_plaintext_secret";
  let store = createControlStore({ dbPath });

  try {
    store.createClient({
      slug: "legacy-pairing",
      businessName: "Legacy Pairing",
      baseUrl: "http://localhost:3100",
    });
    store.close();
    store = null;

    const legacyDb = new Database(dbPath);
    legacyDb.prepare("UPDATE clients SET runtime_config_json = ? WHERE slug = ?").run(JSON.stringify({
      POS_PUBLIC_ORIGIN: "https://legacy.example",
      CONTROL_API_URL: "https://owner-control.example",
      CONTROL_CLIENT_SLUG: "legacy-pairing",
      CONTROL_CLIENT_SECRET: legacySecret,
    }), "legacy-pairing");
    legacyDb.close();

    assert.match(readStoredRuntimeJson(dbPath, "legacy-pairing"), new RegExp(legacySecret));

    store = createControlStore({ dbPath });
    const runtime = store.getClientRuntimeConfig("legacy-pairing", { includeValues: true });
    assert.equal(runtime.runtimeConfig.values.POS_PUBLIC_ORIGIN, "https://legacy.example");
    assert.equal(runtime.runtimeConfig.values.CONTROL_CLIENT_SECRET, undefined);
    store.close();
    store = null;

    assert.doesNotMatch(readStoredRuntimeJson(dbPath, "legacy-pairing"), new RegExp(legacySecret));
  } finally {
    store?.close();
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});

test("owner-control key rotation invalidates the old POS key and accepts the new signed POS key", async (t) => {
  const server = await startServer(t);
  const slug = "cremeria-rincon";
  const created = await createClient(server.baseUrl, slug);
  const oldKey = created.apiKey;

  const initialAuth = await json(server.baseUrl, "/api/client/subscription", {
    headers: signedClientHeaders(slug, oldKey, "GET", "/api/client/subscription"),
  });
  assert.equal(initialAuth.status, 200);

  const rotate = await json(server.baseUrl, `/api/owner/clients/${slug}/rotate-key`, {
    method: "POST",
    headers: ownerHeaders(),
  });
  assert.equal(rotate.status, 200);
  assert.match(rotate.body.apiKey, /^pos_/);
  assert.notEqual(rotate.body.apiKey, oldKey);
  assert.equal(rotate.body.client.runtimeConfig.sync.pairingInSync, false);

  const oldKeyAfterRotate = await json(server.baseUrl, "/api/client/subscription", {
    headers: signedClientHeaders(slug, oldKey, "GET", "/api/client/subscription"),
  });
  assert.equal(oldKeyAfterRotate.status, 403);
  assert.match(String(oldKeyAfterRotate.body?.message || ""), /Credenciales de cliente invalidas/i);

  const newKeyAfterRotate = await json(server.baseUrl, "/api/client/subscription", {
    headers: signedClientHeaders(slug, rotate.body.apiKey, "GET", "/api/client/subscription"),
  });
  assert.equal(newKeyAfterRotate.status, 200);

  const detail = await json(server.baseUrl, `/api/owner/clients/${slug}`, {
    headers: ownerHeaders(),
  });
  assert.equal(detail.status, 200);
  assert.equal(detail.body.client.runtimeConfig.sync.pairingInSync, true);
});

test("owner-control enforces API rate limit before memory buckets grow without bound", async (t) => {
  const server = await startServer(t, {
    apiRateLimitMax: 20,
    apiRateLimitBucketLimit: 4,
  });

  let lastResponse = null;
  for (let attempt = 0; attempt < 21; attempt += 1) {
    lastResponse = await json(server.baseUrl, "/api/health");
  }

  assert.equal(lastResponse.status, 429);
  assert.match(String(lastResponse.body?.message || ""), /Demasiadas solicitudes/i);
  assert.ok(server.app.locals.rateLimitBuckets.size <= 4);
});

test("owner-control prunes signed POS nonces to the configured cap", async (t) => {
  const server = await startServer(t, {
    clientSignatureNonceLimit: 2,
  });
  const slug = "cremeria-rincon";
  const created = await createClient(server.baseUrl, slug);

  for (let attempt = 0; attempt < 5; attempt += 1) {
    const response = await json(server.baseUrl, "/api/client/subscription", {
      headers: signedClientHeaders(slug, created.apiKey, "GET", "/api/client/subscription"),
    });
    assert.equal(response.status, 200);
  }

  assert.ok(server.app.locals.clientSignatureNonces.size <= 2);
});

test("owner-control retains only the latest POS health and validation reports per client", async (t) => {
  const server = await startServer(t, {
    storeOptions: {
      healthReportRetentionLimit: 2,
      validationReportRetentionLimit: 2,
    },
  });
  const slug = "cremeria-rincon";
  const created = await createClient(server.baseUrl, slug);

  for (let index = 0; index < 5; index += 1) {
    const healthBody = JSON.stringify({
      semaphore: {
        status: index % 2 === 0 ? "ok" : "risk",
        reasons: [{ title: `Estado ${index}` }],
        actions: [{ title: `Accion ${index}` }],
      },
      metrics: {
        pendingSync: index,
      },
    });
    const health = await json(server.baseUrl, "/api/client/health", {
      method: "POST",
      headers: signedClientHeaders(slug, created.apiKey, "POST", "/api/client/health", healthBody),
      body: healthBody,
    });
    assert.equal(health.status, 202);

    const validationBody = JSON.stringify({
      url: `http://localhost:3100/${index}`,
      checks: [
        { name: "/api/health", ok: true },
        { name: `/check-${index}`, ok: index % 2 === 0 },
      ],
    });
    const validation = await json(server.baseUrl, "/api/client/validation-report", {
      method: "POST",
      headers: signedClientHeaders(slug, created.apiKey, "POST", "/api/client/validation-report", validationBody),
      body: validationBody,
    });
    assert.equal(validation.status, 202);
  }

  const detail = await json(server.baseUrl, `/api/owner/clients/${slug}`, {
    headers: ownerHeaders(),
  });
  assert.equal(detail.status, 200);
  assert.equal(detail.body.healthReports.length, 2);
  assert.equal(detail.body.validationReports.length, 2);
  assert.equal(detail.body.healthReports[0].metrics.pendingSync, 4);
  assert.equal(detail.body.validationReports[0].url, "http://localhost:3100/4");
});
