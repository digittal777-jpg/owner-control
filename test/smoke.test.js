const assert = require("node:assert/strict");
const fs = require("node:fs");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const { createApp } = require("../src/app");

function getNonLoopbackIpv4() {
  for (const addresses of Object.values(os.networkInterfaces())) {
    for (const addressInfo of addresses || []) {
      const family = typeof addressInfo?.family === "string"
        ? addressInfo.family
        : Number(addressInfo?.family) === 6
          ? "IPv6"
          : "IPv4";
      if (addressInfo?.address && !addressInfo.internal && family === "IPv4") {
        return addressInfo.address;
      }
    }
  }
  return "";
}

async function requestJson(host, port, pathname, headers = {}) {
  return new Promise((resolve, reject) => {
    const request = http.request({ host, port, path: pathname, headers }, (response) => {
      let body = "";
      response.setEncoding("utf8");
      response.on("data", (chunk) => {
        body += chunk;
      });
      response.on("end", () => {
        try {
          resolve({
            status: response.statusCode,
            body: body ? JSON.parse(body) : null,
          });
        } catch (error) {
          reject(error);
        }
      });
    });
    request.on("error", reject);
    request.end();
  });
}

test("owner-control health endpoint reports service status", async (t) => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "owner-control-smoke-"));
  const app = createApp({
    dbPath: path.join(tempDir, "owner-control.sqlite"),
    ownerToken: "test-owner-token",
  });
  const server = http.createServer(app);

  t.after(async () => {
    await new Promise((resolve) => server.close(resolve));
    app.locals.controlStore.close();
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();
  const response = await fetch(`http://127.0.0.1:${port}/api/health`);
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.ok, true);
  assert.equal(body.service, "owner-control");
});

test("Railway healthcheck bypasses internal HTTP rejection without opening protected APIs", async (t) => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "owner-control-railway-health-"));
  const app = createApp({
    dbPath: path.join(tempDir, "owner-control.sqlite"),
    ownerToken: "test-owner-token",
    forceHttps: true,
    publicOrigin: "https://owner-control.example",
    trustProxy: false,
  });
  const server = http.createServer(app);

  t.after(async () => {
    await new Promise((resolve) => server.close(resolve));
    app.locals.controlStore.close();
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  await new Promise((resolve) => server.listen(0, "0.0.0.0", resolve));
  const { port } = server.address();
  const remoteHost = getNonLoopbackIpv4();
  assert.ok(remoteHost, "No encontre una IPv4 no-loopback para simular el healthcheck de Railway.");

  const health = await requestJson(remoteHost, port, "/api/health", {
    Host: "healthcheck.railway.app",
  });
  assert.equal(health.status, 200);
  assert.equal(health.body.ok, true);

  const protectedApi = await requestJson(remoteHost, port, "/api/owner/clients", {
    Host: "healthcheck.railway.app",
  });
  assert.equal(protectedApi.status, 426);
  assert.match(protectedApi.body.message, /HTTPS requerido/i);
});
