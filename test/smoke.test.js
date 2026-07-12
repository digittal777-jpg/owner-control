const assert = require("node:assert/strict");
const fs = require("node:fs");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const { createApp } = require("../src/app");

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
