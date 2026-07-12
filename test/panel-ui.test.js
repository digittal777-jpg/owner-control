const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const APP_SOURCE = fs.readFileSync(path.join(__dirname, "..", "public", "app.js"), "utf8");

function readFunctionBody(functionName) {
  const start = APP_SOURCE.indexOf(`async function ${functionName}(`);
  assert.notEqual(start, -1, `No encontre ${functionName} en public/app.js.`);
  const nextFunction = APP_SOURCE.indexOf("\nasync function ", start + 1);
  return APP_SOURCE.slice(start, nextFunction === -1 ? APP_SOURCE.length : nextFunction);
}

test("quiet client refresh updates status without rebuilding unsaved forms", () => {
  const source = readFunctionBody("refreshSelectedDetailQuietly");

  assert.match(source, /renderClientConfigSyncSummary\(response\)/);
  assert.match(source, /renderClientRuntimeConfigSyncSummary\(response\)/);
  assert.match(source, /renderHealth\(response\.healthReports \|\| \[\]\)/);
  assert.doesNotMatch(source, /renderDetail\(\)/);
  assert.doesNotMatch(source, /renderClientRuntimeConfig\(/);
});

test("Variables POS explains bootstrap pairing instead of rendering it as synced runtime", () => {
  assert.match(APP_SOURCE, /Conexion inicial del POS/);
  assert.match(APP_SOURCE, /CONTROL_CLIENT_SECRET=&lt;API key creada o rotada&gt;/);
  assert.match(APP_SOURCE, /variables\.filter\(\(variable\) => variable\.managedByClientSync !== false\)/);
  assert.match(APP_SOURCE, /if \(!value\) \{\s+return;\s+\}/);
});
