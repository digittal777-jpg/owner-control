#!/usr/bin/env node

const path = require("node:path");
const { createControlStore } = require("../src/store");

function getArgValue(name) {
  const prefix = `${name}=`;
  const directValue = process.argv.find((arg) => arg.startsWith(prefix));
  if (directValue) {
    return directValue.slice(prefix.length);
  }
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : "";
}

function main() {
  const apply = process.argv.includes("--apply");
  const dbPath = getArgValue("--db") || process.env.OWNER_CONTROL_DB_PATH || "";
  const store = createControlStore({
    dbPath: dbPath
      ? path.resolve(dbPath)
      : undefined,
  });

  try {
    const result = store.pruneRetainedReports({ apply });
    console.log(JSON.stringify(result, null, 2));
    if (!apply && (result.deletedHealthReports > 0 || result.deletedValidationReports > 0)) {
      console.log("Dry-run: vuelve a ejecutar con --apply para borrar los reportes excedentes.");
    }
  } finally {
    store.close();
  }
}

main();
