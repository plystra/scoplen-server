// SPDX-License-Identifier: Apache-2.0
// Check that every control-plane route mounted by the server is present in the
// authored OpenAPI contract. The manifest is intentionally empty until the
// control-plane router is implemented; adding a route requires adding its
// method/path pair to the manifest and the contract at the same time.
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

const [contractPath, manifestPath = "scripts/control-plane-routes.json"] = process.argv.slice(2);
if (!contractPath) throw new Error("usage: node check-control-plane-routes.mjs <openapi-json-yaml> [manifest]");
const contract = JSON.parse(await readFile(resolve(contractPath), "utf8"));
const serverRoot = new URL("../", import.meta.url);
const manifestUrl = manifestPath === "scripts/control-plane-routes.json"
  ? new URL("scripts/control-plane-routes.json", serverRoot)
  : undefined;
const manifest = JSON.parse(await readFile(manifestUrl ?? resolve(manifestPath), "utf8"));
if (contract.openapi !== "3.1.0") throw new Error("the control-plane contract is not OpenAPI 3.1");
if (!Array.isArray(manifest)) throw new Error("the route manifest must be an array");

const expected = new Set();
for (const entry of manifest) {
  if (!entry || typeof entry.path !== "string" || typeof entry.method !== "string") {
    throw new Error("route manifest entries require string path and method");
  }
  const method = entry.method.toLowerCase();
  if (!/^(get|post|patch|delete|put)$/.test(method)) throw new Error(`unsupported route method: ${entry.method}`);
  if (!contract.paths?.[entry.path]?.[method]) throw new Error(`route is missing from OpenAPI: ${method.toUpperCase()} ${entry.path}`);
  expected.add(`${method.toUpperCase()} ${entry.path}`);
}

const source = await readFile(new URL("crates/scoplen-server/src/runtime.rs", serverRoot), "utf8");
for (const match of source.matchAll(/\.route\(\s*["'](\/api\/v1\/[^"']+)["']\s*,\s*([^\n]+)/g)) {
  const [, path, expression] = match;
  const method = expression.match(/\b(get|post|patch|put|delete)\s*\(/)?.[1];
  if (!method) throw new Error(`could not determine method for mounted route ${path}`);
  const key = `${method.toUpperCase()} ${path}`;
  if (!expected.has(key)) throw new Error(`mounted route is absent from control-plane manifest: ${key}`);
}
console.log(`validated ${manifest.length} mounted control-plane routes against OpenAPI 3.1`);
