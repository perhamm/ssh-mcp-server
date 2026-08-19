#!/usr/bin/env node

/**
 * Refresh a guard ruleset from a URL.
 *
 * Usage: node scripts/update-guards.js <url> [destination]
 *
 * The download is validated and only then written, so a failed or corrupted
 * fetch leaves the ruleset that is in place untouched. Run it from cron and
 * point --guards-file at the destination to keep a fleet's guards current.
 */

import { writeFileSync, renameSync, mkdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const rootDir = join(dirname(fileURLToPath(import.meta.url)), "..");
const DEFAULT_DESTINATION = join(rootDir, "guards", "default-guards.json");

const [url, destinationArg] = process.argv.slice(2);

if (!url) {
  console.error("Usage: node scripts/update-guards.js <url> [destination]");
  process.exit(1);
}

const destination = destinationArg
  ? resolve(destinationArg)
  : DEFAULT_DESTINATION;

const response = await fetch(url);
if (!response.ok) {
  console.error(`Failed to download guards: ${response.status} ${response.statusText}`);
  process.exit(1);
}

const content = await response.text();

let ruleset;
try {
  ruleset = JSON.parse(content);
} catch (error) {
  console.error(`Downloaded guards are not valid JSON: ${error.message}`);
  process.exit(1);
}

if (typeof ruleset.version !== "string" || typeof ruleset.profiles !== "object") {
  console.error("Downloaded guards must contain a version string and a profiles object");
  process.exit(1);
}

for (const [profileName, profile] of Object.entries(ruleset.profiles)) {
  for (const kind of ["allow", "deny"]) {
    for (const rule of profile[kind] || []) {
      if (!rule.id || typeof rule.pattern !== "string") {
        console.error(`Rule in profile '${profileName}' is missing id or pattern`);
        process.exit(1);
      }
      try {
        new RegExp(rule.pattern, "i");
      } catch (error) {
        console.error(
          `Invalid ${kind} pattern '${rule.id}' in profile '${profileName}': ${error.message}`,
        );
        process.exit(1);
      }
    }
  }
}

mkdirSync(dirname(destination), { recursive: true });
const temporaryPath = `${destination}.tmp-${process.pid}`;
writeFileSync(temporaryPath, content);
renameSync(temporaryPath, destination);

console.log(
  `Updated ${destination} to ruleset ${ruleset.version} (${Object.keys(ruleset.profiles).join(", ")})`,
);
