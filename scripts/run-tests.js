#!/usr/bin/env node

import { execFileSync } from "node:child_process";
import { readdirSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { dirname } from "node:path";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const rootDir = join(__dirname, "..");
const testDir = join(rootDir, "test");

function run(args) {
  try {
    execFileSync(process.execPath, args, { stdio: "inherit", cwd: rootDir });
  } catch {
    process.exit(1);
  }
}

run([join(__dirname, "build.js")]);

// Node 18 and 20 do not expand globs in --test, so the file list is built here.
const testFiles = readdirSync(testDir)
  .filter((name) => name.endsWith(".test.js"))
  .sort()
  .map((name) => join("test", name));

if (testFiles.length === 0) {
  console.error("no test files found in test/");
  process.exit(1);
}

console.log(`Running ${testFiles.length} test files...\n`);

run(["--test", ...testFiles]);
