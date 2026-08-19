import { createHash, createHmac } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

export type HostKeyChecking = "strict" | "accept-new" | "off";

export interface KnownHostEntry {
  marker?: "revoked" | "cert-authority";
  patterns: string[];
  keyType: string;
  keyBase64: string;
}

export type HostKeyStatus = "match" | "mismatch" | "revoked" | "unknown";

export interface HostKeyVerdict {
  status: HostKeyStatus;
  knownKeyTypes: string[];
}

const DEFAULT_SSH_PORT = 22;

export function defaultKnownHostsFiles(): string[] {
  const home = os.homedir();
  return [
    path.join(home, ".ssh", "known_hosts"),
    path.join(home, ".ssh", "known_hosts2"),
    path.join("/etc", "ssh", "ssh_known_hosts"),
  ];
}

export function parseKnownHostsLine(line: string): KnownHostEntry | undefined {
  const trimmed = line.trim();
  if (!trimmed || trimmed.startsWith("#")) {
    return undefined;
  }

  const fields = trimmed.split(/\s+/);
  let marker: KnownHostEntry["marker"];

  if (fields[0] === "@revoked" || fields[0] === "@cert-authority") {
    marker = fields[0].slice(1) as KnownHostEntry["marker"];
    fields.shift();
  }

  const [patterns, keyType, keyBase64] = fields;
  if (!patterns || !keyType || !keyBase64) {
    return undefined;
  }

  return {
    marker,
    patterns: patterns.split(",").filter(Boolean),
    keyType,
    keyBase64,
  };
}

export function loadKnownHosts(files: string[]): KnownHostEntry[] {
  const entries: KnownHostEntry[] = [];

  for (const file of files) {
    let content: string;
    try {
      content = fs.readFileSync(file, "utf8");
    } catch {
      // A missing or unreadable known_hosts file simply contributes nothing.
      continue;
    }

    for (const line of content.split("\n")) {
      const entry = parseKnownHostsLine(line);
      if (entry) {
        entries.push(entry);
      }
    }
  }

  return entries;
}

/**
 * The names a host can be recorded under.
 *
 * OpenSSH writes `[host]:port` for anything that is not on port 22, but the
 * plain name is checked too: the same host is often already recorded from a
 * connection on the default port.
 */
export function knownHostsCandidates(
  host: string,
  port: number,
  aliases: string[] = [],
): string[] {
  const names = [host, ...aliases].filter(Boolean);
  const candidates: string[] = [];

  for (const name of names) {
    if (port !== DEFAULT_SSH_PORT) {
      candidates.push(`[${name}]:${port}`);
    }
    candidates.push(name);
  }

  return Array.from(new Set(candidates));
}

export function hostPatternMatches(candidate: string, pattern: string): boolean {
  if (pattern.startsWith("|1|")) {
    return hashedHostMatches(candidate, pattern);
  }

  if (!pattern.includes("*") && !pattern.includes("?")) {
    return pattern === candidate;
  }

  const regexSource = pattern
    .replace(/[.+^${}()|[\]\\]/g, "\\$&")
    .replace(/\*/g, ".*")
    .replace(/\?/g, ".");

  return new RegExp(`^${regexSource}$`).test(candidate);
}

function hashedHostMatches(candidate: string, pattern: string): boolean {
  const [, , salt, hash] = pattern.split("|");
  if (!salt || !hash) {
    return false;
  }

  try {
    const digest = createHmac("sha1", Buffer.from(salt, "base64"))
      .update(candidate)
      .digest("base64");
    return digest === hash;
  } catch {
    return false;
  }
}

function entryMatchesCandidate(
  entry: KnownHostEntry,
  candidates: string[],
): boolean {
  let matched = false;

  for (const pattern of entry.patterns) {
    const negated = pattern.startsWith("!");
    const body = negated ? pattern.slice(1) : pattern;
    if (!body) {
      continue;
    }

    if (candidates.some((candidate) => hostPatternMatches(candidate, body))) {
      if (negated) {
        return false;
      }
      matched = true;
    }
  }

  return matched;
}

export function verifyHostKey(
  entries: KnownHostEntry[],
  candidates: string[],
  keyType: string,
  keyBase64: string,
): HostKeyVerdict {
  const knownKeyTypes: string[] = [];

  for (const entry of entries) {
    if (!entryMatchesCandidate(entry, candidates)) {
      continue;
    }

    if (entry.marker === "revoked" && entry.keyBase64 === keyBase64) {
      return { status: "revoked", knownKeyTypes };
    }

    if (entry.marker) {
      // A cert-authority line delegates trust to a CA, which this server does
      // not evaluate, so it cannot confirm the key on its own.
      continue;
    }

    if (entry.keyType === keyType) {
      if (entry.keyBase64 === keyBase64) {
        return { status: "match", knownKeyTypes };
      }
      knownKeyTypes.push(entry.keyType);
    } else if (!knownKeyTypes.includes(entry.keyType)) {
      knownKeyTypes.push(entry.keyType);
    }
  }

  return {
    status: knownKeyTypes.length > 0 ? "mismatch" : "unknown",
    knownKeyTypes,
  };
}

export function formatKnownHostsLine(
  host: string,
  port: number,
  keyType: string,
  keyBase64: string,
): string {
  const name =
    port === DEFAULT_SSH_PORT ? host : `[${host}]:${port}`;
  return `${name} ${keyType} ${keyBase64}\n`;
}

export function appendKnownHost(
  file: string,
  host: string,
  port: number,
  keyType: string,
  keyBase64: string,
): void {
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });

  let prefix = "";
  try {
    const existing = fs.readFileSync(file, "utf8");
    if (existing.length > 0 && !existing.endsWith("\n")) {
      prefix = "\n";
    }
  } catch {
    // The file is created by the append below.
  }

  fs.appendFileSync(
    file,
    prefix + formatKnownHostsLine(host, port, keyType, keyBase64),
    { mode: 0o600 },
  );
}

/**
 * The SHA256 fingerprint in the form ssh, ssh-keyscan and the server logs of
 * the remote host print, so the operator can compare it out of band.
 */
export function formatFingerprint(key: Buffer): string {
  return `SHA256:${createHash("sha256")
    .update(key)
    .digest("base64")
    .replace(/=+$/, "")}`;
}

/**
 * Read the key type out of the SSH wire format blob ssh2 hands to the host
 * verifier. The blob starts with the length prefixed algorithm name, which is
 * exactly the type known_hosts records.
 */
export function readKeyType(key: Buffer): string | undefined {
  if (key.length < 4) {
    return undefined;
  }

  const nameLength = key.readUInt32BE(0);
  if (nameLength <= 0 || key.length < 4 + nameLength) {
    return undefined;
  }

  return key.subarray(4, 4 + nameLength).toString("utf8");
}
