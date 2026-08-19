import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { gzipSync } from "node:zlib";
import { Logger } from "./logger.js";

export type AuditEvent =
  | "connect"
  | "command"
  | "download"
  | "upload"
  | "tunnel-open"
  | "tunnel-close"
  | "host-key";

export type AuditResult = "ok" | "blocked" | "error";

export interface AuditRecord {
  event: AuditEvent;
  result: AuditResult;
  connection?: string;
  host?: string;
  port?: number;
  username?: string;
  command?: string;
  directory?: string;
  sudo?: boolean;
  code?: string;
  reason?: string;
  durationMs?: number;
  bytes?: number;
  localPath?: string;
  remotePath?: string;
  tunnel?: string;
}

export interface AuditLogSettings {
  enabled: boolean;
  path?: string;
  maxBytes: number;
  keep: number;
}

export const DEFAULT_AUDIT_MAX_BYTES = 10 * 1024 * 1024;
export const DEFAULT_AUDIT_KEEP = 10;

export function defaultAuditLogPath(): string {
  const stateHome =
    process.env.XDG_STATE_HOME || path.join(os.homedir(), ".local", "state");
  return path.join(stateHome, "ssh-mcp-server", "audit.jsonl");
}

/**
 * Append only record of what the server was asked to do.
 *
 * Rotation is built in because the alternative is an audit file that grows
 * until the disk is full: at `maxBytes` the current file is renamed, gzipped
 * and the older archives shift up, with everything past `keep` dropped.
 * `maxBytes: 0` turns that off for a file that logrotate owns instead.
 */
export class AuditLog {
  private static instance: AuditLog;
  private settings: AuditLogSettings = {
    enabled: false,
    maxBytes: DEFAULT_AUDIT_MAX_BYTES,
    keep: DEFAULT_AUDIT_KEEP,
  };
  private currentSize = 0;
  private failureReported = false;
  private redactions: string[] = [];

  private constructor() {}

  public static getInstance(): AuditLog {
    if (!AuditLog.instance) {
      AuditLog.instance = new AuditLog();
    }
    return AuditLog.instance;
  }

  public configure(settings: AuditLogSettings): void {
    this.settings = settings;
    this.failureReported = false;
    this.currentSize = 0;

    if (!settings.enabled || !settings.path) {
      return;
    }

    try {
      fs.mkdirSync(path.dirname(settings.path), { recursive: true, mode: 0o700 });
      this.currentSize = fs.existsSync(settings.path)
        ? fs.statSync(settings.path).size
        : 0;
      Logger.log(
        `Audit log: ${settings.path} (rotate at ${
          settings.maxBytes === 0 ? "never" : `${settings.maxBytes} bytes`
        }, keep ${settings.keep} archives)`,
        "info",
      );
    } catch (error) {
      this.reportFailure(error as Error);
      this.settings = { ...settings, enabled: false };
    }
  }

  /**
   * Values that must never reach the log even if a caller passes them along.
   */
  public setRedactions(secrets: string[]): void {
    this.redactions = secrets.filter(Boolean);
  }

  public getPath(): string | undefined {
    return this.settings.enabled ? this.settings.path : undefined;
  }

  public record(record: AuditRecord): void {
    if (!this.settings.enabled || !this.settings.path) {
      return;
    }

    const line = `${JSON.stringify({
      time: new Date().toISOString(),
      pid: process.pid,
      ...this.redact(record),
    })}\n`;

    try {
      if (
        this.settings.maxBytes > 0 &&
        this.currentSize + line.length > this.settings.maxBytes &&
        this.currentSize > 0
      ) {
        this.rotate();
      }

      fs.appendFileSync(this.settings.path, line, { mode: 0o600 });
      this.currentSize += line.length;
    } catch (error) {
      this.reportFailure(error as Error);
    }
  }

  private redact(record: AuditRecord): AuditRecord {
    if (this.redactions.length === 0) {
      return record;
    }

    const redacted: AuditRecord = { ...record };
    for (const field of ["command", "reason", "directory"] as const) {
      const value = redacted[field];
      if (typeof value === "string") {
        redacted[field] = this.redactions.reduce(
          (text, secret) => text.split(secret).join("***"),
          value,
        );
      }
    }

    return redacted;
  }

  private rotate(): void {
    const target = this.settings.path as string;
    const keep = Math.max(1, this.settings.keep);

    for (let index = keep - 1; index >= 1; index--) {
      const source = `${target}.${index}.gz`;
      if (!fs.existsSync(source)) {
        continue;
      }
      if (index + 1 > keep) {
        fs.rmSync(source, { force: true });
        continue;
      }
      fs.renameSync(source, `${target}.${index + 1}.gz`);
    }

    fs.rmSync(`${target}.${keep + 1}.gz`, { force: true });

    const rotated = `${target}.1`;
    fs.renameSync(target, rotated);
    fs.writeFileSync(`${rotated}.gz`, gzipSync(fs.readFileSync(rotated)), {
      mode: 0o600,
    });
    fs.rmSync(rotated, { force: true });
    this.currentSize = 0;
  }

  private reportFailure(error: Error): void {
    if (this.failureReported) {
      return;
    }
    this.failureReported = true;
    Logger.log(
      `Audit log is not being written (${this.settings.path}): ${error.message}`,
      "error",
    );
  }
}
