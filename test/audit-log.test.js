import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { gunzipSync } from 'node:zlib';
import {
  AuditLog,
  DEFAULT_AUDIT_KEEP,
  DEFAULT_AUDIT_MAX_BYTES,
  defaultAuditLogPath,
} from '../build/utils/audit-log.js';
import { CommandLineParser } from '../build/cli/command-line-parser.js';

function readRecords(file) {
  return fs
    .readFileSync(file, 'utf8')
    .split('\n')
    .filter(Boolean)
    .map((line) => JSON.parse(line));
}

describe('audit log', () => {
  let fixturesDir;
  let logPath;
  let audit;

  beforeEach(() => {
    fixturesDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ssh-mcp-audit-test-'));
    logPath = path.join(fixturesDir, 'nested', 'audit.jsonl');
    audit = AuditLog.getInstance();
    audit.setRedactions([]);
  });

  afterEach(() => {
    audit.configure({ enabled: false, maxBytes: DEFAULT_AUDIT_MAX_BYTES, keep: DEFAULT_AUDIT_KEEP });
    audit.setRedactions([]);
    fs.rmSync(fixturesDir, { recursive: true, force: true });
  });

  it('writes one JSON record per event and creates the directory', () => {
    audit.configure({ enabled: true, path: logPath, maxBytes: 0, keep: 3 });

    audit.record({ event: 'command', result: 'ok', connection: 'prod', command: 'uptime', durationMs: 12 });
    audit.record({ event: 'command', result: 'blocked', connection: 'prod', command: 'rm -rf /', code: 'COMMAND_VALIDATION_FAILED' });

    const records = readRecords(logPath);

    assert.strictEqual(records.length, 2);
    assert.strictEqual(records[0].event, 'command');
    assert.strictEqual(records[0].result, 'ok');
    assert.strictEqual(records[0].command, 'uptime');
    assert.strictEqual(records[1].result, 'blocked');
    assert.ok(records[0].time);
    assert.strictEqual(records[0].pid, process.pid);
  });

  it('keeps the file private', () => {
    audit.configure({ enabled: true, path: logPath, maxBytes: 0, keep: 3 });
    audit.record({ event: 'command', result: 'ok', command: 'id' });

    if (process.platform !== 'win32') {
      assert.strictEqual(fs.statSync(logPath).mode & 0o077, 0);
    }
  });

  it('never writes a redacted secret', () => {
    audit.configure({ enabled: true, path: logPath, maxBytes: 0, keep: 3 });
    audit.setRedactions(['hunter2']);

    audit.record({ event: 'command', result: 'ok', command: 'echo hunter2 | passwd --stdin' });

    const content = fs.readFileSync(logPath, 'utf8');
    assert.ok(!content.includes('hunter2'));
    assert.match(content, /\*\*\*/);
  });

  it('rotates and gzips when the file grows past the limit', () => {
    audit.configure({ enabled: true, path: logPath, maxBytes: 400, keep: 3 });

    for (let index = 0; index < 20; index++) {
      audit.record({ event: 'command', result: 'ok', command: `command-${index}` });
    }

    assert.ok(fs.existsSync(`${logPath}.1.gz`), 'first archive exists');
    assert.ok(fs.statSync(logPath).size <= 400);

    const archived = gunzipSync(fs.readFileSync(`${logPath}.1.gz`)).toString('utf8');
    const archivedRecords = archived.split('\n').filter(Boolean).map((line) => JSON.parse(line));
    assert.ok(archivedRecords.length > 0);
    assert.match(archivedRecords[0].command, /^command-\d+$/);
    assert.ok(!fs.existsSync(`${logPath}.1`), 'the uncompressed rotation is removed');
  });

  it('keeps only the configured number of archives', () => {
    audit.configure({ enabled: true, path: logPath, maxBytes: 200, keep: 2 });

    for (let index = 0; index < 60; index++) {
      audit.record({ event: 'command', result: 'ok', command: `command-${index}` });
    }

    assert.ok(fs.existsSync(`${logPath}.1.gz`));
    assert.ok(fs.existsSync(`${logPath}.2.gz`));
    assert.ok(!fs.existsSync(`${logPath}.3.gz`), 'archives past keep are dropped');
  });

  it('never rotates when the limit is zero', () => {
    audit.configure({ enabled: true, path: logPath, maxBytes: 0, keep: 3 });

    for (let index = 0; index < 50; index++) {
      audit.record({ event: 'command', result: 'ok', command: `command-${index}` });
    }

    assert.strictEqual(readRecords(logPath).length, 50);
    assert.ok(!fs.existsSync(`${logPath}.1.gz`));
  });

  it('writes nothing when disabled', () => {
    audit.configure({ enabled: false, path: logPath, maxBytes: 0, keep: 3 });

    audit.record({ event: 'command', result: 'ok', command: 'uptime' });

    assert.strictEqual(fs.existsSync(logPath), false);
    assert.strictEqual(audit.getPath(), undefined);
  });
});

describe('audit log options', () => {
  const originalArgv = process.argv;

  afterEach(() => {
    process.argv = originalArgv;
  });

  function parse(args) {
    process.argv = ['node', 'index.js', '--ssh-config-hosts', ...args];
    return CommandLineParser.parseArgs();
  }

  it('is on by default and lands in the state directory', () => {
    const result = parse([]);

    assert.strictEqual(result.auditLog.enabled, true);
    assert.strictEqual(result.auditLog.path, defaultAuditLogPath());
    assert.strictEqual(result.auditLog.maxBytes, DEFAULT_AUDIT_MAX_BYTES);
    assert.strictEqual(result.auditLog.keep, DEFAULT_AUDIT_KEEP);
  });

  it('takes a path, a size and a retention count', () => {
    const result = parse(['--audit-log', '/tmp/ssh-audit.jsonl', '--audit-max-size', '1024', '--audit-keep', '4']);

    assert.strictEqual(result.auditLog.path, '/tmp/ssh-audit.jsonl');
    assert.strictEqual(result.auditLog.maxBytes, 1024);
    assert.strictEqual(result.auditLog.keep, 4);
  });

  it('can be turned off', () => {
    assert.strictEqual(parse(['--audit-log', 'off']).auditLog.enabled, false);
  });

  it('rejects a negative size', () => {
    assert.throws(() => parse(['--audit-max-size=-1']), /auditMaxSize/);
  });

  it('keeps upload off unless it is asked for', () => {
    assert.strictEqual(parse([]).enableUpload, false);
    assert.strictEqual(parse(['--enable-upload']).enableUpload, true);
  });
});
