import { describe, it, before, after, beforeEach } from 'node:test';
import assert from 'node:assert';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { createHmac, randomBytes } from 'node:crypto';
import {
  appendKnownHost,
  formatFingerprint,
  knownHostsCandidates,
  loadKnownHosts,
  parseKnownHostsLine,
  readKeyType,
  verifyHostKey,
} from '../build/utils/known-hosts.js';
import { SSHConnectionManager } from '../build/services/ssh-connection-manager.js';

/**
 * Build an SSH wire format public key blob: the length prefixed algorithm name
 * followed by the key material, which is what ssh2 hands to a host verifier.
 */
function makeHostKey(keyType, material) {
  const name = Buffer.from(keyType, 'utf8');
  const length = Buffer.alloc(4);
  length.writeUInt32BE(name.length, 0);
  return Buffer.concat([length, name, Buffer.from(material, 'utf8')]);
}

const HOST_KEY = makeHostKey('ssh-ed25519', 'real-key-material');
const OTHER_KEY = makeHostKey('ssh-ed25519', 'other-key-material');
const HOST_KEY_BASE64 = HOST_KEY.toString('base64');

describe('known_hosts parsing', () => {
  it('parses a plain entry', () => {
    const entry = parseKnownHostsLine('prod.example.com ssh-ed25519 AAAAB3Nz comment');

    assert.deepStrictEqual(entry.patterns, ['prod.example.com']);
    assert.strictEqual(entry.keyType, 'ssh-ed25519');
    assert.strictEqual(entry.keyBase64, 'AAAAB3Nz');
    assert.strictEqual(entry.marker, undefined);
  });

  it('parses markers and multiple patterns', () => {
    const entry = parseKnownHostsLine('@revoked host-a,host-b ssh-rsa AAAA');

    assert.strictEqual(entry.marker, 'revoked');
    assert.deepStrictEqual(entry.patterns, ['host-a', 'host-b']);
  });

  it('skips comments and blank lines', () => {
    assert.strictEqual(parseKnownHostsLine('# a comment'), undefined);
    assert.strictEqual(parseKnownHostsLine('   '), undefined);
    assert.strictEqual(parseKnownHostsLine('incomplete ssh-rsa'), undefined);
  });

  it('builds the candidate names of a host', () => {
    assert.deepStrictEqual(knownHostsCandidates('prod.example.com', 22), ['prod.example.com']);
    assert.deepStrictEqual(knownHostsCandidates('prod.example.com', 2222), [
      '[prod.example.com]:2222',
      'prod.example.com',
    ]);
    assert.deepStrictEqual(knownHostsCandidates('10.0.0.1', 22, ['prod-master']), [
      '10.0.0.1',
      'prod-master',
    ]);
  });

  it('reads the key type out of the wire format blob', () => {
    assert.strictEqual(readKeyType(HOST_KEY), 'ssh-ed25519');
    assert.strictEqual(readKeyType(Buffer.from([0, 0])), undefined);
  });

  it('formats the fingerprint the way ssh prints it', () => {
    const fingerprint = formatFingerprint(HOST_KEY);

    assert.match(fingerprint, /^SHA256:[A-Za-z0-9+/]+$/);
    assert.strictEqual(fingerprint, formatFingerprint(HOST_KEY));
    assert.notStrictEqual(fingerprint, formatFingerprint(OTHER_KEY));
  });
});

describe('host key verification', () => {
  let fixturesDir;
  let knownHostsPath;

  before(() => {
    fixturesDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ssh-mcp-known-hosts-test-'));
    knownHostsPath = path.join(fixturesDir, 'known_hosts');

    const salt = randomBytes(20);
    const hashedHost = createHmac('sha1', salt).update('hashed.example.com').digest('base64');

    fs.writeFileSync(knownHostsPath, [
      `prod.example.com ssh-ed25519 ${HOST_KEY_BASE64}`,
      `[alt.example.com]:2222 ssh-ed25519 ${HOST_KEY_BASE64}`,
      `*.wild.example.com ssh-ed25519 ${HOST_KEY_BASE64}`,
      `|1|${salt.toString('base64')}|${hashedHost} ssh-ed25519 ${HOST_KEY_BASE64}`,
      `@revoked burned.example.com ssh-ed25519 ${HOST_KEY_BASE64}`,
      `rotated.example.com ssh-ed25519 ${OTHER_KEY.toString('base64')}`,
      '',
    ].join('\n'));
  });

  after(() => {
    fs.rmSync(fixturesDir, { recursive: true, force: true });
  });

  function check(host, port) {
    return verifyHostKey(
      loadKnownHosts([knownHostsPath]),
      knownHostsCandidates(host, port),
      'ssh-ed25519',
      HOST_KEY_BASE64,
    );
  }

  it('accepts a recorded key', () => {
    assert.strictEqual(check('prod.example.com', 22).status, 'match');
  });

  it('accepts a key recorded with a port', () => {
    assert.strictEqual(check('alt.example.com', 2222).status, 'match');
  });

  it('accepts a wildcard entry', () => {
    assert.strictEqual(check('node1.wild.example.com', 22).status, 'match');
  });

  it('accepts a hashed entry', () => {
    assert.strictEqual(check('hashed.example.com', 22).status, 'match');
  });

  it('reports an unknown host', () => {
    assert.strictEqual(check('new.example.com', 22).status, 'unknown');
  });

  it('reports a key that contradicts known_hosts', () => {
    const verdict = check('rotated.example.com', 22);

    assert.strictEqual(verdict.status, 'mismatch');
    assert.deepStrictEqual(verdict.knownKeyTypes, ['ssh-ed25519']);
  });

  it('reports a revoked key', () => {
    assert.strictEqual(check('burned.example.com', 22).status, 'revoked');
  });

  it('records a new host and matches it afterwards', () => {
    const filePath = path.join(fixturesDir, 'accept-new');

    appendKnownHost(filePath, 'fresh.example.com', 2022, 'ssh-ed25519', HOST_KEY_BASE64);

    const verdict = verifyHostKey(
      loadKnownHosts([filePath]),
      knownHostsCandidates('fresh.example.com', 2022),
      'ssh-ed25519',
      HOST_KEY_BASE64,
    );

    assert.strictEqual(verdict.status, 'match');
    assert.match(fs.readFileSync(filePath, 'utf8'), /^\[fresh\.example\.com\]:2022 ssh-ed25519 /);
  });
});

describe('host key checking in the connection manager', () => {
  let fixturesDir;
  let knownHostsPath;
  let manager;

  before(() => {
    fixturesDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ssh-mcp-verifier-test-'));
    knownHostsPath = path.join(fixturesDir, 'known_hosts');
    fs.writeFileSync(knownHostsPath, `known.example.com ssh-ed25519 ${HOST_KEY_BASE64}\n`);
    fs.writeFileSync(path.join(fixturesDir, 'key'), 'PRIVATE KEY PLACEHOLDER');
  });

  after(() => {
    fs.rmSync(fixturesDir, { recursive: true, force: true });
  });

  beforeEach(() => {
    manager = SSHConnectionManager.getInstance();
  });

  function configure(host, extra = {}) {
    manager.setConfig({
      default: {
        name: 'default',
        host,
        port: 22,
        username: 'ops',
        privateKey: path.join(fixturesDir, 'key'),
        knownHostsFiles: [knownHostsPath],
        transportMode: 'exec',
        ...extra,
      },
    });
    return manager.getConfig('default');
  }

  it('is on by default and accepts a recorded key', async () => {
    const config = configure('known.example.com');
    const sshConfig = await manager.buildClientConfig('default', config);

    assert.strictEqual(typeof sshConfig.hostVerifier, 'function');
    assert.strictEqual(sshConfig.hostVerifier(HOST_KEY), true);
  });

  it('refuses an unknown host and explains how to fix it', async () => {
    const config = configure('unknown.example.com');
    const sshConfig = await manager.buildClientConfig('default', config);

    assert.strictEqual(sshConfig.hostVerifier(HOST_KEY), false);
    const error = manager.hostKeyError('default');
    assert.strictEqual(error.code, 'SSH_HOST_KEY_REJECTED');
    assert.match(error.message, /not in known_hosts/);
    assert.match(error.message, /SHA256:/);
    assert.match(error.message, /accept-new/);
  });

  it('refuses a key that contradicts known_hosts', async () => {
    const config = configure('known.example.com');
    const sshConfig = await manager.buildClientConfig('default', config);

    assert.strictEqual(sshConfig.hostVerifier(OTHER_KEY), false);
    assert.match(manager.hostKeyError('default').message, /HOST KEY MISMATCH/);
  });

  it('records the key of an unknown host in accept-new mode', async () => {
    const acceptNewPath = path.join(fixturesDir, 'accept-new-manager');
    const config = configure('fresh.example.com', {
      hostKeyChecking: 'accept-new',
      knownHostsFiles: [acceptNewPath],
    });
    const sshConfig = await manager.buildClientConfig('default', config);

    assert.strictEqual(sshConfig.hostVerifier(HOST_KEY), true);
    assert.match(fs.readFileSync(acceptNewPath, 'utf8'), /^fresh\.example\.com ssh-ed25519 /);
  });

  it('still refuses a mismatch in accept-new mode', async () => {
    const config = configure('known.example.com', { hostKeyChecking: 'accept-new' });
    const sshConfig = await manager.buildClientConfig('default', config);

    assert.strictEqual(sshConfig.hostVerifier(OTHER_KEY), false);
  });

  it('can be turned off explicitly', async () => {
    const config = configure('unknown.example.com', { hostKeyChecking: 'off' });
    const sshConfig = await manager.buildClientConfig('default', config);

    assert.strictEqual(sshConfig.hostVerifier, undefined);
  });
});
