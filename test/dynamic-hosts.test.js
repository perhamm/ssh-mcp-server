import { describe, it, before, after, beforeEach } from 'node:test';
import assert from 'node:assert';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { SSHConnectionManager } from '../build/services/ssh-connection-manager.js';
import { CommandLineParser } from '../build/cli/command-line-parser.js';

describe('SSH config connections resolved on demand', () => {
  let fixturesDir;
  let configPath;
  let keyPath;
  let manager;

  before(() => {
    fixturesDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ssh-mcp-dynamic-test-'));
    configPath = path.join(fixturesDir, 'config');
    keyPath = path.join(fixturesDir, 'prod_key');
    fs.writeFileSync(keyPath, 'not-a-real-key');

    fs.writeFileSync(configPath, [
      'Host prod-master',
      '    HostName 10.20.30.40',
      '    User ops',
      '    Port 2200',
      `    IdentityFile ${keyPath}`,
      '    ProxyJump bastion',
      '',
      'Host dev-master',
      '    HostName 10.20.30.41',
      '    User dev',
      `    IdentityFile ${keyPath}`,
      '',
      'Host bastion',
      '    HostName 10.20.30.1',
      '    User jump',
      `    IdentityFile ${keyPath}`,
      '',
      'Host old-master',
      '    HostName 10.20.30.63',
      '    User ops',
      `    IdentityFile ${keyPath}`,
    ].join('\n'));
  });

  after(() => {
    fs.rmSync(fixturesDir, { recursive: true, force: true });
  });

  beforeEach(() => {
    manager = SSHConnectionManager.getInstance();
    manager.setConfig({});
  });

  it('keeps the connection name when no jump chain is given', () => {
    manager.setDynamicHosts({
      enabled: true,
      sshConfigFile: configPath,
      template: {},
    });

    assert.strictEqual(manager.resolveConnection('prod-master'), 'prod-master');
    assert.strictEqual(manager.resolveConnection('prod-master', '   '), 'prod-master');
  });

  it('puts a caller supplied jump chain under its own connection', () => {
    manager.setDynamicHosts({
      enabled: true,
      sshConfigFile: configPath,
      template: {},
    });

    const key = manager.resolveConnection('old-master', 'prod-master');

    assert.strictEqual(key, 'old-master via prod-master');
    const config = manager.getConfig(key);
    assert.strictEqual(config.host, '10.20.30.63');
    assert.strictEqual(config.proxyJump, 'prod-master');
    assert.strictEqual(manager.getConfig('old-master').proxyJump, undefined);
  });

  it('overrides the jump chain of the SSH config for that call only', () => {
    manager.setDynamicHosts({
      enabled: true,
      sshConfigFile: configPath,
      template: {},
    });

    const key = manager.resolveConnection('prod-master', 'dev-master');

    assert.strictEqual(manager.getConfig(key).proxyJump, 'dev-master');
    assert.strictEqual(manager.getConfig('prod-master').proxyJump, 'bastion');
  });

  it('reuses the connection of a repeated jump chain', () => {
    manager.setDynamicHosts({
      enabled: true,
      sshConfigFile: configPath,
      template: {},
    });

    assert.strictEqual(
      manager.resolveConnection('old-master', 'bastion'),
      manager.resolveConnection('old-master', 'bastion'),
    );
  });

  it('accepts a hop carrying a user and a port', () => {
    manager.setDynamicHosts({
      enabled: true,
      sshConfigFile: configPath,
      template: {},
    });

    const key = manager.resolveConnection('old-master', 'ops@bastion:2222');
    assert.strictEqual(manager.getConfig(key).proxyJump, 'ops@bastion:2222');
  });

  it('refuses a hop that is not declared in the SSH config', () => {
    manager.setDynamicHosts({
      enabled: true,
      sshConfigFile: configPath,
      template: {},
    });

    assert.throws(
      () => manager.resolveConnection('old-master', '10.0.0.1'),
      /SSH_JUMP_NOT_ALLOWED|not an alias declared/,
    );
  });

  it('refuses a hop when the chain has one undeclared entry', () => {
    manager.setDynamicHosts({
      enabled: true,
      sshConfigFile: configPath,
      template: {},
    });

    assert.throws(
      () => manager.resolveConnection('old-master', 'bastion,evil.example.com'),
      /not an alias declared/,
    );
  });

  it('refuses a caller supplied chain without --ssh-config-hosts', () => {
    manager.setDynamicHosts({ enabled: false, template: {} });
    manager.setConfig({
      only: {
        name: 'only',
        host: '10.20.30.99',
        port: 22,
        username: 'ops',
        password: 'pwd',
      },
    });

    assert.throws(
      () => manager.resolveConnection('only', 'bastion'),
      /needs --ssh-config-hosts/,
    );
  });

  it('refuses a jump chain for an alias that does not exist', () => {
    manager.setDynamicHosts({
      enabled: true,
      sshConfigFile: configPath,
      template: {},
    });

    assert.throws(
      () => manager.resolveConnection('no-such-host', 'bastion'),
      /not set and no such host alias/,
    );
  });

  it('builds a connection from a host alias', () => {
    manager.setDynamicHosts({
      enabled: true,
      sshConfigFile: configPath,
      template: { guardProfile: 'safe' },
    });

    const config = manager.getConfig('prod-master');

    assert.strictEqual(config.host, '10.20.30.40');
    assert.strictEqual(config.port, 2200);
    assert.strictEqual(config.username, 'ops');
    assert.strictEqual(config.privateKey, keyPath);
    assert.strictEqual(config.proxyJump, 'bastion');
    assert.strictEqual(config.sshConfigFile, configPath);
  });

  it('compiles the guard profile of the template for the resolved connection', () => {
    manager.setDynamicHosts({
      enabled: true,
      sshConfigFile: configPath,
      template: { guardProfile: 'readonly' },
    });

    manager.getConfig('dev-master');
    const guard = manager.getGuard('dev-master');

    assert.strictEqual(guard.profile, 'readonly');
    assert.strictEqual(
      manager.validateCommand('rm -rf /var/lib/data', 'dev-master').isAllowed,
      false,
    );
  });

  it('applies the guard profile to the first command of a fresh alias', () => {
    manager.setDynamicHosts({
      enabled: true,
      sshConfigFile: configPath,
      template: { guardProfile: 'safe' },
    });

    const verdict = manager.validateCommand('ls; rm -rf /', 'prod-master');

    assert.strictEqual(verdict.isAllowed, false);
    assert.match(verdict.reason, /rm-critical-path/);
  });

  it('lists the aliases it can resolve', () => {
    manager.setDynamicHosts({
      enabled: true,
      sshConfigFile: configPath,
      template: {},
    });

    assert.deepStrictEqual(
      manager.getSshConfigHosts().map((host) => host.alias),
      ['prod-master', 'dev-master', 'bastion', 'old-master'],
    );
  });

  it('honours the allowed host patterns', () => {
    manager.setDynamicHosts({
      enabled: true,
      sshConfigFile: configPath,
      allowPatterns: ['prod-*'],
      template: {},
    });

    assert.deepStrictEqual(
      manager.getSshConfigHosts().map((host) => host.alias),
      ['prod-master'],
    );
    assert.throws(() => manager.getConfig('dev-master'), /not in the allowed hosts/);
  });

  it('connects a declared alias that has no HostName by its own name', () => {
    const bareConfig = path.join(fixturesDir, 'config-bare');
    fs.writeFileSync(bareConfig, [
      'Host gitlab.example.com',
      '',
      'Host *',
      `    IdentityFile ${keyPath}`,
    ].join('\n'));

    manager.setDynamicHosts({
      enabled: true,
      sshConfigFile: bareConfig,
      template: {},
    });

    const config = manager.getConfig('gitlab.example.com');

    assert.strictEqual(config.host, 'gitlab.example.com');
    assert.strictEqual(config.port, 22);
    assert.strictEqual(config.privateKey, keyPath);
  });

  it('refuses a name that only a Host * block would answer for', () => {
    const wildcardConfig = path.join(fixturesDir, 'config-wildcard');
    fs.writeFileSync(wildcardConfig, [
      'Host prod-master',
      '    HostName 10.20.30.40',
      '',
      'Host *',
      '    User ops',
      `    IdentityFile ${keyPath}`,
    ].join('\n'));

    manager.setDynamicHosts({
      enabled: true,
      sshConfigFile: wildcardConfig,
      template: {},
    });

    assert.strictEqual(manager.getConfig('prod-master').host, '10.20.30.40');
    assert.throws(() => manager.getConfig('attacker.example.com'), /no such host alias/);
  });

  it('reports an unknown alias', () => {
    manager.setDynamicHosts({
      enabled: true,
      sshConfigFile: configPath,
      template: {},
    });

    assert.throws(() => manager.getConfig('nope'), /list-ssh-hosts/);
  });

  it('stays disabled unless enabled', () => {
    manager.setDynamicHosts({ enabled: false, template: {} });

    assert.deepStrictEqual(manager.getSshConfigHosts(), []);
    assert.throws(() => manager.getConfig('prod-master'), /not set/);
  });
});

describe('command line options of the fork', () => {
  const originalArgv = process.argv;

  after(() => {
    process.argv = originalArgv;
  });

  function parse(args) {
    process.argv = ['node', 'index.js', ...args];
    return CommandLineParser.parseArgs();
  }

  it('starts without a host when SSH config hosts are enabled', () => {
    const result = parse(['--ssh-config-hosts', '--guards-profile', 'safe']);

    assert.deepStrictEqual(result.configs, {});
    assert.strictEqual(result.dynamicHosts.enabled, true);
    assert.strictEqual(result.dynamicHosts.template.guardProfile, 'safe');
  });

  it('parses the allowed host patterns', () => {
    const result = parse(['--ssh-config-hosts', '--allowed-hosts', 'prod-*, stage-*']);

    assert.deepStrictEqual(result.dynamicHosts.allowPatterns, ['prod-*', 'stage-*']);
  });

  it('applies the guard profile to a static connection', () => {
    const result = parse([
      '--host', '10.0.0.1',
      '--username', 'ops',
      '--password', 'secret',
      '--guards-profile', 'readonly',
      '--sudo-password-env', 'MY_SUDO',
      '--sudo-user', 'app',
    ]);

    assert.strictEqual(result.configs.default.guardProfile, 'readonly');
    assert.strictEqual(result.configs.default.sudoPasswordEnv, 'MY_SUDO');
    assert.strictEqual(result.configs.default.sudoUser, 'app');
  });

  it('rejects an unknown guard profile', () => {
    assert.throws(
      () => parse(['--host', '10.0.0.1', '--username', 'ops', '--password', 'x', '--guards-profile', 'paranoid']),
      /guardsProfile must be one of/,
    );
  });

  it('enables tunnels on loopback by default', () => {
    const result = parse(['--ssh-config-hosts']);

    assert.strictEqual(result.tunnelPolicy.enabled, true);
    assert.strictEqual(result.tunnelPolicy.bindAddress, '127.0.0.1');
    assert.strictEqual(result.tunnelPolicy.maxTunnels, 8);
    assert.strictEqual(result.tunnelPolicy.allowedPorts, undefined);
  });

  it('parses the tunnel policy', () => {
    const result = parse([
      '--ssh-config-hosts',
      '--tunnel-bind-address', '0.0.0.0',
      '--allowed-tunnel-ports', '8777,9050',
      '--max-tunnels', '2',
    ]);

    assert.strictEqual(result.tunnelPolicy.bindAddress, '0.0.0.0');
    assert.deepStrictEqual(result.tunnelPolicy.allowedPorts, [8777, 9050]);
    assert.strictEqual(result.tunnelPolicy.maxTunnels, 2);
  });

  it('disables tunnels on request', () => {
    const result = parse(['--ssh-config-hosts', '--disable-tunnels']);

    assert.strictEqual(result.tunnelPolicy.enabled, false);
  });
});
