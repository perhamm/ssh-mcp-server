import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert';
import {
  SSHConnectionManager,
  redactSecret,
} from '../build/services/ssh-connection-manager.js';

const BASE_CONFIG = {
  name: 'default',
  host: '10.0.0.1',
  port: 22,
  username: 'ops',
  password: 'pwd',
  transportMode: 'exec',
};

describe('sudo', () => {
  let manager;
  let originalPassword;

  beforeEach(() => {
    manager = SSHConnectionManager.getInstance();
    originalPassword = process.env.SSH_MCP_SUDO_PASSWORD;
    delete process.env.SSH_MCP_SUDO_PASSWORD;
  });

  afterEach(() => {
    if (originalPassword === undefined) {
      delete process.env.SSH_MCP_SUDO_PASSWORD;
    } else {
      process.env.SSH_MCP_SUDO_PASSWORD = originalPassword;
    }
  });

  it('fails before connecting when the password variable is empty', async () => {
    manager.setConfig({ default: { ...BASE_CONFIG } });

    await assert.rejects(
      () => manager.executeCommand('systemctl restart nginx', undefined, 'default', { sudo: true }),
      /SSH_MCP_SUDO_PASSWORD is empty/,
    );
  });

  it('reads the password from the configured variable', () => {
    process.env.MY_SUDO_PASSWORD = 'topsecret';
    manager.setConfig({
      default: { ...BASE_CONFIG, sudoPasswordEnv: 'MY_SUDO_PASSWORD' },
    });

    try {
      assert.strictEqual(
        manager.resolveSudoPassword(manager.getConfig('default'), 'default'),
        'topsecret',
      );
    } finally {
      delete process.env.MY_SUDO_PASSWORD;
    }
  });

  it('is blocked by the readonly guard profile', async () => {
    process.env.SSH_MCP_SUDO_PASSWORD = 'topsecret';
    manager.setConfig({
      default: { ...BASE_CONFIG, guardProfile: 'readonly' },
    });

    await assert.rejects(
      () => manager.executeCommand('ls /root', undefined, 'default', { sudo: true }),
      /does not allow sudo/,
    );
  });

  it('keeps the password out of the command line', () => {
    manager.setConfig({ default: { ...BASE_CONFIG } });
    const command = manager.buildSudoCommand(manager.getConfig('default'), 'ls /root');

    assert.strictEqual(command, "sudo -S -k -p '' -u 'root' -- /bin/sh -c 'ls /root'");
    assert.ok(!command.includes('topsecret'));
  });

  it('honours the configured sudo user', () => {
    manager.setConfig({ default: { ...BASE_CONFIG, sudoUser: 'postgres' } });
    const command = manager.buildSudoCommand(manager.getConfig('default'), 'psql -c "select 1"');

    assert.match(command, /-u 'postgres'/);
  });

  it('feeds the password to the shell transport right after the command', () => {
    manager.setConfig({ default: { ...BASE_CONFIG, transportMode: 'shell' } });
    const script = manager.buildShellCommandScript(
      'abc',
      'whoami',
      undefined,
      manager.getConfig('default'),
      'topsecret',
    );
    const lines = script.split('\n');
    const commandIndex = lines.findIndex((line) => line.startsWith('sudo -S'));

    assert.ok(commandIndex > 0);
    assert.strictEqual(lines[commandIndex + 1], 'topsecret');
    assert.strictEqual(lines[commandIndex + 2], '__mcp_rc=$?');
  });

  it('redacts the password from output', () => {
    assert.strictEqual(redactSecret('a topsecret b', 'topsecret'), 'a *** b');
    assert.strictEqual(redactSecret('unchanged', undefined), 'unchanged');
  });
});
