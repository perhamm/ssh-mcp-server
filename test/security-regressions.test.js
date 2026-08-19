import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert';
import { SSHConnectionManager } from '../build/services/ssh-connection-manager.js';
import { compileGuard, describeGuard, loadGuardRuleset } from '../build/guards/guard-rules.js';
import * as os from 'os';
import * as path from 'path';

const BASE_CONFIG = {
  name: 'default',
  host: '10.0.0.1',
  port: 22,
  username: 'ops',
  password: 'pwd',
  transportMode: 'exec',
};

describe('security regressions', () => {
  let manager;

  beforeEach(() => {
    manager = SSHConnectionManager.getInstance();
  });

  it('keeps the command whitelist after a disconnect', () => {
    manager.setConfig({
      default: { ...BASE_CONFIG, commandWhitelist: ['^ls( .*)?$'] },
    });

    manager.disconnect();

    assert.strictEqual(manager.validateCommand('ls -la', 'default').isAllowed, true);
    assert.strictEqual(manager.validateCommand('rm -rf /tmp/x', 'default').isAllowed, false);
  });

  it('keeps the guard profile after a disconnect', () => {
    manager.setConfig({ default: { ...BASE_CONFIG, guardProfile: 'readonly' } });

    manager.disconnect();

    assert.strictEqual(manager.validateCommand('systemctl restart nginx', 'default').isAllowed, false);
  });

  it('refuses an upload under a read-only profile', async () => {
    manager.setConfig({ default: { ...BASE_CONFIG, guardProfile: 'readonly' } });

    await assert.rejects(
      () => manager.upload('/tmp/whatever', '/tmp/whatever', 'default'),
      /read-only and does not allow uploads/,
    );
  });

  it('allows uploads under the safe profile', () => {
    manager.setConfig({ default: { ...BASE_CONFIG, guardProfile: 'safe' } });

    assert.doesNotThrow(() => manager.assertFileWriteAllowed('default'));
  });

  it('refuses to download into a local path of the forbidden core', () => {
    manager.setConfig({
      default: {
        ...BASE_CONFIG,
        guardProfile: 'off',
        allowedLocalPaths: [os.homedir()],
      },
    });

    assert.throws(
      () =>
        manager.validateLocalPath(
          path.join(os.homedir(), '.ssh', 'authorized_keys'),
          'default',
          'write',
        ),
      /forbidden core/,
    );
  });

  it('still writes ordinary local paths', () => {
    manager.setConfig({
      default: { ...BASE_CONFIG, guardProfile: 'off', allowedLocalPaths: [os.tmpdir()] },
    });

    assert.doesNotThrow(() =>
      manager.validateLocalPath(path.join(os.tmpdir(), 'report.txt'), 'default', 'write'),
    );
  });

  it('reports the upload policy of a profile', () => {
    const ruleset = loadGuardRuleset();

    assert.match(describeGuard(compileGuard('readonly', ruleset)), /upload=blocked/);
    assert.match(describeGuard(compileGuard('safe', ruleset)), /upload=allowed/);
  });
});
