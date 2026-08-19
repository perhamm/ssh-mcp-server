import { describe, it, beforeEach, after } from 'node:test';
import assert from 'node:assert';
import * as fs from 'fs';
import * as path from 'path';
import { SSHConnectionManager } from '../build/services/ssh-connection-manager.js';

const BASE_CONFIG = {
  name: 'default',
  host: '10.0.0.1',
  port: 22,
  username: 'ops',
  password: 'pwd',
  transportMode: 'exec',
};

describe('forbidden remote paths over SFTP', () => {
  let manager;

  beforeEach(() => {
    manager = SSHConnectionManager.getInstance();
    manager.setConfig({ default: { ...BASE_CONFIG, guardProfile: 'off' } });
  });

  it('refuses to write the paths of the forbidden core', () => {
    for (const remotePath of [
      '/etc/cron.d/backup',
      '/etc/sudoers.d/deploy',
      '/etc/systemd/system/job.service',
      '/etc/ssh/sshd_config',
      '/root/.ssh/authorized_keys',
      '/home/ops/.ssh/config',
      '/etc/passwd',
    ]) {
      assert.throws(
        () => manager.validateRemotePath(remotePath, 'default', 'write'),
        /forbidden core/,
        remotePath,
      );
    }
  });

  it('refuses to read secrets even when writes are what is blocked elsewhere', () => {
    assert.throws(
      () => manager.validateRemotePath('/etc/shadow', 'default', 'read'),
      /forbidden core/,
    );
    assert.throws(
      () => manager.validateRemotePath('/root/.ssh/id_rsa', 'default', 'read'),
      /forbidden core/,
    );
  });

  it('still allows reading a configuration file it only blocks writing', () => {
    assert.strictEqual(
      manager.validateRemotePath('/etc/ssh/sshd_config', 'default', 'read'),
      '/etc/ssh/sshd_config',
    );
  });

  it('leaves ordinary paths alone', () => {
    assert.strictEqual(
      manager.validateRemotePath('/var/log/syslog', 'default', 'write'),
      '/var/log/syslog',
    );
    assert.strictEqual(
      manager.validateRemotePath('/tmp/report.txt', 'default', 'write'),
      '/tmp/report.txt',
    );
  });

  it('refuses an upload before it opens a connection', async () => {
    const localPath = path.join(process.cwd(), `upload-fixture-${process.pid}.txt`);
    fs.writeFileSync(localPath, 'payload');

    try {
      await assert.rejects(
        () => manager.upload(localPath, '/etc/cron.d/backup', 'default'),
        /REMOTE_PATH_FORBIDDEN|forbidden core/,
      );
    } finally {
      fs.rmSync(localPath, { force: true });
    }
  });
});
