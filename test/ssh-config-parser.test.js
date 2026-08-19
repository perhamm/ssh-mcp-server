import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import { lookupSshConfig } from '../build/utils/ssh-config-parser.js';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
let fixturesDir;

describe('SSH Config Parser', () => {
  let testConfigPath;
  let testConfigWithIncludePath;
  let includedConfigPath;
  let originalHome;

  before(() => {
    originalHome = process.env.HOME;
    fixturesDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ssh-mcp-config-test-'));

    testConfigPath = path.join(fixturesDir, 'ssh-config-basic');
    testConfigWithIncludePath = path.join(fixturesDir, 'ssh-config-include');
    includedConfigPath = path.join(fixturesDir, 'ssh-config-included');

    fs.writeFileSync(testConfigPath, [
      '# multiple aliases',
      'Host dev staging',
      '    HostName 192.168.1.100',
      '    Port 2222',
      '    User devuser',
      '    IdentityFile ~/.ssh/dev_key',
      '',
      '# single alias',
      'Host prod',
      '    HostName 10.0.0.50',
      '    User produser',
      '    IdentityFile ~/.ssh/prod_key',
      '',
      '# wildcard',
      'Host *.example.com',
      '    User wildcarduser',
      '    Port 2200',
      '',
      '# global defaults',
      'Host *',
      '    Port 22',
      '    User defaultuser',
    ].join('\n'));

    fs.writeFileSync(includedConfigPath, [
      'Host included-host',
      '    HostName 172.16.0.1',
      '    Port 3333',
      '    User includeduser',
    ].join('\n'));

    fs.writeFileSync(testConfigWithIncludePath, [
      `Include ${includedConfigPath}`,
      '',
      'Host main-host',
      '    HostName 192.168.1.1',
      '    User mainuser',
      '',
      'Host *',
      '    Port 22',
    ].join('\n'));
  });

  after(() => {
    process.env.HOME = originalHome;
    fs.rmSync(fixturesDir, { recursive: true, force: true });
  });

  describe('basics', () => {
    it('parses a single Host alias', () => {
      const config = lookupSshConfig('prod', testConfigPath);
      assert.ok(config, 'the config must not be null');
      assert.strictEqual(config.hostName, '10.0.0.50');
      assert.strictEqual(config.user, 'produser');
      assert.strictEqual(config.identityFile, path.join(os.homedir(), '.ssh', 'prod_key'));
      assert.strictEqual(config.port, 22); // from the Host * fallback
    });

    it('parses a multi alias Host line, dev', () => {
      const config = lookupSshConfig('dev', testConfigPath);
      assert.ok(config, 'the config must not be null');
      assert.strictEqual(config.hostName, '192.168.1.100');
      assert.strictEqual(config.port, 2222);
      assert.strictEqual(config.user, 'devuser');
    });

    it('parses a multi alias Host line, staging', () => {
      const config = lookupSshConfig('staging', testConfigPath);
      assert.ok(config, 'the config must not be null');
      assert.strictEqual(config.hostName, '192.168.1.100');
      assert.strictEqual(config.port, 2222);
      assert.strictEqual(config.user, 'devuser');
    });

    it('matches wildcards', () => {
      const config = lookupSshConfig('server.example.com', testConfigPath);
      assert.ok(config, 'the config must not be null');
      assert.strictEqual(config.user, 'wildcarduser');
      assert.strictEqual(config.port, 2200);
    });

    it('falls back to Host * for defaults', () => {
      const config = lookupSshConfig('unknown-host', testConfigPath);
      assert.ok(config, 'the config must not be null');
      assert.strictEqual(config.user, 'defaultuser');
      assert.strictEqual(config.port, 22);
      assert.strictEqual(config.hostName, undefined);
    });

    it('escapes regexp metacharacters when matching wildcards', () => {
      const tempConfig = path.join(fixturesDir, 'special-pattern-config');
      fs.writeFileSync(tempConfig, [
        'Host host[1]',
        '    User literaluser',
        '',
        'Host *',
        '    User defaultuser',
      ].join('\n'));

      const literalConfig = lookupSshConfig('host[1]', tempConfig);
      const regexLikeConfig = lookupSshConfig('host1', tempConfig);

      assert.ok(literalConfig);
      assert.strictEqual(literalConfig.user, 'literaluser');
      assert.ok(regexLikeConfig);
      assert.strictEqual(regexLikeConfig.user, 'defaultuser');

      fs.unlinkSync(tempConfig);
    });

    it('supports negated patterns in Host', () => {
      const tempConfig = path.join(fixturesDir, 'negated-pattern-config');
      fs.writeFileSync(tempConfig, [
        'Host *.example.com !blocked.example.com',
        '    User wildcarduser',
        '',
        'Host *',
        '    User defaultuser',
      ].join('\n'));

      const allowedConfig = lookupSshConfig('app.example.com', tempConfig);
      const blockedConfig = lookupSshConfig('blocked.example.com', tempConfig);

      assert.ok(allowedConfig);
      assert.strictEqual(allowedConfig.user, 'wildcarduser');
      assert.ok(blockedConfig);
      assert.strictEqual(blockedConfig.user, 'defaultuser');

      fs.unlinkSync(tempConfig);
    });
  });

  describe('the Include directive', () => {
    it('follows an Include directive', () => {
      const config = lookupSshConfig('included-host', testConfigWithIncludePath);
      assert.ok(config, 'the config must not be null');
      assert.strictEqual(config.hostName, '172.16.0.1');
      assert.strictEqual(config.port, 3333);
      assert.strictEqual(config.user, 'includeduser');
    });

    it('keeps parsing the main file after an Include', () => {
      const config = lookupSshConfig('main-host', testConfigWithIncludePath);
      assert.ok(config, 'the config must not be null');
      assert.strictEqual(config.hostName, '192.168.1.1');
      assert.strictEqual(config.user, 'mainuser');
      assert.strictEqual(config.port, 22);
    });

    it('skips an Include file that does not exist', () => {
      const tempConfig = path.join(fixturesDir, 'temp-include-config');
      fs.writeFileSync(tempConfig, [
        'Include /nonexistent/path/config',
        '',
        'Host test',
        '    HostName 1.2.3.4',
      ].join('\n'));

      const config = lookupSshConfig('test', tempConfig);
      assert.ok(config, 'the config must not be null');
      assert.strictEqual(config.hostName, '1.2.3.4');

      fs.unlinkSync(tempConfig);
    });
  });

  describe('edge cases', () => {
    it('returns null when the default config file is missing', () => {
      const fakeHome = fs.mkdtempSync(path.join(fixturesDir, 'fake-home-'));
      process.env.HOME = fakeHome;

      try {
        const config = lookupSshConfig('any-host');
        assert.strictEqual(config, null);
      } finally {
        process.env.HOME = originalHome;
        fs.rmSync(fakeHome, { recursive: true, force: true });
      }
    });

    it('throws when an explicitly given config file is missing', () => {
      assert.throws(() => {
        lookupSshConfig('any-host', '/nonexistent/config');
      }, /not found/);
    });

    it('returns null when no Host matches', () => {
      const tempConfig = path.join(fixturesDir, 'empty-config');
      fs.writeFileSync(tempConfig, '# Empty config\n');

      const config = lookupSshConfig('any-host', tempConfig);
      assert.strictEqual(config, null);

      fs.unlinkSync(tempConfig);
    });

    it('expands a ~ path', () => {
      const config = lookupSshConfig('dev', testConfigPath);
      assert.ok(config);
      assert.ok(config.identityFile.startsWith(os.homedir()));
      assert.ok(!config.identityFile.includes('~'));
    });

    it('handles comment lines', () => {
      const tempConfig = path.join(fixturesDir, 'comment-config');
      fs.writeFileSync(tempConfig, [
        '# a comment',
        'Host test',
        '    HostName 1.2.3.4 # a trailing comment',
        '    Port 2222',
      ].join('\n'));

      const config = lookupSshConfig('test', tempConfig);
      assert.ok(config);
      assert.strictEqual(config.hostName, '1.2.3.4');
      assert.strictEqual(config.port, 2222);

      fs.unlinkSync(tempConfig);
    });

    it('handles blank lines and indentation', () => {
      const tempConfig = path.join(fixturesDir, 'whitespace-config');
      fs.writeFileSync(tempConfig, [
        '',
        '  Host test  ',
        '    HostName   1.2.3.4  ',
        '',
        '    Port   2222  ',
        '',
      ].join('\n'));

      const config = lookupSshConfig('test', tempConfig);
      assert.ok(config);
      assert.strictEqual(config.hostName, '1.2.3.4');
      assert.strictEqual(config.port, 2222);

      fs.unlinkSync(tempConfig);
    });
  });

  describe('first-match-wins semantics', () => {
    it('takes the first matching value', () => {
      const tempConfig = path.join(fixturesDir, 'priority-config');
      fs.writeFileSync(tempConfig, [
        'Host test',
        '    Port 2222',
        '    User firstuser',
        '',
        'Host test',
        '    Port 3333',
        '    User seconduser',
        '',
        'Host *',
        '    Port 22',
      ].join('\n'));

      const config = lookupSshConfig('test', tempConfig);
      assert.ok(config);
      assert.strictEqual(config.port, 2222);
      assert.strictEqual(config.user, 'firstuser');

      fs.unlinkSync(tempConfig);
    });

    it('prefers a specific Host over Host *', () => {
      const tempConfig = path.join(fixturesDir, 'specific-priority-config');
      fs.writeFileSync(tempConfig, [
        'Host specific',
        '    Port 2222',
        '',
        'Host *',
        '    Port 22',
        '    User globaluser',
      ].join('\n'));

      const config = lookupSshConfig('specific', tempConfig);
      assert.ok(config);
      assert.strictEqual(config.port, 2222); // from Host specific
      assert.strictEqual(config.user, 'globaluser'); // from Host *

      fs.unlinkSync(tempConfig);
    });
  });
});
