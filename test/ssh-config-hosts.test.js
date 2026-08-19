import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import {
  clearSshConfigCache,
  listSshConfigHosts,
  lookupSshConfig,
  resolveJumpChain,
} from '../build/utils/ssh-config-parser.js';

describe('SSH config hosts', () => {
  let fixturesDir;
  let configPath;

  before(() => {
    fixturesDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ssh-mcp-hosts-test-'));
    configPath = path.join(fixturesDir, 'config');

    fs.writeFileSync(configPath, [
      'Host bastion',
      '    HostName bastion.example.com',
      '    User jump',
      '    Port 2222',
      '',
      'Host r-ulybka-prod-master r-ulybka-prod-master-1',
      '    HostName 10.20.30.40',
      '    User ops',
      '    ProxyJump bastion',
      '    IdentityFile ~/.ssh/prod_key',
      '',
      'Host *.internal',
      '    User wildcard',
      '',
      'Host deep',
      '    HostName deep.example.com',
      '    ProxyJump r-ulybka-prod-master',
      '',
      'Host *',
      '    Port 22',
    ].join('\n'));
  });

  after(() => {
    fs.rmSync(fixturesDir, { recursive: true, force: true });
  });

  describe('listSshConfigHosts', () => {
    it('lists literal aliases only', () => {
      const aliases = listSshConfigHosts(configPath).map((host) => host.alias);

      assert.deepStrictEqual(aliases, [
        'bastion',
        'r-ulybka-prod-master',
        'r-ulybka-prod-master-1',
        'deep',
      ]);
    });

    it('resolves the effective values of an alias', () => {
      const hosts = listSshConfigHosts(configPath);
      const master = hosts.find((host) => host.alias === 'r-ulybka-prod-master');

      assert.strictEqual(master.hostName, '10.20.30.40');
      assert.strictEqual(master.user, 'ops');
      assert.strictEqual(master.port, 22);
      assert.strictEqual(master.proxyJump, 'bastion');
    });

    it('returns an empty list when the default config is missing', () => {
      const originalHome = process.env.HOME;
      const originalUserProfile = process.env.USERPROFILE;
      process.env.HOME = path.join(fixturesDir, 'empty-home');
      process.env.USERPROFILE = process.env.HOME;

      try {
        assert.deepStrictEqual(listSshConfigHosts(), []);
      } finally {
        process.env.HOME = originalHome;
        process.env.USERPROFILE = originalUserProfile;
      }
    });
  });

  describe('resolveJumpChain', () => {
    it('resolves an alias into a hop', () => {
      const hops = resolveJumpChain('bastion', configPath);

      assert.strictEqual(hops.length, 1);
      assert.deepStrictEqual(
        { host: hops[0].host, port: hops[0].port, username: hops[0].username },
        { host: 'bastion.example.com', port: 2222, username: 'jump' },
      );
    });

    it('parses user, host and port out of a hop spec', () => {
      const [hop] = resolveJumpChain('alice@10.0.0.1:2022', configPath);

      assert.strictEqual(hop.host, '10.0.0.1');
      assert.strictEqual(hop.port, 2022);
      assert.strictEqual(hop.username, 'alice');
    });

    it('keeps the order of a multi hop chain', () => {
      const hops = resolveJumpChain('bastion,10.0.0.9', configPath);

      assert.deepStrictEqual(hops.map((hop) => hop.host), [
        'bastion.example.com',
        '10.0.0.9',
      ]);
    });

    it('splices in the chain of a hop that jumps itself', () => {
      const hops = resolveJumpChain('r-ulybka-prod-master', configPath);

      assert.deepStrictEqual(hops.map((hop) => hop.host), [
        'bastion.example.com',
        '10.20.30.40',
      ]);
    });

    it('treats none as no jump', () => {
      assert.deepStrictEqual(resolveJumpChain('none', configPath), []);
      assert.deepStrictEqual(resolveJumpChain('', configPath), []);
    });
  });
});

describe('ProxyCommand', () => {
  let fixturesDir;
  let configPath;

  before(() => {
    fixturesDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ssh-mcp-proxycommand-test-'));
    configPath = path.join(fixturesDir, 'config');
    fs.writeFileSync(configPath, [
      'Host bastion',
      '    HostName bastion.example.com',
      '    User jump',
      '    Port 2222',
      '',
      'Host via-proxy-command',
      '    HostName 10.20.30.41',
      '    User ops',
      '    ProxyCommand ssh bastion -W %h:%p',
      '',
      'Host via-proxy-command-same-user',
      '    HostName 10.20.30.42',
      '    User ops',
      '    ProxyCommand ssh bastion -W %h:%p -l %r',
      '',
      'Host via-proxy-command-port',
      '    HostName 10.20.30.43',
      '    ProxyCommand ssh -q -l jump -p 2022 bastion.example.com -W %h:%p',
      '',
      'Host via-proxy-command-quoted',
      '    HostName 10.20.30.46',
      '    ProxyCommand "/usr/bin/ssh" bastion -W %h:%p',
      '',
      'Host via-unsupported-proxy-command',
      '    HostName 10.20.30.44',
      '    ProxyCommand ssh bastion nc %h %p',
      '',
      'Host via-netcat-proxy-command',
      '    HostName 10.20.30.47',
      '    ProxyCommand nc -X connect -x proxy:3128 %h %p',
      '',
      'Host proxy-jump-wins',
      '    HostName 10.20.30.45',
      '    ProxyJump bastion',
      '    ProxyCommand ssh other-hop -W %h:%p',
    ].join('\n'));
  });

  after(() => {
    clearSshConfigCache();
    fs.rmSync(fixturesDir, { recursive: true, force: true });
  });

  it('translates the netcat form into a jump hop', () => {
    assert.strictEqual(
      lookupSshConfig('via-proxy-command', configPath).proxyJump,
      'bastion',
    );
  });

  it('resolves the translated hop through the config of the hop itself', () => {
    assert.deepStrictEqual(
      resolveJumpChain(lookupSshConfig('via-proxy-command', configPath).proxyJump, configPath),
      [
        {
          alias: 'bastion',
          host: 'bastion.example.com',
          port: 2222,
          username: 'jump',
          identityFile: undefined,
        },
      ],
    );
  });

  it('substitutes %r with the user of the target', () => {
    assert.strictEqual(
      lookupSshConfig('via-proxy-command-same-user', configPath).proxyJump,
      'ops@bastion',
    );
  });

  it('carries the user and the port of the hop', () => {
    assert.strictEqual(
      lookupSshConfig('via-proxy-command-port', configPath).proxyJump,
      'jump@bastion.example.com:2022',
    );
  });

  it('accepts a quoted absolute path to ssh', () => {
    assert.strictEqual(
      lookupSshConfig('via-proxy-command-quoted', configPath).proxyJump,
      'bastion',
    );
  });

  it('ignores a ProxyCommand that runs something on the hop', () => {
    assert.strictEqual(
      lookupSshConfig('via-unsupported-proxy-command', configPath).proxyJump,
      undefined,
    );
  });

  it('ignores a ProxyCommand that is not ssh', () => {
    assert.strictEqual(
      lookupSshConfig('via-netcat-proxy-command', configPath).proxyJump,
      undefined,
    );
  });

  it('prefers an explicit ProxyJump over a ProxyCommand', () => {
    assert.strictEqual(
      lookupSshConfig('proxy-jump-wins', configPath).proxyJump,
      'bastion',
    );
  });
});

describe('SSH config caching', () => {
  let fixturesDir;
  let configPath;

  before(() => {
    fixturesDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ssh-mcp-cache-test-'));
    configPath = path.join(fixturesDir, 'config');
    fs.writeFileSync(configPath, 'Host one\n    HostName 10.0.0.1\n');
  });

  after(() => {
    fs.rmSync(fixturesDir, { recursive: true, force: true });
  });

  it('picks up an edited config', () => {
    assert.deepStrictEqual(
      listSshConfigHosts(configPath).map((host) => host.alias),
      ['one'],
    );

    fs.writeFileSync(configPath, 'Host one\n    HostName 10.0.0.1\n\nHost two\n    HostName 10.0.0.2\n');

    assert.deepStrictEqual(
      listSshConfigHosts(configPath).map((host) => host.alias),
      ['one', 'two'],
    );
  });

  it('serves repeated lookups from the cache', () => {
    clearSshConfigCache();

    const started = Date.now();
    for (let index = 0; index < 500; index++) {
      lookupSshConfig('one', configPath);
    }

    assert.ok(Date.now() - started < 1000, 'repeated lookups stay cheap');
    assert.strictEqual(lookupSshConfig('one', configPath).hostName, '10.0.0.1');
  });

  it('keeps first-match-wins with wildcard blocks', () => {
    const mixedPath = path.join(fixturesDir, 'config-mixed');
    fs.writeFileSync(mixedPath, [
      'Host prod-a',
      '    User own',
      '',
      'Host prod-*',
      '    User group',
      '    Port 2200',
      '',
      'Host *',
      '    Port 22',
      '    User fallback',
    ].join('\n'));

    const entry = lookupSshConfig('prod-a', mixedPath);

    assert.strictEqual(entry.user, 'own');
    assert.strictEqual(entry.port, 2200);
    assert.deepStrictEqual(
      listSshConfigHosts(mixedPath).map((host) => host.alias),
      ['prod-a'],
    );
  });
});
