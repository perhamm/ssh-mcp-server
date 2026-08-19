import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

export interface SshConfigEntry {
  hostName?: string;
  user?: string;
  port?: number;
  identityFile?: string;
  proxyJump?: string;
  userKnownHostsFiles?: string[];
}

export interface SshConfigHost {
  alias: string;
  hostName?: string;
  user?: string;
  port?: number;
  proxyJump?: string;
}

export interface SshHopTarget {
  alias?: string;
  host: string;
  port: number;
  username?: string;
  identityFile?: string;
}

interface HostBlock {
  patterns: string[];
  config: Map<string, string>;
}

const MAX_JUMP_CHAIN_DEPTH = 5;
const CONFIG_CACHE_TTL_MS = 60000;

interface ConfigIndex {
  blocks: HostBlock[];
  // Blocks whose patterns are all literal, grouped by the alias they declare.
  literalBlocks: Map<string, number[]>;
  // Blocks with a wildcard or a negation have to be evaluated per alias.
  patternBlocks: number[];
}

interface CachedConfig {
  index: ConfigIndex;
  mtimeMs: number;
  loadedAt: number;
}

/**
 * Parsing is cached because every command resolves its connection through the
 * SSH config, and a real fleet config is thousands of Host blocks across a
 * chain of Include files: re-reading it per command costs seconds.
 *
 * The cache is dropped when the top level file changes, and expires anyway so
 * an edit inside an included file is picked up as well.
 */
const configCache = new Map<string, CachedConfig>();

export function clearSshConfigCache(): void {
  configCache.clear();
}

/**
 * 查找 SSH 配置文件中指定主机别名的配置
 * @param hostAlias 主机别名
 * @param configFilePath 配置文件路径，默认为 ~/.ssh/config
 * @returns 解析后的配置项，未找到返回 null
 */
export function lookupSshConfig(
  hostAlias: string,
  configFilePath?: string
): SshConfigEntry | null {
  const index = readConfigIndex(configFilePath);
  if (!index) {
    return null;
  }

  return matchHost(hostAlias, candidateBlocks(index, hostAlias));
}

/**
 * List the host aliases declared in the SSH config.
 *
 * Only literal aliases are returned: pattern blocks such as `Host *` carry
 * defaults rather than a connectable target, so they would show up as hosts
 * nobody can connect to.
 */
export function listSshConfigHosts(configFilePath?: string): SshConfigHost[] {
  const index = readConfigIndex(configFilePath);
  if (!index) {
    return [];
  }

  const aliases: string[] = [];
  const seen = new Set<string>();
  for (const block of index.blocks) {
    for (const pattern of block.patterns) {
      if (isLiteralAlias(pattern) && !seen.has(pattern)) {
        seen.add(pattern);
        aliases.push(pattern);
      }
    }
  }

  return aliases.map((alias) => {
    const entry = matchHost(alias, candidateBlocks(index, alias));
    return {
      alias,
      hostName: entry?.hostName,
      user: entry?.user,
      port: entry?.port,
      proxyJump: entry?.proxyJump,
    };
  });
}

/**
 * Expand a ProxyJump value into the ordered list of hops to connect through.
 *
 * A hop may itself be an alias with its own ProxyJump, so the chain of the hop
 * is spliced in before the hop, exactly the order OpenSSH connects in.
 */
export function resolveJumpChain(
  proxyJump: string,
  configFilePath?: string,
  depth: number = 0
): SshHopTarget[] {
  if (!proxyJump || proxyJump.trim().toLowerCase() === 'none') {
    return [];
  }

  if (depth >= MAX_JUMP_CHAIN_DEPTH) {
    throw new Error(
      `ProxyJump chain is deeper than ${MAX_JUMP_CHAIN_DEPTH} hops: ${proxyJump}`
    );
  }

  const hops: SshHopTarget[] = [];
  for (const hopSpec of proxyJump.split(',').map((hop) => hop.trim()).filter(Boolean)) {
    const parsed = parseHopSpec(hopSpec);
    const entry = lookupSshConfig(parsed.alias, configFilePath);

    if (entry?.proxyJump) {
      hops.push(...resolveJumpChain(entry.proxyJump, configFilePath, depth + 1));
    }

    hops.push({
      alias: parsed.alias,
      host: entry?.hostName || parsed.alias,
      port: parsed.port || entry?.port || 22,
      username: parsed.username || entry?.user,
      identityFile: entry?.identityFile,
    });
  }

  return hops;
}

function readConfigIndex(configFilePath?: string): ConfigIndex | null {
  const configPath = configFilePath || path.join(os.homedir(), '.ssh', 'config');

  // 默认路径不存在时静默返回 null
  if (!configFilePath && !fs.existsSync(configPath)) {
    return null;
  }

  // 显式指定路径不存在时抛错
  if (configFilePath && !fs.existsSync(configPath)) {
    throw new Error(`SSH config file not found: ${configPath}`);
  }

  const cached = configCache.get(configPath);
  let mtimeMs = 0;
  try {
    mtimeMs = fs.statSync(configPath).mtimeMs;
  } catch {
    // A file that cannot be stat'ed is parsed as before and simply not cached.
  }

  if (
    cached &&
    cached.mtimeMs === mtimeMs &&
    Date.now() - cached.loadedAt < CONFIG_CACHE_TTL_MS
  ) {
    return cached.index;
  }

  const index = buildConfigIndex(parseConfigFile(configPath, new Set()));
  configCache.set(configPath, { index, mtimeMs, loadedAt: Date.now() });
  return index;
}

/**
 * Group the blocks so an alias does not have to be tested against every block
 * of the file: a fleet config is thousands of blocks, and matching each alias
 * against all of them is quadratic.
 */
function buildConfigIndex(blocks: HostBlock[]): ConfigIndex {
  const literalBlocks = new Map<string, number[]>();
  const patternBlocks: number[] = [];

  blocks.forEach((block, blockIndex) => {
    if (block.patterns.every(isLiteralAlias)) {
      for (const pattern of block.patterns) {
        const existing = literalBlocks.get(pattern);
        if (existing) {
          existing.push(blockIndex);
        } else {
          literalBlocks.set(pattern, [blockIndex]);
        }
      }
      return;
    }

    patternBlocks.push(blockIndex);
  });

  return { blocks, literalBlocks, patternBlocks };
}

/**
 * The blocks that can apply to an alias, in file order, which is what
 * first-match-wins depends on.
 */
function candidateBlocks(index: ConfigIndex, hostAlias: string): HostBlock[] {
  const indexes = [
    ...(index.literalBlocks.get(hostAlias) || []),
    ...index.patternBlocks,
  ].sort((left, right) => left - right);

  return indexes.map((blockIndex) => index.blocks[blockIndex]);
}

function isLiteralAlias(pattern: string): boolean {
  return !/[*?!]/.test(pattern);
}

function parseHopSpec(hopSpec: string): {
  alias: string;
  username?: string;
  port?: number;
} {
  let rest = hopSpec;
  let username: string | undefined;

  const atIndex = rest.lastIndexOf('@');
  if (atIndex !== -1) {
    username = rest.slice(0, atIndex);
    rest = rest.slice(atIndex + 1);
  }

  let port: number | undefined;
  if (rest.startsWith('[')) {
    // [2001:db8::1]:2222
    const closingIndex = rest.indexOf(']');
    if (closingIndex !== -1) {
      const portPart = rest.slice(closingIndex + 1);
      rest = rest.slice(1, closingIndex);
      if (portPart.startsWith(':')) {
        port = parsePort(portPart.slice(1));
      }
    }
  } else {
    const colonIndex = rest.lastIndexOf(':');
    if (colonIndex !== -1 && rest.indexOf(':') === colonIndex) {
      port = parsePort(rest.slice(colonIndex + 1));
      rest = rest.slice(0, colonIndex);
    }
  }

  return { alias: rest, username, port };
}

function parsePort(value: string): number | undefined {
  const port = parseInt(value, 10);
  return Number.isInteger(port) && port > 0 && port <= 65535 ? port : undefined;
}

/**
 * 解析 SSH 配置文件
 */
function parseConfigFile(filePath: string, visited: Set<string>): HostBlock[] {
  // 防止循环引用
  const realPath = fs.realpathSync(filePath);
  if (visited.has(realPath)) {
    return [];
  }
  visited.add(realPath);

  const content = fs.readFileSync(filePath, 'utf-8');
  const lines = content.split('\n');
  const blocks: HostBlock[] = [];
  let currentBlock: HostBlock | null = null;

  for (let line of lines) {
    // 移除注释和前后空白
    const commentIndex = line.indexOf('#');
    if (commentIndex !== -1) {
      line = line.substring(0, commentIndex);
    }
    line = line.trim();

    if (!line) continue;

    // 解析 Include 指令
    if (line.toLowerCase().startsWith('include ')) {
      if (currentBlock) {
        blocks.push(currentBlock);
        currentBlock = null;
      }
      const pattern = line.substring(8).trim();
      const includePaths = expandIncludePath(pattern, path.dirname(filePath));
      for (const includePath of includePaths) {
        if (fs.existsSync(includePath)) {
          blocks.push(...parseConfigFile(includePath, visited));
        }
      }
      continue;
    }

    // 解析 Host 行
    if (line.toLowerCase().startsWith('host ')) {
      if (currentBlock) {
        blocks.push(currentBlock);
      }
      const hostPatterns = line.substring(5).trim().split(/\s+/);
      currentBlock = {
        patterns: hostPatterns,
        config: new Map()
      };
      continue;
    }

    // 解析配置项
    if (!currentBlock) {
      currentBlock = {
        patterns: ['*'],
        config: new Map()
      };
    }

    const spaceIndex = line.search(/\s/);
    if (spaceIndex !== -1) {
      const key = line.substring(0, spaceIndex).toLowerCase();
      const value = line.substring(spaceIndex + 1).trim();

      // 只保存第一次出现的值（SSH first-match-wins）
      if (!currentBlock.config.has(key)) {
        currentBlock.config.set(key, value);
      }
    }
  }

  if (currentBlock) {
    blocks.push(currentBlock);
  }

  return blocks;
}

/**
 * 展开 Include 路径（支持 ~ 和通配符）
 */
function expandIncludePath(pattern: string, baseDir: string): string[] {
  // 展开 ~
  if (pattern.startsWith('~/')) {
    pattern = path.join(os.homedir(), pattern.substring(2));
  } else if (pattern.startsWith('~')) {
    // ~user 形式不支持，直接返回空
    return [];
  } else if (!path.isAbsolute(pattern)) {
    // 相对路径相对于配置文件所在目录
    pattern = path.join(baseDir, pattern);
  }

  // 使用 glob 展开通配符
  try {
    // Node.js 22+ 支持 fs.globSync
    if (typeof fs.globSync === 'function') {
      return fs.globSync(pattern);
    }
  } catch (e) {
    // glob 失败时静默跳过
  }

  // 降级：无通配符时直接返回
  if (!pattern.includes('*') && !pattern.includes('?')) {
    return [pattern];
  }

  return [];
}

/**
 * 匹配主机别名
 */
function matchHost(hostAlias: string, blocks: HostBlock[]): SshConfigEntry | null {
  const result: SshConfigEntry = {};

  for (const block of blocks) {
    const matched = hostBlockMatches(hostAlias, block.patterns);

    if (!matched) continue;

    // first-match-wins：只取第一个匹配到的值
    if (!result.hostName && block.config.has('hostname')) {
      result.hostName = block.config.get('hostname');
    }
    if (!result.user && block.config.has('user')) {
      result.user = block.config.get('user');
    }
    if (!result.port && block.config.has('port')) {
      const portStr = block.config.get('port');
      const portNum = parseInt(portStr!, 10);
      if (!isNaN(portNum)) {
        result.port = portNum;
      }
    }
    if (!result.identityFile && block.config.has('identityfile')) {
      result.identityFile = expandTilde(block.config.get('identityfile')!);
    }
    if (!result.proxyJump && block.config.has('proxyjump')) {
      result.proxyJump = block.config.get('proxyjump');
    }
    if (!result.userKnownHostsFiles && block.config.has('userknownhostsfile')) {
      const files = block.config
        .get('userknownhostsfile')!
        .split(/\s+/)
        .filter(Boolean)
        .filter((file) => file !== 'none')
        .map(expandTilde);
      if (files.length > 0) {
        result.userKnownHostsFiles = files;
      }
    }
  }

  return Object.keys(result).length > 0 ? result : null;
}

function hostBlockMatches(hostAlias: string, patterns: string[]): boolean {
  let positiveMatch = false;

  for (const pattern of patterns) {
    const isNegated = pattern.startsWith('!');
    const patternBody = isNegated ? pattern.slice(1) : pattern;
    if (!patternBody) {
      continue;
    }

    if (hostPatternMatches(hostAlias, patternBody)) {
      if (isNegated) {
        return false;
      }
      positiveMatch = true;
    }
  }

  return positiveMatch;
}

const patternRegexCache = new Map<string, RegExp>();

function hostPatternMatches(hostAlias: string, pattern: string): boolean {
  if (pattern === '*') {
    return true;
  }

  if (!pattern.includes('*') && !pattern.includes('?')) {
    return pattern === hostAlias;
  }

  let regex = patternRegexCache.get(pattern);
  if (!regex) {
    const regexSource = pattern
      .replace(/[.+^${}()|[\]\\]/g, '\\$&')
      .replace(/\*/g, '.*')
      .replace(/\?/g, '.');
    regex = new RegExp(`^${regexSource}$`);
    patternRegexCache.set(pattern, regex);
  }

  return regex.test(hostAlias);
}

/**
 * 展开路径中的 ~
 */
function expandTilde(filePath: string): string {
  if (filePath.startsWith('~/')) {
    return path.join(os.homedir(), filePath.substring(2));
  }
  if (filePath === '~') {
    return os.homedir();
  }
  return filePath;
}
