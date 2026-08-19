import fs from "node:fs";

export type GuardProfileName = "off" | "safe" | "readonly";

export interface GuardRule {
  id: string;
  pattern: string;
  reason?: string;
  scope?: "segment" | "command";
}

export interface GuardProfile {
  description?: string;
  extends?: string;
  allowSudo?: boolean;
  allowFileWrite?: boolean;
  maxCommandLength?: number;
  allow?: GuardRule[];
  deny?: GuardRule[];
}

export interface ForbiddenRules {
  description?: string;
  rules?: GuardRule[];
  remoteWritePaths?: string[];
  remoteReadPaths?: string[];
}

export interface GuardRuleset {
  version: string;
  updatedAt?: string;
  source?: string;
  forbidden?: ForbiddenRules;
  profiles: Record<string, GuardProfile>;
}

interface CompiledRule {
  id: string;
  regex: RegExp;
  reason?: string;
}

export interface CompiledGuard {
  profile: GuardProfileName;
  version: string;
  description?: string;
  allowSudo: boolean;
  allowFileWrite: boolean;
  maxCommandLength: number;
  allow: CompiledRule[];
  deny: CompiledRule[];
  commandDeny: CompiledRule[];
  forbidden: CompiledRule[];
  commandForbidden: CompiledRule[];
  forbiddenRemoteWritePaths: string[];
  forbiddenRemoteReadPaths: string[];
}

export interface GuardVerdict {
  allowed: boolean;
  reason?: string;
}

const BUNDLED_RULESET_URL = new URL(
  "../../guards/default-guards.json",
  import.meta.url,
);

const MAX_PROFILE_EXTENDS_DEPTH = 5;
const DEFAULT_MAX_COMMAND_LENGTH = 5000;

// su, doas and pkexec elevate exactly like sudo does, so a profile that blocks
// privilege escalation has to name all of them.
const PRIVILEGE_ESCALATION_PATTERN = /^(sudo|su|doas|pkexec)(\s|$)/i;

// `bash -c "rm -rf /"` is one segment whose first word is an interpreter, so
// the rules have to be matched against the script it carries.
const SHELL_WRAPPER_PATTERN = /^(?:[a-z]*sh)\s+(?:-[a-z]+\s+)*-c\s+(.+)$/i;
const MAX_UNWRAP_DEPTH = 3;

let bundledRuleset: GuardRuleset | undefined;

export function loadBundledRuleset(): GuardRuleset {
  if (!bundledRuleset) {
    let content: string;
    try {
      content = fs.readFileSync(BUNDLED_RULESET_URL, "utf8");
    } catch (error) {
      throw new Error(
        `Cannot read the bundled guard ruleset at ${BUNDLED_RULESET_URL.pathname}: ${
          (error as Error).message
        }. The package is incomplete; reinstall it.`,
      );
    }
    bundledRuleset = parseRuleset(content, BUNDLED_RULESET_URL.pathname);
  }
  return bundledRuleset;
}

/**
 * Load the guard ruleset, optionally overlaying a locally maintained file.
 *
 * The overlay is how a fleet keeps its guards current without rebuilding the
 * server: point `--guards-file` at a file that is refreshed from upstream, and
 * its rules are added to the bundled ones on the next start.
 */
export function loadGuardRuleset(customPath?: string): GuardRuleset {
  const bundled = loadBundledRuleset();
  if (!customPath) {
    return bundled;
  }

  if (!fs.existsSync(customPath)) {
    throw new Error(`Guards file not found: ${customPath}`);
  }

  const custom = parseRuleset(fs.readFileSync(customPath, "utf8"), customPath);
  return mergeRulesets(bundled, custom);
}

export function parseRuleset(content: string, sourcePath: string): GuardRuleset {
  let parsed: unknown;
  try {
    parsed = JSON.parse(content);
  } catch (error) {
    throw new Error(
      `Invalid JSON in guards file ${sourcePath}: ${(error as Error).message}`,
    );
  }

  const ruleset = parsed as GuardRuleset;
  if (!ruleset || typeof ruleset !== "object") {
    throw new Error(`Guards file ${sourcePath} must contain a JSON object`);
  }
  if (typeof ruleset.version !== "string" || !ruleset.version) {
    throw new Error(`Guards file ${sourcePath} must include a string version`);
  }
  if (!ruleset.profiles || typeof ruleset.profiles !== "object") {
    throw new Error(`Guards file ${sourcePath} must include a profiles object`);
  }

  for (const rule of ruleset.forbidden?.rules || []) {
    if (!rule.id || typeof rule.pattern !== "string") {
      throw new Error(
        `Forbidden rule in ${sourcePath} must include id and pattern`,
      );
    }
    try {
      new RegExp(rule.pattern, "i");
    } catch (error) {
      throw new Error(
        `Invalid forbidden pattern '${rule.id}' in ${sourcePath}: ${
          (error as Error).message
        }`,
      );
    }
  }

  for (const [profileName, profile] of Object.entries(ruleset.profiles)) {
    for (const kind of ["allow", "deny"] as const) {
      for (const rule of profile[kind] || []) {
        if (!rule.id || typeof rule.pattern !== "string") {
          throw new Error(
            `Rule in profile '${profileName}' of ${sourcePath} must include id and pattern`,
          );
        }
        try {
          new RegExp(rule.pattern, "i");
        } catch (error) {
          throw new Error(
            `Invalid ${kind} pattern '${rule.id}' in profile '${profileName}' of ${sourcePath}: ${
              (error as Error).message
            }`,
          );
        }
      }
    }
  }

  return ruleset;
}

function mergeRulesets(base: GuardRuleset, custom: GuardRuleset): GuardRuleset {
  const profiles: Record<string, GuardProfile> = { ...base.profiles };

  for (const [name, customProfile] of Object.entries(custom.profiles)) {
    const baseProfile = profiles[name];
    profiles[name] = baseProfile
      ? {
          ...baseProfile,
          ...customProfile,
          allow: [...(baseProfile.allow || []), ...(customProfile.allow || [])],
          deny: [...(baseProfile.deny || []), ...(customProfile.deny || [])],
        }
      : customProfile;
  }

  return {
    version: `${base.version}+${custom.version}`,
    updatedAt: custom.updatedAt || base.updatedAt,
    source: custom.source || base.source,
    // Concatenated on purpose: a local ruleset extends the forbidden core, it
    // never shrinks it.
    forbidden: {
      description: base.forbidden?.description,
      rules: [
        ...(base.forbidden?.rules || []),
        ...(custom.forbidden?.rules || []),
      ],
      remoteWritePaths: [
        ...(base.forbidden?.remoteWritePaths || []),
        ...(custom.forbidden?.remoteWritePaths || []),
      ],
      remoteReadPaths: [
        ...(base.forbidden?.remoteReadPaths || []),
        ...(custom.forbidden?.remoteReadPaths || []),
      ],
    },
    profiles,
  };
}

/**
 * Compile a profile together with the forbidden core.
 *
 * The core is compiled for every profile, `off` included: those rules exist
 * because the operation must not happen from this server at all, so a profile
 * switch or a sudo flag is not supposed to be a way around them.
 */
export function compileGuard(
  profileName: GuardProfileName,
  ruleset: GuardRuleset,
): CompiledGuard {
  const forbidden = ruleset.forbidden || {};
  const resolved: GuardProfile =
    profileName === "off" ? {} : resolveProfile(profileName, ruleset, 0);

  return {
    profile: profileName,
    version: ruleset.version,
    description: resolved.description,
    allowSudo: resolved.allowSudo !== false,
    allowFileWrite: resolved.allowFileWrite !== false,
    maxCommandLength: resolved.maxCommandLength || DEFAULT_MAX_COMMAND_LENGTH,
    allow: compileRules(resolved.allow, "segment"),
    deny: compileRules(resolved.deny, "segment"),
    commandDeny: compileRules(resolved.deny, "command"),
    forbidden: compileRules(forbidden.rules, "segment"),
    commandForbidden: compileRules(forbidden.rules, "command"),
    forbiddenRemoteWritePaths: forbidden.remoteWritePaths || [],
    forbiddenRemoteReadPaths: forbidden.remoteReadPaths || [],
  };
}

function resolveProfile(
  profileName: string,
  ruleset: GuardRuleset,
  depth: number,
): GuardProfile {
  const profile = ruleset.profiles[profileName];
  if (!profile) {
    throw new Error(
      `Unknown guard profile '${profileName}'. Available: ${Object.keys(
        ruleset.profiles,
      ).join(", ")}`,
    );
  }

  if (!profile.extends) {
    return profile;
  }

  if (depth >= MAX_PROFILE_EXTENDS_DEPTH) {
    throw new Error(`Guard profile '${profileName}' has a circular extends chain`);
  }

  const parent = resolveProfile(profile.extends, ruleset, depth + 1);
  return {
    ...profile,
    allow: [...(parent.allow || []), ...(profile.allow || [])],
    deny: [...(parent.deny || []), ...(profile.deny || [])],
  };
}

function compileRules(
  rules: GuardRule[] | undefined,
  scope: "segment" | "command",
): CompiledRule[] {
  return (rules || [])
    .filter((rule) => (rule.scope || "segment") === scope)
    .map((rule) => ({
      id: rule.id,
      regex: new RegExp(rule.pattern, "i"),
      reason: rule.reason,
    }));
}

/**
 * Split a command line into the parts that are executed on their own.
 *
 * A single regex over the whole command is trivial to slip past: `ls; rm -rf /`
 * matches an `^ls` allow rule and still deletes the disk. Every pipe, list
 * separator and command substitution therefore becomes its own segment, and
 * each segment is checked separately.
 */
export function splitCommandSegments(command: string): string[] {
  const segments: string[] = [];
  let current = "";
  let quote: '"' | "'" | undefined;
  let substitutionDepth = 0;

  const pushSegment = () => {
    const trimmed = current.trim();
    if (trimmed) {
      segments.push(trimmed);
    }
    current = "";
  };

  for (let index = 0; index < command.length; index++) {
    const char = command[index];

    if (quote) {
      if (char === "\\" && quote === '"') {
        current += char + (command[index + 1] || "");
        index++;
        continue;
      }
      if (char === quote) {
        quote = undefined;
      }
      current += char;
      continue;
    }

    if (char === "'" || char === '"') {
      quote = char;
      current += char;
      continue;
    }

    if (char === "\\") {
      current += char + (command[index + 1] || "");
      index++;
      continue;
    }

    if (char === "$" && command[index + 1] === "(") {
      pushSegment();
      substitutionDepth++;
      index++;
      continue;
    }

    if (char === ")" && substitutionDepth > 0) {
      pushSegment();
      substitutionDepth--;
      continue;
    }

    if (char === "`") {
      pushSegment();
      continue;
    }

    if (char === ";" || char === "\n" || char === "|" || char === "&") {
      pushSegment();
      if (
        (char === "|" && command[index + 1] === "|") ||
        (char === "&" && command[index + 1] === "&")
      ) {
        index++;
      }
      continue;
    }

    current += char;
  }

  pushSegment();
  return segments;
}

export function evaluateGuard(
  guard: CompiledGuard,
  command: string,
): GuardVerdict {
  return evaluateCommand(guard, command, 0);
}

function evaluateCommand(
  guard: CompiledGuard,
  command: string,
  depth: number,
): GuardVerdict {
  if (command.length > guard.maxCommandLength) {
    return {
      allowed: false,
      reason: `Guard profile '${guard.profile}' (ruleset ${guard.version}) allows at most ${guard.maxCommandLength} characters per command, got ${command.length}. Split the work into separate calls or put it in a script.`,
    };
  }

  for (const rule of guard.commandForbidden) {
    if (rule.regex.test(command)) {
      return { allowed: false, reason: formatForbidden(guard, rule) };
    }
  }

  for (const rule of guard.commandDeny) {
    if (rule.regex.test(command)) {
      return { allowed: false, reason: formatDenial(guard, rule) };
    }
  }

  for (const segment of splitCommandSegments(command)) {
    if (!guard.allowSudo && PRIVILEGE_ESCALATION_PATTERN.test(segment.trim())) {
      return {
        allowed: false,
        reason: `Guard profile '${guard.profile}' (ruleset ${guard.version}) does not allow privilege escalation. Blocked part: ${segment.trim()}`,
      };
    }

    const normalized = stripLeadingModifiers(segment);
    if (!normalized) {
      continue;
    }

    const wrappedScript =
      depth < MAX_UNWRAP_DEPTH ? unwrapShellCommand(normalized) : undefined;
    if (wrappedScript) {
      const verdict = evaluateCommand(guard, wrappedScript, depth + 1);
      if (!verdict.allowed) {
        return verdict;
      }
      continue;
    }

    for (const rule of guard.forbidden) {
      if (rule.regex.test(normalized)) {
        return {
          allowed: false,
          reason: `${formatForbidden(guard, rule)} Blocked part: ${normalized}`,
        };
      }
    }

    for (const rule of guard.deny) {
      if (rule.regex.test(normalized)) {
        return {
          allowed: false,
          reason: `${formatDenial(guard, rule)} Blocked part: ${normalized}`,
        };
      }
    }

    if (guard.allow.length > 0) {
      const matchesAllow = guard.allow.some((rule) => rule.regex.test(normalized));
      if (!matchesAllow) {
        return {
          allowed: false,
          reason: `Guard profile '${guard.profile}' (ruleset ${guard.version}) allows read-only commands only. Blocked part: ${normalized}`,
        };
      }
    }
  }

  return { allowed: true };
}

function unwrapShellCommand(segment: string): string | undefined {
  const match = SHELL_WRAPPER_PATTERN.exec(segment);
  if (!match) {
    return undefined;
  }

  const script = match[1].trim();
  const quote = script[0];
  if ((quote === "'" || quote === '"') && script.endsWith(quote)) {
    return script.slice(1, -1);
  }

  return script;
}

/**
 * Environment assignments, `sudo` and wrappers such as `timeout 5` prefix the
 * command that actually runs, so the rules have to be matched against what
 * follows them rather than against the wrapper.
 */
function stripLeadingModifiers(segment: string): string {
  let rest = segment.trim();
  let changed = true;

  while (changed) {
    changed = false;

    const assignmentMatch = /^[A-Za-z_][A-Za-z0-9_]*=(\S*)\s+/.exec(rest);
    if (assignmentMatch) {
      rest = rest.slice(assignmentMatch[0].length);
      changed = true;
      continue;
    }

    const wrapperMatch =
      /^(sudo|su|doas|pkexec|env|nohup|nice|ionice|stdbuf|time|timeout|command|builtin|exec)\s+(-\S+\s+|\d+\s+)*/.exec(
        rest,
      );
    if (wrapperMatch && wrapperMatch[0].trim() !== rest) {
      rest = rest.slice(wrapperMatch[0].length);
      changed = true;
    }
  }

  return rest.trim();
}

export function formatDenial(guard: CompiledGuard, rule: CompiledRule): string {
  return `Blocked by guard profile '${guard.profile}' (ruleset ${guard.version}), rule '${rule.id}': ${
    rule.reason || "command is not permitted"
  }.`;
}

export function formatForbidden(
  guard: CompiledGuard,
  rule: CompiledRule,
): string {
  return `Blocked by the forbidden core (ruleset ${guard.version}), rule '${rule.id}': ${
    rule.reason || "operation is never permitted"
  }. No guard profile and no sudo lifts this rule.`;
}

/**
 * Match a remote path against a forbidden path pattern.
 *
 * `*` covers one path segment, a leading `**` covers any prefix, and a match
 * on a directory covers everything under it.
 */
export function matchesForbiddenPath(
  remotePath: string,
  pattern: string,
): boolean {
  const escaped = pattern
    .replace(/[.+^${}()|[\]\\]/g, "\\$&")
    .replace(/\*\*/g, "\u0000")
    .replace(/\*/g, "[^/]*")
    .replace(/\u0000/g, ".*");

  return new RegExp(`^${escaped}(/.*)?$`).test(remotePath);
}

export function findForbiddenPath(
  remotePath: string,
  patterns: string[],
): string | undefined {
  return patterns.find((pattern) => matchesForbiddenPath(remotePath, pattern));
}

export function describeGuard(guard: CompiledGuard | undefined): string {
  if (!guard) {
    return "guards=off";
  }

  return `guards=${guard.profile} ruleset=${guard.version} allow=${guard.allow.length} deny=${
    guard.deny.length + guard.commandDeny.length
  } forbidden=${
    guard.forbidden.length + guard.commandForbidden.length
  } sudo=${guard.allowSudo ? "allowed" : "blocked"} upload=${
    guard.allowFileWrite ? "allowed" : "blocked"
  }`;
}
