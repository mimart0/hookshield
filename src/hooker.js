"use strict";

const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawn } = require("child_process");
const dns = require("dns").promises;

const DEFAULT_POLICY = `# HookShield policy
mode = "audit"

encrypt.prompts = true
encrypt.transcripts = true
encrypt.reasoning = true
encrypt.tool_calls = true

allow_git_diffs = true
allow_commit_ids = true
warn_on_unknown_hooks = true
deny_unencrypted_upload = true

blocked_domains = [
  "entire.io",
  "www.entire.io",
  "docs.entire.io"
]

allowed_domains = [
  "github.com"
]
`;

const SENSITIVE_PATTERNS = [
  "entire.io",
  "www.entire.io",
  "docs.entire.io",
  "entire cli hooks",
  "entire hooks",
  "entire search",
  "entire/checkpoints/v1",
  "entire/checkpoints",
  "checkpoint_create",
  "user-prompt-submit",
  "session-start",
  "session-end",
  "transcript",
  "prompt",
  "tool_calls"
];

const SCAN_TARGETS = [
  ".entire",
  ".entire/settings.json",
  ".claude/settings.json",
  ".claude/agents",
  ".cursor/hooks.json",
  ".git/entire-sessions",
  ".git/hooks"
];

const RISKY_FILE_PATTERNS = [
  { pattern: ".entire/", reason: "Entire checkpoint directory" },
  { pattern: ".entire", reason: "Entire checkpoint path" },
  { pattern: ".git/entire-sessions", reason: "Entire git session metadata" },
  { pattern: ".claude/settings.json", reason: "Claude hook settings" },
  { pattern: ".cursor/hooks.json", reason: "Cursor hook settings" },
  { pattern: ".git/hooks/", reason: "Git hook path" },
  { pattern: "checkpoint", reason: "checkpoint-like artifact" },
  { pattern: "transcript", reason: "transcript-like artifact" },
  { pattern: "prompt", reason: "prompt-like artifact" },
  { pattern: "tool_calls", reason: "tool-call artifact" },
  { pattern: "session", reason: "session-like artifact" }
];

function projectRoot() {
  return path.resolve(process.env.HOOKSHIELD_PROJECT || process.env.HOOKER_PROJECT || process.cwd());
}

function toolRoot() {
  return path.resolve(__dirname, "..");
}

function hookerHome() {
  return path.resolve(process.env.HOOKSHIELD_HOME || process.env.HOOKER_HOME || path.join(os.homedir(), ".hookshield"));
}

function hookShieldHome() {
  return hookerHome();
}

function ensureDir(dir) {
  fs.mkdirSync(dir, { recursive: true });
}

function readIfFile(filePath) {
  try {
    const stat = fs.statSync(filePath);
    if (!stat.isFile()) return null;
    return fs.readFileSync(filePath, "utf8");
  } catch (_) {
    return null;
  }
}

function walkFiles(root, limit = 250) {
  const out = [];
  const stack = [root];

  while (stack.length > 0 && out.length < limit) {
    const current = stack.pop();
    let entries;
    try {
      entries = fs.readdirSync(current, { withFileTypes: true });
    } catch (_) {
      continue;
    }

    for (const entry of entries) {
      if (out.length >= limit) break;
      const fullPath = path.join(current, entry.name);
      if (entry.isDirectory()) {
        stack.push(fullPath);
      } else if (entry.isFile()) {
        out.push(fullPath);
      }
    }
  }

  return out;
}

function findMatches(contents) {
  const lower = contents.toLowerCase();
  return SENSITIVE_PATTERNS.filter((pattern) => lower.includes(pattern.toLowerCase()));
}

function parseTomlLike(contents) {
  const policy = {
    mode: "audit",
    blocked_domains: ["entire.io", "www.entire.io", "docs.entire.io"],
    allowed_domains: ["github.com"],
    encrypt: {
      prompts: true,
      transcripts: true,
      reasoning: true,
      tool_calls: true
    },
    allow_git_diffs: true,
    allow_commit_ids: true,
    warn_on_unknown_hooks: true,
    deny_unencrypted_upload: true
  };

  let currentArray = null;
  for (const rawLine of contents.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;

    if (currentArray) {
      if (line.startsWith("]")) {
        currentArray = null;
        continue;
      }
      const value = line.replace(/,$/, "").trim().replace(/^"|"$/g, "");
      if (value) policy[currentArray].push(value);
      continue;
    }

    const arrayStart = line.match(/^([A-Za-z0-9_.-]+)\s*=\s*\[$/);
    if (arrayStart) {
      currentArray = arrayStart[1];
      policy[currentArray] = [];
      continue;
    }

    const scalar = line.match(/^([A-Za-z0-9_.-]+)\s*=\s*(.+)$/);
    if (!scalar) continue;

    const key = scalar[1];
    const rawValue = scalar[2].trim();
    const value = rawValue === "true" ? true : rawValue === "false" ? false : rawValue.replace(/^"|"$/g, "");

    if (key.startsWith("encrypt.")) {
      policy.encrypt[key.slice("encrypt.".length)] = value;
    } else {
      policy[key] = value;
    }
  }

  return policy;
}

function loadPolicy() {
  const root = projectRoot();
  const policyPath = path.join(root, "hookshield.toml");
  const legacyPolicyPath = path.join(root, "hooker.toml");
  const contents = readIfFile(policyPath) || readIfFile(legacyPolicyPath);
  return contents ? parseTomlLike(contents) : parseTomlLike(DEFAULT_POLICY);
}

function initProject() {
  const root = projectRoot();
  const localDir = path.join(root, ".hookshield");
  const sessionsDir = path.join(localDir, "sessions");
  const policyPath = path.join(root, "hookshield.toml");
  ensureDir(sessionsDir);

  let created = false;
  if (!fs.existsSync(policyPath)) {
    fs.writeFileSync(policyPath, DEFAULT_POLICY, "utf8");
    created = true;
  }

  const gitignorePath = path.join(root, ".gitignore");
  const gitignore = readIfFile(gitignorePath) || "";
  const gitignoreLines = gitignore.split(/\r?\n/);
  const missingIgnoreRules = [
    ".hookshield/sessions/",
    ".hookshield/quarantine/",
    ".hookshield/virtualized-hooks/",
    ".hooker/sessions/",
    ".hooker/quarantine/",
    ".hooker/virtualized-hooks/"
  ].filter((rule) => !gitignoreLines.includes(rule));
  if (missingIgnoreRules.length > 0) {
    const prefix = gitignore.endsWith("\n") || gitignore.length === 0 ? "" : "\n";
    fs.writeFileSync(gitignorePath, `${gitignore}${prefix}${missingIgnoreRules.join("\n")}\n`, "utf8");
  }

  return { created, projectRoot: root, policyPath };
}

function scanTarget(targetPath, type, findings) {
  let stat;
  try {
    stat = fs.statSync(targetPath);
  } catch (_) {
    return;
  }

  if (stat.isDirectory()) {
    const files = walkFiles(targetPath);
    if (files.length === 0) {
      findings.push({ type, path: targetPath, severity: "medium", matches: ["directory-present"] });
      return;
    }
    for (const file of files) {
      const contents = readIfFile(file);
      if (contents === null) continue;
      const matches = findMatches(contents);
      if (matches.length > 0) findings.push({ type, path: file, severity: "high", matches });
    }
    return;
  }

  if (stat.isFile()) {
    const contents = readIfFile(targetPath) || "";
    const matches = findMatches(contents);
    findings.push({ type, path: targetPath, severity: matches.length > 0 ? "high" : "medium", matches });
  }
}

function scan() {
  const root = projectRoot();
  const findings = [];

  for (const target of SCAN_TARGETS) {
    const type = target.includes("hooks") ? "hook" : target.includes("entire") ? "entire" : "config";
    scanTarget(path.join(root, target), type, findings);
  }

  for (const rc of [".zshrc", ".bashrc", ".bash_profile", ".profile"]) {
    const filePath = path.join(os.homedir(), rc);
    const contents = readIfFile(filePath);
    if (!contents) continue;
    const matches = findMatches(contents);
    if (matches.length > 0) findings.push({ type: "shell-config", path: filePath, severity: "medium", matches });
  }

  return { projectRoot: root, findings };
}

function keyPath() {
  return path.join(hookerHome(), "key.json");
}

function getOrCreateMasterKey() {
  ensureDir(hookerHome());
  const existing = readIfFile(keyPath());
  if (existing) {
    const parsed = JSON.parse(existing);
    if (!/^[0-9a-f]{64}$/i.test(parsed.key)) throw new Error(`Invalid master key at ${keyPath()}`);
    return Buffer.from(parsed.key, "hex");
  }

  const key = crypto.randomBytes(32);
  fs.writeFileSync(keyPath(), JSON.stringify({ version: 1, key: key.toString("hex"), created_at: new Date().toISOString() }, null, 2), { mode: 0o600 });
  return key;
}

function exportKey() {
  return getOrCreateMasterKey().toString("hex");
}

function importKey(keyHex) {
  if (!/^[0-9a-f]{64}$/i.test(keyHex)) throw new Error("Master key must be 64 hex characters.");
  ensureDir(hookerHome());
  fs.writeFileSync(keyPath(), JSON.stringify({ version: 1, key: keyHex.toLowerCase(), imported_at: new Date().toISOString() }, null, 2), { mode: 0o600 });
  return { keyPath: keyPath() };
}

function rotateKey() {
  ensureDir(hookerHome());
  const current = readIfFile(keyPath());
  const backupPath = path.join(hookerHome(), `key.${Date.now()}.bak.json`);
  if (current) fs.writeFileSync(backupPath, current, { mode: 0o600 });
  const key = crypto.randomBytes(32);
  fs.writeFileSync(keyPath(), JSON.stringify({ version: 1, key: key.toString("hex"), rotated_at: new Date().toISOString() }, null, 2), { mode: 0o600 });
  return { backupPath };
}

function encryptBuffer(buffer, aad) {
  const key = getOrCreateMasterKey();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  if (aad) cipher.setAAD(Buffer.from(aad));
  const ciphertext = Buffer.concat([cipher.update(buffer), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { alg: "AES-256-GCM", iv: iv.toString("hex"), tag: tag.toString("hex"), aad, ciphertext: ciphertext.toString("base64") };
}

function decryptEnvelope(envelope) {
  const key = getOrCreateMasterKey();
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, Buffer.from(envelope.iv, "hex"));
  if (envelope.aad) decipher.setAAD(Buffer.from(envelope.aad));
  decipher.setAuthTag(Buffer.from(envelope.tag, "hex"));
  return Buffer.concat([decipher.update(Buffer.from(envelope.ciphertext, "base64")), decipher.final()]);
}

function encryptFile(filePath) {
  const input = path.resolve(filePath);
  const data = fs.readFileSync(input);
  const envelope = encryptBuffer(data, path.basename(input));
  const output = `${input}.enc`;
  fs.writeFileSync(output, JSON.stringify(envelope, null, 2), "utf8");
  return { input, output };
}

function decryptFile(filePath) {
  const input = path.resolve(filePath);
  const envelope = JSON.parse(fs.readFileSync(input, "utf8"));
  const data = decryptEnvelope(envelope);
  const output = input.endsWith(".enc") ? input.slice(0, -4) : `${input}.dec`;
  fs.writeFileSync(output, data);
  return { input, output };
}

function sessionsDir() {
  return path.join(projectRoot(), ".hookshield", "sessions");
}

function sessionFile(sessionId) {
  ensureDir(sessionsDir());
  return path.join(sessionsDir(), `${sessionId}.json`);
}

function nativeResultFile(sessionId) {
  ensureDir(sessionsDir());
  return path.join(sessionsDir(), `${sessionId}.native-result.json`);
}

function quarantineDir(sessionId) {
  return path.join(projectRoot(), ".hookshield", "quarantine", sessionId);
}

function virtualizationDir(sessionId) {
  return path.join(projectRoot(), ".hookshield", "virtualized-hooks", sessionId);
}

function randomId() {
  return crypto.randomUUID ? crypto.randomUUID() : crypto.randomBytes(16).toString("hex");
}

function hasNativeBackend() {
  return fs.existsSync(path.join(toolRoot(), "cmd", "hookshield-pty", "main.go"));
}

function hostMatches(host, domains) {
  if (!host) return false;
  const normalizedHost = String(host).toLowerCase();
  return domains.some((domain) => {
    const normalizedDomain = String(domain).toLowerCase();
    return normalizedHost === normalizedDomain || normalizedHost.endsWith(`.${normalizedDomain}`);
  });
}

function findHostMatch(host, domains) {
  if (!host) return null;
  const normalizedHost = String(host).toLowerCase();
  for (const domain of domains) {
    const normalizedDomain = String(domain).toLowerCase();
    if (normalizedHost === normalizedDomain || normalizedHost.endsWith(`.${normalizedDomain}`)) {
      return domain;
    }
  }
  return null;
}

function findResolvedHostMatch(host, labels) {
  if (!host || !labels) return null;
  const normalizedHost = String(host).toLowerCase();
  return labels[normalizedHost] || null;
}

function annotateNetworkConnections(connections, policy, policyHosts = { blocked: {}, allowed: {} }) {
  if (!Array.isArray(connections)) return [];
  const blocked = Array.isArray(policy.blocked_domains) ? policy.blocked_domains : [];
  const allowed = Array.isArray(policy.allowed_domains) ? policy.allowed_domains : [];
  const mode = policy.mode || "audit";

  return connections.map((connection) => {
    const remoteHost = connection.remote_host || "";
    let policyAction = mode === "strict" ? "warn-unknown" : "observe";
    let policyReason = "no domain policy match";
    let policyMatchedDomain = null;

    const blockedDomain = findHostMatch(remoteHost, blocked) || findResolvedHostMatch(remoteHost, policyHosts.blocked.labels);
    const allowedDomain = findHostMatch(remoteHost, allowed) || findResolvedHostMatch(remoteHost, policyHosts.allowed.labels);

    if (blockedDomain) {
      policyAction = mode === "strict" ? "block" : "warn";
      policyReason = "matches blocked_domains";
      policyMatchedDomain = blockedDomain;
    } else if (allowedDomain) {
      policyAction = "allow";
      policyReason = "matches allowed_domains";
      policyMatchedDomain = allowedDomain;
    }

    return {
      ...connection,
      policy_action: policyAction,
      policy_reason: policyReason,
      policy_matched_domain: policyMatchedDomain
    };
  });
}

function annotateFileEvents(events) {
  if (!Array.isArray(events)) return [];
  return events.map((event) => {
    const normalizedPath = String(event.path || "").toLowerCase();
    const match = RISKY_FILE_PATTERNS.find((item) => normalizedPath.includes(item.pattern));
    return {
      ...event,
      risk_level: match ? "high" : "low",
      risk_reason: match ? match.reason : "ordinary project file"
    };
  });
}

function safeProjectPath(relativePath) {
  if (!relativePath || path.isAbsolute(relativePath)) return null;
  const root = projectRoot();
  const resolved = path.resolve(root, relativePath);
  if (resolved !== root && !resolved.startsWith(`${root}${path.sep}`)) return null;
  return resolved;
}

function quarantinePath(sessionId, relativePath) {
  const safeRelative = String(relativePath || "")
    .split(/[\\/]+/)
    .filter((part) => part && part !== "." && part !== "..")
    .join(path.sep);
  if (!safeRelative) return null;
  return path.join(quarantineDir(sessionId), safeRelative);
}

function relativeProjectPath(filePath) {
  return path.relative(projectRoot(), filePath).split(path.sep).join("/");
}

function moveFileWithFallback(source, destination) {
  ensureDir(path.dirname(destination));
  try {
    fs.renameSync(source, destination);
  } catch (error) {
    if (error.code !== "EXDEV") throw error;
    fs.copyFileSync(source, destination);
    fs.unlinkSync(source);
  }
}

function copyFileForReview(source, destination) {
  ensureDir(path.dirname(destination));
  fs.copyFileSync(source, destination);
}

function copyPathRecursive(source, destination) {
  ensureDir(path.dirname(destination));
  fs.cpSync(source, destination, { recursive: true, preserveTimestamps: true });
}

function removeEmptyProjectParents(startDir) {
  const root = projectRoot();
  let current = path.resolve(startDir);
  while (current !== root && current.startsWith(`${root}${path.sep}`)) {
    let entries = [];
    try {
      entries = fs.readdirSync(current);
    } catch (_) {
      return;
    }
    if (entries.length > 0) return;
    try {
      fs.rmdirSync(current);
    } catch (_) {
      return;
    }
    current = path.dirname(current);
  }
}

function enforceFilePolicy(fileEvents, policy, sessionId) {
  const events = [];
  if (!Array.isArray(fileEvents) || policy.mode !== "strict") {
    return { triggered: false, events };
  }

  for (const event of fileEvents.filter((item) => item.risk_level === "high")) {
    const source = safeProjectPath(event.path);
    const destination = quarantinePath(sessionId, event.path);
    const at = new Date().toISOString();
    const base = {
      at,
      path: event.path,
      reason: event.risk_reason || "high-risk file event"
    };

    if (!source || !destination) {
      events.push({ ...base, action: "failed", detail: "unsafe or absolute path refused" });
      continue;
    }

    if (!fs.existsSync(source)) {
      events.push({
        ...base,
        action: event.action === "deleted" ? "review" : "missing",
        detail: "file was not present after command completed"
      });
      continue;
    }

    try {
      if (event.action === "created") {
        moveFileWithFallback(source, destination);
        removeEmptyProjectParents(path.dirname(source));
        events.push({
          ...base,
          action: "quarantined",
          quarantine_path: relativeProjectPath(destination),
          detail: "created high-risk artifact moved out of the project path"
        });
      } else {
        copyFileForReview(source, destination);
        events.push({
          ...base,
          action: "copied-for-review",
          quarantine_path: relativeProjectPath(destination),
          detail: "existing high-risk file preserved in place and copied for review"
        });
      }
    } catch (error) {
      events.push({
        ...base,
        action: "failed",
        quarantine_path: relativeProjectPath(destination),
        detail: error.message
      });
    }
  }

  return { triggered: events.length > 0, events };
}

function safeVirtualizationPath(sessionId, relativePath) {
  const safeRelative = String(relativePath || "")
    .split(/[\\/]+/)
    .filter((part) => part && part !== "." && part !== "..")
    .join(path.sep);
  if (!safeRelative) return null;
  return path.join(virtualizationDir(sessionId), safeRelative);
}

function projectRelativeFromAbsolute(absolutePath) {
  const root = projectRoot();
  const resolved = path.resolve(absolutePath);
  if (resolved !== root && !resolved.startsWith(`${root}${path.sep}`)) return null;
  return relativeProjectPath(resolved);
}

function neutralizedPayload(relativePath, sessionId) {
  const normalized = relativePath.split(path.sep).join("/");
  if (normalized.endsWith(".json")) {
    return `${JSON.stringify({
      _hooker_virtualized: {
        session_id: sessionId,
        original_path: normalized,
        detail: "Original hook/config payload is temporarily isolated during this HookShield strict-mode run."
      },
      hooks: []
    }, null, 2)}\n`;
  }

  if (normalized.startsWith(".git/hooks/")) {
    return `#!/bin/sh\n# HookShield virtualized this hook for session ${sessionId}.\n# The original payload is preserved under .hookshield/virtualized-hooks/.\nexit 0\n`;
  }

  return `# HookShield virtualized this payload for session ${sessionId}.\n`;
}

function virtualizeHookPayloads(findings, policy, sessionId) {
  const events = [];
  if (policy.mode !== "strict") {
    return { triggered: false, events };
  }

  const seen = new Set();
  for (const finding of Array.isArray(findings) ? findings : []) {
    if (!["hook", "config", "entire"].includes(finding.type)) continue;
    const matches = Array.isArray(finding.matches) ? finding.matches : [];
    if (matches.length === 0 && policy.warn_on_unknown_hooks === false) continue;
    const relative = projectRelativeFromAbsolute(finding.path);
    const at = new Date().toISOString();
    const base = {
      at,
      path: relative || finding.path,
      type: finding.type,
      severity: finding.severity || "unknown",
      matches,
      reason: matches.length > 0 ? `matches: ${matches.join(", ")}` : "strict mode isolates unknown hook/config payloads"
    };

    if (!relative) {
      events.push({ ...base, action: "skipped", detail: "outside project root" });
      continue;
    }
    if (seen.has(relative)) continue;
    seen.add(relative);

    const source = safeProjectPath(relative);
    const destination = safeVirtualizationPath(sessionId, relative);
    if (!source || !destination) {
      events.push({ ...base, action: "failed", detail: "unsafe path refused" });
      continue;
    }

    let stat;
    try {
      stat = fs.statSync(source);
    } catch (error) {
      events.push({ ...base, action: "failed", detail: error.message });
      continue;
    }

    try {
      if (stat.isDirectory()) {
        copyPathRecursive(source, destination);
        fs.rmSync(source, { recursive: true, force: true });
        events.push({
          ...base,
          action: "virtualized-directory",
          virtualized_path: relativeProjectPath(destination),
          detail: "directory payload removed during strict-mode run and preserved for restore"
        });
      } else if (stat.isFile()) {
        copyPathRecursive(source, destination);
        fs.writeFileSync(source, neutralizedPayload(relative, sessionId), { mode: stat.mode & 0o777 });
        fs.chmodSync(source, stat.mode & 0o777);
        events.push({
          ...base,
          action: "virtualized-file",
          virtualized_path: relativeProjectPath(destination),
          mode: stat.mode & 0o777,
          detail: "file payload replaced with inert strict-mode stub"
        });
      }
    } catch (error) {
      events.push({
        ...base,
        action: "failed",
        virtualized_path: relativeProjectPath(destination),
        detail: error.message
      });
    }
  }

  return { triggered: events.some((event) => event.action.startsWith("virtualized-")), events };
}

function restoreHookPayloads(virtualization) {
  if (!virtualization || !Array.isArray(virtualization.events)) {
    return { triggered: false, events: [] };
  }

  const events = virtualization.events.map((event) => ({ ...event }));
  for (const event of events) {
    if (!event.action || !event.action.startsWith("virtualized-")) continue;
    const source = safeProjectPath(event.virtualized_path);
    const destination = safeProjectPath(event.path);
    const restoredAt = new Date().toISOString();
    if (!source || !destination) {
      event.restore_action = "failed";
      event.restored_at = restoredAt;
      event.restore_detail = "unsafe restore path refused";
      continue;
    }

    try {
      if (event.action === "virtualized-directory") {
        fs.rmSync(destination, { recursive: true, force: true });
        copyPathRecursive(source, destination);
      } else {
        ensureDir(path.dirname(destination));
        fs.copyFileSync(source, destination);
        if (typeof event.mode === "number") fs.chmodSync(destination, event.mode);
      }
      event.restore_action = "restored";
      event.restored_at = restoredAt;
    } catch (error) {
      event.restore_action = "failed";
      event.restored_at = restoredAt;
      event.restore_detail = error.message;
    }
  }

  return { ...virtualization, events };
}

function hookVirtualizationFailed(virtualization) {
  return Boolean(virtualization && Array.isArray(virtualization.events) && virtualization.events.some((event) => event.action === "failed"));
}

async function resolvePolicyHosts(policy) {
  async function resolveList(domains) {
    const values = new Set();
    const labels = {};
    for (const domain of Array.isArray(domains) ? domains : []) {
      const normalizedDomain = String(domain).toLowerCase();
      values.add(normalizedDomain);
      labels[normalizedDomain] = normalizedDomain;
      try {
        const records = await dns.lookup(domain, { all: true });
        for (const record of records) {
          const address = record.address.toLowerCase();
          values.add(address);
          labels[address] = normalizedDomain;
        }
      } catch (_) {
        // Domain may be offline or intentionally synthetic; keep the raw name.
      }
    }
    return { values: Array.from(values).sort(), labels };
  }

  return {
    blocked: await resolveList(policy.blocked_domains),
    allowed: await resolveList(policy.allowed_domains)
  };
}

async function runCommand(command) {
  const sessionId = randomId();
  const startedAt = new Date().toISOString();
  const policy = loadPolicy();
  const policyHosts = await resolvePolicyHosts(policy);
  const audit = scan();
  let hookVirtualization = virtualizeHookPayloads(audit.findings, policy, sessionId);
  const metadata = {
    session_id: sessionId,
    created_at: startedAt,
    tool_name: command[0],
    argv: command,
    policy_name: policy.mode,
    findings_at_start: audit.findings,
    hook_virtualization: hookVirtualization,
    encrypted_data_key: encryptBuffer(crypto.randomBytes(32), sessionId),
    note: "HookShield prefers the native Go PTY backend; set HOOKSHIELD_NATIVE=0 to force the Node stdio fallback."
  };
  fs.writeFileSync(sessionFile(sessionId), JSON.stringify(metadata, null, 2), "utf8");

  if (hookVirtualizationFailed(hookVirtualization)) {
    hookVirtualization = restoreHookPayloads(hookVirtualization);
    const finished = {
      ...metadata,
      hook_virtualization: hookVirtualization,
      backend: "hookshield-preflight",
      finished_at: new Date().toISOString(),
      exit_code: 156,
      signal: null,
      native_error: "strict hook payload virtualization failed"
    };
    fs.writeFileSync(sessionFile(sessionId), JSON.stringify(finished, null, 2), "utf8");
    return { sessionId, exitCode: 156, signal: null };
  }

  if (process.env.HOOKSHIELD_NATIVE !== "0" && process.env.HOOKER_NATIVE !== "0" && hasNativeBackend()) {
    return runNativeCommand(command, sessionId, metadata, policy, policyHosts);
  }

  return runNodeCommand(command, sessionId, metadata);
}

function runNativeCommand(command, sessionId, metadata, policy, policyHosts) {
  const resultPath = nativeResultFile(sessionId);
  const nativeArgs = ["run", "./cmd/hookshield-pty", "--result-file", resultPath, "--", ...command];

  return new Promise((resolve, reject) => {
    const child = spawn("go", nativeArgs, {
      stdio: "inherit",
      cwd: toolRoot(),
      env: {
        ...process.env,
        HOOKSHIELD_SESSION_ID: sessionId,
        HOOKSHIELD_POLICY_MODE: metadata.policy_name,
        HOOKSHIELD_STRICT_NETWORK: policy.mode === "strict" ? "1" : "0",
        HOOKSHIELD_DENY_UNKNOWN_NETWORK: policy.deny_unencrypted_upload ? "1" : "0",
        HOOKSHIELD_BLOCKED_HOSTS: JSON.stringify(policyHosts.blocked.values),
        HOOKSHIELD_ALLOWED_HOSTS: JSON.stringify(policyHosts.allowed.values),
        HOOKSHIELD_PROJECT_ROOT: projectRoot(),
        HOOKER_SESSION_ID: sessionId,
        HOOKER_POLICY_MODE: metadata.policy_name,
        HOOKER_STRICT_NETWORK: policy.mode === "strict" ? "1" : "0",
        HOOKER_DENY_UNKNOWN_NETWORK: policy.deny_unencrypted_upload ? "1" : "0",
        HOOKER_BLOCKED_HOSTS: JSON.stringify(policyHosts.blocked.values),
        HOOKER_ALLOWED_HOSTS: JSON.stringify(policyHosts.allowed.values),
        HOOKER_PROJECT_ROOT: projectRoot()
      }
    });

    child.on("error", (error) => {
      restoreHookPayloads(metadata.hook_virtualization);
      reject(error);
    });
    child.on("close", (code, signal) => {
      let native = null;
      try {
        native = JSON.parse(fs.readFileSync(resultPath, "utf8"));
      } catch (_) {
        native = {
          backend: "go-pty",
          exit_code: code ?? 1,
          signal,
          error: "native backend did not write a result file"
        };
      }

      const fileEvents = annotateFileEvents(native.file_events);
      const fileEnforcement = enforceFilePolicy(fileEvents, policy, sessionId);
      const hookVirtualization = restoreHookPayloads(metadata.hook_virtualization);
      const nativeExitCode = typeof native.exit_code === "number" ? native.exit_code : code ?? 1;
      const finalExitCode = fileEnforcement.triggered && nativeExitCode === 0 ? 155 : nativeExitCode;
      const finished = {
        ...metadata,
        hook_virtualization: hookVirtualization,
        backend: native.backend || "go-pty",
        runner_pid: native.runner_pid || null,
        child_pid: native.child_pid || null,
        observed_pids: Array.isArray(native.observed_pids) ? native.observed_pids : [],
        file_events: fileEvents,
        file_enforcement: fileEnforcement,
        network_policy_hosts: policyHosts,
        network_connections: annotateNetworkConnections(native.connections, policy, policyHosts),
        network_enforcement: {
          triggered: Boolean(native.enforcement_triggered),
          events: Array.isArray(native.enforcement_events) ? native.enforcement_events : []
        },
        native_started_at: native.started_at,
        finished_at: native.finished_at || new Date().toISOString(),
        exit_code: finalExitCode,
        signal: native.signal || signal || null,
        native_error: native.error || null
      };
      fs.writeFileSync(sessionFile(sessionId), JSON.stringify(finished, null, 2), "utf8");
      try {
        fs.unlinkSync(resultPath);
      } catch (_) {
        // Nothing to clean up.
      }
      resolve({ sessionId, exitCode: finished.exit_code, signal: finished.signal });
    });
  });
}

function runNodeCommand(command, sessionId, metadata) {
  return new Promise((resolve, reject) => {
    const child = spawn(command[0], command.slice(1), {
      stdio: "inherit",
      cwd: projectRoot(),
      env: {
        ...process.env,
        HOOKSHIELD_SESSION_ID: sessionId,
        HOOKSHIELD_POLICY_MODE: metadata.policy_name,
        HOOKER_SESSION_ID: sessionId,
        HOOKER_POLICY_MODE: metadata.policy_name
      }
    });

    child.on("error", (error) => {
      restoreHookPayloads(metadata.hook_virtualization);
      reject(error);
    });
    child.on("close", (code, signal) => {
      const hookVirtualization = restoreHookPayloads(metadata.hook_virtualization);
      const finished = {
        ...metadata,
        hook_virtualization: hookVirtualization,
        backend: "node-stdio",
        finished_at: new Date().toISOString(),
        exit_code: code,
        signal
      };
      fs.writeFileSync(sessionFile(sessionId), JSON.stringify(finished, null, 2), "utf8");
      resolve({ sessionId, exitCode: code ?? 1, signal });
    });
  });
}

function inspectSessions() {
  const dir = sessionsDir();
  let sessions = [];
  try {
    sessions = fs.readdirSync(dir)
      .filter((name) => name.endsWith(".json"))
      .map((name) => JSON.parse(fs.readFileSync(path.join(dir, name), "utf8")))
      .sort((a, b) => String(b.created_at).localeCompare(String(a.created_at)));
  } catch (_) {
    sessions = [];
  }
  return { projectRoot: projectRoot(), sessions };
}

function findSession(sessionId) {
  const sessions = inspectSessions().sessions;
  if (!sessionId) return sessions[0] || null;
  return sessions.find((session) => session.session_id === sessionId || session.session_id.startsWith(sessionId)) || null;
}

function reviewItems({ sessionId } = {}) {
  const session = findSession(sessionId);
  if (!session) return { projectRoot: projectRoot(), session: null, items: [] };
  const events = session.file_enforcement && Array.isArray(session.file_enforcement.events) ? session.file_enforcement.events : [];
  const items = events
    .filter((event) => event.quarantine_path)
    .map((event) => {
      const source = safeProjectPath(event.quarantine_path);
      let size = null;
      try {
        size = source ? fs.statSync(source).size : null;
      } catch (_) {
        size = null;
      }
      return {
        session_id: session.session_id,
        path: event.path,
        action: event.action,
        reason: event.reason,
        quarantine_path: event.quarantine_path,
        exists: Boolean(source && fs.existsSync(source)),
        size
      };
    });
  return { projectRoot: projectRoot(), session: { session_id: session.session_id, created_at: session.created_at, command: session.argv || [session.tool_name] }, items };
}

function sanitizedDraftPath(sessionId, requestedPath) {
  const safeRelative = String(requestedPath || "approved-context/session-summary.json")
    .split(/[\\/]+/)
    .filter((part) => part && part !== "." && part !== "..")
    .join(path.sep);
  if (!safeRelative) return null;
  return path.join(projectRoot(), safeRelative);
}

function redactReviewItem({ sessionId, quarantinePath: requestedQuarantinePath, outputPath }) {
  const review = reviewItems({ sessionId });
  if (!review.session) throw new Error(sessionId ? `No HookShield session matches ${sessionId}` : "No HookShield sessions recorded.");
  const item = requestedQuarantinePath
    ? review.items.find((entry) => entry.quarantine_path === requestedQuarantinePath || entry.path === requestedQuarantinePath)
    : review.items[0];
  if (!item) throw new Error("No quarantined review item matched.");
  const source = safeProjectPath(item.quarantine_path);
  if (!source || !fs.existsSync(source)) throw new Error(`Quarantined file is missing: ${item.quarantine_path}`);
  const destination = sanitizedDraftPath(review.session.session_id, outputPath);
  if (!destination) throw new Error("Unsafe output path.");
  ensureDir(path.dirname(destination));
  const draft = {
    hookshield_review: {
      session_id: review.session.session_id,
      source_path: item.path,
      quarantine_path: item.quarantine_path,
      reason: item.reason,
      created_at: new Date().toISOString(),
      instructions: "Edit approved_context before promoting. Do not paste private prompts, secrets, credentials, customer data, or raw tool output."
    },
    summary: "",
    approved_context: [],
    withheld: [
      "prompt",
      "tool_calls",
      "reasoning",
      "secrets",
      "credentials",
      "customer_data"
    ]
  };
  fs.writeFileSync(destination, `${JSON.stringify(draft, null, 2)}\n`, "utf8");
  return { session_id: review.session.session_id, source: item.quarantine_path, output: relativeProjectPath(destination) };
}

function revealReviewItem({ sessionId, quarantinePath: requestedQuarantinePath, confirm = false } = {}) {
  if (!confirm) {
    throw new Error("reveal prints raw quarantined prompt/session data. Re-run with --i-understand to confirm local viewing.");
  }
  const review = reviewItems({ sessionId });
  if (!review.session) throw new Error(sessionId ? `No HookShield session matches ${sessionId}` : "No HookShield sessions recorded.");
  const item = requestedQuarantinePath
    ? review.items.find((entry) => entry.quarantine_path === requestedQuarantinePath || entry.path === requestedQuarantinePath)
    : review.items[0];
  if (!item) throw new Error("No quarantined review item matched.");
  const source = safeProjectPath(item.quarantine_path);
  if (!source || !fs.existsSync(source)) throw new Error(`Quarantined file is missing: ${item.quarantine_path}`);
  return {
    session_id: review.session.session_id,
    source_path: item.path,
    quarantine_path: item.quarantine_path,
    content: fs.readFileSync(source, "utf8")
  };
}

function promoteReviewDraft({ draftPath, outputPath }) {
  const source = safeProjectPath(draftPath);
  const destination = safeProjectPath(outputPath);
  if (!source || !destination) throw new Error("promote requires safe project-relative --draft and --out paths.");
  if (!fs.existsSync(source)) throw new Error(`Draft file is missing: ${draftPath}`);
  ensureDir(path.dirname(destination));
  fs.copyFileSync(source, destination);
  return { draft: relativeProjectPath(source), output: relativeProjectPath(destination) };
}

function status() {
  const audit = scan();
  return {
    hookShieldHome: hookShieldHome(),
    hookerHome: hookShieldHome(),
    projectRoot: projectRoot(),
    policy: loadPolicy(),
    masterKeyPresent: fs.existsSync(keyPath()),
    nativeBackendPresent: hasNativeBackend(),
    findings: audit.findings,
    sessions: inspectSessions().sessions
  };
}

function trustReport() {
  const current = status();
  const connections = current.sessions.flatMap((session) => Array.isArray(session.network_connections) ? session.network_connections : []);
  const fileEvents = current.sessions.flatMap((session) => Array.isArray(session.file_events) ? session.file_events : []);
  const riskyFileEvents = fileEvents.filter((event) => event.risk_level === "high");
  const fileEnforcementEvents = current.sessions.flatMap((session) => session.file_enforcement && Array.isArray(session.file_enforcement.events) ? session.file_enforcement.events : []);
  const hookVirtualizationEvents = current.sessions.flatMap((session) => session.hook_virtualization && Array.isArray(session.hook_virtualization.events) ? session.hook_virtualization.events : []);
  const enforcementEvents = current.sessions.flatMap((session) => session.network_enforcement && Array.isArray(session.network_enforcement.events) ? session.network_enforcement.events : []);
  const warnedConnections = connections.filter((connection) => connection.policy_action === "warn" || connection.policy_action === "warn-unknown");
  const blockedConnections = connections.filter((connection) => connection.policy_action === "block");
  const items = [
    { label: "Master key", ok: current.masterKeyPresent, detail: current.masterKeyPresent ? "present" : "missing; generated on first encryption/run" },
    { label: "Policy", ok: Boolean(current.policy.mode), detail: current.policy.mode },
    { label: "Hook scan", ok: current.findings.length === 0, detail: `${current.findings.length} finding(s)` },
    { label: "Encryption defaults", ok: Boolean(current.policy.encrypt.prompts && current.policy.encrypt.transcripts), detail: "prompts/transcripts enabled" },
    { label: "PTY backend", ok: current.nativeBackendPresent, detail: current.nativeBackendPresent ? "native Go PTY runner present" : "native PTY runner missing" },
    { label: "File monitor", ok: true, detail: `${fileEvents.length} file event(s), ${riskyFileEvents.length} high-risk` },
    { label: "File enforcement", ok: true, detail: `${fileEnforcementEvents.length} strict file event(s) recorded` },
    { label: "Hook virtualization", ok: true, detail: `${hookVirtualizationEvents.length} hook/config event(s) recorded` },
    { label: "Network monitor", ok: true, detail: `${connections.length} observed connection(s), ${warnedConnections.length} warning(s), ${blockedConnections.length} strict block candidate(s)` },
    { label: "Network enforcement", ok: true, detail: `${enforcementEvents.length} strict termination event(s) recorded` }
  ];

  const score = Math.max(0, 100 - items.filter((item) => !item.ok).length * 15 - current.findings.length * 5);
  return { score, items, findings: current.findings, files: { observed: fileEvents.length, highRisk: riskyFileEvents.length, enforcementEvents: fileEnforcementEvents.length }, hooks: { virtualizationEvents: hookVirtualizationEvents.length }, network: { observed: connections.length, warnings: warnedConnections.length, blockCandidates: blockedConnections.length, enforcementEvents: enforcementEvents.length } };
}

module.exports = {
  DEFAULT_POLICY,
  decryptFile,
  encryptFile,
  exportKey,
  hookShieldHome,
  hookerHome,
  importKey,
  initProject,
  inspectSessions,
  loadPolicy,
  promoteReviewDraft,
  projectRoot,
  redactReviewItem,
  revealReviewItem,
  reviewItems,
  rotateKey,
  runCommand,
  scan,
  status,
  trustReport,
  _internals: {
    annotateNetworkConnections,
    annotateFileEvents,
    enforceFilePolicy,
    restoreHookPayloads,
    virtualizeHookPayloads,
    resolvePolicyHosts
  }
};
