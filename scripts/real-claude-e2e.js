"use strict";

const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const repoRoot = path.resolve(__dirname, "..");
const hookshieldCli = path.join(repoRoot, "bin", "hookshield.js");
const prompt = "Reply with exactly HOOKSHIELD_CLAUDE_REAL_TEST. Do not use tools.";
const expected = "HOOKSHIELD_CLAUDE_REAL_TEST";

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: options.cwd || repoRoot,
    env: options.env || process.env,
    encoding: "utf8",
    input: options.input,
    stdio: options.stdio || "pipe"
  });

  const expectedStatus = options.expectedStatus;
  if (expectedStatus !== undefined && result.status !== expectedStatus) {
    throw new Error([
      `${command} ${args.join(" ")} exited ${result.status}, expected ${expectedStatus}`,
      "stdout:",
      result.stdout,
      "stderr:",
      result.stderr
    ].join("\n"));
  }

  return result;
}

function findClaudeBinary() {
  if (process.env.CLAUDE_BIN) return process.env.CLAUDE_BIN;

  const fromPath = spawnSync("sh", ["-lc", "command -v claude"], { encoding: "utf8" });
  const candidate = fromPath.stdout.trim();
  if (candidate) return candidate;

  const localCandidate = path.join(os.homedir(), ".local", "bin", "claude");
  if (fs.existsSync(localCandidate)) return localCandidate;

  throw new Error("Claude Code binary not found. Set CLAUDE_BIN=/path/to/claude or add claude to PATH.");
}

function hookshield(projectRoot, hookshieldHome, args, options = {}) {
  return run(process.execPath, [hookshieldCli, ...args], {
    cwd: projectRoot,
    env: {
      ...process.env,
      HOOKSHIELD_PROJECT: projectRoot,
      HOOKSHIELD_HOME: hookshieldHome
    },
    expectedStatus: options.expectedStatus
  });
}

function rewritePolicy(projectRoot) {
  const policyPath = path.join(projectRoot, "hookshield.toml");
  let policy = fs.readFileSync(policyPath, "utf8");
  policy = policy.replace('mode = "audit"', 'mode = "strict"');
  // This real e2e verifies file quarantine. Let Claude reach its API so the
  // real transcript is created, then require HookShield review afterward.
  policy = policy.replace("deny_unencrypted_upload = true", "deny_unencrypted_upload = false");
  fs.writeFileSync(policyPath, policy, "utf8");
}

function resolveHomeArtifact(relativePath) {
  if (!relativePath.startsWith("~/.claude/")) {
    throw new Error(`Refusing to restore non-Claude home artifact: ${relativePath}`);
  }
  return path.join(os.homedir(), relativePath.slice(2));
}

function resolveProjectArtifact(projectRoot, relativePath) {
  const resolved = path.resolve(projectRoot, relativePath);
  if (resolved !== projectRoot && !resolved.startsWith(`${projectRoot}${path.sep}`)) {
    throw new Error(`Refusing unsafe project artifact path: ${relativePath}`);
  }
  return resolved;
}

function restoreClaudeTranscript(projectRoot, item) {
  const quarantinePath = resolveProjectArtifact(projectRoot, item.quarantine_path);
  const originalPath = resolveHomeArtifact(item.path);

  if (!fs.existsSync(quarantinePath)) {
    return { restored: false, reason: "quarantine-missing", original_path: originalPath };
  }
  if (fs.existsSync(originalPath)) {
    return { restored: false, reason: "original-exists", original_path: originalPath };
  }

  fs.mkdirSync(path.dirname(originalPath), { recursive: true });
  fs.copyFileSync(quarantinePath, originalPath);
  return { restored: true, reason: "copied-back", original_path: originalPath };
}

function main() {
  const claudeBin = findClaudeBinary();
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "hookshield-real-claude-"));
  const projectRoot = path.join(tempRoot, "proj");
  const hookshieldHome = path.join(tempRoot, "hookshield-home");
  fs.mkdirSync(projectRoot, { recursive: true });
  fs.mkdirSync(hookshieldHome, { recursive: true });

  let keepTemp = process.env.HOOKSHIELD_KEEP_TMP === "1";
  try {
    run("git", ["init", "-q"], { cwd: projectRoot, expectedStatus: 0 });
    hookshield(projectRoot, hookshieldHome, ["init"], { expectedStatus: 0 });
    rewritePolicy(projectRoot);

    const wrapped = hookshield(projectRoot, hookshieldHome, [
      "run",
      "--",
      claudeBin,
      "-p",
      prompt,
      "--output-format",
      "json",
      "--permission-mode",
      "default"
    ], { expectedStatus: 155 });

    assert.match(wrapped.stdout, new RegExp(expected));

    const review = hookshield(projectRoot, hookshieldHome, ["review", "--json"], { expectedStatus: 0 });
    const reviewJson = JSON.parse(review.stdout);
    const transcriptItem = reviewJson.items.find((item) => (
      /^~\/\.claude\/projects\/.+\.jsonl$/.test(item.path) &&
      item.action === "quarantined" &&
      item.reason === "Claude project transcript artifact"
    ));
    assert.ok(transcriptItem, `Expected a quarantined Claude project transcript item. Items: ${JSON.stringify(reviewJson.items, null, 2)}`);

    const sessionId = reviewJson.session.session_id;
    const reveal = hookshield(projectRoot, hookshieldHome, [
      "reveal",
      "--session",
      sessionId,
      "--item",
      transcriptItem.quarantine_path,
      "--i-understand"
    ], { expectedStatus: 0 });
    assert.match(reveal.stdout, new RegExp(expected));
    assert.match(reveal.stdout, /"type":"user"/);

    hookshield(projectRoot, hookshieldHome, [
      "redact",
      "--session",
      sessionId,
      "--item",
      transcriptItem.quarantine_path,
      "--out",
      "approved-context/real-claude-draft.json"
    ], { expectedStatus: 0 });
    const draftPath = path.join(projectRoot, "approved-context", "real-claude-draft.json");
    const draft = fs.readFileSync(draftPath, "utf8");
    assert.doesNotMatch(draft, new RegExp(expected));
    assert.doesNotMatch(draft, /Reply with exactly/);
    assert.doesNotMatch(draft, /claude-opus|claude-sonnet|total_cost_usd|AskUserQuestion/);

    const restore = restoreClaudeTranscript(projectRoot, transcriptItem);
    if (!restore.restored) {
      keepTemp = true;
    }

    console.log(JSON.stringify({
      ok: true,
      claude_bin: claudeBin,
      temp_root: tempRoot,
      temp_root_kept: keepTemp,
      session_id: sessionId,
      review_item_count: reviewJson.items.length,
      quarantined_path: transcriptItem.quarantine_path,
      restore,
      note: "Set HOOKSHIELD_KEEP_TMP=1 to keep temp files after a successful run. Claude's real transcript is copied back to ~/.claude after successful verification."
    }, null, 2));
  } catch (error) {
    keepTemp = true;
    console.error(error.stack || error.message);
    console.error(`Preserved temp root for debugging: ${tempRoot}`);
    process.exitCode = 1;
  } finally {
    if (!keepTemp) {
      fs.rmSync(tempRoot, { recursive: true, force: true });
    }
  }
}

main();
