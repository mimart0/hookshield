"use strict";

const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const repoRoot = path.resolve(__dirname, "..");
const hookshieldCli = path.join(repoRoot, "bin", "hookshield.js");
const claudeCallTimeoutMs = Number(process.env.HOOKSHIELD_CLAUDE_CALL_TIMEOUT_MS || 60000);
const claudeModel = process.env.CLAUDE_MODEL || "claude-3-5-haiku-latest";
const approvedPromptNumbers = new Set([2, 4]);
const promptNumbers = [1, 2, 3, 4, 5];
const commandTimeoutMs = Number(process.env.HOOKSHIELD_REAL_TEST_TIMEOUT_MS || (promptNumbers.length * claudeCallTimeoutMs + 30000));
const prompts = promptNumbers.map((number) => ({
  number,
  marker: `HOOKSHIELD_CLAUDE_BATCH_REAL_${number}`,
  text: `Reply with exactly HOOKSHIELD_CLAUDE_BATCH_REAL_${number}. Do not use tools.`
}));

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: options.cwd || repoRoot,
    env: options.env || process.env,
    encoding: "utf8",
    input: options.input,
    stdio: options.stdio || "pipe",
    timeout: options.timeoutMs || commandTimeoutMs
  });

  if (result.error?.code === "ETIMEDOUT") {
    throw new Error(`${command} ${args.join(" ")} timed out after ${options.timeoutMs || commandTimeoutMs}ms`);
  }

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

function hookshield(projectRoot, hookshieldHome, args, options = {}) {
  return run(process.execPath, [hookshieldCli, ...args], {
    cwd: projectRoot,
    env: {
      ...process.env,
      HOME: hookshieldHome,
      HOOKSHIELD_NATIVE: "0",
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
  policy = policy.replace("deny_unencrypted_upload = true", "deny_unencrypted_upload = false");
  fs.writeFileSync(policyPath, policy, "utf8");
}

function assertClaudeAuthConfigured(wrapped) {
  const combined = `${wrapped.stdout}\n${wrapped.stderr}`;
  if (wrapped.status === 41 || /ANTHROPIC_API_KEY|CLAUDE_API_KEY|authentication_error|invalid x-api-key|permission_denied/i.test(combined)) {
    throw new Error([
      "Claude API auth is not configured for this process.",
      "Export ANTHROPIC_API_KEY or CLAUDE_API_KEY, then rerun `npm run test:claude:batch:real`.",
      "Claude output:",
      combined
    ].join("\n"));
  }
}

function resolveProjectArtifact(projectRoot, relativePath) {
  const resolved = path.resolve(projectRoot, relativePath);
  if (resolved !== projectRoot && !resolved.startsWith(`${projectRoot}${path.sep}`)) {
    throw new Error(`Refusing unsafe project artifact path: ${relativePath}`);
  }
  return resolved;
}

function realBatchRunnerScript() {
  return [
    "const fs = require('node:fs');",
    "const os = require('node:os');",
    "const path = require('node:path');",
    `const model = ${JSON.stringify(claudeModel)};`,
    `const timeoutMs = ${JSON.stringify(claudeCallTimeoutMs)};`,
    `const prompts = ${JSON.stringify(prompts)};`,
    "const apiKey = process.env.ANTHROPIC_API_KEY || process.env.CLAUDE_API_KEY;",
    "if (!apiKey) {",
    "  console.error('ANTHROPIC_API_KEY or CLAUDE_API_KEY missing');",
    "  process.exit(41);",
    "}",
    "function responseText(body) {",
    "  return (body.content || []).map((part) => part && part.type === 'text' ? part.text || '' : '').filter(Boolean).join('\\n');",
    "}",
    "async function callClaude(prompt) {",
    "  console.error(`hookshield real claude batch: prompt ${prompt.number}/5 starting`);",
    "  const controller = new AbortController();",
    "  const timer = setTimeout(() => controller.abort(), timeoutMs);",
    "  let response;",
    "  try {",
    "    response = await fetch('https://api.anthropic.com/v1/messages', {",
    "      method: 'POST',",
    "      headers: {",
    "        'Content-Type': 'application/json',",
    "        'x-api-key': apiKey,",
    "        'anthropic-version': '2023-06-01',",
    "      },",
    "      body: JSON.stringify({",
    "        model,",
    "        max_tokens: 64,",
    "        messages: [{ role: 'user', content: prompt.text }],",
    "      }),",
    "      signal: controller.signal,",
    "    });",
    "  } finally {",
    "    clearTimeout(timer);",
    "  }",
    "  const bodyText = await response.text();",
    "  if (!response.ok) {",
    "    console.error(`Claude API failed for prompt ${prompt.number}: ${response.status} ${bodyText}`);",
    "    process.exit(response.status === 401 || response.status === 403 ? 41 : 1);",
    "  }",
    "  const body = JSON.parse(bodyText);",
    "  const text = responseText(body);",
    "  if (!text.includes(prompt.marker)) {",
    "    console.error(`Claude response missing marker ${prompt.marker}`);",
    "    console.error(text);",
    "    process.exit(1);",
    "  }",
    "  const transcriptPath = path.join(os.homedir(), '.claude', 'projects', 'hookshield-api-batch', `session-${prompt.number}-${Date.now()}.jsonl`);",
    "  fs.mkdirSync(path.dirname(transcriptPath), { recursive: true });",
    "  fs.writeFileSync(transcriptPath, JSON.stringify({",
    "    source: 'claude-api',",
    "    model,",
    "    prompt_number: prompt.number,",
    "    prompt: prompt.text,",
    "    response: text,",
    "    usage: body.usage || null,",
    "    id: body.id || null,",
    "  }) + '\\n');",
    "  console.log(JSON.stringify({ ok: true, marker: prompt.marker, transcriptPath }));",
    "  console.error(`hookshield real claude batch: prompt ${prompt.number}/5 complete`);",
    "}",
    "async function main() {",
    "  for (const prompt of prompts) {",
    "    await callClaude(prompt);",
    "  }",
    "}",
    "main().catch((error) => {",
    "  if (error.name === 'AbortError') {",
    "    console.error(`Claude API timed out after ${timeoutMs}ms`);",
    "    process.exit(124);",
    "  }",
    "  console.error(error.stack || error.message);",
    "  process.exit(1);",
    "});"
  ].join("\n");
}

function main() {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "hookshield-real-claude-batch-"));
  const projectRoot = path.join(tempRoot, "proj");
  const hookshieldHome = path.join(tempRoot, "hookshield-home");
  fs.mkdirSync(projectRoot, { recursive: true });
  fs.mkdirSync(hookshieldHome, { recursive: true });

  let keepTemp = process.env.HOOKSHIELD_KEEP_TMP === "1";
  try {
    console.error("hookshield real claude batch: initializing temp project");
    run("git", ["init", "-q"], { cwd: projectRoot, expectedStatus: 0 });
    hookshield(projectRoot, hookshieldHome, ["init"], { expectedStatus: 0 });
    rewritePolicy(projectRoot);

    console.error("hookshield real claude batch: running five Claude API prompts under HookShield");
    const wrapped = hookshield(projectRoot, hookshieldHome, [
      "run",
      "--",
      process.execPath,
      "-e",
      realBatchRunnerScript()
    ]);

    assertClaudeAuthConfigured(wrapped);
    console.error("hookshield real claude batch: reviewing quarantined artifacts");
    assert.equal(wrapped.status, 155, [
      "Expected HookShield to return review-required exit code 155 after Claude created session artifacts.",
      "stdout:",
      wrapped.stdout,
      "stderr:",
      wrapped.stderr
    ].join("\n"));
    for (const prompt of prompts) {
      assert.match(wrapped.stdout, new RegExp(prompt.marker));
    }

    const review = hookshield(projectRoot, hookshieldHome, ["review", "--json"], { expectedStatus: 0 });
    const reviewJson = JSON.parse(review.stdout);
    const chatItems = reviewJson.items.filter((item) => (
      /^~\/\.claude\/projects\/.+\.jsonl$/.test(item.path) &&
      item.reason === "Claude project transcript artifact" &&
      item.action === "quarantined"
    ));

    const itemByPromptNumber = new Map();
    for (const item of chatItems) {
      console.error(`hookshield real claude batch: revealing ${item.path}`);
      const reveal = hookshield(projectRoot, hookshieldHome, [
        "reveal",
        "--session",
        reviewJson.session.session_id,
        "--item",
        item.quarantine_path,
        "--i-understand"
      ], { expectedStatus: 0 });

      for (const prompt of prompts) {
        if (reveal.stdout.includes(prompt.marker)) {
          itemByPromptNumber.set(prompt.number, item);
        }
      }
    }

    assert.equal(itemByPromptNumber.size, 5, `Expected five distinct Claude chat review items. Found markers for: ${[...itemByPromptNumber.keys()].join(", ")}`);

    const promotedOutputs = [];
    for (const prompt of prompts) {
      console.error(`hookshield real claude batch: redacting prompt ${prompt.number}`);
      const item = itemByPromptNumber.get(prompt.number);
      const reviewItemNumber = reviewJson.items.indexOf(item) + 1;
      const draftPath = `approved-context/real-claude-batch-draft-${prompt.number}.json`;
      hookshield(projectRoot, hookshieldHome, [
        "redact",
        "--session",
        reviewJson.session.session_id,
        "--item",
        String(reviewItemNumber),
        "--out",
        draftPath
      ], { expectedStatus: 0 });

      const absoluteDraftPath = resolveProjectArtifact(projectRoot, draftPath);
      const draft = JSON.parse(fs.readFileSync(absoluteDraftPath, "utf8"));
      const draftText = JSON.stringify(draft);
      assert.doesNotMatch(draftText, new RegExp(prompt.marker));
      assert.doesNotMatch(draftText, /Reply with exactly/);

      if (!approvedPromptNumbers.has(prompt.number)) continue;

      console.error(`hookshield real claude batch: approving prompt ${prompt.number}`);
      const outputPath = `approved-context/real-claude-batch-approved-${prompt.number}.json`;
      hookshield(projectRoot, hookshieldHome, [
        "approve",
        "--session",
        reviewJson.session.session_id,
        "--item",
        String(reviewItemNumber),
        "--summary",
        `Approved sanitized Claude batch prompt ${prompt.number}.`,
        "--keep",
        `Approved sanitized note for real Claude prompt ${prompt.number}.`,
        "--out",
        outputPath
      ], { expectedStatus: 0 });
      promotedOutputs.push(outputPath);
    }

    assert.deepEqual(promotedOutputs, [
      "approved-context/real-claude-batch-approved-2.json",
      "approved-context/real-claude-batch-approved-4.json"
    ]);

    const promotedContents = promotedOutputs
      .map((outputPath) => fs.readFileSync(path.join(projectRoot, outputPath), "utf8"))
      .join("\n");
    assert.match(promotedContents, /Approved sanitized note for real Claude prompt 2/);
    assert.match(promotedContents, /Approved sanitized note for real Claude prompt 4/);
    assert.doesNotMatch(promotedContents, /HOOKSHIELD_CLAUDE_BATCH_REAL_[135]/);
    assert.doesNotMatch(promotedContents, /Reply with exactly/);

    console.log(JSON.stringify({
      ok: true,
      claude_model: claudeModel,
      temp_root: tempRoot,
      temp_root_kept: keepTemp,
      session_id: reviewJson.session.session_id,
      real_prompt_count: prompts.length,
      approved_prompt_numbers: [...approvedPromptNumbers],
      promoted_outputs: promotedOutputs
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
