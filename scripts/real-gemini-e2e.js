"use strict";

const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const repoRoot = path.resolve(__dirname, "..");
const hookshieldCli = path.join(repoRoot, "bin", "hookshield.js");
const prompt = "Reply with exactly HOOKSHIELD_GEMINI_REAL_TEST. Do not use tools.";
const expected = "HOOKSHIELD_GEMINI_REAL_TEST";
const commandTimeoutMs = Number(process.env.HOOKSHIELD_REAL_TEST_TIMEOUT_MS || 120000);
const geminiCallTimeoutMs = Number(process.env.HOOKSHIELD_GEMINI_CALL_TIMEOUT_MS || 60000);
const geminiModel = process.env.GEMINI_MODEL || "gemini-flash-latest";

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

function resolveProjectArtifact(projectRoot, relativePath) {
  const resolved = path.resolve(projectRoot, relativePath);
  if (resolved !== projectRoot && !resolved.startsWith(`${projectRoot}${path.sep}`)) {
    throw new Error(`Refusing unsafe project artifact path: ${relativePath}`);
  }
  return resolved;
}

function assertGeminiAuthConfigured(wrapped) {
  const combined = `${wrapped.stdout}\n${wrapped.stderr}`;
  if (wrapped.status === 41 || /GEMINI_API_KEY|API key missing|API_KEY_INVALID|PERMISSION_DENIED/.test(combined)) {
    throw new Error([
      "Gemini API auth is not configured for this process.",
      "Export GEMINI_API_KEY or GOOGLE_API_KEY, then rerun `npm run test:gemini:real`.",
      "Gemini output:",
      combined
    ].join("\n"));
  }
}

function realGeminiApiRunnerScript() {
  return [
    "const fs = require('node:fs');",
    "const os = require('node:os');",
    "const path = require('node:path');",
    `const prompt = ${JSON.stringify(prompt)};`,
    `const expected = ${JSON.stringify(expected)};`,
    `const model = ${JSON.stringify(geminiModel)};`,
    `const timeoutMs = ${JSON.stringify(geminiCallTimeoutMs)};`,
    "const apiKey = process.env.GEMINI_API_KEY || process.env.GOOGLE_API_KEY;",
    "if (!apiKey) {",
    "  console.error('GEMINI_API_KEY or GOOGLE_API_KEY missing');",
    "  process.exit(41);",
    "}",
    "async function main() {",
    "  console.error('hookshield real gemini api: request starting');",
    "  const controller = new AbortController();",
    "  const timer = setTimeout(() => controller.abort(), timeoutMs);",
    "  let response;",
    "  try {",
    "    response = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent`, {",
    "      method: 'POST',",
    "      headers: {",
    "        'Content-Type': 'application/json',",
    "        'X-goog-api-key': apiKey",
    "      },",
    "      body: JSON.stringify({ contents: [{ parts: [{ text: prompt }] }] }),",
    "      signal: controller.signal,",
    "    });",
    "  } finally {",
    "    clearTimeout(timer);",
    "  }",
    "  const bodyText = await response.text();",
    "  if (!response.ok) {",
    "    console.error(`Gemini API failed: ${response.status} ${bodyText}`);",
    "    process.exit(response.status === 401 || response.status === 403 ? 41 : 1);",
    "  }",
    "  const body = JSON.parse(bodyText);",
    "  const text = (body.candidates || []).flatMap((candidate) => candidate.content?.parts || []).map((part) => part.text || '').join('\\n');",
    "  if (!text.includes(expected)) {",
    "    console.error(`Gemini response missing marker ${expected}`);",
    "    console.error(text);",
    "    process.exit(1);",
    "  }",
    "  const transcriptPath = path.join(os.homedir(), '.gemini', 'tmp', 'hookshield-api-single', 'chats', `session-${Date.now()}.jsonl`);",
    "  fs.mkdirSync(path.dirname(transcriptPath), { recursive: true });",
    "  fs.writeFileSync(transcriptPath, JSON.stringify({",
    "    source: 'gemini-api',",
    "    model,",
    "    prompt,",
    "    response: text,",
    "    usageMetadata: body.usageMetadata || null,",
    "    responseId: body.responseId || null,",
    "  }) + '\\n');",
    "  console.log(JSON.stringify({ ok: true, marker: expected, transcriptPath }));",
    "  console.error('hookshield real gemini api: request complete');",
    "}",
    "main().catch((error) => {",
    "  if (error.name === 'AbortError') {",
    "    console.error(`Gemini API timed out after ${timeoutMs}ms`);",
    "    process.exit(124);",
    "  }",
    "  console.error(error.stack || error.message);",
    "  process.exit(1);",
    "});"
  ].join("\n");
}

function main() {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "hookshield-real-gemini-"));
  const projectRoot = path.join(tempRoot, "proj");
  const hookshieldHome = path.join(tempRoot, "hookshield-home");
  fs.mkdirSync(projectRoot, { recursive: true });
  fs.mkdirSync(hookshieldHome, { recursive: true });

  let keepTemp = process.env.HOOKSHIELD_KEEP_TMP === "1";
  try {
    console.error("hookshield real gemini: initializing temp project");
    run("git", ["init", "-q"], { cwd: projectRoot, expectedStatus: 0 });
    hookshield(projectRoot, hookshieldHome, ["init"], { expectedStatus: 0 });
    rewritePolicy(projectRoot);

    console.error("hookshield real gemini: running Gemini API call under HookShield");
    const wrapped = hookshield(projectRoot, hookshieldHome, [
      "run",
      "--",
      process.execPath,
      "-e",
      realGeminiApiRunnerScript()
    ]);

    assertGeminiAuthConfigured(wrapped);
    console.error("hookshield real gemini: reviewing quarantined artifacts");
    assert.equal(wrapped.status, 155, [
      "Expected HookShield to return review-required exit code 155 after Gemini created a session artifact.",
      "stdout:",
      wrapped.stdout,
      "stderr:",
      wrapped.stderr
    ].join("\n"));
    assert.match(wrapped.stdout, new RegExp(expected));

    const review = hookshield(projectRoot, hookshieldHome, ["review", "--json"], { expectedStatus: 0 });
    const reviewJson = JSON.parse(review.stdout);
    const sessionItem = reviewJson.items.find((item) => (
      /^~\/\.gemini\/tmp\/.+\/chats\/.+\.jsonl$/.test(item.path) &&
      item.reason === "Gemini session artifact" &&
      item.action === "quarantined"
    ));
    assert.ok(sessionItem, `Expected a quarantined Gemini chat session item. Items: ${JSON.stringify(reviewJson.items, null, 2)}`);

    console.error("hookshield real gemini: revealing selected chat artifact locally");
    const sessionId = reviewJson.session.session_id;
    const reveal = hookshield(projectRoot, hookshieldHome, [
      "reveal",
      "--session",
      sessionId,
      "--item",
      sessionItem.quarantine_path,
      "--i-understand"
    ], { expectedStatus: 0 });
    assert.match(reveal.stdout, new RegExp(expected));

    console.error("hookshield real gemini: redacting selected chat artifact");
    hookshield(projectRoot, hookshieldHome, [
      "redact",
      "--session",
      sessionId,
      "--item",
      sessionItem.quarantine_path,
      "--out",
      "approved-context/real-gemini-draft.json"
    ], { expectedStatus: 0 });
    const draftPath = path.join(projectRoot, "approved-context", "real-gemini-draft.json");
    const draft = fs.readFileSync(draftPath, "utf8");
    const draftJson = JSON.parse(draft);
    assert.doesNotMatch(draft, new RegExp(expected));
    assert.doesNotMatch(draft, /Reply with exactly/);
    assert.deepEqual(draftJson.approved_context, []);
    assert.ok(draftJson.withheld.includes("tool_calls"));

    console.log(JSON.stringify({
      ok: true,
      gemini_model: geminiModel,
      temp_root: tempRoot,
      temp_root_kept: keepTemp,
      session_id: sessionId,
      review_item_count: reviewJson.items.length,
      quarantined_path: sessionItem.quarantine_path
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
