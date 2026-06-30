"use strict";

const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const repoRoot = path.resolve(__dirname, "..");
const hookshieldCli = path.join(repoRoot, "bin", "hookshield.js");
const geminiCallTimeoutMs = Number(process.env.HOOKSHIELD_GEMINI_CALL_TIMEOUT_MS || 60000);
const geminiModel = process.env.GEMINI_MODEL || "gemini-flash-latest";
const approvedPromptNumbers = new Set([2, 4]);
const promptNumbers = [1, 2, 3, 4, 5];
const commandTimeoutMs = Number(process.env.HOOKSHIELD_REAL_TEST_TIMEOUT_MS || (promptNumbers.length * geminiCallTimeoutMs + 30000));
const prompts = promptNumbers.map((number) => ({
  number,
  marker: `HOOKSHIELD_GEMINI_BATCH_REAL_${number}`,
  text: `Reply with exactly HOOKSHIELD_GEMINI_BATCH_REAL_${number}. Do not use tools.`
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

function assertGeminiAuthConfigured(wrapped) {
  const combined = `${wrapped.stdout}\n${wrapped.stderr}`;
  if (wrapped.status === 41 || /GEMINI_API_KEY|API key missing|API_KEY_INVALID|PERMISSION_DENIED/.test(combined)) {
    throw new Error([
      "Gemini API auth is not configured for this process.",
      "Export GEMINI_API_KEY or GOOGLE_API_KEY, then rerun `npm run test:gemini:batch:real`.",
      "Gemini output:",
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
    `const model = ${JSON.stringify(geminiModel)};`,
    `const timeoutMs = ${JSON.stringify(geminiCallTimeoutMs)};`,
    `const prompts = ${JSON.stringify(prompts)};`,
    "const apiKey = process.env.GEMINI_API_KEY || process.env.GOOGLE_API_KEY;",
    "if (!apiKey) {",
    "  console.error('GEMINI_API_KEY or GOOGLE_API_KEY missing');",
    "  process.exit(41);",
    "}",
    "async function callGemini(prompt) {",
    "  console.error(`hookshield real gemini batch: prompt ${prompt.number}/5 starting`);",
    "  const controller = new AbortController();",
    "  const timer = setTimeout(() => controller.abort(), timeoutMs);",
    "  let response;",
    "  try {",
    "    response = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent`, {",
    "      method: 'POST',",
    "      headers: {",
    "        'Content-Type': 'application/json',",
    "        'X-goog-api-key': apiKey,",
    "      },",
    "      body: JSON.stringify({ contents: [{ parts: [{ text: prompt.text }] }] }),",
    "      signal: controller.signal,",
    "    });",
    "  } finally {",
    "    clearTimeout(timer);",
    "  }",
    "  const bodyText = await response.text();",
    "  if (!response.ok) {",
    "    console.error(`Gemini API failed for prompt ${prompt.number}: ${response.status} ${bodyText}`);",
    "    process.exit(response.status === 401 || response.status === 403 ? 41 : 1);",
    "  }",
    "  const body = JSON.parse(bodyText);",
    "  const text = (body.candidates || []).flatMap((candidate) => candidate.content?.parts || []).map((part) => part.text || '').join('\\n');",
    "  if (!text.includes(prompt.marker)) {",
    "    console.error(`Gemini response missing marker ${prompt.marker}`);",
    "    console.error(text);",
    "    process.exit(1);",
    "  }",
    "  const transcriptPath = path.join(os.homedir(), '.gemini', 'tmp', 'hookshield-api-batch', 'chats', `session-${prompt.number}-${Date.now()}.jsonl`);",
    "  fs.mkdirSync(path.dirname(transcriptPath), { recursive: true });",
    "  fs.writeFileSync(transcriptPath, JSON.stringify({",
    "    source: 'gemini-api',",
    "    model,",
    "    prompt_number: prompt.number,",
    "    prompt: prompt.text,",
    "    response: text,",
    "    usageMetadata: body.usageMetadata || null,",
    "    responseId: body.responseId || null,",
    "  }) + '\\n');",
    "  console.log(JSON.stringify({ ok: true, marker: prompt.marker, transcriptPath }));",
    "  console.error(`hookshield real gemini batch: prompt ${prompt.number}/5 complete`);",
    "}",
    "async function main() {",
    "  for (const prompt of prompts) {",
    "    await callGemini(prompt);",
    "  }",
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
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "hookshield-real-gemini-batch-"));
  const projectRoot = path.join(tempRoot, "proj");
  const hookshieldHome = path.join(tempRoot, "hookshield-home");
  fs.mkdirSync(projectRoot, { recursive: true });
  fs.mkdirSync(hookshieldHome, { recursive: true });

  let keepTemp = process.env.HOOKSHIELD_KEEP_TMP === "1";
  try {
    console.error("hookshield real gemini batch: initializing temp project");
    run("git", ["init", "-q"], { cwd: projectRoot, expectedStatus: 0 });
    hookshield(projectRoot, hookshieldHome, ["init"], { expectedStatus: 0 });
    rewritePolicy(projectRoot);

    console.error("hookshield real gemini batch: running five Gemini API prompts under HookShield");
    const wrapped = hookshield(projectRoot, hookshieldHome, [
      "run",
      "--",
      process.execPath,
      "-e",
      realBatchRunnerScript()
    ]);

    assertGeminiAuthConfigured(wrapped);
    console.error("hookshield real gemini batch: reviewing quarantined artifacts");
    assert.equal(wrapped.status, 155, [
      "Expected HookShield to return review-required exit code 155 after Gemini created session artifacts.",
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
      /^~\/\.gemini\/tmp\/.+\/chats\/.+\.jsonl$/.test(item.path) &&
      item.reason === "Gemini session artifact" &&
      item.action === "quarantined"
    ));

    const itemByPromptNumber = new Map();
    for (const item of chatItems) {
      console.error(`hookshield real gemini batch: revealing ${item.path}`);
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

    assert.equal(itemByPromptNumber.size, 5, `Expected five distinct Gemini chat review items. Found markers for: ${[...itemByPromptNumber.keys()].join(", ")}`);

    const promotedOutputs = [];
    for (const prompt of prompts) {
      console.error(`hookshield real gemini batch: redacting prompt ${prompt.number}`);
      const item = itemByPromptNumber.get(prompt.number);
      const reviewItemNumber = reviewJson.items.indexOf(item) + 1;
      const draftPath = `approved-context/real-batch-draft-${prompt.number}.json`;
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

      console.error(`hookshield real gemini batch: approving prompt ${prompt.number}`);
      const outputPath = `approved-context/real-batch-approved-${prompt.number}.json`;
      hookshield(projectRoot, hookshieldHome, [
        "approve",
        "--session",
        reviewJson.session.session_id,
        "--item",
        String(reviewItemNumber),
        "--summary",
        `Approved sanitized Gemini batch prompt ${prompt.number}.`,
        "--keep",
        `Approved sanitized note for real Gemini prompt ${prompt.number}.`,
        "--out",
        outputPath
      ], { expectedStatus: 0 });
      promotedOutputs.push(outputPath);
    }

    assert.deepEqual(promotedOutputs, [
      "approved-context/real-batch-approved-2.json",
      "approved-context/real-batch-approved-4.json"
    ]);

    const promotedContents = promotedOutputs
      .map((outputPath) => fs.readFileSync(path.join(projectRoot, outputPath), "utf8"))
      .join("\n");
    assert.match(promotedContents, /Approved sanitized note for real Gemini prompt 2/);
    assert.match(promotedContents, /Approved sanitized note for real Gemini prompt 4/);
    assert.doesNotMatch(promotedContents, /HOOKSHIELD_GEMINI_BATCH_REAL_[135]/);
    assert.doesNotMatch(promotedContents, /Reply with exactly/);

    console.log(JSON.stringify({
      ok: true,
      gemini_model: geminiModel,
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
