"use strict";

const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const cliPath = path.resolve(__dirname, "..", "bin", "hookshield.js");

function withTempProject(fn) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "hookshield-review-e2e-"));
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "hookshield-review-home-"));

  try {
    return fn(root, home);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
    fs.rmSync(home, { recursive: true, force: true });
  }
}

function runHookshield(root, home, args, options = {}) {
  const result = spawnSync(process.execPath, [cliPath, ...args], {
    cwd: root,
    env: {
      ...process.env,
      ...(options.env || {}),
      HOOKSHIELD_PROJECT: root,
      HOOKSHIELD_HOME: home
    },
    encoding: "utf8"
  });

  const expectedStatus = options.expectedStatus ?? 0;
  assert.equal(
    result.status,
    expectedStatus,
    [
      `hookshield ${args.join(" ")} exited ${result.status}, expected ${expectedStatus}`,
      result.stdout,
      result.stderr
    ].join("\n")
  );

  return result;
}

function assertNoPrivateData(contents) {
  assert.doesNotMatch(contents, /PRIVATE PROMPT/);
  assert.doesNotMatch(contents, /HOOKSHIELD_TEST_MARKER_E2E_12345/);
  assert.doesNotMatch(contents, /jane@example\.com/);
  assert.doesNotMatch(contents, /secrets\.env/);
  assert.doesNotMatch(contents, /dead-end reasoning/);
}

test("CLI review workflow quarantines fake prompt data and promotes only approved context", () => {
  withTempProject((root, home) => {
    runHookshield(root, home, ["init"]);

    const policyPath = path.join(root, "hookshield.toml");
    fs.writeFileSync(
      policyPath,
      fs.readFileSync(policyPath, "utf8").replace('mode = "audit"', 'mode = "strict"'),
      "utf8"
    );

    const fakeAgentScript = [
      "const fs = require('fs');",
      "fs.mkdirSync('.entire/checkpoints', { recursive: true });",
      "fs.writeFileSync('.entire/checkpoints/prompt.json', JSON.stringify({",
      "  prompt: 'PRIVATE PROMPT: inspect secrets.env and customer data',",
      "  private_marker: 'HOOKSHIELD_TEST_MARKER_E2E_12345',",
      "  email: 'jane@example.com',",
      "  tool_calls: ['cat secrets.env'],",
      "  reasoning: 'dead-end reasoning that should not ship'",
      "}, null, 2));"
    ].join("\n");

    const wrappedRun = runHookshield(
      root,
      home,
      ["run", "--", process.execPath, "-e", fakeAgentScript],
      { expectedStatus: 155 }
    );
    assert.equal(wrappedRun.stderr, "");
    assert.equal(fs.existsSync(path.join(root, ".entire", "checkpoints", "prompt.json")), false);

    const review = runHookshield(root, home, ["review", "--json"]);
    const reviewJson = JSON.parse(review.stdout);
    assert.equal(reviewJson.items.length, 1);
    assert.equal(reviewJson.items[0].exists, true);
    assert.equal(reviewJson.items[0].path, ".entire/checkpoints/prompt.json");

    const sessionId = reviewJson.session.session_id;
    const blockedReveal = runHookshield(root, home, ["reveal", "--session", sessionId], { expectedStatus: 1 });
    assert.match(blockedReveal.stderr, /--i-understand/);

    const reveal = runHookshield(root, home, ["reveal", "--session", sessionId, "--i-understand"]);
    assert.match(reveal.stdout, /PRIVATE PROMPT: inspect secrets\.env/);
    assert.match(reveal.stdout, /HOOKSHIELD_TEST_MARKER_E2E_12345/);

    runHookshield(root, home, ["redact", "--session", sessionId, "--out", "approved-context/draft.json"]);

    const draftPath = path.join(root, "approved-context", "draft.json");
    const draft = JSON.parse(fs.readFileSync(draftPath, "utf8"));
    assertNoPrivateData(JSON.stringify(draft));

    draft.summary = "Approved e2e summary.";
    draft.approved_context = ["The tested flow quarantined a session artifact and kept only this sanitized note."];
    fs.writeFileSync(draftPath, `${JSON.stringify(draft, null, 2)}\n`, "utf8");

    runHookshield(root, home, [
      "promote",
      "--draft",
      "approved-context/draft.json",
      "--out",
      "approved-context/session-summary.json"
    ]);

    const promotedContents = fs.readFileSync(path.join(root, "approved-context", "session-summary.json"), "utf8");
    assert.match(promotedContents, /Approved e2e summary/);
    assert.match(promotedContents, /sanitized note/);
    assertNoPrivateData(promotedContents);
  });
});

test("CLI review workflow quarantines Gemini artifacts through Node fallback backend", () => {
  withTempProject((root, home) => {
    runHookshield(root, home, ["init"]);

    const policyPath = path.join(root, "hookshield.toml");
    fs.writeFileSync(
      policyPath,
      fs.readFileSync(policyPath, "utf8").replace('mode = "audit"', 'mode = "strict"'),
      "utf8"
    );

    const fakeGeminiScript = [
      "const fs = require('fs');",
      "const os = require('os');",
      "const path = require('path');",
      "const transcript = path.join(os.homedir(), '.gemini', 'tmp', 'fallback-project', 'chats', 'session.jsonl');",
      "fs.mkdirSync(path.dirname(transcript), { recursive: true });",
      "fs.writeFileSync(transcript, JSON.stringify({",
      "  prompt: 'PRIVATE GEMINI FALLBACK PROMPT',",
      "  response: 'HOOKSHIELD_GEMINI_FALLBACK_TEST',",
      "  tool_calls: ['cat fallback.env']",
      "}) + '\\n');"
    ].join("\n");

    const wrappedRun = runHookshield(
      root,
      home,
      ["run", "--", process.execPath, "-e", fakeGeminiScript],
      { expectedStatus: 155, env: { HOME: home, HOOKSHIELD_NATIVE: "0" } }
    );
    assert.equal(wrappedRun.stderr, "");

    const inspect = runHookshield(root, home, ["inspect", "--json"], { env: { HOME: home } });
    const inspectJson = JSON.parse(inspect.stdout);
    assert.equal(inspectJson.sessions[0].backend, "node-stdio");

    const review = runHookshield(root, home, ["review", "--json"], { env: { HOME: home } });
    const reviewJson = JSON.parse(review.stdout);
    const item = reviewJson.items.find((entry) => entry.path === "~/.gemini/tmp/fallback-project/chats/session.jsonl");
    assert.ok(item);
    assert.equal(item.action, "quarantined");
    assert.equal(fs.existsSync(path.join(home, ".gemini", "tmp", "fallback-project", "chats", "session.jsonl")), false);
  });
});

test("CLI review workflow quarantines Claude home transcript artifacts", () => {
  withTempProject((root, home) => {
    runHookshield(root, home, ["init"]);

    const policyPath = path.join(root, "hookshield.toml");
    fs.writeFileSync(
      policyPath,
      fs.readFileSync(policyPath, "utf8").replace('mode = "audit"', 'mode = "strict"'),
      "utf8"
    );

    const fakeClaudeScript = [
      "const fs = require('fs');",
      "const os = require('os');",
      "const path = require('path');",
      "const transcript = path.join(os.homedir(), '.claude', 'projects', '-tmp-test', 'session.jsonl');",
      "fs.mkdirSync(path.dirname(transcript), { recursive: true });",
      "fs.writeFileSync(transcript, JSON.stringify({",
      "  type: 'user',",
      "  prompt: 'PRIVATE CLAUDE PROMPT: remind me about dads birthday',",
      "  private_marker: 'HOOKSHIELD_TEST_MARKER_CLAUDE_E2E_12345',",
      "  tool_calls: ['cat secrets.env']",
      "}) + '\\n');"
    ].join("\n");

    const wrappedRun = runHookshield(
      root,
      home,
      ["run", "--", process.execPath, "-e", fakeClaudeScript],
      { expectedStatus: 155 }
    );
    assert.equal(wrappedRun.stderr, "");
    assert.equal(fs.existsSync(path.join(home, ".claude", "projects", "-tmp-test", "session.jsonl")), false);

    const review = runHookshield(root, home, ["review", "--json"]);
    const reviewJson = JSON.parse(review.stdout);
    assert.equal(reviewJson.items.length, 1);
    assert.equal(reviewJson.items[0].path, "~/.claude/projects/-tmp-test/session.jsonl");

    const sessionId = reviewJson.session.session_id;
    const reveal = runHookshield(root, home, ["reveal", "--session", sessionId, "--i-understand"]);
    assert.match(reveal.stdout, /PRIVATE CLAUDE PROMPT: remind me about dads birthday/);
    assert.match(reveal.stdout, /HOOKSHIELD_TEST_MARKER_CLAUDE_E2E_12345/);

    runHookshield(root, home, ["redact", "--session", sessionId, "--out", "approved-context/claude-draft.json"]);
    const draft = fs.readFileSync(path.join(root, "approved-context", "claude-draft.json"), "utf8");
    assert.doesNotMatch(draft, /PRIVATE CLAUDE PROMPT|HOOKSHIELD_TEST_MARKER_CLAUDE_E2E_12345|dads birthday|secrets\.env/);
  });
});

test("CLI review workflow quarantines Gemini home session artifacts", () => {
  withTempProject((root, home) => {
    runHookshield(root, home, ["init"]);

    const policyPath = path.join(root, "hookshield.toml");
    fs.writeFileSync(
      policyPath,
      fs.readFileSync(policyPath, "utf8").replace('mode = "audit"', 'mode = "strict"'),
      "utf8"
    );

    const fakeGeminiScript = [
      "const fs = require('fs');",
      "const os = require('os');",
      "const path = require('path');",
      "const transcript = path.join(os.homedir(), '.gemini', 'tmp', 'project-hash', 'chats', 'session.json');",
      "fs.mkdirSync(path.dirname(transcript), { recursive: true });",
      "fs.writeFileSync(transcript, JSON.stringify({",
      "  prompt: 'PRIVATE GEMINI PROMPT: remind me about dads birthday',",
      "  response: 'HOOKSHIELD_GEMINI_REAL_TEST',",
      "  private_marker: 'HOOKSHIELD_TEST_MARKER_GEMINI_E2E_12345',",
      "  tool_calls: ['cat secrets.env']",
      "}, null, 2));"
    ].join("\n");

    const wrappedRun = runHookshield(
      root,
      home,
      ["run", "--", process.execPath, "-e", fakeGeminiScript],
      { expectedStatus: 155 }
    );
    assert.equal(wrappedRun.stderr, "");
    assert.equal(fs.existsSync(path.join(home, ".gemini", "tmp", "project-hash", "chats", "session.json")), false);

    const review = runHookshield(root, home, ["review", "--json"]);
    const reviewJson = JSON.parse(review.stdout);
    assert.equal(reviewJson.items.length, 1);
    assert.equal(reviewJson.items[0].path, "~/.gemini/tmp/project-hash/chats/session.json");
    assert.equal(reviewJson.items[0].reason, "Gemini session artifact");

    const sessionId = reviewJson.session.session_id;
    const reveal = runHookshield(root, home, ["reveal", "--session", sessionId, "--i-understand"]);
    assert.match(reveal.stdout, /PRIVATE GEMINI PROMPT: remind me about dads birthday/);
    assert.match(reveal.stdout, /HOOKSHIELD_GEMINI_REAL_TEST/);

    runHookshield(root, home, ["redact", "--session", sessionId, "--out", "approved-context/gemini-draft.json"]);
    const draft = fs.readFileSync(path.join(root, "approved-context", "gemini-draft.json"), "utf8");
    assert.doesNotMatch(draft, /PRIVATE GEMINI PROMPT|HOOKSHIELD_GEMINI_REAL_TEST|HOOKSHIELD_TEST_MARKER_GEMINI_E2E_12345|dads birthday|secrets\.env/);
  });
});

test("CLI review workflow quarantines Codex home session artifacts", () => {
  withTempProject((root, home) => {
    runHookshield(root, home, ["init"]);

    const policyPath = path.join(root, "hookshield.toml");
    fs.writeFileSync(
      policyPath,
      fs.readFileSync(policyPath, "utf8").replace('mode = "audit"', 'mode = "strict"'),
      "utf8"
    );

    const fakeCodexScript = [
      "const fs = require('fs');",
      "const os = require('os');",
      "const path = require('path');",
      "const transcript = path.join(os.homedir(), '.codex', 'sessions', 'hookshield-test', 'session.jsonl');",
      "fs.mkdirSync(path.dirname(transcript), { recursive: true });",
      "fs.writeFileSync(transcript, JSON.stringify({",
      "  type: 'user_message',",
      "  prompt: 'PRIVATE CODEX PROMPT: remind me about dads birthday',",
      "  private_marker: 'HOOKSHIELD_TEST_MARKER_CODEX_E2E_12345',",
      "  tool_calls: ['cat secrets.env']",
      "}) + '\\n');"
    ].join("\n");

    const wrappedRun = runHookshield(
      root,
      home,
      ["run", "--", process.execPath, "-e", fakeCodexScript],
      { expectedStatus: 155 }
    );
    assert.equal(wrappedRun.stderr, "");
    assert.equal(fs.existsSync(path.join(home, ".codex", "sessions", "hookshield-test", "session.jsonl")), false);

    const review = runHookshield(root, home, ["review", "--json"]);
    const reviewJson = JSON.parse(review.stdout);
    assert.equal(reviewJson.items.length, 1);
    assert.equal(reviewJson.items[0].path, "~/.codex/sessions/hookshield-test/session.jsonl");
    assert.equal(reviewJson.items[0].reason, "Codex session transcript artifact");

    const sessionId = reviewJson.session.session_id;
    const reveal = runHookshield(root, home, ["reveal", "--session", sessionId, "--i-understand"]);
    assert.match(reveal.stdout, /PRIVATE CODEX PROMPT: remind me about dads birthday/);
    assert.match(reveal.stdout, /HOOKSHIELD_TEST_MARKER_CODEX_E2E_12345/);

    runHookshield(root, home, ["redact", "--session", sessionId, "--out", "approved-context/codex-draft.json"]);
    const draft = fs.readFileSync(path.join(root, "approved-context", "codex-draft.json"), "utf8");
    assert.doesNotMatch(draft, /PRIVATE CODEX PROMPT|HOOKSHIELD_TEST_MARKER_CODEX_E2E_12345|dads birthday|secrets\.env/);
  });
});

test("CLI review workflow can approve two of five Gemini prompt drafts", () => {
  withTempProject((root, home) => {
    runHookshield(root, home, ["init"]);

    const policyPath = path.join(root, "hookshield.toml");
    fs.writeFileSync(
      policyPath,
      fs.readFileSync(policyPath, "utf8").replace('mode = "audit"', 'mode = "strict"'),
      "utf8"
    );

    const fakeBatchScript = [
      "const fs = require('fs');",
      "const os = require('os');",
      "const path = require('path');",
      "const chats = path.join(os.homedir(), '.gemini', 'tmp', 'batch-project', 'chats');",
      "fs.mkdirSync(chats, { recursive: true });",
      "for (let i = 1; i <= 5; i += 1) {",
      "  fs.writeFileSync(path.join(chats, `session-${i}.jsonl`), JSON.stringify({",
      "    prompt: `PRIVATE GEMINI BATCH PROMPT ${i}: inspect sensitive-file-${i}.env`,",
      "    response: `PRIVATE GEMINI BATCH RESPONSE ${i}` ,",
      "    tool_calls: [`cat sensitive-file-${i}.env`],",
      "    reasoning: `private reasoning ${i}`",
      "  }) + '\\n');",
      "}"
    ].join("\n");

    const wrappedRun = runHookshield(
      root,
      home,
      ["run", "--", process.execPath, "-e", fakeBatchScript],
      { expectedStatus: 155 }
    );
    assert.equal(wrappedRun.stderr, "");

    const review = runHookshield(root, home, ["review", "--json"]);
    const reviewJson = JSON.parse(review.stdout);
    const geminiItems = reviewJson.items
      .filter((item) => /^~\/\.gemini\/tmp\/batch-project\/chats\/session-\d+\.jsonl$/.test(item.path))
      .sort((a, b) => a.path.localeCompare(b.path));
    assert.equal(geminiItems.length, 5);

    const humanReview = runHookshield(root, home, ["review"]);
    assert.match(humanReview.stdout, /\[1\] READY/);
    assert.match(humanReview.stdout, /Use --item <number>/);

    const approvedIndexes = new Set([2, 4]);
    const promotedOutputs = [];
    for (let index = 0; index < geminiItems.length; index += 1) {
      const itemNumber = index + 1;
      const reviewItemNumber = reviewJson.items.indexOf(geminiItems[index]) + 1;
      const draftPath = `approved-context/batch-draft-${itemNumber}.json`;
      runHookshield(root, home, [
        "redact",
        "--session",
        reviewJson.session.session_id,
        "--item",
        String(reviewItemNumber),
        "--out",
        draftPath
      ]);

      const absoluteDraftPath = path.join(root, draftPath);
      const draft = JSON.parse(fs.readFileSync(absoluteDraftPath, "utf8"));
      const draftText = JSON.stringify(draft);
      assert.doesNotMatch(draftText, /PRIVATE GEMINI BATCH|sensitive-file-|private reasoning/);

      if (!approvedIndexes.has(itemNumber)) continue;

      const outputPath = `approved-context/batch-approved-${itemNumber}.json`;
      runHookshield(root, home, [
        "approve",
        "--session",
        reviewJson.session.session_id,
        "--item",
        String(reviewItemNumber),
        "--summary",
        `Approved sanitized Gemini prompt ${itemNumber}.`,
        "--keep",
        `Approved sanitized note for Gemini prompt ${itemNumber}.`,
        "--out",
        outputPath
      ]);
      promotedOutputs.push(outputPath);
    }

    assert.deepEqual(promotedOutputs, [
      "approved-context/batch-approved-2.json",
      "approved-context/batch-approved-4.json"
    ]);

    const approvedDir = path.join(root, "approved-context");
    const approvedFiles = fs.readdirSync(approvedDir).filter((file) => file.startsWith("batch-approved-")).sort();
    assert.deepEqual(approvedFiles, ["batch-approved-2.json", "batch-approved-4.json"]);

    const promotedContents = approvedFiles
      .map((file) => fs.readFileSync(path.join(approvedDir, file), "utf8"))
      .join("\n");
    assert.match(promotedContents, /Approved sanitized note for Gemini prompt 2/);
    assert.match(promotedContents, /Approved sanitized note for Gemini prompt 4/);
    assert.doesNotMatch(promotedContents, /prompt 1|prompt 3|prompt 5|PRIVATE GEMINI BATCH|sensitive-file-|private reasoning/);
  });
});
