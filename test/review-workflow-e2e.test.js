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
  const home = path.join(root, "home");
  fs.mkdirSync(home);

  try {
    return fn(root, home);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

function runHookshield(root, home, args, options = {}) {
  const result = spawnSync(process.execPath, [cliPath, ...args], {
    cwd: root,
    env: {
      ...process.env,
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
  assert.doesNotMatch(contents, /sk-live-e2e-12345/);
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
      "  token: 'sk-live-e2e-12345',",
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
    assert.match(reveal.stdout, /sk-live-e2e-12345/);

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
