"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const hooker = require("../src/hooker");

function withTempProject(fn) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "hookshield-test-"));
  const home = path.join(root, "home");
  fs.mkdirSync(home);
  const previousProject = process.env.HOOKSHIELD_PROJECT;
  const previousHome = process.env.HOOKSHIELD_HOME;
  const previousNative = process.env.HOOKSHIELD_NATIVE;
  process.env.HOOKSHIELD_PROJECT = root;
  process.env.HOOKSHIELD_HOME = home;
  process.env.HOOKSHIELD_NATIVE = "0";

  return Promise.resolve()
    .then(() => fn(root, home))
    .finally(() => {
      if (previousProject === undefined) delete process.env.HOOKSHIELD_PROJECT;
      else process.env.HOOKSHIELD_PROJECT = previousProject;
      if (previousHome === undefined) delete process.env.HOOKSHIELD_HOME;
      else process.env.HOOKSHIELD_HOME = previousHome;
      if (previousNative === undefined) delete process.env.HOOKSHIELD_NATIVE;
      else process.env.HOOKSHIELD_NATIVE = previousNative;
      fs.rmSync(root, { recursive: true, force: true });
    });
}

function withTempProjectNative(fn) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "hookshield-native-test-"));
  const home = path.join(root, "home");
  fs.mkdirSync(home);
  const previousProject = process.env.HOOKSHIELD_PROJECT;
  const previousHome = process.env.HOOKSHIELD_HOME;
  const previousNative = process.env.HOOKSHIELD_NATIVE;
  process.env.HOOKSHIELD_PROJECT = root;
  process.env.HOOKSHIELD_HOME = home;
  delete process.env.HOOKSHIELD_NATIVE;

  return Promise.resolve()
    .then(() => fn(root, home))
    .finally(() => {
      if (previousProject === undefined) delete process.env.HOOKSHIELD_PROJECT;
      else process.env.HOOKSHIELD_PROJECT = previousProject;
      if (previousHome === undefined) delete process.env.HOOKSHIELD_HOME;
      else process.env.HOOKSHIELD_HOME = previousHome;
      if (previousNative === undefined) delete process.env.HOOKSHIELD_NATIVE;
      else process.env.HOOKSHIELD_NATIVE = previousNative;
      fs.rmSync(root, { recursive: true, force: true });
    });
}

test("init creates policy and session ignore rule", async () => {
  await withTempProject((root) => {
    const result = hooker.initProject();
    assert.equal(result.created, true);
    assert.equal(fs.existsSync(path.join(root, "hookshield.toml")), true);
    assert.match(fs.readFileSync(path.join(root, ".gitignore"), "utf8"), /\.hookshield\/sessions\//);
    assert.match(fs.readFileSync(path.join(root, ".gitignore"), "utf8"), /\.hookshield\/quarantine\//);
    assert.match(fs.readFileSync(path.join(root, ".gitignore"), "utf8"), /\.hookshield\/virtualized-hooks\//);
  });
});

test("scan detects Entire hooks and transcript capture", async () => {
  await withTempProject((root) => {
    const hooks = path.join(root, ".git", "hooks");
    fs.mkdirSync(hooks, { recursive: true });
    fs.writeFileSync(path.join(hooks, "post-commit"), "curl https://entire.io/entire/checkpoints/v1 --data transcript", "utf8");

    const result = hooker.scan();
    assert.equal(result.findings.length, 1);
    assert.equal(result.findings[0].type, "hook");
    assert.ok(result.findings[0].matches.includes("entire.io"));
  });
});

test("scan stays quiet for a clean repo with no watched artifacts", async () => {
  await withTempProject(() => {
    const result = hooker.scan();
    assert.equal(result.findings.length, 0);
  });
});

test("scan detects real Entire-managed git hooks", async () => {
  await withTempProject((root) => {
    const hooks = path.join(root, ".git", "hooks");
    fs.mkdirSync(hooks, { recursive: true });
    fs.writeFileSync(path.join(hooks, "prepare-commit-msg"), [
      "#!/bin/sh",
      "# Entire CLI hooks",
      "if command -v entire >/dev/null 2>&1; then entire hooks git prepare-commit-msg \"$1\" \"$2\" 2>/dev/null || true; else :; fi",
      ""
    ].join("\n"), "utf8");
    fs.writeFileSync(path.join(hooks, "post-commit"), [
      "#!/bin/sh",
      "# Entire CLI hooks",
      "# Post-commit hook: condense session data if commit has Entire-Checkpoint trailer",
      "if command -v entire >/dev/null 2>&1; then entire hooks git post-commit 2>/dev/null || true; else :; fi",
      ""
    ].join("\n"), "utf8");
    fs.writeFileSync(path.join(hooks, "pre-push"), [
      "#!/bin/sh",
      "# Entire CLI hooks",
      "# Pre-push hook: push session logs alongside user's push",
      "if command -v entire >/dev/null 2>&1; then entire hooks git pre-push \"$1\" || true; else :; fi",
      ""
    ].join("\n"), "utf8");

    const findings = hooker.scan().findings;
    const hookFindings = findings.filter((finding) => finding.type === "hook");
    assert.equal(hookFindings.length, 3);
    assert.ok(hookFindings.every((finding) => finding.matches.includes("entire cli hooks")));
    assert.ok(hookFindings.every((finding) => finding.matches.includes("entire hooks")));
  });
});

test("scan detects Entire prompt metadata stored under git internals", async () => {
  await withTempProject((root) => {
    const sessionsDir = path.join(root, ".git", "entire-sessions");
    fs.mkdirSync(sessionsDir, { recursive: true });
    fs.writeFileSync(path.join(sessionsDir, "lab-session.json"), JSON.stringify({
      session_id: "lab-session",
      last_prompt: "private prompt: inspect secrets.env"
    }, null, 2), "utf8");

    const findings = hooker.scan().findings;
    assert.equal(findings.length, 1);
    assert.equal(findings[0].type, "entire");
    assert.equal(findings[0].path, path.join(sessionsDir, "lab-session.json"));
    assert.ok(findings[0].matches.includes("prompt"));
  });
});

test("encryptFile and decryptFile round trip", async () => {
  await withTempProject((root) => {
    const file = path.join(root, "session.txt");
    fs.writeFileSync(file, "secret prompt and transcript", "utf8");

    const encrypted = hooker.encryptFile(file);
    fs.writeFileSync(file, "", "utf8");
    const decrypted = hooker.decryptFile(encrypted.output);

    assert.equal(decrypted.output, file);
    assert.equal(fs.readFileSync(file, "utf8"), "secret prompt and transcript");
  });
});

test("runCommand records session metadata", async () => {
  await withTempProject(async (root) => {
    hooker.initProject();
    const result = await hooker.runCommand([process.execPath, "-e", "process.exit(0)"]);
    assert.equal(result.exitCode, 0);

    const sessions = hooker.inspectSessions().sessions;
    assert.equal(sessions.length, 1);
    assert.equal(sessions[0].session_id, result.sessionId);
    assert.equal(sessions[0].exit_code, 0);
    assert.equal(sessions[0].backend, "node-stdio");
    assert.match(sessions[0].note, /native Go PTY backend/);
    assert.equal(fs.existsSync(path.join(root, ".hookshield", "sessions", `${result.sessionId}.json`)), true);
  });
});

test("network annotation uses resolved allowed-domain IPs", () => {
  const annotated = hooker._internals.annotateNetworkConnections([
    {
      remote_host: "140.82.112.4",
      raw_name: "192.168.1.10:55555->140.82.112.4:443"
    }
  ], {
    mode: "strict",
    allowed_domains: ["github.com"],
    blocked_domains: []
  }, {
    allowed: {
      values: ["github.com", "140.82.112.4"],
      labels: {
        "github.com": "github.com",
        "140.82.112.4": "github.com"
      }
    },
    blocked: {
      values: [],
      labels: {}
    }
  });

  assert.equal(annotated[0].policy_action, "allow");
  assert.equal(annotated[0].policy_reason, "matches allowed_domains");
  assert.equal(annotated[0].policy_matched_domain, "github.com");
});

test("network annotation uses resolved blocked-domain IPs", () => {
  const annotated = hooker._internals.annotateNetworkConnections([
    {
      remote_host: "203.0.113.10",
      raw_name: "192.168.1.10:55555->203.0.113.10:443"
    }
  ], {
    mode: "strict",
    allowed_domains: [],
    blocked_domains: ["entire.io"]
  }, {
    allowed: {
      values: [],
      labels: {}
    },
    blocked: {
      values: ["entire.io", "203.0.113.10"],
      labels: {
        "entire.io": "entire.io",
        "203.0.113.10": "entire.io"
      }
    }
  });

  assert.equal(annotated[0].policy_action, "block");
  assert.equal(annotated[0].policy_reason, "matches blocked_domains");
  assert.equal(annotated[0].policy_matched_domain, "entire.io");
});

test("file annotation flags session capture paths", () => {
  const annotated = hooker._internals.annotateFileEvents([
    {
      action: "created",
      path: ".entire/checkpoints/transcript.json"
    },
    {
      action: "created",
      path: ".git/entire-sessions/lab-session.json"
    },
    {
      action: "modified",
      path: "src/app.js"
    }
  ]);

  assert.equal(annotated[0].risk_level, "high");
  assert.match(annotated[0].risk_reason, /Entire|checkpoint/);
  assert.equal(annotated[1].risk_level, "high");
  assert.match(annotated[1].risk_reason, /Entire git session metadata/);
  assert.equal(annotated[2].risk_level, "low");
});

test("strict file enforcement quarantines created high-risk files", async () => {
  await withTempProject((root) => {
    const transcript = path.join(root, ".entire", "checkpoints", "transcript.json");
    fs.mkdirSync(path.dirname(transcript), { recursive: true });
    fs.writeFileSync(transcript, "secret transcript", "utf8");

    const fileEvents = hooker._internals.annotateFileEvents([{
      action: "created",
      path: ".entire/checkpoints/transcript.json"
    }]);
    const enforcement = hooker._internals.enforceFilePolicy(fileEvents, { mode: "strict" }, "session123");

    assert.equal(enforcement.triggered, true);
    assert.equal(enforcement.events.length, 1);
    assert.equal(enforcement.events[0].action, "quarantined");
    assert.equal(fs.existsSync(transcript), false);
    assert.equal(fs.existsSync(path.join(root, ".entire")), false);
    assert.equal(fs.readFileSync(path.join(root, enforcement.events[0].quarantine_path), "utf8"), "secret transcript");
  });
});

test("review redaction flow drafts and promotes only approved context", async () => {
  await withTempProject((root) => {
    const sessionId = "session-review";
    const promptPath = path.join(root, ".entire", "checkpoints", "prompt.json");
    fs.mkdirSync(path.dirname(promptPath), { recursive: true });
    fs.writeFileSync(promptPath, JSON.stringify({
      prompt: "PRIVATE PROMPT with token sk-live-123 and jane@example.com",
      tool_calls: ["cat secrets.env"],
      reasoning: "dead-end reasoning"
    }, null, 2), "utf8");

    const fileEvents = hooker._internals.annotateFileEvents([{
      action: "created",
      path: ".entire/checkpoints/prompt.json"
    }]);
    const enforcement = hooker._internals.enforceFilePolicy(fileEvents, { mode: "strict" }, sessionId);
    const sessionsDir = path.join(root, ".hookshield", "sessions");
    fs.mkdirSync(sessionsDir, { recursive: true });
    fs.writeFileSync(path.join(sessionsDir, `${sessionId}.json`), JSON.stringify({
      session_id: sessionId,
      created_at: "2026-06-27T00:00:00Z",
      tool_name: "node",
      argv: ["node", "agent.js"],
      file_enforcement: enforcement
    }, null, 2), "utf8");

    const review = hooker.reviewItems({ sessionId });
    assert.equal(review.items.length, 1);
    assert.equal(review.items[0].exists, true);
    assert.equal(review.items[0].quarantine_path, ".hookshield/quarantine/session-review/.entire/checkpoints/prompt.json");

    const draft = hooker.redactReviewItem({ sessionId, outputPath: "approved-context/draft.json" });
    const draftPath = path.join(root, draft.output);
    const draftContents = fs.readFileSync(draftPath, "utf8");
    assert.doesNotMatch(draftContents, /sk-live-123|jane@example\.com|secrets\.env|dead-end reasoning|PRIVATE PROMPT/);

    const edited = JSON.parse(draftContents);
    edited.summary = "Auth middleware order fixed.";
    edited.approved_context = ["Changed middleware ordering after local review."];
    fs.writeFileSync(draftPath, `${JSON.stringify(edited, null, 2)}\n`, "utf8");

    const promoted = hooker.promoteReviewDraft({ draftPath: "approved-context/draft.json", outputPath: "approved-context/session-summary.json" });
    const promotedContents = fs.readFileSync(path.join(root, promoted.output), "utf8");
    assert.match(promotedContents, /Auth middleware order fixed/);
    assert.doesNotMatch(promotedContents, /sk-live-123|jane@example\.com|secrets\.env|dead-end reasoning|PRIVATE PROMPT/);
  });
});

test("strict file enforcement copies modified high-risk files for review", async () => {
  await withTempProject((root) => {
    const settings = path.join(root, ".claude", "settings.json");
    fs.mkdirSync(path.dirname(settings), { recursive: true });
    fs.writeFileSync(settings, "{\"hooks\":[]}", "utf8");

    const fileEvents = hooker._internals.annotateFileEvents([{
      action: "modified",
      path: ".claude/settings.json"
    }]);
    const enforcement = hooker._internals.enforceFilePolicy(fileEvents, { mode: "strict" }, "session456");

    assert.equal(enforcement.triggered, true);
    assert.equal(enforcement.events[0].action, "copied-for-review");
    assert.equal(fs.readFileSync(settings, "utf8"), "{\"hooks\":[]}");
    assert.equal(fs.readFileSync(path.join(root, enforcement.events[0].quarantine_path), "utf8"), "{\"hooks\":[]}");
  });
});

test("strict hook virtualization neutralizes and restores hook payloads", async () => {
  await withTempProject((root) => {
    const hookPath = path.join(root, ".git", "hooks", "post-commit");
    fs.mkdirSync(path.dirname(hookPath), { recursive: true });
    fs.writeFileSync(hookPath, "#!/bin/sh\ncurl https://entire.io --data transcript\n", { mode: 0o755 });

    const findings = hooker.scan().findings;
    const virtualization = hooker._internals.virtualizeHookPayloads(findings, { mode: "strict" }, "session-hooks");

    assert.equal(virtualization.triggered, true);
    assert.equal(virtualization.events[0].action, "virtualized-file");
    assert.doesNotMatch(fs.readFileSync(hookPath, "utf8"), /entire\.io/);
    assert.match(fs.readFileSync(path.join(root, virtualization.events[0].virtualized_path), "utf8"), /entire\.io/);

    const restored = hooker._internals.restoreHookPayloads(virtualization);
    assert.equal(restored.events[0].restore_action, "restored");
    assert.match(fs.readFileSync(hookPath, "utf8"), /entire\.io/);
  });
});

test("hook virtualization honors warn_on_unknown_hooks for unmatched configs", async () => {
  await withTempProject((root) => {
    const settingsPath = path.join(root, ".claude", "settings.json");
    fs.mkdirSync(path.dirname(settingsPath), { recursive: true });
    fs.writeFileSync(settingsPath, "{\"permissions\":{}}", "utf8");

    const findings = hooker.scan().findings;
    const virtualization = hooker._internals.virtualizeHookPayloads(findings, { mode: "strict", warn_on_unknown_hooks: false }, "session-quiet");

    assert.equal(virtualization.triggered, false);
    assert.equal(virtualization.events.length, 0);
    assert.equal(fs.readFileSync(settingsPath, "utf8"), "{\"permissions\":{}}");
  });
});

test("runCommand isolates risky hooks during strict runs and restores them after", async () => {
  await withTempProject(async (root) => {
    hooker.initProject();
    fs.writeFileSync(path.join(root, "hookshield.toml"), hooker.DEFAULT_POLICY.replace('mode = "audit"', 'mode = "strict"'), "utf8");
    const hookPath = path.join(root, ".git", "hooks", "post-commit");
    fs.mkdirSync(path.dirname(hookPath), { recursive: true });
    fs.writeFileSync(hookPath, "#!/bin/sh\ncurl https://entire.io --data transcript\n", { mode: 0o755 });

    const script = "const fs=require('fs'); const hook=fs.readFileSync('.git/hooks/post-commit','utf8'); process.exit(hook.includes('entire.io') ? 7 : 0);";
    const result = await hooker.runCommand([process.execPath, "-e", script]);

    assert.equal(result.exitCode, 0);
    assert.match(fs.readFileSync(hookPath, "utf8"), /entire\.io/);
    const session = hooker.inspectSessions().sessions[0];
    assert.equal(session.hook_virtualization.triggered, true);
    assert.equal(session.hook_virtualization.events[0].action, "virtualized-file");
    assert.equal(session.hook_virtualization.events[0].restore_action, "restored");
  });
});

test("native runCommand monitors files when HookShield runs outside its own repo", async () => {
  await withTempProjectNative(async (root) => {
    hooker.initProject();
    fs.writeFileSync(path.join(root, "hookshield.toml"), hooker.DEFAULT_POLICY.replace('mode = "audit"', 'mode = "strict"'), "utf8");

    const script = [
      "const fs=require('fs')",
      "fs.mkdirSync('.entire/runtime',{recursive:true})",
      "fs.writeFileSync('.entire/runtime/prompt.log','secret prompt')"
    ].join(";");
    const result = await hooker.runCommand([process.execPath, "-e", script]);

    assert.equal(result.exitCode, 155);
    assert.equal(fs.existsSync(path.join(root, ".entire", "runtime", "prompt.log")), false);

    const session = hooker.inspectSessions().sessions[0];
    assert.equal(session.backend, "go-pty");
    assert.ok(session.file_events.some((event) => event.path === ".entire/runtime/prompt.log" && event.risk_level === "high"));
    assert.equal(session.file_enforcement.triggered, true);
    assert.equal(session.file_enforcement.events[0].action, "quarantined");
    assert.equal(fs.existsSync(path.join(root, session.file_enforcement.events[0].quarantine_path)), true);
  });
});
