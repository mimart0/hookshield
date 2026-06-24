"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const { main } = require("../src/cli");

function withTempProject(fn) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "hookshield-cli-test-"));
  const previousProject = process.env.HOOKSHIELD_PROJECT;
  const previousHome = process.env.HOOKSHIELD_HOME;
  process.env.HOOKSHIELD_PROJECT = root;
  process.env.HOOKSHIELD_HOME = path.join(root, "home");

  return Promise.resolve()
    .then(() => fn(root))
    .finally(() => {
      if (previousProject === undefined) delete process.env.HOOKSHIELD_PROJECT;
      else process.env.HOOKSHIELD_PROJECT = previousProject;
      if (previousHome === undefined) delete process.env.HOOKSHIELD_HOME;
      else process.env.HOOKSHIELD_HOME = previousHome;
      fs.rmSync(root, { recursive: true, force: true });
    });
}

async function captureStdout(fn) {
  const originalWrite = process.stdout.write;
  let output = "";
  process.stdout.write = (chunk, encoding, callback) => {
    output += chunk;
    if (typeof callback === "function") callback();
    return true;
  };
  try {
    await fn();
  } finally {
    process.stdout.write = originalWrite;
  }
  return output;
}

test("inspect --session prints readable session detail", async () => {
  await withTempProject(async (root) => {
    const sessionsDir = path.join(root, ".hookshield", "sessions");
    fs.mkdirSync(sessionsDir, { recursive: true });
    fs.writeFileSync(path.join(sessionsDir, "abc123.json"), JSON.stringify({
      session_id: "abc123",
      tool_name: "node",
      argv: ["node", "--version"],
      policy_name: "strict",
      backend: "go-pty",
      exit_code: 143,
      signal: "terminated",
      created_at: "2026-06-19T00:00:00Z",
      finished_at: "2026-06-19T00:00:01Z",
      runner_pid: 100,
      child_pid: 101,
      observed_pids: [101],
      file_events: [{
        action: "created",
        path: ".entire/checkpoints/transcript.json",
        size_after: 42,
        risk_level: "high",
        risk_reason: "Entire checkpoint directory"
      }],
      file_enforcement: {
        events: [{
          action: "quarantined",
          path: ".entire/checkpoints/transcript.json",
          quarantine_path: ".hookshield/quarantine/abc123/.entire/checkpoints/transcript.json",
          reason: "Entire checkpoint directory",
          detail: "created high-risk artifact moved out of the project path"
        }]
      },
      hook_virtualization: {
        events: [{
          action: "virtualized-file",
          path: ".git/hooks/post-commit",
          virtualized_path: ".hookshield/virtualized-hooks/abc123/.git/hooks/post-commit",
          reason: "matches: entire.io, transcript",
          detail: "file payload replaced with inert strict-mode stub",
          restore_action: "restored"
        }]
      },
      network_connections: [{
        pid: 101,
        command: "node",
        protocol: "TCP",
        local: "127.0.0.1:5000",
        remote: "203.0.113.10:443",
        state: "ESTABLISHED",
        policy_action: "block",
        policy_reason: "matches blocked_domains",
        policy_matched_domain: "entire.io"
      }],
      network_enforcement: {
        events: [{
          action: "terminate",
          at: "2026-06-19T00:00:01Z",
          reason: "matches blocked network policy",
          connection: {
            pid: 101,
            command: "node",
            local: "127.0.0.1:5000",
            remote: "203.0.113.10:443"
          }
        }]
      }
    }, null, 2), "utf8");

    const output = await captureStdout(() => main(["inspect", "--session", "abc"]));
    assert.match(output, /Session: abc123/);
    assert.match(output, /File Events: 1/);
    assert.match(output, /\.entire\/checkpoints\/transcript\.json risk=high/);
    assert.match(output, /File Enforcement Events: 1/);
    assert.match(output, /quarantined \.entire\/checkpoints\/transcript\.json/);
    assert.match(output, /Hook Virtualization Events: 1/);
    assert.match(output, /virtualized-file \.git\/hooks\/post-commit/);
    assert.match(output, /Network Connections: 1/);
    assert.match(output, /block matched=entire\.io/);
    assert.match(output, /Enforcement Events: 1/);
  });
});
