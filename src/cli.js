"use strict";

const {
  encryptFile,
  decryptFile,
  exportKey,
  importKey,
  initProject,
  inspectSessions,
  loadPolicy,
  promoteReviewDraft,
  redactReviewItem,
  revealReviewItem,
  reviewItems,
  rotateKey,
  runCommand,
  scan,
  status,
  trustReport
} = require("./hooker");

const USAGE = `hookshield - local AI agent security tool

Usage:
  hookshield init [--yes]
  hookshield scan [--json]
  hookshield status [--json]
  hookshield run -- <command> [args...]
  hookshield inspect [--json] [--session <id>]
  hookshield review [--json] [--session <id>]
  hookshield reveal --i-understand [--json] [--session <id>] [--item <path>]
  hookshield redact [--session <id>] [--item <path>] [--out <path>]
  hookshield promote --draft <path> --out <path>
  hookshield encrypt-file <path>
  hookshield decrypt-file <path.enc>
  hookshield rotate-key [--yes]
  hookshield export-key
  hookshield import-key <key-hex>
  hookshield trust-report [--json]

Environment:
  HOOKSHIELD_HOME     Override ~/.hookshield
  HOOKSHIELD_PROJECT  Override current project root

Compatibility:
  The legacy hooker command and HOOKER_* environment variables still work.
`;

function hasFlag(args, flag) {
  return args.includes(flag);
}

function withoutFlags(args) {
  return args.filter((arg) => !arg.startsWith("--"));
}

function flagValue(args, flag) {
  const index = args.indexOf(flag);
  if (index === -1) return null;
  return args[index + 1] || null;
}

function printJson(value) {
  console.log(JSON.stringify(value, null, 2));
}

function printFindings(findings) {
  if (findings.length === 0) {
    console.log("No hook or reporting risks found.");
    return;
  }

  for (const finding of findings) {
    console.log(`[${finding.severity}] ${finding.type}: ${finding.path}`);
    if (finding.matches.length > 0) {
      console.log(`  matches: ${finding.matches.join(", ")}`);
    }
  }
}

function sessionMatches(session, requestedId) {
  if (!requestedId) return true;
  return session.session_id === requestedId || session.session_id.startsWith(requestedId);
}

function printSessionSummary(session) {
  const connectionCount = Array.isArray(session.network_connections) ? session.network_connections.length : 0;
  const fileEventCount = Array.isArray(session.file_events) ? session.file_events.length : 0;
  const highRiskFileEventCount = Array.isArray(session.file_events) ? session.file_events.filter((event) => event.risk_level === "high").length : 0;
  const networkEnforcementCount = session.network_enforcement && Array.isArray(session.network_enforcement.events) ? session.network_enforcement.events.length : 0;
  const fileEnforcementCount = session.file_enforcement && Array.isArray(session.file_enforcement.events) ? session.file_enforcement.events.length : 0;
  const hookVirtualizationCount = session.hook_virtualization && Array.isArray(session.hook_virtualization.events) ? session.hook_virtualization.events.length : 0;
  const backend = session.backend || "unknown";
  const exit = session.exit_code === undefined || session.exit_code === null ? "pending" : session.exit_code;
  console.log(`${session.session_id} ${session.tool_name} backend=${backend} exit=${exit} files=${fileEventCount}/${highRiskFileEventCount}high file_enforcement=${fileEnforcementCount} hooks=${hookVirtualizationCount} connections=${connectionCount} network_enforcement=${networkEnforcementCount} created=${session.created_at}`);
}

function printSessionDetail(session) {
  const command = Array.isArray(session.argv) ? session.argv.join(" ") : session.tool_name;
  console.log(`Session: ${session.session_id}`);
  console.log(`Command: ${command}`);
  console.log(`Policy: ${session.policy_name || "unknown"}`);
  console.log(`Backend: ${session.backend || "unknown"}`);
  console.log(`Exit: ${session.exit_code === undefined || session.exit_code === null ? "pending" : session.exit_code}${session.signal ? ` (${session.signal})` : ""}`);
  console.log(`Started: ${session.created_at}`);
  console.log(`Finished: ${session.finished_at || "pending"}`);
  console.log(`Runner PID: ${session.runner_pid || "n/a"}`);
  console.log(`Child PID: ${session.child_pid || "n/a"}`);
  console.log(`Observed PIDs: ${Array.isArray(session.observed_pids) && session.observed_pids.length > 0 ? session.observed_pids.join(", ") : "none"}`);

  const fileEvents = Array.isArray(session.file_events) ? session.file_events : [];
  console.log("");
  console.log(`File Events: ${fileEvents.length}`);
  if (fileEvents.length === 0) {
    console.log("  none observed");
  } else {
    for (const event of fileEvents) {
      const risk = event.risk_level || "unknown";
      console.log(`  ${event.action || "changed"} ${event.path || "?"} risk=${risk}`);
      if (event.risk_reason) {
        console.log(`    reason: ${event.risk_reason}`);
      }
      if (event.size_before !== undefined || event.size_after !== undefined) {
        console.log(`    size: ${event.size_before ?? "-"} -> ${event.size_after ?? "-"}`);
      }
    }
  }

  const fileEnforcementEvents = session.file_enforcement && Array.isArray(session.file_enforcement.events) ? session.file_enforcement.events : [];
  console.log("");
  console.log(`File Enforcement Events: ${fileEnforcementEvents.length}`);
  if (fileEnforcementEvents.length === 0) {
    console.log("  none");
  } else {
    for (const event of fileEnforcementEvents) {
      const quarantine = event.quarantine_path ? ` -> ${event.quarantine_path}` : "";
      console.log(`  ${event.action || "action"} ${event.path || "?"}${quarantine}`);
      console.log(`    reason: ${event.reason || "no reason"}`);
      if (event.detail) {
        console.log(`    detail: ${event.detail}`);
      }
    }
  }

  const hookVirtualizationEvents = session.hook_virtualization && Array.isArray(session.hook_virtualization.events) ? session.hook_virtualization.events : [];
  console.log("");
  console.log(`Hook Virtualization Events: ${hookVirtualizationEvents.length}`);
  if (hookVirtualizationEvents.length === 0) {
    console.log("  none");
  } else {
    for (const event of hookVirtualizationEvents) {
      const archived = event.virtualized_path ? ` -> ${event.virtualized_path}` : "";
      const restored = event.restore_action ? ` restore=${event.restore_action}` : "";
      console.log(`  ${event.action || "action"} ${event.path || "?"}${archived}${restored}`);
      console.log(`    reason: ${event.reason || "no reason"}`);
      if (event.detail) {
        console.log(`    detail: ${event.detail}`);
      }
      if (event.restore_detail) {
        console.log(`    restore detail: ${event.restore_detail}`);
      }
    }
  }

  const connections = Array.isArray(session.network_connections) ? session.network_connections : [];
  console.log("");
  console.log(`Network Connections: ${connections.length}`);
  if (connections.length === 0) {
    console.log("  none observed");
  } else {
    for (const connection of connections) {
      const action = connection.policy_action || "unknown";
      const matched = connection.policy_matched_domain ? ` matched=${connection.policy_matched_domain}` : "";
      const state = connection.state ? ` state=${connection.state}` : "";
      console.log(`  ${action}${matched}: ${connection.command || "process"}[${connection.pid || "?"}] ${connection.protocol || "?"} ${connection.local || "?"} -> ${connection.remote || "?"}${state}`);
      if (connection.policy_reason) {
        console.log(`    reason: ${connection.policy_reason}`);
      }
    }
  }

  const events = session.network_enforcement && Array.isArray(session.network_enforcement.events) ? session.network_enforcement.events : [];
  console.log("");
  console.log(`Enforcement Events: ${events.length}`);
  if (events.length === 0) {
    console.log("  none");
  } else {
    for (const event of events) {
      const conn = event.connection || {};
      console.log(`  ${event.action || "action"} at ${event.at || "unknown"}: ${event.reason || "no reason"}`);
      console.log(`    ${conn.command || "process"}[${conn.pid || "?"}] ${conn.local || "?"} -> ${conn.remote || "?"}`);
    }
  }
}

async function main(args) {
  const command = args[0];

  if (!command || command === "help" || command === "--help" || command === "-h") {
    console.log(USAGE);
    return;
  }

  if (command === "init") {
    const result = initProject({ yes: hasFlag(args, "--yes") });
    console.log(result.created ? `Initialized HookShield at ${result.projectRoot}` : `HookShield already initialized at ${result.projectRoot}`);
    console.log(`Policy: ${result.policyPath}`);
    return;
  }

  if (command === "scan") {
    const result = scan();
    if (hasFlag(args, "--json")) {
      printJson(result);
    } else {
      console.log(`Project: ${result.projectRoot}`);
      printFindings(result.findings);
    }
    return;
  }

  if (command === "status") {
    const result = status();
    if (hasFlag(args, "--json")) {
      printJson(result);
    } else {
      console.log(`HookShield home: ${result.hookShieldHome || result.hookerHome}`);
      console.log(`Project: ${result.projectRoot}`);
      console.log(`Policy mode: ${result.policy.mode}`);
      console.log(`Master key: ${result.masterKeyPresent ? "present" : "missing"}`);
      console.log(`Findings: ${result.findings.length}`);
      console.log(`Sessions: ${result.sessions.length}`);
    }
    return;
  }

  if (command === "run") {
    const separator = args.indexOf("--");
    const runArgs = separator >= 0 ? args.slice(separator + 1) : args.slice(1);
    if (runArgs.length === 0) {
      throw new Error("hookshield run requires a command. Example: hookshield run -- node --version");
    }
    const result = await runCommand(runArgs);
    process.exitCode = result.exitCode;
    return;
  }

  if (command === "inspect") {
    const result = inspectSessions();
    const requestedSession = flagValue(args, "--session");
    const sessions = result.sessions.filter((session) => sessionMatches(session, requestedSession));
    if (requestedSession && sessions.length === 0) {
      throw new Error(`No HookShield session matches ${requestedSession}`);
    }
    if (hasFlag(args, "--json")) {
      printJson(requestedSession ? { projectRoot: result.projectRoot, sessions } : result);
    } else if (sessions.length === 0) {
      console.log("No HookShield sessions recorded.");
    } else if (requestedSession) {
      printSessionDetail(sessions[0]);
    } else {
      for (const session of sessions) printSessionSummary(session);
    }
    return;
  }

  if (command === "review") {
    const result = reviewItems({ sessionId: flagValue(args, "--session") });
    if (hasFlag(args, "--json")) {
      printJson(result);
    } else if (!result.session) {
      console.log("No HookShield sessions recorded.");
    } else if (result.items.length === 0) {
      console.log(`No quarantined review items for session ${result.session.session_id}.`);
    } else {
      console.log(`Session: ${result.session.session_id}`);
      for (const item of result.items) {
        console.log(`${item.exists ? "READY" : "MISSING"} ${item.path} -> ${item.quarantine_path} (${item.reason || "review"})`);
      }
    }
    return;
  }

  if (command === "redact") {
    const result = redactReviewItem({
      sessionId: flagValue(args, "--session"),
      quarantinePath: flagValue(args, "--item"),
      outputPath: flagValue(args, "--out")
    });
    console.log(`Created sanitized draft ${result.output} from ${result.source}`);
    return;
  }

  if (command === "reveal") {
    const result = revealReviewItem({
      sessionId: flagValue(args, "--session"),
      quarantinePath: flagValue(args, "--item"),
      confirm: hasFlag(args, "--i-understand")
    });
    if (hasFlag(args, "--json")) {
      printJson(result);
    } else {
      console.log(`Raw quarantined item: ${result.source_path}`);
      console.log(`Quarantine path: ${result.quarantine_path}`);
      console.log("");
      console.log(result.content);
    }
    return;
  }

  if (command === "promote") {
    const result = promoteReviewDraft({
      draftPath: flagValue(args, "--draft"),
      outputPath: flagValue(args, "--out")
    });
    console.log(`Promoted ${result.draft} -> ${result.output}`);
    return;
  }

  if (command === "encrypt-file") {
    const [file] = withoutFlags(args.slice(1));
    if (!file) throw new Error("encrypt-file requires a path.");
    const result = encryptFile(file);
    console.log(`Encrypted ${result.input} -> ${result.output}`);
    return;
  }

  if (command === "decrypt-file") {
    const [file] = withoutFlags(args.slice(1));
    if (!file) throw new Error("decrypt-file requires a path.");
    const result = decryptFile(file);
    console.log(`Decrypted ${result.input} -> ${result.output}`);
    return;
  }

  if (command === "rotate-key") {
    const result = rotateKey({ yes: hasFlag(args, "--yes") });
    console.log(`Rotated master key. Previous key backup: ${result.backupPath}`);
    return;
  }

  if (command === "export-key") {
    console.log(exportKey());
    return;
  }

  if (command === "import-key") {
    const [keyHex] = withoutFlags(args.slice(1));
    if (!keyHex) throw new Error("import-key requires a hex key.");
    const result = importKey(keyHex);
    console.log(`Imported master key at ${result.keyPath}`);
    return;
  }

  if (command === "trust-report") {
    const result = trustReport();
    if (hasFlag(args, "--json")) {
      printJson(result);
    } else {
      console.log(`Trust score: ${result.score}/100`);
      for (const item of result.items) {
        console.log(`${item.ok ? "OK" : "WARN"} ${item.label}: ${item.detail}`);
      }
    }
    return;
  }

  if (command === "policy") {
    printJson(loadPolicy());
    return;
  }

  throw new Error(`Unknown command: ${command}\n\n${USAGE}`);
}

module.exports = { main };
