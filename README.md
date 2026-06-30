# HookShield

HookShield is a local-first review layer for AI coding sessions. It helps you see what prompts, tool calls, session files, hooks, and network activity an agent run may leave behind before that context becomes part of project history.

Status: coming soon, currently testing and looking for contributors.

The CLI is open source, MIT licensed, and does not send telemetry. The public website uses basic Google Analytics so we can understand launch traffic.

## What It Does

- Initializes a local `hookshield.toml` policy for a repo.
- Scans repo hooks, agent configs, and known session-reporting artifacts.
- Runs commands through `hookshield run -- <cmd>` using a native Go PTY backend when available.
- Records session metadata locally under `.hookshield/`.
- Samples child-process outbound sockets during wrapped runs.
- Records project file creations, modifications, and deletions during wrapped runs.
- Works with local AI coding CLIs when they are launched through `hookshield run -- ...`.
- Watches known local agent artifacts during wrapped runs, including Claude `~/.claude/projects/...`, Gemini `~/.gemini/tmp/...`, and Codex `~/.codex/sessions/...`.
- Encrypts/decrypts files with AES-256-GCM.
- Provides `status`, `inspect`, `review`, `redact`, `promote`, and `trust-report` commands.
- In strict mode, virtualizes risky hooks/configs and quarantines high-risk artifacts for review.

## What It Does Not Do Yet

HookShield is an early MVP. It is useful for testing and review workflows, but it is not a complete sandbox.

- It does not provide syscall-level filesystem monitoring.
- It does not provide packet/firewall-level blocking before a socket opens.
- It does not guarantee full DNS-history attribution for every IP-only socket.
- Hook virtualization is preflight file isolation, not full hook execution tracing.
- It cannot inspect hosted ChatGPT conversations that never create local files or run through the local wrapper.

Use it as a local review point, not as a hardened isolation boundary.

## Install From Source

This project is not published as a stable package yet. To try the current source build:

Prerequisites:

- Node 20 or newer
- Go, for the native PTY backend and native tests

```bash
gh repo clone mimart0/hookshield
cd hookshield
npm install
```

Then verify the CLI:

```bash
node bin/hookshield.js status
```

Run commands through the local source checkout:

```bash
node bin/hookshield.js init
node bin/hookshield.js scan
node bin/hookshield.js run -- node --version
```

Optional: if your npm global prefix is writable, `npm link` will create a global `hookshield` command. If it fails with `EACCES`, keep using `node bin/hookshield.js ...` or configure npm to use a user-owned global prefix.

## Quick Start

In a test repo:

```bash
node /path/to/hookshield/bin/hookshield.js init
node /path/to/hookshield/bin/hookshield.js scan
node /path/to/hookshield/bin/hookshield.js status
node /path/to/hookshield/bin/hookshield.js run -- node --version
node /path/to/hookshield/bin/hookshield.js inspect
node /path/to/hookshield/bin/hookshield.js review
node /path/to/hookshield/bin/hookshield.js trust-report
```

Inspect one session:

```bash
node /path/to/hookshield/bin/hookshield.js inspect --session <session-id-prefix>
```

Review quarantined prompt/session artifacts:

```bash
node /path/to/hookshield/bin/hookshield.js review
node /path/to/hookshield/bin/hookshield.js reveal --session <session-id-prefix> --item 2 --i-understand
node /path/to/hookshield/bin/hookshield.js approve --session <session-id-prefix> --item 2 --keep "Safe summary of what changed." --out approved-context/session-summary.json
node /path/to/hookshield/bin/hookshield.js redact --session <session-id-prefix> --item 2 --out approved-context/draft.json
# edit approved-context/draft.json
node /path/to/hookshield/bin/hookshield.js promote --draft approved-context/draft.json --out approved-context/session-summary.json
```

`review` numbers each quarantined item, so `--item 2` can be used with `reveal`, `redact`, or `approve`. `reveal` prints the raw quarantined item locally so you can manually decide what is safe to keep. `approve` writes only explicit `--keep` notes into approved context. `redact` still creates a sanitized draft when you want to edit JSON before promoting.

## Claude Code

HookShield can wrap Claude Code and review the local transcript artifacts Claude writes under `~/.claude/projects`.

Example:

```bash
node /path/to/hookshield/bin/hookshield.js init
# set mode = "strict" in hookshield.toml
node /path/to/hookshield/bin/hookshield.js run -- claude -p "Reply with exactly HOOKSHIELD_CLAUDE_REAL_TEST. Do not use tools." --output-format json --permission-mode default
node /path/to/hookshield/bin/hookshield.js review
```

In a real Claude Code test, Claude completed the API call, wrote a JSONL transcript under `~/.claude/projects/...`, and HookShield quarantined that transcript for local review. `reveal --i-understand` showed the raw prompt/session transcript locally; `redact` produced a draft that withheld the prompt, response, model/cost fields, and tool/agent listing.

Strict file enforcement and strict network enforcement are separate. If you want Claude's API call to complete during a strict run, configure `allowed_domains` for the required provider endpoints or set `deny_unencrypted_upload = false` while testing file quarantine. File enforcement still quarantines Claude transcript artifacts when `mode = "strict"`.

Run the real Claude automations:

```bash
npm run test:claude:real
npm run test:claude:batch:real
```

`test:claude:real` requires a working Claude Code login and makes a small API call through the Claude CLI. Set `CLAUDE_BIN=/path/to/claude` if `claude` is not on `PATH`. After verifying quarantine, the test copies Claude's real transcript back to `~/.claude` so it does not remove local Claude history.

`test:claude:batch:real` uses the Anthropic Messages API directly instead of the Claude CLI. It requires `ANTHROPIC_API_KEY` or `CLAUDE_API_KEY`, makes five small API calls, writes Claude-shaped local transcript artifacts in a temporary home directory, quarantines all five, and approves only prompts 2 and 4.

## OpenAI Codex

HookShield can wrap local Codex-style coding sessions when the agent is launched as a command from your repo:

```bash
node /path/to/hookshield/bin/hookshield.js init
# set mode = "strict" in hookshield.toml
node /path/to/hookshield/bin/hookshield.js run -- codex
node /path/to/hookshield/bin/hookshield.js review
```

During a wrapped Codex run, HookShield records the process tree, outbound sockets, and file changes visible from the local machine. In strict mode it quarantines newly created high-risk artifacts, including prompt-like files, transcript-like files, tool-call logs, checkpoints, git hook payloads, and known reporting artifacts.

If your Codex setup is launched by another desktop app instead of a shell command, run the underlying CLI or test command through `hookshield run -- ...` for coverage. HookShield only observes processes it starts.

Run the real Codex-style OpenAI batch automation:

```bash
npm run test:codex:batch:real
```

This uses the OpenAI Responses API and writes Codex-shaped local session artifacts under a temporary `~/.codex/sessions/...` directory. It requires `OPENAI_API_KEY`, makes five small API calls, quarantines all five artifacts, and approves only prompts 2 and 4. The default OpenAI model follows the current OpenAI latest-model guidance; override it with `OPENAI_MODEL` if your account uses a different model.

## Real Provider Batch Tests

The real batch tests are designed to exercise the full review loop without relying on provider CLIs staying attached to HookShield. Each test makes five real API calls, writes local provider-shaped session artifacts into a temporary home directory, lets HookShield quarantine all five, reveals and redacts each artifact, and promotes only sanitized notes for prompts 2 and 4.

Configure the keys you want to test:

```bash
export GEMINI_API_KEY=...
export ANTHROPIC_API_KEY=...
export OPENAI_API_KEY=...
```

Run the batch tests:

```bash
npm run test:gemini:batch:real
npm run test:claude:batch:real
npm run test:codex:batch:real
```

Provider model overrides are available with `GEMINI_MODEL`, `CLAUDE_MODEL`, and `OPENAI_MODEL`. Use `HOOKSHIELD_KEEP_TMP=1` to keep the temporary project and quarantine files after a successful run.

## ChatGPT

HookShield is a local tool, so ChatGPT coverage depends on where the session data lives:

- Local or CLI-driven ChatGPT/OpenAI coding workflows can be wrapped with `hookshield run -- <command>`.
- Browser-only ChatGPT conversations at `chatgpt.com` are not visible to HookShield unless they produce local files in the watched project or selected agent artifact paths.
- Exported transcripts, copied prompts, generated session logs, or local files created by ChatGPT-driven tooling can still be reviewed if they are inside the project or created during a wrapped run.

For hosted ChatGPT, treat HookShield as a local review layer for files and tool output, not as a browser account monitor.

Encrypt a session artifact:

```bash
node /path/to/hookshield/bin/hookshield.js encrypt-file ./some-session-log.txt
node /path/to/hookshield/bin/hookshield.js decrypt-file ./some-session-log.txt.enc
```

Legacy note: the old `hooker` command, `hooker.toml`, `.hooker/`, and `HOOKER_*` environment variables are still supported as compatibility aliases. New installs should use `hookshield`, `hookshield.toml`, `.hookshield/`, and `HOOKSHIELD_*`.

## Policy

`hookshield init` creates `hookshield.toml`:

```toml
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
```

Set `mode = "strict"` to enable strict enforcement behavior during wrapped runs.

## Strict Mode

When strict mode is active, HookShield:

- resolves `allowed_domains` and `blocked_domains` before launch
- records resolved policy hosts in session metadata
- attributes observed IP sockets back to matching policy domains when possible
- allows loopback/localhost sockets for local dev workflows
- terminates the wrapped process if it opens a blocked external socket
- terminates unknown external sockets when `deny_unencrypted_upload = true`
- records enforcement events in `hookshield inspect`
- temporarily virtualizes risky repo hooks and agent hook configs before launch
- restores the original hook/config payloads after the wrapped command exits
- quarantines newly created high-risk files such as `.entire/` checkpoints, Claude Code `~/.claude/projects` transcripts, Gemini `~/.gemini/tmp` sessions, Codex `~/.codex/sessions` transcripts, prompts, tool-call logs, and hook artifacts under `.hookshield/quarantine/<session-id>/`
- copies modified high-risk files into quarantine for review while preserving the original file in place
- exits with code `155` when file enforcement triggers after an otherwise successful command

## Architecture

- Session Broker: creates a session ID and encrypted data key for each run.
- Policy Engine: loads `hookshield.toml`.
- Scanner: audits `.entire`, agent configs, git hooks, and shell config references.
- Crypto Engine: stores a local master key and encrypts files with AES-256-GCM.
- Native PTY Runner: launches wrapped commands under `cmd/hookshield-pty` with real pseudoterminal ownership.
- Network Monitor: samples the wrapped process tree with `lsof` and records outbound sockets.
- File Monitor: snapshots project files and selected agent home artifacts before/after wrapped commands and records created, modified, and deleted files.
- Strict Network Enforcement: terminates wrapped processes that open blocked or unknown external connections in strict mode.
- Strict File Enforcement: quarantines newly created high-risk artifacts in strict mode and fails the wrapped run for review.
- Hook Payload Virtualization: replaces risky repo hooks and agent hook configs with inert stubs during strict-mode wrapped runs, preserving originals under `.hookshield/virtualized-hooks/<session-id>/`.
- DNS Policy Attribution: resolves policy domains before launch so IP-only socket records can still be attributed back to `allowed_domains` or `blocked_domains`.
- Node Fallback Runner: set `HOOKSHIELD_NATIVE=0` to use the simple stdio fallback.

## Test

```bash
npm test
```

Run only one layer:

```bash
npm run test:node
npm run test:e2e
npm run test:claude:real
npm run test:claude:batch:real
npm run test:codex:batch:real
npm run test:gemini:real
npm run test:gemini:batch:real
npm run test:native
```

The `*:real` scripts are opt-in because they require provider auth, network access, Node 20+, and small paid API calls. The batch real tests quarantine five provider-shaped local artifacts and promote only two sanitized review drafts.

Run syntax checks:

```bash
npm run lint
```

## Project Status

HookShield is currently testing. If you try it and find a bug, please open an issue with sanitized details. The roadmap is in [ROADMAP.md](ROADMAP.md).

## Security

Please do not open public issues for vulnerabilities or bypasses that expose private session context. See [SECURITY.md](SECURITY.md).
