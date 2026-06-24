# HookShield Roadmap

HookShield is coming soon and currently testing. This roadmap is intentionally short so the current direction is easy to inspect.

## Now

- Validate the CLI against real AI coding agent workflows.
- Improve detection for prompts, transcripts, tool-call logs, checkpoints, and hook/config artifacts.
- Keep the website and README honest about current capabilities and limitations.
- Add example sanitized reports.

## Next

- Harden strict-mode network enforcement.
- Improve file monitoring beyond before/after snapshots.
- Add stronger platform coverage for macOS, Linux, and Windows.
- Add BYO LLM review hooks for local or user-selected filtering.
- Improve install flow once the package is ready to publish.

## Later

- Consider packet/firewall-level blocking integrations.
- Explore richer local review UI.
- Add signed releases and supply-chain hardening.
- Document stable policies for teams.

## Areas To Validate

- Real-world testing with Codex, Claude Code, Cursor, and other coding agents.
- Sanitized examples of session artifacts from tools HookShield should detect.
- Threat-model review from people who work on developer tooling or appsec.
- Docs feedback from first-time users.
