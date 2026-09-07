# CodeShield AI for VS Code

CodeShield provides local sensitive-data diagnostics and confirmed protection
edits for trusted workspaces. It launches a separately installed CodeShield
`0.9.x` engine with fixed arguments and sends unsaved editor text only over
standard input.

Scanning is manual by default. `codeshield.scanOnSave` is opt-in, and the
extension never scans while typing. Content commands are disabled in untrusted
workspaces. The extension does not download an engine, use telemetry, or make
network requests.

See the repository's Phase 7 documentation for local VSIX installation,
settings, security properties, and limitations.
