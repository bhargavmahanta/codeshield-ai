import path from "node:path";

import * as vscode from "vscode";

import {
  EngineExecutionError,
  EngineProcessRunner,
  EditorSessionRunner,
  type Cancellation,
  type EditorSessionRequest,
  type EngineResult,
} from "./engine.js";
import {
  parseAttestationStatus,
  parseProtectionResult,
  parseProviderProfiles,
  parseScanResult,
  safeFindingMessage,
  safeRemediation,
  type SafeFinding,
  type SafeScanResult,
} from "./protocol.js";
import {
  contentFingerprint,
  formatOperationEvent,
  isBinaryText,
  normalizeRelativePath,
  resolveWorkspaceFile,
  resolveTrustedPolicy,
  safeSourcePath,
  validateOneBasedRange,
} from "./security.js";

const DIAGNOSTIC_SOURCE = "CodeShield";
const runners = new Map<string, EngineProcessRunner>();
const editorRunners = new Map<string, EditorSessionRunner>();
const activeOperations = new Set<string>();
let diagnostics: vscode.DiagnosticCollection;
let output: vscode.OutputChannel;
let status: vscode.StatusBarItem;

interface ProtectionTarget {
  readonly uri: string;
  readonly start: number;
  readonly end: number;
}

export function activate(context: vscode.ExtensionContext): void {
  diagnostics = vscode.languages.createDiagnosticCollection("codeshield");
  output = vscode.window.createOutputChannel("CodeShield");
  status = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 50);
  status.command = "codeshield.scanCurrentFile";
  setStatus("idle");
  status.show();

  context.subscriptions.push(
    diagnostics,
    output,
    status,
    register("codeshield.scanCurrentFile", () => scanActiveDocument(false)),
    register("codeshield.scanSelection", () => scanActiveDocument(true)),
    register("codeshield.scanWorkspace", scanWorkspace),
    register("codeshield.checkStaged", checkStaged),
    register("codeshield.protectSelection", protectSelection),
    register("codeshield.clearDiagnostics", clearDiagnostics),
    register("codeshield.showDetectorStatus", () => showDetectorStatus(context)),
    register("codeshield.showProviderProfiles", showProviderProfiles),
    register(
      "codeshield.verifyProviderAttestation",
      verifyProviderAttestation,
    ),
    vscode.workspace.onDidSaveTextDocument((document) => {
      const configuration = vscode.workspace.getConfiguration(
        "codeshield",
        document.uri,
      );
      if (
        vscode.workspace.isTrusted &&
        configuration.get<boolean>("scanOnSave", false)
      ) {
        void scanDocument(document, undefined, false);
      }
    }),
    vscode.languages.registerHoverProvider(
      [{ scheme: "file" }, { scheme: "untitled" }],
      {
        provideHover(document, position) {
          const matching = diagnostics
            .get(document.uri)
            ?.find(
              (diagnostic) =>
                diagnostic.source === DIAGNOSTIC_SOURCE &&
                diagnostic.range.contains(position),
            );
          if (!matching) {
            return undefined;
          }
          const markdown = new vscode.MarkdownString(undefined, true);
          markdown.appendText(matching.message);
          markdown.appendMarkdown("\n\n");
          markdown.appendText("Use a confirmed CodeShield protection edit or review locally.");
          markdown.isTrusted = false;
          return new vscode.Hover(markdown, matching.range);
        },
      },
    ),
    vscode.languages.registerCodeActionsProvider(
      [{ scheme: "file" }, { scheme: "untitled" }],
      {
        provideCodeActions(document, _range, actionContext) {
          return actionContext.diagnostics
            .filter((item) => item.source === DIAGNOSTIC_SOURCE)
            .map((item) => {
              const action = new vscode.CodeAction(
                "Protect this finding…",
                vscode.CodeActionKind.QuickFix,
              );
              action.command = {
                command: "codeshield.protectSelection",
                title: "Protect this finding…",
                arguments: [
                  {
                    uri: document.uri.toString(),
                    start: document.offsetAt(item.range.start),
                    end: document.offsetAt(item.range.end),
                  } satisfies ProtectionTarget,
                ],
              };
              action.diagnostics = [item];
              return action;
            });
        },
      },
      {
        providedCodeActionKinds: [vscode.CodeActionKind.QuickFix],
      },
    ),
  );
}

export function deactivate(): void {
  for (const runner of editorRunners.values()) {
    runner.dispose();
  }
  editorRunners.clear();
  runners.clear();
  activeOperations.clear();
}

async function scanActiveDocument(selectionOnly: boolean): Promise<void> {
  const editor = vscode.window.activeTextEditor;
  if (!editor) {
    await vscode.window.showInformationMessage("CodeShield: no active text editor.");
    return;
  }
  const selection =
    selectionOnly && !editor.selection.isEmpty ? editor.selection : undefined;
  if (selectionOnly && !selection) {
    await vscode.window.showInformationMessage("CodeShield: select text to scan.");
    return;
  }
  await scanDocument(editor.document, selection, true);
}

async function scanDocument(
  document: vscode.TextDocument,
  range: vscode.Range | undefined,
  showProgress: boolean,
): Promise<void> {
  if (!requireTrustedWorkspace()) {
    return;
  }
  const location = documentLocation(document);
  if (!location) {
    await vscode.window.showWarningMessage(
      "CodeShield: open the document in a trusted workspace.",
    );
    return;
  }
  const text = range ? document.getText(range) : document.getText();
  const configuration = configurationFor(document.uri);
  const maxBytes = configuration.get<number>("maxFileBytes", 1_000_000);
  if (isBinaryText(text) || Buffer.byteLength(text, "utf8") > maxBytes) {
    logEvent("CS_SCAN_SKIPPED");
    return;
  }
  const version = document.version;
  const baseOffset = range ? document.offsetAt(range.start) : 0;
  const policy = policyValue(location.root, configuration);
  const request: EditorSessionRequest = {
    command: "scan-text",
    content: text,
    repository: location.root.uri.fsPath,
    source_path: location.sourcePath,
    destination: configuration.get<string>("destination", "local_file"),
    profile: configuration.get<string>("detectorProfile", "core"),
    max_input_bytes: maxBytes,
    ...(policy ? { policy } : {}),
  };
  const timeoutMs =
    boundedSetting(configuration, "scanTimeoutSeconds", 15, 1, 120) * 1000;

  const operation = async (token?: vscode.CancellationToken) => {
    setStatus("scanning");
    try {
      const result = await executeEditor(
        location.root.uri.fsPath,
        request,
        timeoutMs,
        token,
      );
      if (![0, 1, 2].includes(result.exitCode)) {
        throw new EngineExecutionError("CS_ENGINE_EXECUTION_FAILED");
      }
      const parsed = parseScanResult(result.stdout, text.length);
      if (document.version !== version) {
        logEvent("CS_SCAN_STALE");
        return;
      }
      const mapped = parsed.findings.map((finding) =>
        diagnosticForFinding(document, finding, baseOffset),
      );
      diagnostics.set(document.uri, mapped);
      setRiskStatus(parsed);
      logEvent(
        "CS_SCAN_COMPLETED",
        parsed.findings.length,
        highestSeverity(parsed),
      );
    } catch (error) {
      setStatus("error");
      await showSafeError(error);
    }
  };

  if (showProgress) {
    await vscode.window.withProgress(
      {
        location: vscode.ProgressLocation.Notification,
        title: "CodeShield: scanning locally",
        cancellable: true,
      },
      async (_progress, token) => operation(token),
    );
  } else {
    const source = new vscode.CancellationTokenSource();
    try {
      await operation(source.token);
    } finally {
      source.dispose();
    }
  }
}

async function scanWorkspace(): Promise<void> {
  if (!requireTrustedWorkspace()) {
    return;
  }
  const folders = vscode.workspace.workspaceFolders ?? [];
  if (folders.length === 0) {
    await vscode.window.showWarningMessage("CodeShield: open a workspace to scan.");
    return;
  }
  await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: "CodeShield: scanning workspace locally",
      cancellable: true,
    },
    async (_progress, token) => {
      for (const folder of folders) {
        if (token.isCancellationRequested) {
          return;
        }
        const configuration = configurationFor(folder.uri);
        const args = [
          "scan",
          folder.uri.fsPath,
          "--destination",
          configuration.get<string>("destination", "local_file"),
          "--format",
          "json",
          "--relative-paths",
          "--max-file-size",
          String(configuration.get<number>("maxFileBytes", 1_000_000)),
          "--timeout",
          String(
            boundedSetting(
              configuration,
              "workspaceTimeoutSeconds",
              120,
              5,
              600,
            ),
          ),
          ...policyArguments(folder, configuration),
        ];
        try {
          const result = await execute(
            folder.uri.fsPath,
            args,
            "",
            boundedSetting(
              configuration,
              "workspaceTimeoutSeconds",
              120,
              5,
              600,
            ) * 1000,
            token,
          );
          if (![0, 1, 2].includes(result.exitCode)) {
            throw new EngineExecutionError("CS_ENGINE_EXECUTION_FAILED");
          }
          const parsed = parseScanResult(result.stdout);
          await applyPathDiagnostics(folder, parsed);
          setRiskStatus(parsed);
          logEvent(
            "CS_WORKSPACE_SCAN_COMPLETED",
            parsed.findings.length,
            highestSeverity(parsed),
          );
        } catch (error) {
          setStatus("error");
          await showSafeError(error);
          return;
        }
      }
    },
  );
}

async function checkStaged(): Promise<void> {
  if (!requireTrustedWorkspace()) {
    return;
  }
  const folder = await pickWorkspaceFolder("Select the repository to check");
  if (!folder) {
    return;
  }
  const configuration = configurationFor(folder.uri);
  const timeout =
    boundedSetting(configuration, "workspaceTimeoutSeconds", 120, 5, 600) * 1000;
  const args = [
    "check-staged",
    "--repository",
    folder.uri.fsPath,
    "--destination",
    configuration.get<string>("destination", "private_git"),
    "--format",
    "json",
    "--relative-paths",
    "--timeout",
    String(timeout / 1000),
    ...policyArguments(folder, configuration),
  ];
  await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: "CodeShield: checking staged changes locally",
      cancellable: true,
    },
    async (_progress, token) => {
      try {
        const result = await execute(folder.uri.fsPath, args, "", timeout, token);
        if (![0, 2].includes(result.exitCode)) {
          throw new EngineExecutionError("CS_ENGINE_EXECUTION_FAILED");
        }
        const parsed = parseScanResult(result.stdout);
        await applyPathDiagnostics(folder, parsed);
        setRiskStatus(parsed);
        logEvent(
          "CS_STAGED_CHECK_COMPLETED",
          parsed.findings.length,
          highestSeverity(parsed),
        );
      } catch (error) {
        setStatus("error");
        await showSafeError(error);
      }
    },
  );
}

async function protectSelection(target?: ProtectionTarget): Promise<void> {
  if (!requireTrustedWorkspace()) {
    return;
  }
  let editor = vscode.window.activeTextEditor;
  if (target) {
    const document = await vscode.workspace.openTextDocument(vscode.Uri.parse(target.uri));
    editor = await vscode.window.showTextDocument(document);
    editor.selection = new vscode.Selection(
      document.positionAt(target.start),
      document.positionAt(target.end),
    );
  }
  if (!editor || editor.selection.isEmpty) {
    await vscode.window.showInformationMessage(
      "CodeShield: select text to protect.",
    );
    return;
  }
  const document = editor.document;
  const range = new vscode.Range(editor.selection.start, editor.selection.end);
  const selected = document.getText(range);
  const location = documentLocation(document);
  if (!location) {
    await vscode.window.showWarningMessage(
      "CodeShield: open the document in a trusted workspace.",
    );
    return;
  }
  const configuration = configurationFor(document.uri);
  const mode = configuration.get<string>("protectionMode", "type_placeholder");
  const maxBytes = configuration.get<number>("maxFileBytes", 1_000_000);
  if (isBinaryText(selected) || Buffer.byteLength(selected, "utf8") > maxBytes) {
    await vscode.window.showWarningMessage(
      "CodeShield: selection is binary or exceeds the configured limit.",
    );
    return;
  }
  const originalVersion = document.version;
  const originalHash = contentFingerprint(selected);
  const policy = policyValue(location.root, configuration);
  let vaultPath: string | undefined;
  if (mode === "pseudonymize") {
    vaultPath = configuration.get<string>("vaultPath", "");
    if (!vaultPath || !path.isAbsolute(vaultPath)) {
      await vscode.window.showWarningMessage(
        "CodeShield: configure an absolute local vault path for pseudonymization.",
      );
      return;
    }
  }
  const request: EditorSessionRequest = {
    command: "protect-text",
    content: selected,
    repository: location.root.uri.fsPath,
    source_path: location.sourcePath,
    destination: configuration.get<string>("destination", "local_file"),
    profile: configuration.get<string>("detectorProfile", "core"),
    mode,
    session: "vscode",
    max_input_bytes: maxBytes,
    ...(policy ? { policy } : {}),
    ...(vaultPath ? { vault: vaultPath } : {}),
  };
  const timeout =
    boundedSetting(configuration, "scanTimeoutSeconds", 15, 1, 120) * 1000;
  await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: "CodeShield: preparing local protection preview",
      cancellable: true,
    },
    async (_progress, token) => {
      try {
        const result = await executeEditor(
          location.root.uri.fsPath,
          request,
          timeout,
          token,
        );
        if (![0, 1, 2].includes(result.exitCode)) {
          throw new EngineExecutionError("CS_ENGINE_EXECUTION_FAILED");
        }
        const preview = parseProtectionResult(
          result.stdout,
          Math.max(2_000_000, maxBytes * 2),
        );
        if (preview.blocked) {
          await vscode.window.showWarningMessage(
            "CodeShield: policy blocked automatic protection.",
          );
          return;
        }
        if (preview.replacementCount === 0 || preview.protectedText === selected) {
          await vscode.window.showInformationMessage(
            "CodeShield: no eligible replacements were found.",
          );
          return;
        }
        const confirmation = await vscode.window.showWarningMessage(
          `CodeShield will apply ${preview.replacementCount} ${mode} replacement(s).`,
          { modal: true },
          "Apply protection",
        );
        if (confirmation !== "Apply protection") {
          return;
        }
        if (
          document.version !== originalVersion ||
          contentFingerprint(document.getText(range)) !== originalHash
        ) {
          await vscode.window.showWarningMessage(
            "CodeShield: the selection changed; protection was not applied.",
          );
          return;
        }
        const edit = new vscode.WorkspaceEdit();
        edit.replace(document.uri, range, preview.protectedText);
        if (!(await vscode.workspace.applyEdit(edit))) {
          throw new EngineExecutionError("CS_EDIT_FAILED");
        }
        diagnostics.delete(document.uri);
        logEvent("CS_PROTECTION_APPLIED", preview.replacementCount);
      } catch (error) {
        setStatus("error");
        await showSafeError(error);
      }
    },
  );
}

function clearDiagnostics(): void {
  diagnostics.clear();
  setStatus("idle");
  logEvent("CS_DIAGNOSTICS_CLEARED");
}

async function showDetectorStatus(context: vscode.ExtensionContext): Promise<void> {
  const folder = vscode.workspace.workspaceFolders?.[0];
  const root =
    vscode.workspace.isTrusted && folder ? folder.uri.fsPath : context.extensionPath;
  try {
    const result = await execute(
      root,
      ["detector", "status", "--repository", root],
      "",
      15_000,
    );
    if (result.exitCode !== 0) {
      throw new EngineExecutionError("CS_ENGINE_EXECUTION_FAILED");
    }
    const summary = parseDetectorStatus(result.stdout);
    await vscode.window.showInformationMessage(
      `CodeShield ${summary.profile}: ${summary.ready} ready, ${summary.unavailable} unavailable.`,
    );
  } catch (error) {
    await showSafeError(error);
  }
}

async function showProviderProfiles(): Promise<void> {
  const folder = vscode.workspace.workspaceFolders?.[0];
  const root = folder?.uri.fsPath ?? process.cwd();
  try {
    const result = await execute(
      root,
      ["provider", "list", "--format", "json"],
      "",
      15_000,
    );
    if (result.exitCode !== 0) {
      throw new EngineExecutionError("CS_ENGINE_EXECUTION_FAILED");
    }
    const profiles = parseProviderProfiles(result.stdout);
    await vscode.window.showQuickPick(
      profiles.map((profile) => ({
        label: profile.profileId,
        description: `${profile.provider} — ${profile.product}`,
        detail: `review due ${profile.reviewDue}; reference only ${String(profile.referenceOnly)}`,
      })),
      { title: "CodeShield reviewed provider profiles" },
    );
  } catch (error) {
    await showSafeError(error);
  }
}

async function verifyProviderAttestation(): Promise<void> {
  const folder = vscode.workspace.workspaceFolders?.[0];
  const root = folder?.uri.fsPath ?? process.cwd();
  const configuration = configurationFor(folder?.uri);
  const profile = configuration.get<string>("providerProfile", "openai-api-zdr");
  const attestation = configuration.get<string>("attestationId", "");
  const args = [
    "provider",
    "attestation-status",
    profile,
    "--format",
    "json",
  ];
  if (attestation) {
    args.push("--id", attestation);
  }
  try {
    const result = await execute(root, args, "", 15_000);
    if (result.exitCode !== 0) {
      throw new EngineExecutionError("CS_ENGINE_EXECUTION_FAILED");
    }
    const parsed = parseAttestationStatus(result.stdout);
    await vscode.window.showInformationMessage(
      `CodeShield attestation ${parsed.status} for ${parsed.profileId} (${parsed.profileVersion}).`,
    );
  } catch (error) {
    await showSafeError(error);
  }
}

async function execute(
  root: string,
  args: readonly string[],
  stdin: string,
  timeoutMs: number,
  token?: vscode.CancellationToken,
): Promise<EngineResult> {
  const executable = engineExecutable();
  if (!executable) {
    throw new EngineExecutionError("CS_ENGINE_MISSING");
  }
  const key = `${root}\0${executable}`;
  if (activeOperations.has(key)) {
    throw new EngineExecutionError("CS_ENGINE_BUSY");
  }
  activeOperations.add(key);
  let runner = runners.get(key);
  if (!runner) {
    runner = new EngineProcessRunner(executable, root);
    runners.set(key, runner);
  }
  try {
    await runner.verifyCompatibility(Math.min(timeoutMs, 15_000));
    return await runner.run(
      args,
      stdin,
      timeoutMs,
      token as Cancellation | undefined,
    );
  } finally {
    activeOperations.delete(key);
  }
}

async function executeEditor(
  root: string,
  request: EditorSessionRequest,
  timeoutMs: number,
  token?: vscode.CancellationToken,
): Promise<EngineResult> {
  const executable = engineExecutable();
  const key = `${root}\0${executable}`;
  if (activeOperations.has(key)) {
    throw new EngineExecutionError("CS_ENGINE_BUSY");
  }
  activeOperations.add(key);
  let commandRunner = runners.get(key);
  if (!commandRunner) {
    commandRunner = new EngineProcessRunner(executable, root);
    runners.set(key, commandRunner);
  }
  try {
    await commandRunner.verifyCompatibility(Math.min(timeoutMs, 15_000));
    let editorRunner = editorRunners.get(key);
    if (!editorRunner) {
      editorRunner = new EditorSessionRunner(executable, root);
      editorRunners.set(key, editorRunner);
    }
    return await editorRunner.run(
      request,
      timeoutMs,
      token as Cancellation | undefined,
    );
  } finally {
    activeOperations.delete(key);
  }
}

function engineExecutable(): string {
  const executable = vscode.workspace
    .getConfiguration("codeshield")
    .get<string>("enginePath", "codeshield")
    .trim();
  if (!executable) {
    throw new EngineExecutionError("CS_ENGINE_MISSING");
  }
  return executable;
}

function documentLocation(
  document: vscode.TextDocument,
): { root: vscode.WorkspaceFolder; sourcePath: string } | undefined {
  const root =
    vscode.workspace.getWorkspaceFolder(document.uri) ??
    vscode.workspace.workspaceFolders?.[0];
  if (!root) {
    return undefined;
  }
  if (document.uri.scheme === "untitled") {
    return {
      root,
      sourcePath: `untitled/${safeLanguageName(document.languageId)}.txt`,
    };
  }
  const relative = safeSourcePath(document.uri.fsPath, root.uri.fsPath);
  return relative ? { root, sourcePath: relative } : undefined;
}

function policyArguments(
  folder: vscode.WorkspaceFolder,
  configuration: vscode.WorkspaceConfiguration,
): string[] {
  const relative = policyValue(folder, configuration);
  return relative ? ["--policy", relative] : [];
}

function policyValue(
  folder: vscode.WorkspaceFolder,
  configuration: vscode.WorkspaceConfiguration,
): string | undefined {
  const configured = configuration.get<string>("policyPath", "").trim();
  return resolveTrustedPolicy(folder.uri.fsPath, configured);
}

function diagnosticForFinding(
  document: vscode.TextDocument,
  finding: SafeFinding,
  baseOffset: number,
): vscode.Diagnostic {
  const start = baseOffset + finding.start;
  const end = baseOffset + finding.end;
  if (start < 0 || end <= start || end > document.getText().length) {
    throw new Error("CS_ENGINE_RESULT_INVALID");
  }
  const diagnostic = new vscode.Diagnostic(
    new vscode.Range(document.positionAt(start), document.positionAt(end)),
    `${safeFindingMessage(finding)} ${safeRemediation(finding)}`,
    diagnosticSeverity(finding.severity),
  );
  diagnostic.source = DIAGNOSTIC_SOURCE;
  diagnostic.code = `CS.${finding.category}`;
  return diagnostic;
}

async function applyPathDiagnostics(
  folder: vscode.WorkspaceFolder,
  result: SafeScanResult,
): Promise<void> {
  const grouped = new Map<string, SafeFinding[]>();
  for (const finding of result.findings) {
    if (!finding.filePath) {
      throw new Error("CS_ENGINE_RESULT_INVALID");
    }
    const relative = normalizeRelativePath(finding.filePath);
    if (!relative) {
      throw new Error("CS_ENGINE_RESULT_INVALID");
    }
    const entries = grouped.get(relative) ?? [];
    entries.push(finding);
    grouped.set(relative, entries);
  }
  const prepared: Array<{
    uri: vscode.Uri;
    entries: vscode.Diagnostic[];
  }> = [];
  for (const [relative, findings] of grouped) {
    const resolved = resolveWorkspaceFile(folder.uri.fsPath, relative);
    const uri = vscode.Uri.file(resolved);
    const document = await vscode.workspace.openTextDocument(uri);
    const lineLengths = Array.from(
      { length: document.lineCount },
      (_value, index) => document.lineAt(index).text.length,
    );
    const mapped = findings.map((finding) => {
      if (!finding.line || !finding.column) {
        throw new Error("CS_ENGINE_RESULT_INVALID");
      }
      const validated = validateOneBasedRange(
        {
          line: finding.line,
          column: finding.column,
          ...(finding.endLine ? { endLine: finding.endLine } : {}),
          ...(finding.endColumn ? { endColumn: finding.endColumn } : {}),
        },
        lineLengths,
      );
      const start = new vscode.Position(
        validated.startLine,
        validated.startColumn,
      );
      const end = new vscode.Position(
        validated.endLine,
        validated.endColumn,
      );
      const diagnostic = new vscode.Diagnostic(
        new vscode.Range(start, end),
        `${safeFindingMessage(finding)} ${safeRemediation(finding)}`,
        diagnosticSeverity(finding.severity),
      );
      diagnostic.source = DIAGNOSTIC_SOURCE;
      diagnostic.code = `CS.${finding.category}`;
      return diagnostic;
    });
    prepared.push({ uri: document.uri, entries: mapped });
  }
  for (const item of prepared) {
    diagnostics.set(item.uri, item.entries);
  }
}

function diagnosticSeverity(value: string): vscode.DiagnosticSeverity {
  if (value === "critical" || value === "high") {
    return vscode.DiagnosticSeverity.Error;
  }
  if (value === "medium") {
    return vscode.DiagnosticSeverity.Warning;
  }
  return vscode.DiagnosticSeverity.Information;
}

function requireTrustedWorkspace(): boolean {
  if (vscode.workspace.isTrusted) {
    return true;
  }
  void vscode.window.showWarningMessage(
    "CodeShield: trust this workspace before scanning or protecting content.",
  );
  return false;
}

function configurationFor(uri?: vscode.Uri): vscode.WorkspaceConfiguration {
  return vscode.workspace.getConfiguration("codeshield", uri);
}

async function pickWorkspaceFolder(
  title: string,
): Promise<vscode.WorkspaceFolder | undefined> {
  const folders = vscode.workspace.workspaceFolders ?? [];
  if (folders.length <= 1) {
    return folders[0];
  }
  const selected = await vscode.window.showQuickPick(
    folders.map((folder) => ({ label: folder.name, folder })),
    { title },
  );
  return selected?.folder;
}

function boundedSetting(
  configuration: vscode.WorkspaceConfiguration,
  key: string,
  fallback: number,
  minimum: number,
  maximum: number,
): number {
  const value = configuration.get<number>(key, fallback);
  return Number.isFinite(value)
    ? Math.min(maximum, Math.max(minimum, value))
    : fallback;
}

function setRiskStatus(result: SafeScanResult): void {
  const highest = highestSeverity(result);
  status.text = `$(shield) CodeShield: ${result.findings.length} ${highest}`;
  status.tooltip = "Local CodeShield finding count and highest severity";
}

function highestSeverity(result: SafeScanResult): string {
  const rank: Record<string, number> = {
    low: 1,
    medium: 2,
    high: 3,
    critical: 4,
  };
  const highest = result.findings.reduce(
    (current, finding) =>
      (rank[finding.severity] ?? 0) > (rank[current] ?? 0)
        ? finding.severity
        : current,
    "none",
  );
  return highest;
}

function setStatus(state: "idle" | "scanning" | "error"): void {
  const icon = state === "scanning" ? "sync~spin" : state === "error" ? "error" : "shield";
  status.text = `$(${icon}) CodeShield: ${state}`;
  status.tooltip = "CodeShield local engine status";
}

function logEvent(
  code: string,
  count?: number,
  highest?: string,
): void {
  output.appendLine(formatOperationEvent(code, count, highest));
}

async function showSafeError(error: unknown): Promise<void> {
  const code =
    error instanceof EngineExecutionError
      ? error.code
      : error instanceof Error && /^CS_[A-Z_]+$/u.test(error.message)
        ? error.message
        : "CS_EXTENSION_ERROR";
  logEvent(code);
  const messages: Record<string, string> = {
    CS_ENGINE_MISSING: "CodeShield: the configured local engine is unavailable.",
    CS_ENGINE_VERSION_INCOMPATIBLE:
      "CodeShield: engine 0.7.x is required for this extension.",
    CS_ENGINE_BUSY: "CodeShield: another operation is already running for this workspace.",
    CS_ENGINE_TIMEOUT: "CodeShield: the local engine timed out.",
    CS_ENGINE_CANCELLED: "CodeShield: the operation was cancelled.",
    CS_POLICY_PATH_INVALID:
      "CodeShield: the configured policy must be a file inside the trusted workspace.",
    CS_EDIT_FAILED: "CodeShield: the confirmed edit could not be applied.",
    CS_ENGINE_RESULT_INVALID: "CodeShield: the local engine returned an invalid result.",
  };
  await vscode.window.showErrorMessage(
    messages[code] ?? "CodeShield: the local operation failed safely.",
  );
}

function parseDetectorStatus(raw: string): {
  profile: string;
  ready: number;
  unavailable: number;
} {
  let value: unknown;
  try {
    value = JSON.parse(raw) as unknown;
  } catch {
    throw new Error("CS_ENGINE_RESULT_INVALID");
  }
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error("CS_ENGINE_RESULT_INVALID");
  }
  const record = value as Record<string, unknown>;
  if (
    (record.profile !== "core" && record.profile !== "enhanced") ||
    !Array.isArray(record.detectors)
  ) {
    throw new Error("CS_ENGINE_RESULT_INVALID");
  }
  let ready = 0;
  let unavailable = 0;
  for (const item of record.detectors) {
    if (typeof item !== "object" || item === null || Array.isArray(item)) {
      throw new Error("CS_ENGINE_RESULT_INVALID");
    }
    const statusValue = (item as Record<string, unknown>).status;
    if (statusValue === "ready") {
      ready += 1;
    } else if (statusValue === "unavailable") {
      unavailable += 1;
    } else if (statusValue !== "disabled") {
      throw new Error("CS_ENGINE_RESULT_INVALID");
    }
  }
  return { profile: record.profile, ready, unavailable };
}

function safeLanguageName(value: string): string {
  return /^[A-Za-z0-9_-]{1,64}$/u.test(value) ? value : "text";
}

function register(
  command: string,
  handler: (...args: never[]) => unknown,
): vscode.Disposable {
  return vscode.commands.registerCommand(command, handler);
}
