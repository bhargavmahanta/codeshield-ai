const assert = require("node:assert/strict");
const vscode = require("vscode");

async function run() {
  const extension = vscode.extensions.getExtension(
    "codeshield-ai.codeshield-ai",
  );
  assert.ok(extension);
  await extension.activate();
  const commands = new Set(await vscode.commands.getCommands(true));
  for (const command of [
    "codeshield.scanCurrentFile",
    "codeshield.scanSelection",
    "codeshield.scanWorkspace",
    "codeshield.checkStaged",
    "codeshield.protectSelection",
    "codeshield.clearDiagnostics",
    "codeshield.showDetectorStatus",
    "codeshield.showProviderProfiles",
    "codeshield.verifyProviderAttestation",
  ]) {
    assert.ok(commands.has(command), `${command} should be registered`);
  }

  assert.equal(vscode.workspace.isTrusted, true);
  const folder = vscode.workspace.workspaceFolders?.[0];
  assert.ok(folder);
  const configuration = vscode.workspace.getConfiguration("codeshield");
  const uri = vscode.Uri.joinPath(folder.uri, ".codeshield-extension-test.txt");
  const content = "contact=extension.person@example.test\n";
  try {
    await configuration.update(
      "enginePath",
      "codeshield",
      vscode.ConfigurationTarget.Global,
    );
    await vscode.workspace.fs.writeFile(uri, Buffer.from(content, "utf8"));
    const document = await vscode.workspace.openTextDocument(uri);
    await vscode.window.showTextDocument(document);
    await vscode.commands.executeCommand("codeshield.scanCurrentFile");

    const findings = vscode.languages
      .getDiagnostics(uri)
      .filter((diagnostic) => diagnostic.source === "CodeShield");
    assert.ok(findings.length > 0);
    assert.ok(findings.every((diagnostic) => !diagnostic.message.includes(content)));
    assert.ok(findings.every((diagnostic) => diagnostic.code === "CS.EMAIL"));

    await vscode.commands.executeCommand("codeshield.clearDiagnostics");
    assert.equal(vscode.languages.getDiagnostics(uri).length, 0);
  } finally {
    await vscode.workspace.fs.delete(uri, { useTrash: false }).then(
      () => undefined,
      () => undefined,
    );
    await configuration.update(
      "enginePath",
      undefined,
      vscode.ConfigurationTarget.Global,
    );
  }
}

module.exports = { run };
