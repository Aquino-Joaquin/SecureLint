import * as vscode from "vscode";

import { scanDocument } from "./services/scanner";
import { createHoverProvider } from "./hover/hoverProvider";
import { Vulnerability } from "./models/vulnerability";

// Store current vulnerabilities globally
let currentVulnerabilities: Vulnerability[] = [];

export function activate(context: vscode.ExtensionContext) {
  console.log("Security Scanner Active");

  // Create diagnostics collection
  const diagnosticCollection =
    vscode.languages.createDiagnosticCollection("security-scanner");

  // Main function to analyze the current document
  function analyzeDocument(editor: vscode.TextEditor) {
    const text = editor.document.getText();

    // Scan document for vulnerabilities
    currentVulnerabilities = scanDocument(text);

    console.log(currentVulnerabilities);

    const diagnostics: vscode.Diagnostic[] = [];

    currentVulnerabilities.forEach((vulnerability) => {
      const line = editor.document.lineAt(vulnerability.line);

      // Create range for the entire line
      const range = new vscode.Range(
        vulnerability.line,
        0,
        vulnerability.line,
        line.text.length,
      );

      // Default severity
      let severity = vscode.DiagnosticSeverity.Warning;

      // High severity vulnerabilities become errors
      if (vulnerability.severity === "HIGH") {
        severity = vscode.DiagnosticSeverity.Error;
      }

      // Create diagnostic object
      const diagnostic = new vscode.Diagnostic(
        range,
        `${vulnerability.type}: ${vulnerability.message}`,
        severity,
      );

      diagnostics.push(diagnostic);
    });

    // Display diagnostics in editor
    diagnosticCollection.set(editor.document.uri, diagnostics);
  }

  // Register hover provider ONLY once
  const hoverProvider = createHoverProvider(() => currentVulnerabilities);

  context.subscriptions.push(hoverProvider);

  // Analyze currently opened document
  if (vscode.window.activeTextEditor) {
    analyzeDocument(vscode.window.activeTextEditor);
  }

  // Re-analyze document whenever text changes
  vscode.workspace.onDidChangeTextDocument(() => {
    const editor = vscode.window.activeTextEditor;

    if (editor) {
      analyzeDocument(editor);
    }
  });
}

export function deactivate() {}
