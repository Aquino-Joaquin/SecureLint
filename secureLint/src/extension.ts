import * as vscode from "vscode"; 

import { scanDocument } from "./services/scanner";
import { createHoverProvider } from "./hover/hoverProvider";
import { Vulnerability } from "./models/vulnerability";

const SUPPORTED_LANGUAGES = ['typescript', 'javascript'];
 
// Global variable that stores the current vulnerabilities found in the active document
let currentVulnerabilities: Vulnerability[] = [];
 
// Main function that runs when the extension is activated
export function activate(context: vscode.ExtensionContext) {

  // Message shown in the VS Code development console
  console.log("SecureLint: Security Scanner Active");
 
  // Collection of diagnostics (warnings, errors, info) that will appear in the editor
  const diagnosticCollection = vscode.languages.createDiagnosticCollection("securelint");

  // Registered so VS Code can dispose it automatically
  context.subscriptions.push(diagnosticCollection);
 
  /**
   * Function responsible for analyzing an open document
   * and generating security diagnostics.
   */
  function analyzeDocument(editor: vscode.TextEditor) {

    // Get the language of the current file
    const langId = editor.document.languageId;
 
    // If the language is not supported:
    // - remove previous diagnostics
    // - stop execution
    if (!SUPPORTED_LANGUAGES.includes(langId)) {
      diagnosticCollection.delete(editor.document.uri);
      return;
    }
 
    // Get the full text of the file
    const text = editor.document.getText();

    // Scan the document and store found vulnerabilities
    currentVulnerabilities = scanDocument(text, langId);
 
    // Convert each vulnerability into a VS Code Diagnostic
    const diagnostics: vscode.Diagnostic[] = currentVulnerabilities.map(vuln => {

      // Get the line where the vulnerability was detected
      const line = editor.document.lineAt(vuln.line);

      // Define the full range of the line to highlight it in the editor
      const range = new vscode.Range(
        vuln.line, 
        0, 
        vuln.line, 
        line.text.length
      );
 
      // Define the severity level of the diagnostic
      let severity: vscode.DiagnosticSeverity;

      switch (vuln.severity) {

        // High severity → Error
        case 'HIGH':
          severity = vscode.DiagnosticSeverity.Error;
          break;

        // Medium severity → Warning
        case 'MEDIUM':
          severity = vscode.DiagnosticSeverity.Warning;
          break;

        // Low severity → Information
        default:
          severity = vscode.DiagnosticSeverity.Information;
          break;
      }
 
      // Create the diagnostic that will appear in the editor
      const diagnostic = new vscode.Diagnostic(
        range,
        `[SecureLint] ${vuln.type}: ${vuln.message}`,
        severity
      );
 
      return diagnostic;
    });
 
    // Associate all diagnostics with the current document
    diagnosticCollection.set(editor.document.uri, diagnostics);
  }
 
  // ==============================
  // HOVER PROVIDER REGISTRATION
  // ==============================
  // Allows showing information when hovering over
  // a line with vulnerabilities
  context.subscriptions.push(
    createHoverProvider(() => currentVulnerabilities)
  );
 
  // ==============================
  // ANALYZE ON FILE OPEN
  // ==============================
  // If an editor is already active when the extension starts,
  // analyze it automatically
  if (vscode.window.activeTextEditor) {
    analyzeDocument(vscode.window.activeTextEditor);
  }
 
  // ==============================
  // ANALYZE ON TAB CHANGE
  // ==============================
  // Every time the user switches files,
  // the analysis is re-run
  context.subscriptions.push(
    vscode.window.onDidChangeActiveTextEditor(editor => {
      if (editor) {
        analyzeDocument(editor);
      }
    })
  );
 
  // ==========================================
  // ANALYZE ON TEXT CHANGE (DEBOUNCE)
  // ==========================================
  // Prevents running analysis on every keystroke.
  // Waits 500ms after the last change.
  let debounceTimer: ReturnType<typeof setTimeout> | undefined;

  context.subscriptions.push(
    vscode.workspace.onDidChangeTextDocument(event => {

      // Get the active editor
      const editor = vscode.window.activeTextEditor;

      // Ensure the change belongs to the current document
      if (editor && event.document === editor.document) {

        // Reset the timer
        clearTimeout(debounceTimer);

        // Run analysis after 500ms of no changes
        debounceTimer = setTimeout(() => analyzeDocument(editor), 500);
      }
    })
  );
 
  // ==========================================
  // CLEAR DIAGNOSTICS ON FILE CLOSE
  // ==========================================
  context.subscriptions.push(
    vscode.workspace.onDidCloseTextDocument(doc => {

      // Remove diagnostics from closed file
      diagnosticCollection.delete(doc.uri);
    })
  );
}
 
// Function that runs when the extension is deactivated
export function deactivate() {}