import * as vscode from "vscode";

import { Vulnerability } from "../models/vulnerability";

export function createHoverProvider(getVulnerabilities: () => Vulnerability[]) {
  return vscode.languages.registerHoverProvider("javascript", {
    provideHover(document, position) {
      // Current line number
      const line = position.line;

      // Find vulnerability for this line
      const vulnerability = getVulnerabilities().find((v) => v.line === line);

      // If no vulnerability exists, stop
      if (!vulnerability) {
        return;
      }

      // Create custom hover message
      const message = new vscode.MarkdownString(
        `# ${vulnerability.type}\n\n` +
          `**Severity:** ${vulnerability.severity}\n\n` +
          `${vulnerability.message}`,
      );

      return new vscode.Hover(message);
    },
  });
}
