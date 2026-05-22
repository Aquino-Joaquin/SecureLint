import * as vscode from "vscode";
import { Vulnerability } from "../models/vulnerability";
 
// Map that relates severity levels to a visual icon
const severityIcon: Record<string, string> = {

  HIGH: '🔴',
  MEDIUM: '🟡',
  LOW: '🟢'
};
 
/**
 * Creates and registers a HoverProvider.
 * 
 * The HoverProvider allows showing information
 * when the user hovers over a line.
 * 
 * It receives a function that returns the current vulnerabilities.
 */
export function createHoverProvider(
  getVulnerabilities: () => Vulnerability[]
) {

  // Defines the languages where the hover will work
  const selector = [
    { language: 'typescript' },
    { language: 'javascript' }
  ];
 
  // Registers the hover provider in VS Code
  return vscode.languages.registerHoverProvider(selector, {

    /**
     * Method that is automatically executed
     * when the user hovers over the code.
     */
    provideHover(document, position) {

      // Gets the line where the cursor is
      const line = position.line;

      // Looks for a vulnerability
      // associated with that line
      const vulnerability = getVulnerabilities()
        .find(v => v.line === line);
 
      // If there is no vulnerability on that line,
      // do not show anything
      if (!vulnerability) {
        return;
      }
 
      // Gets the icon based on severity
      // If not found, defaults to ⚪
      const icon =
        severityIcon[vulnerability.severity] ?? '⚪';
 
      // Builds the content that will appear in the hover
      // using Markdown
      const message = new vscode.MarkdownString(

        // Title with icon and vulnerability type
        `## ${icon} ${vulnerability.type.replace(/_/g, ' ')}\n\n` +

        // Severity level
        `**Severity:** ${vulnerability.severity}\n\n` +

        // Problem description
        `**Issue:** ${vulnerability.message}\n\n` +

        // Fix recommendation
        `**Fix:** ${vulnerability.recommendation}`
      );
 
      // Returns the hover that VS Code will display
      return new vscode.Hover(message);
    }
  });
}