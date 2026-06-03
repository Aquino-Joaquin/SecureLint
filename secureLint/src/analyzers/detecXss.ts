import { Vulnerability } from "../models/vulnerability";
import { pythonXssRules, jsXssRules } from "../rules/xssRules";
import { isComment } from "../services/utils";
/**
 * Analyzes the file text searching for XSS vulnerabilities.
 */
export function detectXSS(text: string, languageId: string): Vulnerability[] {
  // Array where detected vulnerabilities will be stored
  const vulnerabilities: Vulnerability[] = [];

  // Splits the document into lines
  const lines = text.split("\n");

  // Decide which rules to use based on the language
  const activePatterns = languageId === "python" ? pythonXssRules : jsXssRules;

  // Iterates over each line of the file
  lines.forEach((line, index) => {
    // Skip the line if it's a comment before executing regex rules
    if (isComment(line, languageId)) {
      return;
    }
    // Iterates over all defined patterns
    activePatterns.forEach((pattern) => {
      // Resets regex internal state (important when using /g)
      pattern.regex.lastIndex = 0;

      // Finds all matches in the line
      const matches = [...line.matchAll(pattern.regex)];

      // Iterates over each match found
      matches.forEach(() => {
        // Adds the detected vulnerability
        vulnerabilities.push({
          // Vulnerability type
          type: "XSS",

          // Severity defined in the pattern
          severity: pattern.severity,

          // Descriptive message
          message: pattern.message,

          // Line where it was detected
          line: index,

          // Fix recommendation
          recommendation: pattern.recommendation,
        });
      });
    });
  });

  // Returns all detected vulnerabilities
  return vulnerabilities;
}
