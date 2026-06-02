import { Vulnerability } from "../models/vulnerability";
import { pythonXSSRules, jsXSSRules } from "../rules/xssRules";

/**
 * Analyzes the file text searching for XSS vulnerabilities.
 */
export function detectXSS(text: string, languageId: string): Vulnerability[] {
  // Array where detected vulnerabilities will be stored
  const vulnerabilities: Vulnerability[] = [];

  // Splits the document into lines
  const lines = text.split("\n");

  // Decide which rules to use based on the language
  const activePatterns = languageId === "python" ? pythonXSSRules : jsXSSRules;

  // Iterates over each line of the file
  lines.forEach((line, index) => {
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
