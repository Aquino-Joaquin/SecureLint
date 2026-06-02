import { Vulnerability } from "../models/vulnerability";
import { jsSQLRules, pythonSQLRules } from "../rules/sqlInjectionRules";
import { isComment } from "../services/utils";
/**
 * Analyzes the text searching for SQL Injection vulnerabilities.
 */
export function detectSQLInjection(
  text: string,
  languageId: string,
): Vulnerability[] {
  // Array where detected vulnerabilities are stored
  const vulnerabilities: Vulnerability[] = [];

  // Splits the document into lines
  const lines = text.split("\n");

  // Decide which rules to use based on the language
  const singleLinePatterns =
    languageId === "python" ? pythonSQLRules : jsSQLRules;

  lines.forEach((line, index) => {
    // Skip the line if it's a comment before executing regex rules
    if (isComment(line, languageId)) {
      return;
    }

    // Iterates over all defined patterns
    singleLinePatterns.forEach((pattern) => {
      // Resets regex internal state (important when using /g)
      pattern.regex.lastIndex = 0;

      // Finds matches in the current line
      const matches = [...line.matchAll(pattern.regex)];

      // Iterates over all matches found
      matches.forEach(() => {
        // If pattern requires SQL context
        if (pattern.context) {
          // Checks if line contains any SQL keyword
          const hasSQLContext = pattern.context.some((kw) =>
            line.toUpperCase().includes(kw),
          );

          // If it does not look like SQL, ignore it
          if (!hasSQLContext) {
            return;
          }
        }

        // Adds detected vulnerability
        vulnerabilities.push({
          // Vulnerability type
          type: "SQL_INJECTION",

          // Severity level
          severity: "HIGH",

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
