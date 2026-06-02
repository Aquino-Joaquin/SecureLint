import { Vulnerability } from "../models/vulnerability";
import {
  jsBufferOverflowRules,
  pythonBufferOverflowRules,
} from "../rules/bufferOverflowRules";

/**
 * Analyzes the given text searching for buffer overflow vulnerabilities.
 */
export function detectBufferOverflow(
  text: string,
  languageId: string,
): Vulnerability[] {
  // Array where detected vulnerabilities will be stored
  const vulnerabilities: Vulnerability[] = [];

  // Split the document into individual lines
  const lines = text.split("\n");

  // Decide which rules to use based on the language
  const activePatterns =
    languageId === "python" ? pythonBufferOverflowRules : jsBufferOverflowRules;

  // Iterate over each line of the file
  lines.forEach((line, index) => {
    // Iterate over all defined patterns
    activePatterns.forEach((pattern) => {
      // Reset regex internal state (important when using /g)
      pattern.regex.lastIndex = 0;

      // Find all matches in the current line
      const matches = [...line.matchAll(pattern.regex)];

      // Process each match found
      matches.forEach(() => {
        // Add detected vulnerability to the results list
        vulnerabilities.push({
          // Type of vulnerability
          type: "BUFFER_OVERFLOW",

          // Severity level defined in the pattern
          severity: pattern.severity,

          // Human-readable description of the issue
          message: pattern.message,

          // Line number where the issue was found
          line: index,

          // Recommended fix for the vulnerability
          recommendation: pattern.recommendation,
        });
      });
    });
  });

  // Return all detected vulnerabilities
  return vulnerabilities;
}
