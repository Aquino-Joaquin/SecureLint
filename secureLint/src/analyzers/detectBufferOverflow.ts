import { Vulnerability } from "../models/vulnerability";

/**
 * List of patterns used to detect buffer overflow related issues.
 * 
 * Each pattern contains:
 * - regex: regular expression used to detect unsafe code
 * - severity: severity level of the issue
 * - message: descriptive message explaining the problem
 * - recommendation: suggested fix to avoid the vulnerability
 */
const patterns = [

  // Detects usage of Buffer.allocUnsafe()
  {
    regex: /Buffer\.allocUnsafe\s*\(/gi,
    severity: 'MEDIUM' as const,
    message: 'Potential buffer overflow: allocUnsafe creates uninitialized memory',
    recommendation: 'Use Buffer.alloc() instead to ensure zero-filled buffer'
  }
];

/**
 * Analyzes the given text searching for buffer overflow vulnerabilities.
 */
export function detectBufferOverflow(text: string): Vulnerability[] {

  // Array where detected vulnerabilities will be stored
  const vulnerabilities: Vulnerability[] = [];

  // Split the document into individual lines
  const lines = text.split('\n');

  // Iterate over each line of the file
  lines.forEach((line, index) => {

    // Iterate over all defined patterns
    patterns.forEach(pattern => {

      // Reset regex internal state (important when using /g)
      pattern.regex.lastIndex = 0;

      // Find all matches in the current line
      const matches = [...line.matchAll(pattern.regex)];

      // Process each match found
      matches.forEach(() => {

        // Add detected vulnerability to the results list
        vulnerabilities.push({

          // Type of vulnerability
          type: 'BUFFER_OVERFLOW',

          // Severity level defined in the pattern
          severity: pattern.severity,

          // Human-readable description of the issue
          message: pattern.message,

          // Line number where the issue was found
          line: index,

          // Recommended fix for the vulnerability
          recommendation: pattern.recommendation
        });
      });
    });
  });

  // Return all detected vulnerabilities
  return vulnerabilities;
}