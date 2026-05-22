import { Vulnerability } from "../models/vulnerability";

/**
 * List of dangerous patterns related to XSS.
 * 
 * Each pattern contains:
 * - regex: regular expression used to detect unsafe code
 * - severity: severity level
 * - message: descriptive message
 * - recommendation: suggestion to fix the issue
 */
const patterns = [

  // Detects usage of innerHTML
  {
    regex: /\.innerHTML\s*=/gi,
    severity: 'MEDIUM' as const,
    message: 'Potential XSS: innerHTML assignment detected',
    recommendation: 'Use textContent or sanitize HTML before inserting into DOM'
  },

  // Detects usage of outerHTML
  {
    regex: /\.outerHTML\s*=/gi,
    severity: 'MEDIUM' as const,
    message: 'Potential XSS: outerHTML assignment detected',
    recommendation: 'Use textContent or sanitize HTML before inserting into DOM'
  },

  // Detects document.write()
  {
    regex: /document\.write\s*\(/gi,
    severity: 'HIGH' as const,
    message: 'Potential XSS: document.write() usage detected',
    recommendation: 'Avoid document.write(); use DOM manipulation methods instead'
  },

  // Detects eval()
  {
    regex: /eval\s*\(/gi,
    severity: 'HIGH' as const,
    message: 'Potential XSS: eval() usage detected',
    recommendation: 'Avoid eval(); use safer alternatives like JSON.parse()'
  },

  // Detects setTimeout with strings
  // Example:
  // setTimeout("alert('XSS')", 1000)
  {
    regex: /setTimeout\s*\(\s*["'`]/gi,
    severity: 'MEDIUM' as const,
    message: 'Potential XSS: String-based setTimeout detected',
    recommendation: 'Pass function references instead of strings to setTimeout'
  },

  // Detects setInterval with strings
  {
    regex: /setInterval\s*\(\s*["'`]/gi,
    severity: 'MEDIUM' as const,
    message: 'Potential XSS: String-based setInterval detected',
    recommendation: 'Pass function references instead of strings to setInterval'
  },

  // Detects dangerouslySetInnerHTML in React
  {
    regex: /dangerouslySetInnerHTML/gi,
    severity: 'MEDIUM' as const,
    message: 'Potential XSS: dangerouslySetInnerHTML usage detected',
    recommendation: 'Sanitize content before using dangerouslySetInnerHTML in React'
  }
];

/**
 * Analyzes the file text searching for XSS vulnerabilities.
 */
export function detectXSS(text: string): Vulnerability[] {

  // Array where detected vulnerabilities will be stored
  const vulnerabilities: Vulnerability[] = [];

  // Splits the document into lines
  const lines = text.split('\n');

  // Iterates over each line of the file
  lines.forEach((line, index) => {

    // Iterates over all defined patterns
    patterns.forEach(pattern => {

      // Resets regex internal state (important when using /g)
      pattern.regex.lastIndex = 0;

      // Finds all matches in the line
      const matches = [...line.matchAll(pattern.regex)];

      // Iterates over each match found
      matches.forEach(() => {

        // Adds the detected vulnerability
        vulnerabilities.push({

          // Vulnerability type
          type: 'XSS',

          // Severity defined in the pattern
          severity: pattern.severity,

          // Descriptive message
          message: pattern.message,

          // Line where it was detected
          line: index,

          // Fix recommendation
          recommendation: pattern.recommendation
        });
      });
    });
  });

  // Returns all detected vulnerabilities
  return vulnerabilities;
}