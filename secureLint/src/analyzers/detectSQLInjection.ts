import { Vulnerability } from "../models/vulnerability";

/**
 * SQL keywords used to check
 * whether a line actually looks like an SQL query.
 */
const SQL_KEYWORDS = [
  'SELECT',
  'INSERT',
  'UPDATE',
  'DELETE',
  'WHERE',
  'FROM'
];

/**
 * Patterns that detect SQL Injection vulnerabilities
 * in a single line.
 * 
 * Each pattern contains:
 * - regex: detection regular expression
 * - context: required SQL keywords in the line
 * - message: description of the issue
 * - recommendation: suggested fix
 */
const singleLinePatterns = [

  // ==============================
  // Dangerous template literals
  // ==============================
  // Detects:
  // `SELECT * FROM users WHERE id = ${userId}`
  {
    regex: /(\$\{|`[^`]*\$\{[^`]*\}`)/gi,

    // Requires SQL context in the line
    context: SQL_KEYWORDS,

    message: 'Potential SQL injection: Template literal in SQL query',

    recommendation:
      'Use parameterized queries or prepared statements instead of string interpolation'
  },

  // ==========================================
  // String concatenation in SQL queries
  // ==========================================
  // Detects:
  // "SELECT * FROM users WHERE id=" + userId
  {
    regex:
      /["'`][^"'`]*["'`]\s*\+\s*\w+|\w+\s*\+\s*["'`][^"'`]*["'`]/gi,

    context: SQL_KEYWORDS,

    message:
      'Potential SQL injection: String concatenation in SQL query',

    recommendation:
      'Use parameterized queries instead of string concatenation'
  },

  // ======================================
  // execute("SELECT ...")
  // ======================================
  {
    regex: /execute\s*\(\s*["'`]/gi,

    message:
      'Potential SQL injection: Execute with string literal',

    recommendation:
      'Validate and sanitize all inputs before executing queries'
  },

  // ======================================
  // query(`SELECT ${userInput}`)
  // ======================================
  {
    regex: /query\s*\(\s*["'`].*\$\{/gi,

    message:
      'Potential SQL injection: Query with template literal',

    recommendation:
      'Use parameterized queries instead of string interpolation'
  }
];

/**
 * Analyzes the text searching for SQL Injection vulnerabilities.
 */
export function detectSQLInjection(
  text: string
): Vulnerability[] {

  // Array where detected vulnerabilities are stored
  const vulnerabilities: Vulnerability[] = [];

  // Splits the document into lines
  const lines = text.split('\n');

  lines.forEach((line, index) => {

    // Iterates over all defined patterns
    singleLinePatterns.forEach(pattern => {

      // Resets regex internal state (important when using /g)
      pattern.regex.lastIndex = 0;

      // Finds matches in the current line
      const matches = [...line.matchAll(pattern.regex)];

      // Iterates over all matches found
      matches.forEach(() => {

        // If pattern requires SQL context
        if (pattern.context) {

          // Checks if line contains any SQL keyword
          const hasSQLContext = pattern.context.some(kw =>
            line.toUpperCase().includes(kw)
          );

          // If it does not look like SQL, ignore it
          if (!hasSQLContext) {
            return;
          }
        }

        // Adds detected vulnerability
        vulnerabilities.push({

          // Vulnerability type
          type: 'SQL_INJECTION',

          // Severity level
          severity: 'HIGH',

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