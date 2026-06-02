import { DetectionRule } from "../models/detectionRule";

/**
 * SQL keywords used to check
 * whether a line actually looks like an SQL query.
 */
export const SQL_KEYWORDS = [
  "SELECT",
  "INSERT",
  "UPDATE",
  "DELETE",
  "WHERE",
  "FROM",
];

/**
 * SQL Injection detection rules for JavaScript and TypeScript.
 */
export const jsSQLRules: DetectionRule[] = [
  // Dangerous template literals
  // e.g., `SELECT * FROM users WHERE id = ${userId}`
  {
    regex: /(\$\{|`[^`]*\$\{[^`]*\}`)/gi,
    context: SQL_KEYWORDS,
    severity: "HIGH",
    message: "Potential SQL injection: Template literal in SQL query",
    recommendation:
      "Use parameterized queries or prepared statements instead of string interpolation",
  },

  // String concatenation in SQL queries
  // e.g., "SELECT * FROM users WHERE id=" + userId
  {
    regex: /["'`][^"'`]*["'`]\s*\+\s*\w+|\w+\s*\+\s*["'`][^"'`]*["'`]/gi,
    context: SQL_KEYWORDS,
    severity: "HIGH",
    message: "Potential SQL injection: String concatenation in SQL query",
    recommendation: "Use parameterized queries instead of string concatenation",
  },

  // execute("SELECT ...")
  {
    regex: /execute\s*\(\s*["'`].*?["'`]\s*\)/gi,
    severity: "HIGH",
    message: "Potential SQL injection: Execute with string literal",
    recommendation: "Validate and sanitize all inputs before executing queries",
  },

  // query(`SELECT ${userInput}`)
  {
    regex: /query\s*\(\s*["'`].*\$\{/gi,
    severity: "HIGH",
    message: "Potential SQL injection: Query with template literal",
    recommendation: "Use parameterized queries instead of string interpolation",
  },
];

/**
 * SQL Injection detection rules for Python.
 */
export const pythonSQLRules: DetectionRule[] = [
  // Dangerous f-strings
  // e.g., f"SELECT * FROM users WHERE id={user_id}"
  {
    regex: /f["'][^"']*\{[^}]*\}[^"']*["']/gi,
    context: SQL_KEYWORDS,
    severity: "HIGH",
    message: "Potential SQL injection: Using f-strings to build SQL queries.",
    recommendation:
      'Use database parameterized queries (e.g., cursor.execute("... %s", (user_id,)))',
  },

  // String concatenation in SQL queries
  // e.g., "SELECT * FROM " + table_name
  {
    regex: /(["']\s*\+\s*\w+)|(\w+\s*\+\s*["'])/gi,
    context: SQL_KEYWORDS,
    severity: "HIGH",
    message: "Potential SQL injection: String concatenation in SQL query.",
    recommendation:
      "Use parameterized queries instead of string concatenation.",
  },

  // execute("SELECT ...")
  // e.g., cursor.execute("DELETE FROM users")
  {
    regex: /execute\s*\(\s*["'][^"']*["']\s*\)/gi,
    severity: "HIGH",
    message: "Potential SQL injection: Execute with string literal.",
    recommendation:
      "Use parameterized queries instead of executing raw strings.",
  },
];
