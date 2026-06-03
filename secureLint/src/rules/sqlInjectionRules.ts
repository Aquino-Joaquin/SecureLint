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
  {
    regex: /`[\s\S]*?\$\{[\s\S]*?\}[\s\S]*?`/gi,
    context: SQL_KEYWORDS,
    severity: "HIGH",
    message:
      "Potential SQL injection: Template literal interpolation in SQL query.",
    recommendation:
      "Use parameterized queries or prepared statements instead of string interpolation.",
  },

  {
    regex:
      /(["'`])[\s\S]*?\1\s*\+\s*[^"'\d\s]|[^"'\d\s]\s*\+\s*(["'`])[\s\S]*?\2/gi,
    context: SQL_KEYWORDS,
    severity: "HIGH",
    message:
      "Potential SQL injection: String concatenation detected in SQL query.",
    recommendation:
      "Use parameterized queries instead of string concatenation.",
  },

  {
    regex: /(?:execute|query)\s*\(\s*(?![ "'`\d(])\w+/gi,
    severity: "HIGH",
    message:
      "Potential SQL injection: Executing a raw variable directly without parameters.",
    recommendation:
      "Ensure the variable passed is a safely parameterized query or use prepared statements.",
  },
];

/**
 * SQL Injection detection rules for Python.
 */
export const pythonSQLRules: DetectionRule[] = [
  {
    regex: /f(["'])[\s\S]*?\{[\s\S]*?\}[\s\S]*?\1/gi,
    context: SQL_KEYWORDS,
    severity: "HIGH",
    message: "Potential SQL injection: Using f-strings to build SQL queries.",
    recommendation:
      "Use database parameterized queries (e.g., cursor.execute('... %s', (user_id,))).",
  },

  {
    regex:
      /(["'])[\s\S]*?\1\s*\+\s*[^"'\d\s]|[^"'\d\s]\s*\+\s*(["'])[\s\S]*?\2/gi,
    context: SQL_KEYWORDS,
    severity: "HIGH",
    message: "Potential SQL injection: String concatenation in SQL query.",
    recommendation:
      "Use parameterized queries instead of string concatenation.",
  },

  {
    regex:
      /(["'])[\s\S]*?%[sd]\1\s*%\s*[^"'\s]|(["'])[\s\S]*?\2\.format\s*\(/gi,
    context: SQL_KEYWORDS,
    severity: "HIGH",
    message:
      "Potential SQL injection: Using .format() or '%' operator to build SQL queries.",
    recommendation:
      "Pass variables as parameters into cursor.execute() instead.",
  },

  {
    regex: /execute\s*\(\s*(?![ "'`\d(])\w+/gi,
    severity: "HIGH",
    message:
      "Potential SQL injection: Executing a raw variable directly in database driver.",
    recommendation:
      "Do not pass dynamically constructed strings. Use parameterized inputs.",
  },
];
