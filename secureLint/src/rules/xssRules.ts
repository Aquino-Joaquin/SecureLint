import { DetectionRule } from "../models/detectionRule";

/**
 * XSS and Code Injection detection rules for JavaScript and TypeScript.
 * Targets dangerous DOM sinks and arbitrary code execution vectors.
 */
export const jsXssRules: DetectionRule[] = [
  {
    regex: /\.(?:inner|outer)HTML\s*=|\binsertAdjacentHTML\s*\(/gi,
    severity: "MEDIUM" as const,
    message: "Potential DOM XSS: Insecure HTML insertion sink detected.",
    recommendation:
      "Use textContent/innerText instead, or sanitize the HTML string before DOM insertion.",
  },

  {
    regex: /\bdocument\.write(?:ln)?\s*\(/gi,
    severity: "HIGH" as const,
    message:
      "Potential XSS: document.write() or document.writeln() usage detected.",
    recommendation:
      "Avoid document.write() methods; use modern, safe DOM manipulation tools like document.createElement().",
  },

  {
    regex: /\beval\s*\(|\bnew\s+Function\s*\(/gi,
    severity: "HIGH" as const,
    message:
      "Critical Code Injection risk: Dynamic code execution via eval() or new Function().",
    recommendation:
      "Avoid arbitrary code evaluation. Use safer alternatives like JSON.parse() for data parsing.",
  },

  {
    regex: /\bset(?:Timeout|Interval)\s*\(\s*["'`]/gi,
    severity: "MEDIUM" as const,
    message: "Potential XSS: String-based execution inside timer function.",
    recommendation:
      "Pass actual function references instead of evaluation strings to timer functions.",
  },

  {
    regex: /\bdangerouslySetInnerHTML\b/gi,
    severity: "MEDIUM" as const,
    message: "Potential XSS: React dangerouslySetInnerHTML attribute detected.",
    recommendation:
      "Ensure all content passed to dangerouslySetInnerHTML is sanitized.",
  },
];

/**
 * XSS and Server-Side Injection detection rules for Python templates and code execution.
 */
export const pythonXssRules: DetectionRule[] = [
  {
    regex: /\b(?:eval|exec)\s*\(/gi,
    severity: "HIGH" as const,
    message:
      "Critical Code Injection risk: Arbitrary Python code execution via eval() or exec().",
    recommendation:
      "Avoid dynamic execution of untrusted strings. Use ast.literal_eval() if parsing literals is required.",
  },

  {
    regex: /\|\s*safe\b/gi,
    severity: "MEDIUM" as const,
    message:
      "Potential XSS: The '|safe' filter explicitly bypasses template auto-escaping protections.",
    recommendation:
      "Ensure that any variable passed through the '|safe' filter has been properly validated or sanitized.",
  },

  {
    regex: /\b(?:mark_safe|Markup|SafeString|SafeText)\s*\(/gi,
    severity: "MEDIUM" as const,
    message:
      "Potential XSS: Disabling template HTML escaping programmatically.",
    recommendation:
      "Verify that inputs passed into auto-escape bypass utilities are sanitized beforehand.",
  },
];
