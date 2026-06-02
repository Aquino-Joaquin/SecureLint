import { DetectionRule } from "../models/detectionRule";

export const jsXSSRules: DetectionRule[] = [
  // Detects usage of innerHTML
  {
    regex: /\.innerHTML\s*=/gi,
    severity: "MEDIUM" as const,
    message: "Potential XSS: innerHTML assignment detected",
    recommendation:
      "Use textContent or sanitize HTML before inserting into DOM",
  },

  // Detects usage of outerHTML
  {
    regex: /\.outerHTML\s*=/gi,
    severity: "MEDIUM" as const,
    message: "Potential XSS: outerHTML assignment detected",
    recommendation:
      "Use textContent or sanitize HTML before inserting into DOM",
  },

  // Detects document.write()
  {
    regex: /document\.write\s*\(/gi,
    severity: "HIGH" as const,
    message: "Potential XSS: document.write() usage detected",
    recommendation:
      "Avoid document.write(); use DOM manipulation methods instead",
  },

  // Detects eval()
  {
    regex: /eval\s*\(/gi,
    severity: "HIGH" as const,
    message: "Potential XSS: eval() usage detected",
    recommendation: "Avoid eval(); use safer alternatives like JSON.parse()",
  },

  // Detects setTimeout with strings
  // Example:
  // setTimeout("alert('XSS')", 1000)
  {
    regex: /setTimeout\s*\(\s*["'`]/gi,
    severity: "MEDIUM" as const,
    message: "Potential XSS: String-based setTimeout detected",
    recommendation: "Pass function references instead of strings to setTimeout",
  },

  // Detects setInterval with strings
  {
    regex: /setInterval\s*\(\s*["'`]/gi,
    severity: "MEDIUM" as const,
    message: "Potential XSS: String-based setInterval detected",
    recommendation:
      "Pass function references instead of strings to setInterval",
  },

  // Detects dangerouslySetInnerHTML in React
  {
    regex: /dangerouslySetInnerHTML/gi,
    severity: "MEDIUM" as const,
    message: "Potential XSS: dangerouslySetInnerHTML usage detected",
    recommendation:
      "Sanitize content before using dangerouslySetInnerHTML in React",
  },
];

export const pythonXSSRules: DetectionRule[] = [
  // Detects eval()
  {
    regex: /(?<![\w\.])eval\s*\(/gi,
    severity: "HIGH" as const,
    message: "Potential XSS: eval() usage detected",
    recommendation: "Avoid eval(); use ast.literal_eval() for safe evaluation.",
  },

  // Detects exec()
  {
    regex: /(?<![\w\.])exec\s*\(/gi,
    severity: "HIGH" as const,
    message: "Potential XSS: exec() usage detected",
    recommendation:
      "Avoid exec(); it executes arbitrary strings as Python code.",
  },

  // Detects Jinja2/Django safe filters which bypass XSS protections
  // Example: {{ user_input | safe }}
  {
    regex: /\|\s*safe\b/gi,
    severity: "MEDIUM" as const,
    message: 'Potential XSS: Usage of "|safe" filter detected in template.',
    recommendation:
      'Ensure the variable passed to "|safe" is strictly sanitized.',
  },

  // Detects Django's mark_safe()
  {
    regex: /mark_safe\s*\(/gi,
    severity: "MEDIUM" as const,
    message: "Potential XSS: Usage of mark_safe() detected.",
    recommendation:
      "Ensure the content passed to mark_safe() is strictly sanitized.",
  },
];
