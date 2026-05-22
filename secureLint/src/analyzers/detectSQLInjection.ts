import { Vulnerability } from "../models/vulnerability";

export function detectSQLInjection(text: string): Vulnerability[] {
  const vulnerabilities: Vulnerability[] = [];

  const lines = text.split("\n");

  lines.forEach((line, index) => {
    const sqlRegex = /(SELECT|INSERT|UPDATE|DELETE).*(\+|\$\{)/i;

    if (sqlRegex.test(line)) {
      vulnerabilities.push({
        type: "SQL Injection",
        severity: "HIGH",
        message: "Possible unsafe SQL query concatenation",
        line: index,
      });
    }
  });

  return vulnerabilities;
}
