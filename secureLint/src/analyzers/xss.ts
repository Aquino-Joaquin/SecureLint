import { Vulnerability } from "../models/vulnerability";

export function detectXSS(text: string): Vulnerability[] {
  const vulnerabilities: Vulnerability[] = [];

  const lines = text.split("\n");

  lines.forEach((line, index) => {
    const xssRegex = /(innerHTML|document\.write|dangerouslySetInnerHTML)/i;

    if (xssRegex.test(line)) {
      vulnerabilities.push({
        type: "XSS",
        severity: "MEDIUM",
        message: "Possible Cross-Site Scripting vulnerability",
        line: index,
      });
    }
  });

  return vulnerabilities;
}
