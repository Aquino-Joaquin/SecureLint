import { detectSQLInjection } from "../analyzers/detectSQLInjection";
import { detectXSS } from "../analyzers/xss";
import { Vulnerability } from "../models/vulnerability";

export function scanDocument(text: string): Vulnerability[] {
  const sqlResults = detectSQLInjection(text);

  const xssResults = detectXSS(text);

  return [...sqlResults, ...xssResults];
}
