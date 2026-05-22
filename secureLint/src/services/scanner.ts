import { detectSQLInjection } from "../analyzers/detectSQLInjection";
import { detectXSS } from "../analyzers/xss";
import { detectBufferOverflow } from "../analyzers/detectBufferOverflow";
import { Vulnerability } from "../models/vulnerability";
 
// List of languages supported by the scanner
const SUPPORTED_LANGUAGES = ['typescript', 'javascript', 'ts', 'js'];
 
/**
 * Analyzes a full document and returns
 * a list of detected vulnerabilities.
 */
export function scanDocument(
  text: string,
  languageId: string = 'typescript'
): Vulnerability[] {

  // Checks if the language is supported.
  // If not, returns an empty array.
  if (!SUPPORTED_LANGUAGES.includes(languageId)) {
    return [];
  }
 
  // Runs all analyzers and combines
  // their results into a single array.
  const results: Vulnerability[] = [

    // Detects possible SQL Injection vulnerabilities
    ...detectSQLInjection(text),

    // Detects XSS vulnerabilities
    ...detectXSS(text),

    // Detects possible Buffer Overflow vulnerabilities
    ...detectBufferOverflow(text),
  ];
 
  // Removes duplicate vulnerabilities
  // before returning the final result.
  return removeDuplicates(results);
}
 
/**
 * Removes duplicate vulnerabilities.
 * 
 * How does it detect duplicates?
 * It uses:
 * - the line where it occurs
 * - the type of vulnerability
 * 
 * Example key:
 * "15-SQL_INJECTION"
 */
function removeDuplicates(
  vulns: Vulnerability[]
): Vulnerability[] {

  // Set used to store unique keys
  const seen = new Set<string>();

  // filter iterates over all vulnerabilities
  // and decides which ones to keep
  return vulns.filter(v => {

    // Creates a unique key using line + type
    const key = `${v.line}-${v.type}`;

    // If the key already exists:
    // it means it's a duplicate
    if (seen.has(key)) {
      return false;
    }

    // Marks the key as seen
    seen.add(key);

    // Keeps the vulnerability
    return true;
  });
}