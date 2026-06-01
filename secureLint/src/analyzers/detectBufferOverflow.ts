import { Vulnerability } from "../models/vulnerability";

/**
 * List of patterns used to detect buffer overflow related issues.
 * 
 * Each pattern contains:
 * - regex: regular expression used to detect unsafe code
 * - severity: severity level of the issue
 * - message: descriptive message explaining the problem
 * - recommendation: suggested fix to avoid the vulnerability
 */
const jsPatterns = [

  // Detects usage of Buffer.allocUnsafe()
  {
    regex: /Buffer\.allocUnsafe\s*\(/gi,
    severity: 'MEDIUM' as const,
    message: 'Potential buffer overflow: allocUnsafe creates uninitialized memory',
    recommendation: 'Use Buffer.alloc() instead to ensure zero-filled buffer'
  }
];

/**
 * Python patterns for Buffer Overflow.
 * Standard Python is memory-safe, but the `ctypes` library 
 * exposes raw C memory management which can cause overflows.
 */
const pythonPatterns = [
  // Detects raw memory allocation
  {
    regex: /ctypes\.create_string_buffer\s*\(/gi,
    severity: 'MEDIUM' as const,
    message: 'Potential memory risk: ctypes exposes raw, unmanaged C memory.',
    recommendation: 'Avoid ctypes unless strictly necessary for C integrations. Use native bytearrays.'
  },
  
  // Detects manual memory moving (Classic C Buffer Overflow vector)
  {
    regex: /ctypes\.memmove\s*\(/gi,
    severity: 'HIGH' as const,
    message: 'Potential Buffer Overflow: memmove bypasses Python memory safety.',
    recommendation: 'Do not manually move memory blocks. Rely on standard Python assignment.'
  }
];

/**
 * Analyzes the given text searching for buffer overflow vulnerabilities.
 */
export function detectBufferOverflow(text: string, languageId: string): Vulnerability[] {

  // Array where detected vulnerabilities will be stored
  const vulnerabilities: Vulnerability[] = [];

  // Split the document into individual lines
  const lines = text.split('\n');

  // Decide which rules to use based on the language
  const activePatterns = languageId === 'python' ? pythonPatterns : jsPatterns;

  // Iterate over each line of the file
  lines.forEach((line, index) => {

    // Iterate over all defined patterns
    activePatterns.forEach(pattern => {

      // Reset regex internal state (important when using /g)
      pattern.regex.lastIndex = 0;

      // Find all matches in the current line
      const matches = [...line.matchAll(pattern.regex)];

      // Process each match found
      matches.forEach(() => {

        // Add detected vulnerability to the results list
        vulnerabilities.push({

          // Type of vulnerability
          type: 'BUFFER_OVERFLOW',

          // Severity level defined in the pattern
          severity: pattern.severity,

          // Human-readable description of the issue
          message: pattern.message,

          // Line number where the issue was found
          line: index,

          // Recommended fix for the vulnerability
          recommendation: pattern.recommendation
        });
      });
    });
  });

  // Return all detected vulnerabilities
  return vulnerabilities;
}