import { DetectionRule } from "../models/detectionRule";

/**
 * Buffer Overflow detection rules for JavaScript and TypeScript.
 * Node.js buffers can expose uninitialized memory if allocated incorrectly.
 */
export const jsBufferOverflowRules: DetectionRule[] = [
  // Detects usage of Buffer.allocUnsafe()
  {
    regex: /Buffer\.allocUnsafe\s*\(/gi,
    severity: "MEDIUM",
    message:
      "Potential buffer overflow: allocUnsafe creates uninitialized memory",
    recommendation: "Use Buffer.alloc() instead to ensure zero-filled buffer",
  },
];

/**
 * Buffer Overflow detection rules for Python.
 * Standard Python is memory-safe, but the `ctypes` library
 * exposes raw C memory management which can cause overflows.
 */
export const pythonBufferOverflowRules: DetectionRule[] = [
  // Detects raw memory allocation
  {
    regex: /ctypes\.create_string_buffer\s*\(/gi,
    severity: "MEDIUM",
    message: "Potential memory risk: ctypes exposes raw, unmanaged C memory.",
    recommendation:
      "Avoid ctypes unless strictly necessary for C integrations. Use native bytearrays.",
  },

  // Detects manual memory moving (Classic C Buffer Overflow vector)
  {
    regex: /ctypes\.memmove\s*\(/gi,
    severity: "HIGH",
    message:
      "Potential Buffer Overflow: memmove bypasses Python memory safety.",
    recommendation:
      "Do not manually move memory blocks. Rely on standard Python assignment.",
  },
];
