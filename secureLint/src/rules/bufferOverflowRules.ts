import { DetectionRule } from "../models/detectionRule";

/**
 * Buffer Overflow detection rules for JavaScript and TypeScript.
 * Node.js buffers can expose uninitialized memory if allocated incorrectly.
 */
export const jsBufferOverflowRules: DetectionRule[] = [
  {
    regex: /Buffer\.allocUnsafe(?:Slow)?\s*\(/gi,
    severity: "MEDIUM",
    message:
      "Unsafe buffer allocation detected. Uninitialized memory may be exposed.",
    recommendation:
      "Use Buffer.alloc() instead to ensure the buffer is zero-filled.",
  },

  {
    regex: /new\s+Buffer\s*\(/gi,
    severity: "HIGH",
    message: "Deprecated Buffer constructor detected.",
    recommendation:
      "Use Buffer.alloc() for size-based allocation or Buffer.from() for strings and arrays.",
  },
];

/**
 * Buffer Overflow detection rules for Python.
 * Standard Python is memory-safe, but ctypes exposes raw C memory operations.
 */
export const pythonBufferOverflowRules: DetectionRule[] = [
  {
    regex: /\b(?:ctypes\.)?create_string_buffer\s*\(/gi,
    severity: "LOW",
    message: "Raw C buffer allocation detected.",
    recommendation:
      "Use native Python types unless C interoperability is required.",
  },

  {
    regex: /\b(?:ctypes\.)?(?:memmove|memset)\s*\(/gi,
    severity: "HIGH",
    message: "Potential unsafe memory operation detected.",
    recommendation:
      "Ensure memory boundaries and buffer sizes are validated before use.",
  },
];
