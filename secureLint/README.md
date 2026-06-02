# SecureLint

`SecureLint` is a lightweight, high-performance static security analysis extension for Visual Studio Code. It scans your source code in real-time to detect common security vulnerabilities, helping you fix flaws before they ever reach production.

---

## 🚀 Features

SecureLint performs on-the-fly line-by-line scanning to pinpoint security issues without slowing down your editor. It currently provides specialized detection engines for:

* **Cross-Site Scripting (XSS):** Flags risky DOM manipulations (like `innerHTML` or `outerHTML`), unsafe timer strings, and dangerous template renderings (e.g., React's `dangerouslySetInnerHTML`).
* **SQL Injection (SQLi):** Smart pattern matching that checks context keywords (`SELECT`, `FROM`, etc.) to intercept unsafe string concatenations or raw f-strings being passed directly to database queries.
* **Buffer Overflow:** Detects memory-safety risks in Node.js (like `Buffer.allocUnsafe`) and Python raw memory bypasses (using `ctypes`).
* **Smart Comment Filtering:** Automatically ignores commented-out lines code to eliminate annoying false positives while you work.

---

## 🛠️ Supported Languages

The extension is designed to run efficiently only when needed. It activates automatically when working with:
* **JavaScript** (`.js`)
* **TypeScript** (`.ts`, `.tsx`)
* **Python** (`.py`)

---

## 📦 Installation & Requirements

No external dependencies or global security tools are required. 

To run or develop this extension locally:
1. Ensure you have [Node.js](https://nodejs.org/) installed.
2. Clone this repository.
3. Install dependencies using **pnpm** (preferred package manager for this project):
   ```bash
   pnpm install
