## 📌 Project Topic & Core Objectives

**07 – Development of a Static Code Analyzer for Security Verification (SecureLint)**

The primary focus of this project is the design and implementation of a lightweight Static Application Security Testing (SAST) tool integrated into Visual Studio Code. The objective is to parse source code files in real-time, mapping and flagging security anti-patterns before they can be compiled or deployed.

The analyzer scans codebases line-by-line to intercept critical vectors, satisfying and exceeding the initial project benchmarks:

* **Multi-Vector Vulnerability Detection:** Full support for identifying three major flaw categories: **SQL Injection (SQLi)**, **Cross-Site Scripting (XSS)**, **and Buffer Overflow**.
* **Context-Aware Analysis:** Built-in logic filters (such as `SQL_KEYWORDS` validation) to match patterns against their semantic context, drastically reducing noise and false positives.
* **Intelligent Syntactic Skipping:** Seamless comment detection for JS/TS (`//`, `/*`) and Python (`#`, `"""`) to isolate actual execution blocks from documentation.
* **Vulnerability Assessment & Severity Scoring:** Every detected issue is compiled into a structured report mapping the exact line, vulnerability type, descriptive payload, actionable fix recommendations, and strict risk triage (**HIGH** or **MEDIUM** severity levels).

---

### 📋 Project Requirements Compliance Matrix

| Requirement | Project Implementation Status |
| :--- | :--- |
| **Analyze code for security flaws** | 🔌 Fully implemented via automated extension diagnostics on file open/save. |
| **Detect at least 2 vulnerability types** | 🚀 **Exceeded.** Built-in detection for 3 distinct engines: XSS, SQLi, and Buffer Overflow. |
| **Provide clear issue information** | 📝 Returns explicit, human-readable messages detailing exactly *why* the code is unsafe. |
| **Include a basic vulnerability assessment** | 🏷️ Fully typed via the `DetectionRule` interface, enforcing strict risk-level mapping. |
