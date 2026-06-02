export interface DetectionRule {
  regex: RegExp;
  severity: "HIGH" | "MEDIUM" | "LOW";
  message: string;
  recommendation: string;
  context?: string[];
}
