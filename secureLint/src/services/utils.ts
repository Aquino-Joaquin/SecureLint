/**
 * Checks if a line is a comment based on the language.
 */
export function isComment(line: string, languageId: string): boolean {
  const trimmed = line.trim();

  if (
    languageId === "javascript" ||
    languageId === "typescript" ||
    languageId === "js" ||
    languageId === "ts"
  ) {
    return (
      trimmed.startsWith("//") ||
      trimmed.startsWith("/*") ||
      trimmed.startsWith("*")
    );
  }

  if (languageId === "python" || languageId === "py") {
    return (
      trimmed.startsWith("#") ||
      trimmed.startsWith('"""') ||
      trimmed.startsWith("'''")
    );
  }

  return false;
}
