// Injected into the active tab with chrome.scripting.executeScript({ func }).
// It must stay self-contained: no imports, no outer variables.

export function collectPageText(): string[] {
  const max = 1_500_000;
  const parts: string[] = [];
  const body = document.body?.innerText ?? "";
  parts.push(body.slice(0, max));
  document.querySelectorAll("input, textarea").forEach((el) => {
    const f = el as HTMLInputElement;
    if (f.type !== "password" && typeof f.value === "string" && f.value) parts.push(f.value.slice(0, 4096));
  });
  return parts;
}
