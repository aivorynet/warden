import { copyFileSync, mkdirSync } from "node:fs";

mkdirSync("dist/icons", { recursive: true });
for (const f of ["manifest.json", "popup.html", "popup.css"]) {
  copyFileSync(f === "manifest.json" ? f : `static/${f}`, `dist/${f}`);
}
for (const s of ["16", "32", "48", "128"]) {
  copyFileSync(`static/icons/${s}.png`, `dist/icons/${s}.png`);
}
