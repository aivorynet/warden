import { copyFileSync, mkdirSync } from "node:fs";

mkdirSync("dist", { recursive: true });
for (const f of ["manifest.json", "popup.html", "popup.css"]) {
  copyFileSync(f === "manifest.json" ? f : `static/${f}`, `dist/${f}`);
}
