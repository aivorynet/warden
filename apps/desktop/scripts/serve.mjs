// Tiny static server for the UI in mock mode: `npm run serve`, then open http://localhost:8080/#tokens
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { extname, join, normalize, sep } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(fileURLToPath(new URL(".", import.meta.url)), "..", "ui");
const types = { ".html": "text/html", ".js": "text/javascript", ".css": "text/css", ".ttf": "font/ttf", ".png": "image/png" };
createServer(async (req, res) => {
  const rel = decodeURIComponent((req.url ?? "/").split("?")[0] ?? "/");
  const file = normalize(join(root, rel === "/" ? "index.html" : rel));
  if (!file.startsWith(root + sep)) return void res.writeHead(403).end("forbidden");
  try {
    const body = await readFile(file);
    res.writeHead(200, { "content-type": types[extname(file)] ?? "application/octet-stream" });
    res.end(body);
  } catch {
    res.writeHead(404).end("not found");
  }
}).listen(Number(process.env.PORT ?? 8080), () => console.log("serving ui"));
