import { cp, mkdir } from "node:fs/promises";
import path from "node:path";

const root = path.resolve(new URL("..", import.meta.url).pathname);
const src = path.join(root, "src");
const dist = path.join(root, "dist");

await mkdir(dist, { recursive: true });

await cp(path.join(src, "styles.css"), path.join(dist, "styles.css"));
await cp(path.join(src, "styles"), path.join(dist, "styles"), { recursive: true });
await cp(path.join(src, "tokens", "tokens.json"), path.join(dist, "tokens", "tokens.json"));
await cp(path.join(src, "grammars"), path.join(dist, "grammars"), { recursive: true });
