import { copyFile, mkdir, writeFile } from "node:fs/promises";
import path from "node:path";

const root = path.resolve(new URL("..", import.meta.url).pathname);
const coreRoot = path.resolve(root, "../design-system-core");

await mkdir(path.join(root, "dist", "tokens"), { recursive: true });
await writeFile(
  path.join(root, "dist", "styles.css"),
  '@import "@mindburn/ui-core/styles.css";\n',
);
await copyFile(
  path.join(coreRoot, "dist", "tokens", "tokens.json"),
  path.join(root, "dist", "tokens", "tokens.json"),
);
