import { copyFile, cp, mkdir, rename, rm } from "node:fs/promises";
import path from "node:path";

const root = path.resolve(new URL("..", import.meta.url).pathname);
const src = path.join(root, "src");
const dist = path.join(root, "dist");

async function copyAssetFile(source, target) {
  await mkdir(path.dirname(target), { recursive: true });
  await copyFile(source, target);
}

async function replaceDirectoryFromSource(source, target) {
  await mkdir(path.dirname(target), { recursive: true });
  const tempTarget = path.join(
    path.dirname(target),
    `.${path.basename(target)}.${process.pid}.${Date.now()}.tmp`,
  );

  await rm(tempTarget, { recursive: true, force: true });
  await cp(source, tempTarget, { recursive: true });

  for (let attempt = 0; attempt < 5; attempt += 1) {
    try {
      await rm(target, { recursive: true, force: true });
      await rename(tempTarget, target);
      return;
    } catch (error) {
      if (!["EEXIST", "ENOTEMPTY", "ENOENT"].includes(error?.code)) {
        await rm(tempTarget, { recursive: true, force: true });
        throw error;
      }
    }
  }

  await rm(tempTarget, { recursive: true, force: true });
  throw new Error(`Unable to copy ${source} to ${target}`);
}

await mkdir(dist, { recursive: true });

await copyAssetFile(path.join(src, "styles.css"), path.join(dist, "styles.css"));
await replaceDirectoryFromSource(path.join(src, "styles"), path.join(dist, "styles"));
await copyAssetFile(path.join(src, "tokens", "tokens.json"), path.join(dist, "tokens", "tokens.json"));
await replaceDirectoryFromSource(path.join(src, "grammars"), path.join(dist, "grammars"));
