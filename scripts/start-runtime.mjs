import { access, readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const generatedServer = path.join(root, "src", ".server.generated.js");

let shouldGenerate = false;
try {
  await access(generatedServer);
  const generatedSource = await readFile(generatedServer, "utf8");
  shouldGenerate = !generatedSource.includes("migration-safety-runtime-v1");
} catch {
  shouldGenerate = true;
}

if (shouldGenerate) {
  process.env.CONSTRAVA_GENERATE_ONLY = "1";
  await import("./generate-runtime.mjs");
  delete process.env.CONSTRAVA_GENERATE_ONLY;
}

await import(`${pathToFileURL(generatedServer).href}?start=${Date.now()}`);
