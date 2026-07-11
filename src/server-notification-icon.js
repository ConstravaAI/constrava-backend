import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const serverPath = path.join(here, "server.js");

let source = await fs.readFile(serverPath, "utf8");
source = source.replace(">🔔<span class=\"notifyDot\"", ">○<span class=\"notifyDot\"");
await fs.writeFile(serverPath, source);

await import("./server-crm-actions-scope.js");