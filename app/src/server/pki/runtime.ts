import { fork } from "node:child_process";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { PkiStore } from "./store.js";
import type { WorkerInput } from "./worker.js";
export function launchCollection(input: WorkerInput) {
  let worker = fileURLToPath(new URL("./worker.js", import.meta.url));
  if (!existsSync(worker))
    worker = fileURLToPath(new URL("./worker.ts", import.meta.url));
  const env = { ...process.env };
  for (const key of Object.keys(env))
    if (/TOKEN|SECRET|PASSWORD/.test(key)) delete env[key];
  const child = fork(worker, [], {
    detached: true,
    stdio: ["ignore", "ignore", "ignore", "ipc"],
    env,
  });
  const store = new PkiStore(input.dbPath);
  store.db
    .prepare("UPDATE jobs SET pid=? WHERE id=?")
    .run(child.pid ?? null, input.id);
  store.close();
  child.once("error", () => {
    const s = new PkiStore(input.dbPath);
    s.state(input.id, "interrupted", "Could not start collection process");
    s.close();
  });
  child.send(input);
  child.unref();
}
