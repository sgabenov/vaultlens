// Repeat query measurements on an existing synthetic benchmark database.
import { PkiStore } from "../dist/server/pki/store.js";
import { performance } from "node:perf_hooks";
const store = new PkiStore(process.argv[2]),
  base = {
    sources: Array.from({ length: 10 }, (_, i) => "source-" + i),
    conditions: [],
    match: "all",
    sort: "notAfter",
    direction: "asc",
    limit: 50,
  };
const results = {};
for (const field of ["serial", "fingerprint"])
  for (const operator of ["equals", "prefix"]) {
    const value =
      field === "serial" ? "1f5" : (501).toString(16).padStart(64, "0");
    const times = [];
    for (let i = 0; i < 6; i++) {
      const t = performance.now();
      store.query({ ...base, conditions: [{ field, operator, value }] });
      times.push(performance.now() - t);
    }
    results[field + "_" + operator] = {
      firstMs: times[0],
      warmMaxMs: Math.max(...times.slice(1)),
    };
  }
store.close();
console.log(JSON.stringify(results, null, 2));
