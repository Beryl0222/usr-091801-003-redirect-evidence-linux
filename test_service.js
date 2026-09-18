"use strict";

const { spawnSync } = require("node:child_process");

const steps = [
  ["python3", ["-m", "unittest", "-v",
    "service_contract", "test_rules", "test_workflow", "test_api"]],
  ["python3", ["demo.py"]],
];

for (const [cmd, args] of steps) {
  const result = spawnSync(cmd, args, { stdio: "inherit" });
  if (result.error) {
    console.error(result.error.message);
    process.exit(1);
  }
  if (result.status !== 0) {
    process.exit(result.status ?? 1);
  }
}
