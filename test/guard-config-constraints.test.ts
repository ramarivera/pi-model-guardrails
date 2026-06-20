// loadGuardConfig — constraint detect.regex is validated at load (ReDoS gate).

import assert from "node:assert/strict";
import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { loadGuardConfig } from "../src/config.ts";

async function writeProjectConfig(body: unknown): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "pi-guardrails-gc-"));
  await mkdir(join(dir, ".pi"));
  await writeFile(
    join(dir, ".pi/guardrails.json"),
    JSON.stringify(body),
    "utf8",
  );
  return dir;
}

test("loadGuardConfig: a safe constraint regex is kept", async () => {
  const dir = await writeProjectConfig({
    policy: {
      constraints: [
        {
          id: "no-force-push",
          title: "No force push",
          statement: "Do not force-push.",
          severity: "high",
          detect: { regex: "push\\s+--force" },
        },
      ],
    },
  });
  const config = await loadGuardConfig(dir, { globalConfigPath: false });
  const c = config.policy.constraints.find((x) => x.id === "no-force-push");
  assert.ok(c, "constraint loaded");
  assert.equal(c.detect?.regex, "push\\s+--force", "safe regex preserved");
});

test("loadGuardConfig: a ReDoS-prone constraint regex is dropped, constraint + ruleIds kept", async () => {
  // Silence the expected load-time console.warn for a clean test run.
  const original = console.warn;
  const warnings: string[] = [];
  console.warn = (msg?: unknown) => {
    warnings.push(String(msg));
  };
  try {
    const dir = await writeProjectConfig({
      policy: {
        constraints: [
          {
            id: "evil",
            title: "Evil regex",
            statement: "catastrophic backtracking",
            severity: "high",
            detect: { ruleIds: ["core.git:reset-hard"], regex: "(a+)+$" },
          },
        ],
      },
    });
    const config = await loadGuardConfig(dir, { globalConfigPath: false });
    const c = config.policy.constraints.find((x) => x.id === "evil");
    assert.ok(c, "constraint still loaded");
    assert.equal(c.detect?.regex, undefined, "ReDoS regex was dropped");
    assert.deepEqual(
      c.detect?.ruleIds,
      ["core.git:reset-hard"],
      "the safe ruleIds detector is preserved",
    );
    assert.ok(
      warnings.some((w) => /REJECTED at load/.test(w) && /evil/.test(w)),
      "a loud warning was emitted",
    );
  } finally {
    console.warn = original;
  }
});

test("loadGuardConfig: a non-compiling constraint regex is dropped", async () => {
  const original = console.warn;
  console.warn = () => {};
  try {
    const dir = await writeProjectConfig({
      policy: {
        constraints: [
          {
            id: "broken",
            title: "Broken regex",
            statement: "does not compile",
            severity: "medium",
            detect: { regex: "(unclosed" },
          },
        ],
      },
    });
    const config = await loadGuardConfig(dir, { globalConfigPath: false });
    const c = config.policy.constraints.find((x) => x.id === "broken");
    assert.ok(c);
    assert.equal(c.detect?.regex, undefined, "non-compiling regex dropped");
  } finally {
    console.warn = original;
  }
});
