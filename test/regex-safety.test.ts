// validateRegexSafety — load-time ReDoS gate for untrusted patterns.

import assert from "node:assert/strict";
import test from "node:test";

import { validateRegexSafety } from "../src/engine/regex-safety.ts";

test("rejects the exponential nested-quantifier family", () => {
  for (const p of [
    "(a+)+",
    "(a*)*",
    "(a+)*",
    "(a*)+",
    "(.*)+",
    "(.+)*",
    "(\\d+)*",
    "([a-z]+)*",
    "(\\w+)+",
    "(?:a+)+", // non-capturing group, same risk
    "(ab+)+", // conservative over-reject (documented)
    "([a-z]+)+$",
    "(x+)+y",
    "(a{1,}){1,}", // {n,} unbounded form on both
  ]) {
    const r = validateRegexSafety(p);
    assert.equal(r.ok, false, `should reject: ${p}`);
    assert.ok(r.reason && r.reason.length > 0);
  }
});

test("accepts safe / benign patterns", () => {
  for (const p of [
    "rm\\s+-rf",
    "git\\s+reset\\s+--hard",
    "(abc)+", // group with NO inner quantifier
    "(abc)*",
    "a+b+c+", // sequential quantifiers, not nested
    "[a-z]+",
    ".*", // single polynomial star, not nested
    "a.*b.*c", // polynomial, left to the runtime input cap
    "(foo|bar)", // alternation, no quantifier
    "(foo|bar)?", // bounded
    "(a+){2,5}", // bounded outer quantifier => not exponential
    "(a+){3}", // fixed outer count
    "kubectl\\s+delete",
    "push\\s+--force",
  ]) {
    const r = validateRegexSafety(p);
    assert.equal(r.ok, true, `should accept: ${p} (got: ${r.reason})`);
  }
});

test("rejects a non-compiling pattern", () => {
  const r = validateRegexSafety("(unclosed");
  assert.equal(r.ok, false);
  assert.match(r.reason ?? "", /invalid regex/);
});

test("rejects an absurdly long pattern", () => {
  const r = validateRegexSafety("a".repeat(1001));
  assert.equal(r.ok, false);
  assert.match(r.reason ?? "", /exceeds/);
});

test("escaped quantifiers + char-class literals are not mistaken for nesting", () => {
  // `\(` `\)` are literals; `[*+]` are literal chars in a class, not quantifiers.
  assert.equal(validateRegexSafety("\\(a+\\)+").ok, true); // literal parens
  assert.equal(validateRegexSafety("([*+])+").ok, true); // *,+ literal in class
  assert.equal(validateRegexSafety("(a\\+)+").ok, true); // escaped + inside group
});
