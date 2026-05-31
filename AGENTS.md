# AGENTS.md

This repository contains `@ramarivera/pi-model-guardrails`, a Pi coding-agent extension.

## Local Rules

- Keep the real implementation in `src/extension.ts`.
- Keep `src/index.ts` as the package and Pi extension entrypoint.
- Keep `.pi/extensions/model-guardrails/index.ts` as a local live-testing shim that imports the package entrypoint.
- Keep `.pi/extensions/entire/index.ts` enabled so local Pi sessions record history.
- Do not publish `.pi/`; it exists for local Pi testing only.
- Run `npm run check`, `npm test`, `npm run test:e2e`, and `npm pack --dry-run` before publishing.
- Keep Entire and Husky hooks enabled for Codex and Pi session history.

## Publishing

Use GitHub Actions trusted publishing. Do not add `NPM_TOKEN` unless Ramiro explicitly chooses token publishing.
