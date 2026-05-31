# @ramarivera/pi-model-guardrails

Model guardrails for Pi coding agent

## Install

```sh
pi install npm:@ramarivera/pi-model-guardrails@0.0.1
```

## Local Development

This checkout is live-enabled for Pi through:

```text
.pi/extensions/model-guardrails/index.ts
```

That shim imports the package entrypoint in `src/index.ts`, which imports the extension factory from `src/extension.ts`. Tests use the same symbol so local behavior, package behavior, and manual Pi behavior do not drift.

```sh
npm install
npm run check
npm test
npm run test:e2e
npm pack --dry-run
```

## Publishing

Publishing uses GitHub Actions trusted publishing in `.github/workflows/publish.yml`.

Before the first publish, configure npm trusted publishing:

- owner/repo: `ramarivera/pi-model-guardrails`
- workflow: `.github/workflows/publish.yml`
- environment: blank unless the workflow is changed to require one

No `NPM_TOKEN` is required for trusted publishing.

