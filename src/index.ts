import guardrailsExtension, {
  createExtension,
  extensionInfo,
} from "./extension.ts";

export { createExtension, extensionInfo };

const defaultExport = {
  ...createExtension(),
  activate: () => guardrailsExtension,
};

export default defaultExport;
