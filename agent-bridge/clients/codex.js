// codex: placeholder until the codex writer lands. See clients/common.js for the module interface.
export const label = "codex";
export function writeConfig() {
  throw new Error("--client codex is not implemented yet");
}
export const peekOutput = (notes) => (notes.length ? notes.join("\n") + "\n" : "");
export const readServerEnv = () => null;
