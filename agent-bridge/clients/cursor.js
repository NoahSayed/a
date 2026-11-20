// cursor: placeholder until the cursor writer lands. See clients/common.js for the module interface.
export const label = "cursor";
export function writeConfig() {
  throw new Error("--client cursor is not implemented yet");
}
export const peekOutput = (notes) => (notes.length ? notes.join("\n") + "\n" : "");
export const readServerEnv = () => null;
