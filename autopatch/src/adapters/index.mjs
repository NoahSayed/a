// Adapter registry. Each adapter implements the interface documented in docs/ADAPTERS.md.
export async function loadAdapter(name) {
  switch (name) {
    case 'npm': return (await import('./npm.mjs')).default;
    case 'nextjs': return (await import('./nextjs.mjs')).default;
    case 'wordpress': return (await import('./wordpress.mjs')).default;
    default: throw new Error(`unknown adapter "${name}" (npm, nextjs, wordpress)`);
  }
}
