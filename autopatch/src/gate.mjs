// The gate decides whether a staged change may ship. Rules learned in the labs:
//  - baseline first: checks already failing before the change don't block it; only NEW failures do
//  - restart the app after every change (stale PHP state once let a broken update pass staging)
//  - run the checks again AFTER ANOTHER RESTART when restartCheck is on (catches keys generated at boot,
//    in-memory state, sessions that do not survive a restart)
//  - exploit probes for the finding must be blocked
export async function runGate(adapter, ctx, dir, { findingKeys = [], known = [], restartCheck = true } = {}) {
  await adapter.restart(ctx, dir);
  const jar = {};
  let checks = await adapter.checks(ctx, dir, { findingKeys, phase: 'before-restart', jar });
  if (restartCheck && adapter.hasServer) {
    await adapter.restart(ctx, dir);
    const after = await adapter.checks(ctx, dir, { findingKeys, phase: 'after-restart', jar });
    checks = checks.concat(after.map((c) => ({ ...c, name: `${c.name} (after restart)` })));
  }
  for (const c of checks) c.known = !c.pass && known.some((k) => c.name === k || c.name.startsWith(`${k} (`));
  return { pass: checks.every((c) => c.pass || c.known), checks, newFailures: checks.filter((c) => !c.pass && !c.known) };
}

export async function baseline(adapter, ctx, dir) {
  const g = await runGate(adapter, ctx, dir, { findingKeys: [], known: [], restartCheck: ctx.cfg.checks.restartCheck });
  return g.checks.filter((c) => !c.pass).map((c) => c.name.replace(/ \(after restart\)$/, ''));
}
