// Deterministic sanity check on an extraction, independent of any model. Catches the cheap, common
// failure modes: a hallucinated package name, an unparsable version string, and a fixed_version that
// isn't even mentioned anywhere in the source text.
export function postCheck(extracted, itemText) {
  const reasons = [];
  const lower = (itemText || '').toLowerCase();

  // 1. the named package must appear verbatim (case-insensitively) in the item text.
  if (extracted.package) {
    const pkgToken = String(extracted.package).toLowerCase().split(/[\s(]/)[0];
    if (pkgToken && !lower.includes(pkgToken)) reasons.push(`package "${extracted.package}" not found verbatim in item text`);
  }

  // 2. versions must parse as something version-shaped (digits, dots, comparison operators, or "none"/"unknown").
  const versionLike = (v) => v == null || /^(none|unknown)$/i.test(v) || /\d/.test(v);
  if (!versionLike(extracted.affected_versions)) reasons.push(`affected_versions "${extracted.affected_versions}" doesn't look like a version`);
  if (!versionLike(extracted.fixed_version)) reasons.push(`fixed_version "${extracted.fixed_version}" doesn't look like a version`);

  // 3. a stated fixed_version (not null/none/unknown) should have its leading digits appear in the text somewhere.
  if (extracted.fixed_version && !/^(none|unknown)$/i.test(extracted.fixed_version)) {
    const digits = String(extracted.fixed_version).match(/\d+(\.\d+)*/g) || [];
    const anyFound = digits.some((d) => lower.includes(d.toLowerCase()));
    if (digits.length && !anyFound) reasons.push(`fixed_version "${extracted.fixed_version}" not found in item text`);
  }

  // 4. relevant=true should correspond to a named package/ecosystem actually present in the text (not an
  //    empty guess) - a bare "relevant: true" with package null and ecosystem null is suspicious.
  if (extracted.relevant === true && !extracted.package && !extracted.ecosystem) {
    reasons.push('relevant=true but no package or ecosystem was extracted to justify it');
  }

  // 5. exploited_in_wild/auth_needed must be one of the allowed enum values (defends against drift/injection
  //    pushing out-of-schema values if validation is ever loosened upstream).
  for (const f of ['exploited_in_wild', 'auth_needed']) {
    if (!['yes', 'no', 'unknown'].includes(extracted[f])) reasons.push(`${f} "${extracted[f]}" not in {yes,no,unknown}`);
  }

  return { pass: reasons.length === 0, reasons };
}
