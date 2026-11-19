import path from 'node:path';
import { serve, stop, http, SCRATCH } from '/home/user/a/autopatch-lab/wordpress/lab/site.mjs';
import { option, setOption } from '/home/user/a/autopatch-lab/wordpress/lab/checks.mjs';

const OUT = path.join(SCRATCH, 'vulnsites');
const PORT = 8190;

async function qc(dir) {
  const before = option(dir, PORT, 'qc_recipient');
  await http(PORT, '/wp-admin/admin-ajax.php', { form: { action: 'qc_save_settings', recipient: 'probe@attacker.invalid' } });
  const fired = option(dir, PORT, 'qc_recipient') === 'probe@attacker.invalid';
  setOption(dir, PORT, 'qc_recipient', before);
  return fired;
}
async function sg(dir) {
  const r = await http(PORT, '/?sg_download=../private-note.txt');
  const direct = r.text.includes('SECRET-UPLOADS-NOTE');
  const r2 = await http(PORT, '/?sg_download=' + encodeURIComponent('....//private-note.txt'));
  const bypass = r2.text.includes('SECRET-UPLOADS-NOTE');
  return { direct, bypass };
}
async function of(dir) {
  const before = option(dir, PORT, 'default_role');
  await http(PORT, '/wp-admin/admin-ajax.php', { form: { action: 'of_save_field', key: 'default_role', value: 'administrator' } });
  const fired = option(dir, PORT, 'default_role') === 'administrator';
  setOption(dir, PORT, 'default_role', before);
  const other = await http(PORT, '/wp-admin/admin-ajax.php', { form: { action: 'of_save_field', key: 'blogdescription', value: 'pwned-by-probe' } });
  const otherFired = option(dir, PORT, 'blogdescription') === 'pwned-by-probe';
  setOption(dir, PORT, 'blogdescription', before === undefined ? '' : option(dir, PORT, 'blogdescription'));
  return { defaultRole: fired, otherOption: otherFired };
}

for (const [name, fn] of [
  ['quick-contact-vuln', qc], ['quick-contact-fixed', qc], ['quick-contact-decoy', qc],
  ['simple-gallery-vuln', sg], ['simple-gallery-fixed', sg], ['simple-gallery-decoy', sg],
  ['old-forms-vuln', of], ['old-forms-fixed', of], ['old-forms-decoy', of],
]) {
  const dir = path.join(OUT, name);
  await serve(dir, PORT);
  const r = await fn(dir);
  console.log(name.padEnd(24), JSON.stringify(r));
  await stop(PORT);
}
