// exit 0 = still vulnerable (anonymous user can change the contact recipient)
import { getOption, setOption, post, vulnerable, blocked } from './lib.mjs';
const before = getOption('qc_recipient');
await post('/wp-admin/admin-ajax.php', { action: 'qc_save_settings', recipient: 'probe@attacker.invalid' });
const fired = getOption('qc_recipient') === 'probe@attacker.invalid';
setOption('qc_recipient', before);
fired ? vulnerable() : blocked();
