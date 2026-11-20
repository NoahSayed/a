// exit 0 = still vulnerable (anonymous user overwrites an arbitrary option)
import { getOption, setOption, post, vulnerable, blocked } from './lib.mjs';
const before = getOption('default_role');
await post('/wp-admin/admin-ajax.php', { action: 'of_save_field', key: 'default_role', value: 'administrator' });
const fired = getOption('default_role') === 'administrator';
setOption('default_role', before);
fired ? vulnerable() : blocked();
