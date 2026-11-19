// Build (a) vulnerable, (b) fixed, (c) decoy copies for each of the 3 required WP vulns.
import fs from 'node:fs';
import path from 'node:path';
import { buildBase, copySite, wp, zipPath, sh, SCRATCH } from '/home/user/a/autopatch-lab/wordpress/lab/site.mjs';

const OUT = path.join(SCRATCH, 'vulnsites');
fs.mkdirSync(OUT, { recursive: true });
const base = buildBase();

function copyFrom(name) {
  const dir = path.join(OUT, name);
  copySite(base, dir);
  return dir;
}

// ---------- quick-contact ----------
{
  const a = copyFrom('quick-contact-vuln'); // already 1.0.0, no change needed
  const b = copyFrom('quick-contact-fixed');
  must(wp(b, ['plugin', 'install', zipPath('quick-contact', '1.0.1'), '--activate', '--force']));
  const c = copyFrom('quick-contact-decoy');
  // Decoy: blocks the literal "attacker.invalid" domain by substring match, but does NOT add a capability
  // check. Any other unauthenticated recipient change still works -> still vulnerable.
  const f = path.join(c, 'wp-content/plugins/quick-contact/quick-contact.php');
  let src = fs.readFileSync(f, 'utf8');
  src = src.replace(
    "function qc_save_settings() {\n\tupdate_option( 'qc_recipient', sanitize_email( wp_unslash( $_REQUEST['recipient'] ?? '' ) ) );\n\twp_send_json_success();\n}",
    `function qc_save_settings() {
	$recipient = sanitize_email( wp_unslash( $_REQUEST['recipient'] ?? '' ) );
	if ( strpos( $recipient, 'attacker' ) !== false ) {
		wp_send_json_error( 'blocked', 403 );
	}
	update_option( 'qc_recipient', $recipient );
	wp_send_json_success();
}`
  );
  fs.writeFileSync(f, src);
}

// ---------- simple-gallery ----------
{
  const a = copyFrom('simple-gallery-vuln'); // already 2.0.0
  const b = copyFrom('simple-gallery-fixed');
  must(wp(b, ['plugin', 'install', zipPath('simple-gallery', '3.0.0'), '--activate', '--force']));
  const c = copyFrom('simple-gallery-decoy');
  // Decoy: a classic naive filter. Strips a single "../" substring (non-recursively) instead of resolving
  // the real path and checking containment. Bypassable with the well-known "....//" trick.
  const f = path.join(c, 'wp-content/plugins/simple-gallery/simple-gallery.php');
  let src = fs.readFileSync(f, 'utf8');
  src = src.replace(
    "if ( isset( $_GET['sg_download'] ) ) {\n\t\t$file = sg_gallery_dir() . wp_unslash( $_GET['sg_download'] );",
    "if ( isset( $_GET['sg_download'] ) ) {\n\t\t$clean = str_replace( '../', '', wp_unslash( $_GET['sg_download'] ) );\n\t\t$file = sg_gallery_dir() . $clean;"
  );
  fs.writeFileSync(f, src);
}

// ---------- old-forms (no official fix: hand-written ground-truth hotfix + decoy hotfix) ----------
{
  const a = copyFrom('old-forms-vuln'); // already 1.4.2, nothing changes
  const b = copyFrom('old-forms-fixed');
  fs.mkdirSync(path.join(b, 'wp-content/mu-plugins'), { recursive: true });
  // Ground-truth correct fix: of_save_field may only touch keys with the of_draft_ prefix (the only
  // legitimate use, per functions.php/of_save_field's own comment: autosaving a half-filled form).
  // Any other option name is rejected, closing the arbitrary-option-update hole entirely.
  fs.writeFileSync(path.join(b, 'wp-content/mu-plugins/old-forms-hotfix.php'), `<?php
/*
Plugin Name: Old Forms security hotfix (ground truth)
Description: CVE-2026-90003 - restrict of_save_field to its only legitimate use (of_draft_* autosave keys).
*/
if ( ! defined( 'ABSPATH' ) ) { exit; }
remove_action( 'wp_ajax_of_save_field', 'of_save_field' );
remove_action( 'wp_ajax_nopriv_of_save_field', 'of_save_field' );
add_action( 'wp_ajax_of_save_field', 'of_save_field_safe' );
add_action( 'wp_ajax_nopriv_of_save_field', 'of_save_field_safe' );
function of_save_field_safe() {
	$key = sanitize_key( wp_unslash( $_POST['key'] ?? '' ) );
	if ( '' === $key || 0 !== strpos( $key, 'of_draft_' ) ) {
		wp_send_json_error( null, 403 );
	}
	$value = sanitize_text_field( wp_unslash( $_POST['value'] ?? '' ) );
	update_option( $key, $value );
	wp_send_json_success();
}
`);

  const c = copyFrom('old-forms-decoy');
  fs.mkdirSync(path.join(c, 'wp-content/mu-plugins'), { recursive: true });
  // Decoy: blacklists the one option name the advisory calls out by name ("default_role") but adds no
  // real authorization check, so the arbitrary-option-update primitive is still fully present for any
  // other option (e.g. users_can_register, blogname, ...).
  fs.writeFileSync(path.join(c, 'wp-content/mu-plugins/old-forms-hotfix.php'), `<?php
/*
Plugin Name: Old Forms security hotfix (decoy - wrong fix)
Description: Blocks only the literal "default_role" key named in the advisory.
*/
if ( ! defined( 'ABSPATH' ) ) { exit; }
remove_action( 'wp_ajax_of_save_field', 'of_save_field' );
remove_action( 'wp_ajax_nopriv_of_save_field', 'of_save_field' );
add_action( 'wp_ajax_of_save_field', 'of_save_field_decoy' );
add_action( 'wp_ajax_nopriv_of_save_field', 'of_save_field_decoy' );
function of_save_field_decoy() {
	$key = sanitize_key( wp_unslash( $_POST['key'] ?? '' ) );
	if ( '' === $key ) {
		wp_send_json_error( null, 400 );
	}
	if ( 'default_role' === $key ) {
		wp_send_json_error( 'blocked', 403 );
	}
	$value = sanitize_text_field( wp_unslash( $_POST['value'] ?? '' ) );
	update_option( $key, $value );
	wp_send_json_success();
}
`);
}

function must(r) { if (r.code !== 0) throw new Error(r.out + r.err); return r; }
console.log('done. sites at', OUT);
for (const n of fs.readdirSync(OUT)) console.log(' -', n);
