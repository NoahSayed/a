<?php
/*
Plugin Name: Quick Contact
Description: A tiny contact form. (Lab fixture.)
Version: 1.0.0
*/
if ( ! defined( 'ABSPATH' ) ) { exit; }

function qc_form_shortcode() {
	return '<form class="quick-contact" method="post" action="' . esc_url( admin_url( 'admin-ajax.php' ) ) . '">'
		. '<input type="hidden" name="action" value="qc_send"><input name="name" placeholder="Name">'
		. '<textarea name="message"></textarea><button type="submit">Send</button></form>';
}
add_shortcode( 'quick_contact', 'qc_form_shortcode' );

function qc_send() {
	$messages   = get_option( 'qc_messages', array() );
	$messages[] = array(
		'name'    => sanitize_text_field( wp_unslash( $_POST['name'] ?? '' ) ),
		'message' => sanitize_textarea_field( wp_unslash( $_POST['message'] ?? '' ) ),
		'to'      => get_option( 'qc_recipient', get_option( 'admin_email' ) ),
	);
	update_option( 'qc_messages', $messages );
	wp_send_json_success( array( 'sent' => true ) );
}
add_action( 'wp_ajax_qc_send', 'qc_send' );
add_action( 'wp_ajax_nopriv_qc_send', 'qc_send' );

function qc_save_settings() {
	update_option( 'qc_recipient', sanitize_email( wp_unslash( $_REQUEST['recipient'] ?? '' ) ) );
	wp_send_json_success();
}
add_action( 'wp_ajax_qc_save_settings', 'qc_save_settings' );
add_action( 'wp_ajax_nopriv_qc_save_settings', 'qc_save_settings' );
