<?php
/*
Plugin Name: Old Forms
Description: Newsletter sign-up with draft autosave. (Lab fixture.)
Version: 1.4.2
*/
if ( ! defined( 'ABSPATH' ) ) { exit; }

function of_form_shortcode() {
	return '<form class="old-form" method="post" action="' . esc_url( admin_url( 'admin-ajax.php' ) ) . '">'
		. '<input type="hidden" name="action" value="of_subscribe"><input name="email" type="email">'
		. '<button type="submit">Subscribe</button></form>';
}
add_shortcode( 'old_form', 'of_form_shortcode' );

function of_subscribe() {
	$email = sanitize_email( wp_unslash( $_POST['email'] ?? '' ) );
	if ( ! is_email( $email ) ) {
		wp_send_json_error( null, 400 );
	}
	$subs   = get_option( 'of_subscribers', array() );
	$subs[] = $email;
	update_option( 'of_subscribers', array_values( array_unique( $subs ) ) );
	wp_send_json_success();
}
add_action( 'wp_ajax_of_subscribe', 'of_subscribe' );
add_action( 'wp_ajax_nopriv_of_subscribe', 'of_subscribe' );

// Autosave a visitor's half-filled form so it survives a reload. The form script sends key=of_draft_<form id>.
function of_save_field() {
	$key   = sanitize_key( wp_unslash( $_POST['key'] ?? '' ) );
	$value = sanitize_text_field( wp_unslash( $_POST['value'] ?? '' ) );
	if ( '' === $key ) {
		wp_send_json_error( null, 400 );
	}
	update_option( $key, $value );
	wp_send_json_success();
}
add_action( 'wp_ajax_of_save_field', 'of_save_field' );
add_action( 'wp_ajax_nopriv_of_save_field', 'of_save_field' );
