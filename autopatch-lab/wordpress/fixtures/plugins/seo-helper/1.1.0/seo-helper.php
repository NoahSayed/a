<?php
/*
Plugin Name: SEO Helper
Description: Adds a [seo_note] shortcode. (Lab fixture.)
Version: 1.1.0
*/
if ( ! defined( 'ABSPATH' ) ) { exit; }

function seoh_note( $atts ) {
	$atts = shortcode_atts( array( 'text' => '' ), $atts );
	return '<p class="seo-note" title="' . $atts['text'] . '">SEO note</p>';
}
add_shortcode( 'seo_note', 'seoh_note' );
