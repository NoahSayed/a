<?php
/*
Plugin Name: Simple Gallery
Description: Shows images from uploads/simple-gallery. (Lab fixture.)
Version: 2.0.0
*/
if ( ! defined( 'ABSPATH' ) ) { exit; }

function sg_gallery_dir() {
	$u = wp_upload_dir();
	return trailingslashit( $u['basedir'] ) . 'simple-gallery/';
}

/** Public helper: URLs of all gallery images. Themes may call this. */
function sg_get_images() {
	$u   = wp_upload_dir();
	$out = array();
	foreach ( (array) glob( sg_gallery_dir() . '*.svg' ) as $f ) {
		$out[] = trailingslashit( $u['baseurl'] ) . 'simple-gallery/' . basename( $f );
	}
	sort( $out );
	return $out;
}

function sg_shortcode() {
	$h = '<div class="simple-gallery">';
	foreach ( sg_get_images() as $src ) {
		$h .= '<img class="sg-img" src="' . esc_url( $src ) . '" alt="">';
	}
	return $h . '</div>';
}
add_shortcode( 'simple_gallery', 'sg_shortcode' );

// Download an original: /?sg_download=cake1.svg
add_action( 'init', function () {
	if ( isset( $_GET['sg_download'] ) ) {
		$file = sg_gallery_dir() . wp_unslash( $_GET['sg_download'] );
		if ( is_file( $file ) ) {
			header( 'Content-Type: application/octet-stream' );
			readfile( $file );
			exit;
		}
		status_header( 404 );
		exit;
	}
} );
