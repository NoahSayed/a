<?php
/*
Plugin Name: Simple Gallery
Description: Shows images from uploads/simple-gallery. (Lab fixture.)
Version: 3.0.0
*/
namespace SimpleGallery;

if ( ! defined( 'ABSPATH' ) ) { exit; }

class Gallery {
	public static function dir() {
		$u = wp_upload_dir();
		return trailingslashit( $u['basedir'] ) . 'simple-gallery/';
	}

	/** URLs of all gallery images. Replaces the old sg_get_images() helper. */
	public static function get_images() {
		$u   = wp_upload_dir();
		$out = array();
		foreach ( (array) glob( self::dir() . '*.svg' ) as $f ) {
			$out[] = trailingslashit( $u['baseurl'] ) . 'simple-gallery/' . basename( $f );
		}
		sort( $out );
		return $out;
	}

	public static function shortcode() {
		$h = '<div class="simple-gallery">';
		foreach ( self::get_images() as $src ) {
			$h .= '<img class="sg-img" src="' . esc_url( $src ) . '" alt="">';
		}
		return $h . '</div>';
	}

	public static function download() {
		$name = basename( wp_unslash( $_GET['sg_download'] ) );
		$base = realpath( self::dir() );
		$file = $base ? realpath( $base . '/' . $name ) : false;
		if ( $file && 0 === strpos( $file, $base . DIRECTORY_SEPARATOR ) && is_file( $file ) ) {
			header( 'Content-Type: application/octet-stream' );
			readfile( $file );
			exit;
		}
		status_header( 404 );
		exit;
	}
}

add_shortcode( 'simple_gallery', array( Gallery::class, 'shortcode' ) );
add_action( 'init', function () {
	if ( isset( $_GET['sg_download'] ) ) {
		Gallery::download();
	}
} );
