<?php
/** Featured cakes strip shown on every page. Uses the Simple Gallery plugin's helper. */
function bakery_featured_cakes() {
	$images = sg_get_images();
	$html   = '<section class="featured"><h2>Featured cakes</h2>';
	foreach ( array_slice( $images, 0, 3 ) as $src ) {
		$html .= '<img class="featured-img" src="' . esc_url( $src ) . '" alt="cake">';
	}
	return $html . '</section>';
}

add_action( 'wp_enqueue_scripts', function () {
	wp_enqueue_style( 'bakery', get_stylesheet_uri(), array(), '1.0' );
} );
