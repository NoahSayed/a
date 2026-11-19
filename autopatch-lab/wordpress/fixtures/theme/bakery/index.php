<!doctype html>
<html <?php language_attributes(); ?>>
<head><meta charset="<?php bloginfo( 'charset' ); ?>"><title><?php wp_title( '|', true, 'right' ); bloginfo( 'name' ); ?></title><?php wp_head(); ?></head>
<body <?php body_class(); ?>>
<header><h1><a href="<?php echo esc_url( home_url( '/' ) ); ?>"><?php bloginfo( 'name' ); ?></a></h1></header>
<?php echo bakery_featured_cakes(); ?>
<main>
<?php if ( have_posts() ) : while ( have_posts() ) : the_post(); ?>
	<article><h2><?php the_title(); ?></h2><?php the_content(); ?></article>
<?php endwhile; endif; ?>
</main>
<?php wp_footer(); ?>
</body>
</html>
