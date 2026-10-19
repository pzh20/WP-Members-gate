<?php
/** Remove everything the plugin stored. The upload rule is already gone (deactivation). */
defined( 'WP_UNINSTALL_PLUGIN' ) || exit;

foreach ( array( 'hmg_settings', 'hmg_log', 'hmg_test', 'hmg_test_time' ) as $hmg_option ) {
	delete_option( $hmg_option );
}
$hmg_up = wp_get_upload_dir();
if ( ! empty( $hmg_up['basedir'] ) ) {
	$hmg_dir = $hmg_up['basedir'] . '/hhh-members-gate';
	foreach ( array( '/public/index.php', '/public/.htaccess', '/index.php', '/canary.txt' ) as $hmg_file ) {
		@unlink( $hmg_dir . $hmg_file ); // phpcs:ignore WordPress.WP.AlternativeFunctions,WordPress.PHP.NoSilencedErrors
	}
	@rmdir( $hmg_dir . '/public' ); // phpcs:ignore WordPress.WP.AlternativeFunctions,WordPress.PHP.NoSilencedErrors
	@rmdir( $hmg_dir ); // phpcs:ignore WordPress.WP.AlternativeFunctions,WordPress.PHP.NoSilencedErrors
}
$hmg_webp = WP_CONTENT_DIR . '/webp-express/webp-images/uploads/hhh-members-gate';
@unlink( $hmg_webp . '/canary.txt' ); // phpcs:ignore WordPress.WP.AlternativeFunctions,WordPress.PHP.NoSilencedErrors
@rmdir( $hmg_webp ); // phpcs:ignore WordPress.WP.AlternativeFunctions,WordPress.PHP.NoSilencedErrors
