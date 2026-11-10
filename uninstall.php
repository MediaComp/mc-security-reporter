<?php
/**
 * Remove only Reporter settings.
 *
 * @package MediaComponents\SecurityReporter
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

// Network activation is refused; do not traverse or change unrelated sites.
delete_option( 'mc_security_reporter_settings' );
delete_site_transient( 'mc_security_reporter_update_metadata' );
global $wpdb;
// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Enumerate owned names once during uninstall; delete_option() invalidates caches.
$mc_security_reporter_names = $wpdb->get_col( $wpdb->prepare( "SELECT option_name FROM {$wpdb->options} WHERE option_name LIKE %s", $wpdb->esc_like( 'mc_security_reporter_ticket_' ) . '%' ) );
foreach ( $mc_security_reporter_names as $mc_security_reporter_name ) {
	delete_option( $mc_security_reporter_name );
}
