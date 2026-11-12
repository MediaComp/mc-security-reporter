<?php
/**
 * Plugin Name: MC Security Reporter
 * Description: Provides an authenticated read-only component inventory for MC Security Monitor.
 * Version: 0.2.3
 * Requires at least: 6.4
 * Requires PHP: 8.1
 * Author: Media Components
 * Update URI: https://github.com/MediaComp/mc-security-reporter
 * Text Domain: mc-security-reporter
 *
 * @package MediaComponents\SecurityReporter
 */

namespace MediaComponents\SecurityReporter;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'MC_SECURITY_REPORTER_FILE', __FILE__ );
define( 'MC_SECURITY_REPORTER_VERSION', '0.2.3' );

require_once __DIR__ . '/includes/class-credentials.php';
require_once __DIR__ . '/includes/class-inventory.php';
require_once __DIR__ . '/includes/class-rest-controller.php';
require_once __DIR__ . '/includes/class-admin.php';
require_once __DIR__ . '/includes/class-updater.php';

register_activation_hook( __FILE__, array( Credentials::class, 'activate' ) );
register_deactivation_hook( __FILE__, array( Credentials::class, 'deactivate' ) );

add_action( 'rest_api_init', array( Rest_Controller::class, 'register' ) );
add_filter( 'rest_post_dispatch', array( Rest_Controller::class, 'no_cache' ), PHP_INT_MAX, 3 );
add_filter( 'rest_pre_serve_request', array( Rest_Controller::class, 'serve_headers' ), PHP_INT_MAX, 4 );
Admin::register();
Updater::register();
