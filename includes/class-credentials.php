<?php
/**
 * Credential and site identity lifecycle.
 *
 * @package MediaComponents\SecurityReporter
 */

namespace MediaComponents\SecurityReporter;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/** Owns site identity, token hashes and one-use administrative tickets. */
final class Credentials {
	const OPTION        = 'mc_security_reporter_settings';
	const TICKET_PREFIX = 'mc_security_reporter_ticket_';

	/**
	 * Valid id.
	 *
	 * @param mixed $value Value.
	 */
	public static function valid_id( $value ) {
		return is_string( $value ) && 1 === preg_match( '/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/D', $value );
	}

	/**
	 * Settings.
	 */
	public static function settings() {
		$value = get_option( self::OPTION, array() );
		return is_array( $value ) ? $value : array();
	}

	/**
	 * Store.
	 *
	 * @param mixed $settings Settings.
	 */
	private static function store( $settings ) {
		return self::settings() === $settings || update_option( self::OPTION, $settings, false );
	}

	/**
	 * Activate.
	 *
	 * @param mixed $network_wide Network wide.
	 */
	public static function activate( $network_wide = false ) {
		if ( is_multisite() || $network_wide ) {
			wp_die( 'MC Security Reporter supports single-site WordPress only.', '', array( 'response' => 403 ) );
		}
		$previous = get_option( self::OPTION, false );
		$id       = false === $previous ? wp_generate_uuid4() : ( is_array( $previous ) ? ( $previous['site_id'] ?? '' ) : '' );
		if ( ! self::store(
			array(
				'site_id'    => $id,
				'enabled'    => false,
				'token_hash' => '',
				'rotated_at' => null,
			)
		) ) {
			wp_die( 'Unable to initialize MC Security Reporter credentials.', '', array( 'response' => 500 ) );
		}
	}

	/**
	 * Deactivate.
	 */
	public static function deactivate() {
		$settings               = self::settings();
		$settings['enabled']    = false;
		$settings['token_hash'] = '';
		if ( ! self::store( $settings ) ) {
			wp_die( 'Unable to revoke MC Security Reporter credentials. Retry deactivation.', '', array( 'response' => 500 ) );
		}
		self::clear_tickets();
	}

	/**
	 * Clear tickets.
	 */
	public static function clear_tickets() {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Owned ticket cleanup/atomic consume; option caches are explicitly invalidated.
		$names = $wpdb->get_col( $wpdb->prepare( "SELECT option_name FROM {$wpdb->options} WHERE option_name LIKE %s", $wpdb->esc_like( self::TICKET_PREFIX ) . '%' ) );
		foreach ( $names as $name ) {
			delete_option( $name );
		}
	}

	/** One current five-minute ticket per admin; only its hash is persisted. */
	public static function issue_ticket() {
		$ticket = bin2hex( random_bytes( 32 ) );
		update_option(
			self::TICKET_PREFIX . get_current_user_id(),
			array(
				'hash'    => hash( 'sha256', $ticket ),
				'expires' => time() + 300,
			),
			false
		);
		return $ticket;
	}

	/**
	 * Atomic compare-and-delete prevents two requests from consuming one ticket.
	 *
	 * @param mixed $ticket Ticket.
	 */
	public static function consume_ticket( $ticket ) {
		global $wpdb;
		if ( ! is_string( $ticket ) || 1 !== preg_match( '/^[a-f0-9]{64}$/D', $ticket ) ) {
			return false;
		}
		$name     = self::TICKET_PREFIX . get_current_user_id();
		$expected = get_option( $name );
		if ( ! is_array( $expected ) || ! isset( $expected['expires'], $expected['hash'] ) || ! is_int( $expected['expires'] ) || ! is_string( $expected['hash'] ) || 1 !== preg_match( '/^[a-f0-9]{64}$/D', $expected['hash'] ) || $expected['expires'] < time() || ! hash_equals( $expected['hash'], hash( 'sha256', $ticket ) ) ) {
			return false;
		}
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- Atomic compare-and-delete prevents replay; option caches are invalidated below.
		$deleted = $wpdb->delete(
			$wpdb->options,
			array(
				'option_name'  => $name,
				'option_value' => maybe_serialize( $expected ),
			),
			array( '%s', '%s' )
		);
		wp_cache_delete( $name, 'options' );
		return 1 === $deleted;
	}

	/**
	 * Called only after admin capability, nonce, method and one-use ticket checks.
	 *
	 * @param mixed $operation Operation.
	 */
	public static function change( $operation ) {
		if ( is_multisite() ) {
			return new \WP_Error( 'unsupported_multisite', 'Single-site WordPress is required.', array( 'status' => 403 ) );
		}
		$settings = self::settings();
		if ( 'disable' === $operation || 'reset_identity' === $operation ) {
			$settings['enabled']    = false;
			$settings['token_hash'] = '';
			if ( 'reset_identity' === $operation ) {
				$settings['site_id']    = wp_generate_uuid4();
				$settings['rotated_at'] = null;
			}
			if ( ! self::store( $settings ) ) {
				return new \WP_Error( 'settings_write_failed', 'Unable to save credentials. Reload and retry.', array( 'status' => 500 ) );
			}
			self::clear_tickets();
			return array( 'message' => 'API disabled. Reload settings before another action.' );
		}
		if ( ! in_array( $operation, array( 'generate', 'rotate' ), true ) ) {
			return new \WP_Error( 'invalid_operation', 'Invalid operation.', array( 'status' => 400 ) );
		}
		if ( ! is_ssl() || 'https' !== wp_parse_url( rest_url( Rest_Controller::ROUTE ), PHP_URL_SCHEME ) ) {
			return new \WP_Error( 'https_required', 'HTTPS is required to generate a token.', array( 'status' => 400 ) );
		}
		if ( ! self::valid_id( $settings['site_id'] ?? null ) ) {
			return new \WP_Error( 'invalid_site_identity', 'Reset the site identity before generating a token.', array( 'status' => 409 ) );
		}
		$enabled = true === ( $settings['enabled'] ?? false );
		if ( ( 'generate' === $operation && $enabled ) || ( 'rotate' === $operation && ! $enabled ) ) {
			return new \WP_Error( 'invalid_token_state', 'Reload settings and choose the current action.', array( 'status' => 409 ) );
		}
		$token                  = bin2hex( random_bytes( 32 ) );
		$settings['token_hash'] = hash( 'sha256', $token );
		$settings['enabled']    = true;
		$settings['rotated_at'] = gmdate( 'Y-m-d\TH:i:s\Z' );
		if ( ! update_option( self::OPTION, $settings, false ) ) {
			return new \WP_Error( 'settings_write_failed', 'Unable to save credentials. Reload and retry.', array( 'status' => 500 ) );
		}
		return array(
			'message' => 'Copy the token now. It will not be shown again. Reload settings before another action.',
			'token'   => $token,
		);
	}

	/**
	 * Authorized.
	 *
	 * @param mixed $token Token.
	 */
	public static function authorized( $token ) {
		$settings = self::settings();
		return true === ( $settings['enabled'] ?? false ) && self::valid_id( $settings['site_id'] ?? null ) &&
			is_string( $token ) && 1 === preg_match( '/^[a-f0-9]{64}$/D', $token ) &&
			is_string( $settings['token_hash'] ?? null ) && 1 === preg_match( '/^[a-f0-9]{64}$/D', $settings['token_hash'] ) &&
			hash_equals( $settings['token_hash'], hash( 'sha256', $token ) );
	}
}
