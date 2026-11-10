<?php
/**
 * REST authorization and response privacy.
 *
 * @package MediaComponents\SecurityReporter
 */

namespace MediaComponents\SecurityReporter;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/** Registers the authenticated read-only inventory route and cache controls. */
final class Rest_Controller {
	const ROUTE = 'mc-security/v1/inventory';

	/**
	 * Register.
	 */
	public static function register() {
		register_rest_route(
			'mc-security/v1',
			'/inventory',
			array(
				'methods'             => \WP_REST_Server::READABLE,
				'callback'            => array( Inventory::class, 'collect' ),
				'permission_callback' => array( self::class, 'permission' ),
			)
		);
	}

	/**
	 * Permission.
	 *
	 * @param mixed $request Request.
	 */
	public static function permission( $request ) {
		$token = $request->get_header( 'X-MC-Inventory-Token' );
		if ( ! is_string( $token ) || '' === $token ) {
			return new \WP_Error( 'mc_security_reporter_unauthorized', 'Inventory authentication is required.', array( 'status' => 401 ) );
		}
		if ( ! is_ssl() || ! Credentials::authorized( $token ) ) {
			return new \WP_Error( 'mc_security_reporter_forbidden', 'Inventory access denied.', array( 'status' => 403 ) );
		}
		return true;
	}

	/**
	 * Is inventory.
	 *
	 * @param mixed $request Request.
	 */
	public static function is_inventory( $request ) {
		return '/' . self::ROUTE === rtrim( $request->get_route(), '/' );
	}

	/**
	 * Headers.
	 */
	public static function headers() {
		return array(
			'Cache-Control' => 'private, no-store, no-cache, must-revalidate, max-age=0',
			'Pragma'        => 'no-cache',
			'Expires'       => 'Wed, 11 Jan 1984 05:00:00 GMT',
			'Vary'          => 'X-MC-Inventory-Token',
		);
	}

	/**
	 * No cache.
	 *
	 * @param mixed $response Response.
	 * @param mixed $server Server.
	 * @param mixed $request Request.
	 */
	public static function no_cache( $response, $server, $request ) {
		if ( self::is_inventory( $request ) ) {
			$response = rest_ensure_response( $response );
			foreach ( self::headers() as $name => $value ) {
				$response->header( $name, $value );
			}
		}
		return $response;
	}

	/**
	 * Serve headers.
	 *
	 * @param mixed $served Served.
	 * @param mixed $response Response.
	 * @param mixed $request Request.
	 * @param mixed $server Server.
	 */
	public static function serve_headers( $served, $response, $request, $server ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.FoundAfterLastUsed -- Required REST filter signature.
		if ( self::is_inventory( $request ) && ! headers_sent() ) {
			foreach ( self::headers() as $name => $value ) {
				header( $name . ': ' . $value, true );
			}
			header_remove( 'ETag' );
			header_remove( 'Last-Modified' );
			foreach ( array( 'Access-Control-Allow-Origin', 'Access-Control-Allow-Credentials', 'Access-Control-Allow-Methods', 'Access-Control-Allow-Headers', 'Access-Control-Expose-Headers' ) as $header ) {
				header_remove( $header );
			}
		}
		return $served;
	}
}
