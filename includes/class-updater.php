<?php
/**
 * Native WordPress updates from a fixed public release channel.
 *
 * @package MediaComponents\SecurityReporter
 */

namespace MediaComponents\SecurityReporter;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/** No GitHub credentials, site URLs or inventory data enter update requests. */
final class Updater {
	const HOME         = 'https://github.com/MediaComp/mc-security-reporter';
	const METADATA_URL = 'https://raw.githubusercontent.com/MediaComp/mc-security-reporter/main/update.json';
	const PLUGIN       = 'mc-security-reporter/mc-security-reporter.php';
	const SLUG         = 'mc-security-reporter';
	const CACHE        = 'mc_security_reporter_update_metadata';
	const MAX_METADATA = 32768;
	const MAX_PACKAGE  = 2097152;

	/** Register only native update hooks; no independent cron or automatic-update override. */
	public static function register() {
		add_filter( 'update_plugins_github.com', array( self::class, 'update' ), 10, 4 );
		add_filter( 'plugins_api', array( self::class, 'information' ), 10, 3 );
		add_filter( 'upgrader_pre_download', array( self::class, 'download' ), PHP_INT_MAX, 4 );
		add_action( 'upgrader_process_complete', array( self::class, 'complete' ), 10, 2 );
	}

	/**
	 * Stable canonical release versions only.
	 *
	 * @param mixed $version Candidate version.
	 * @return bool
	 */
	private static function stable( $version ) {
		return is_string( $version ) && 1 === preg_match( '/^(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})$/D', $version );
	}

	/**
	 * Strict public metadata validation, including a version-specific package URL.
	 *
	 * @param mixed $data Decoded metadata.
	 * @return array|false
	 */
	public static function validate( $data ) {
		$keys = array( 'schema_version', 'slug', 'version', 'requires', 'requires_php', 'tested', 'package', 'sha256', 'size', 'changelog' );
		if ( ! is_array( $data ) || array_diff( $keys, array_keys( $data ) ) || array_diff( array_keys( $data ), $keys ) ||
			1 !== $data['schema_version'] || self::SLUG !== $data['slug'] || ! self::stable( $data['version'] ) ) {
			return false;
		}
		foreach ( array( 'requires', 'requires_php', 'tested' ) as $field ) {
			if ( ! is_string( $data[ $field ] ) || 1 !== preg_match( '/^[0-9]{1,3}\.[0-9]{1,3}(?:\.[0-9]{1,3})?$/D', $data[ $field ] ) ) {
				return false;
			}
		}
		if ( version_compare( $data['requires'], '6.4', '<' ) || version_compare( $data['requires_php'], '8.1', '<' ) ||
			version_compare( $data['tested'], $data['requires'], '<' ) ||
			self::HOME . '/releases/download/v' . $data['version'] . '/mc-security-reporter-' . $data['version'] . '.zip' !== $data['package'] ||
			! is_string( $data['sha256'] ) || 1 !== preg_match( '/^[0-9a-f]{64}$/D', $data['sha256'] ) ||
			! is_int( $data['size'] ) || $data['size'] < 1 || $data['size'] > self::MAX_PACKAGE ||
			! is_string( $data['changelog'] ) || strlen( $data['changelog'] ) > 6000 || false !== strpos( $data['changelog'], "\0" ) ) {
			return false;
		}
		return $data;
	}

	/**
	 * Bounded fixed-source metadata; failure is cached briefly without a stale success fallback.
	 *
	 * @return array|false
	 */
	private static function metadata() {
		if ( is_multisite() || ( defined( 'REST_REQUEST' ) && REST_REQUEST ) ) {
			return false;
		}
		$cached = get_site_transient( self::CACHE );
		if ( false !== $cached ) {
			return is_array( $cached ) ? self::validate( $cached ) : false;
		}
		$response = wp_safe_remote_get(
			self::METADATA_URL,
			array(
				'timeout'             => 5,
				'redirection'         => 0,
				'sslverify'           => true,
				'limit_response_size' => self::MAX_METADATA + 1,
				'user-agent'          => 'MC-Security-Reporter/' . MC_SECURITY_REPORTER_VERSION,
				'headers'             => array( 'Accept' => 'application/json, text/plain' ),
				'cookies'             => array(),
			)
		);
		$data     = false;
		$mime     = is_wp_error( $response ) ? '' : wp_remote_retrieve_header( $response, 'content-type' );
		if ( ! is_wp_error( $response ) && 200 === wp_remote_retrieve_response_code( $response ) &&
			is_string( $mime ) && preg_match( '/^(application\/json|text\/plain)(?:\s*;|$)/i', $mime ) ) {
			$body = wp_remote_retrieve_body( $response );
			if ( strlen( $body ) <= self::MAX_METADATA ) {
				$data = self::validate( json_decode( $body, true, 16 ) );
			}
		}
		set_site_transient( self::CACHE, false === $data ? 'unavailable' : $data, false === $data ? 10 * MINUTE_IN_SECONDS : 6 * HOUR_IN_SECONDS );
		return $data;
	}

	/**
	 * Supply only this plugin's native update response.
	 *
	 * @param mixed  $update Previous update response.
	 * @param array  $plugin_data WordPress plugin headers.
	 * @param string $plugin_file Plugin basename.
	 * @param array  $locales Requested locales.
	 * @return mixed
	 */
	public static function update( $update, $plugin_data, $plugin_file, $locales ) {
		if ( self::PLUGIN !== $plugin_file || self::HOME !== ( $plugin_data['UpdateURI'] ?? null ) ) {
			return $update;
		}
		if ( ! is_array( $locales ) ) {
			return false;
		}
		$data = self::metadata();
		if ( false === $data ) {
			return false;
		}
		return array(
			'id'           => self::HOME,
			'slug'         => self::SLUG,
			'version'      => $data['version'],
			'url'          => self::HOME,
			'package'      => $data['package'],
			'tested'       => $data['tested'],
			'requires'     => $data['requires'],
			'requires_php' => $data['requires_php'],
		);
	}

	/**
	 * Native View details dialog; untrusted changelog is rendered as plain text.
	 *
	 * @param mixed  $result Existing API result.
	 * @param string $action API action.
	 * @param object $args API arguments.
	 * @return mixed
	 */
	public static function information( $result, $action, $args ) {
		if ( 'plugin_information' !== $action || self::SLUG !== ( $args->slug ?? null ) ) {
			return $result;
		}
		$data = self::metadata();
		if ( false === $data ) {
			return new \WP_Error( 'mc_update_unavailable', 'Reporter release information is currently unavailable.' );
		}
		return (object) array(
			'name'          => 'MC Security Reporter',
			'slug'          => self::SLUG,
			'version'       => $data['version'],
			'homepage'      => self::HOME,
			'requires'      => $data['requires'],
			'requires_php'  => $data['requires_php'],
			'tested'        => $data['tested'],
			'download_link' => $data['package'],
			'sections'      => array(
				'description' => 'Read-only authenticated inventory. Known matches do not guarantee security.',
				'changelog'   => nl2br( esc_html( $data['changelog'] ) ),
			),
		);
	}

	/**
	 * Restrict GitHub asset redirects without leaking credentials or following arbitrary hosts.
	 *
	 * @param mixed $url Redirect URL.
	 * @return bool
	 */
	private static function asset_url( $url ) {
		if ( ! is_string( $url ) || strlen( $url ) > 8192 ) {
			return false;
		}
		$p = wp_parse_url( $url );
		return is_array( $p ) && 'https' === ( $p['scheme'] ?? '' ) &&
			in_array( $p['host'] ?? '', array( 'release-assets.githubusercontent.com', 'objects.githubusercontent.com' ), true ) &&
			! isset( $p['user'] ) && ! isset( $p['pass'] ) && ! isset( $p['fragment'] ) &&
			( ! isset( $p['port'] ) || 443 === $p['port'] );
	}

	/**
	 * Download and verify only our package before the native installer touches plugin files.
	 *
	 * @param mixed  $reply Prior download interception.
	 * @param string $package Requested package.
	 * @param object $upgrader WordPress upgrader.
	 * @param array  $extra Upgrade context.
	 * @return mixed
	 */
	public static function download( $reply, $package, $upgrader, $extra ) {
		$ours = self::PLUGIN === ( $extra['plugin'] ?? null ) ||
			( is_string( $package ) && 0 === strpos( $package, self::HOME . '/releases/' ) );
		if ( ! $ours ) {
			return $reply;
		}
		$data = self::metadata();
		if ( false !== $reply || false === $data || $package !== $data['package'] ||
			! version_compare( $data['version'], MC_SECURITY_REPORTER_VERSION, '>' ) ||
			! is_php_version_compatible( $data['requires_php'] ) || ! is_wp_version_compatible( $data['requires'] ) ) {
			return new \WP_Error( 'mc_update_rejected', 'Reporter update metadata or compatibility could not be verified. Check for updates again.' );
		}
		$file = wp_tempnam( 'mc-security-reporter-update.zip' );
		if ( ! $file ) {
			return new \WP_Error( 'mc_update_download', 'Unable to create the Reporter update temporary file.' );
		}
		$url = $package;
		for ( $i = 0; $i < 4; ++$i ) {
			$response = wp_safe_remote_get(
				$url,
				array(
					'timeout'             => 30,
					'redirection'         => 0,
					'sslverify'           => true,
					'limit_response_size' => self::MAX_PACKAGE + 1,
					'user-agent'          => 'MC-Security-Reporter/' . MC_SECURITY_REPORTER_VERSION,
					'headers'             => array( 'Accept' => 'application/octet-stream' ),
					'cookies'             => array(),
					'stream'              => true,
					'filename'            => $file,
				)
			);
			if ( is_wp_error( $response ) ) {
				break;
			}
			$status = wp_remote_retrieve_response_code( $response );
			if ( in_array( $status, array( 301, 302, 303, 307, 308 ), true ) ) {
				$url = wp_remote_retrieve_header( $response, 'location' );
				if ( ! self::asset_url( $url ) ) {
					break;
				}
				continue;
			}
			clearstatcache( true, $file );
			if ( 200 === $status && is_file( $file ) && filesize( $file ) === $data['size'] &&
				hash_equals( $data['sha256'], hash_file( 'sha256', $file ) ) ) {
				return $file;
			}
			break;
		}
		wp_delete_file( $file );
		return new \WP_Error( 'mc_update_download', 'Reporter update download failed its source, size or SHA-256 check.' );
	}

	/**
	 * Clear only the update metadata cache after an update to this plugin.
	 *
	 * @param object $upgrader WordPress upgrader.
	 * @param array  $extra Upgrade context.
	 */
	public static function complete( $upgrader, $extra ) {
		if ( 'plugin' === ( $extra['type'] ?? null ) && 'update' === ( $extra['action'] ?? null ) &&
			( self::PLUGIN === ( $extra['plugin'] ?? null ) || in_array( self::PLUGIN, $extra['plugins'] ?? array(), true ) ) ) {
			delete_site_transient( self::CACHE );
		}
	}
}
