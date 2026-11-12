<?php
/**
 * Read-only bounded WordPress inventory.
 *
 * @package MediaComponents\SecurityReporter
 */

namespace MediaComponents\SecurityReporter;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/** Collects bounded public component metadata without outbound requests. */
final class Inventory {
	/** Keep WordPress's lazy theme-roots cache maintenance request-local during inventory. */
	private static function themes() {
		$roots    = get_option( '_site_transient_theme_roots', array() );
		$read     = static function () use ( &$roots ) {
			return is_array( $roots ) ? $roots : array();
		};
		$capture  = static function ( $value ) use ( &$roots ) {
			$roots = $value;
			return $value;
		};
		$no_write = static function ( $value, $old_value ) {
			return $old_value;
		};
		$fresh    = static function ( $value, $context ) {
			return 'search_theme_directories' === $context ? false : $value;
		};
		add_filter( 'pre_site_transient_theme_roots', $read, PHP_INT_MAX );
		add_filter( 'pre_site_option__site_transient_theme_roots', $read, PHP_INT_MAX );
		add_filter( 'pre_set_site_transient_theme_roots', $capture, PHP_INT_MAX );
		add_filter( 'pre_update_site_option__site_transient_theme_roots', $no_write, PHP_INT_MAX, 2 );
		add_filter( 'pre_update_site_option__site_transient_timeout_theme_roots', $no_write, PHP_INT_MAX, 2 );
		add_filter( 'wp_cache_themes_persistently', $fresh, PHP_INT_MAX, 2 );
		try {
			return wp_get_themes( array( 'errors' => null ) );
		} finally {
			remove_filter( 'pre_site_transient_theme_roots', $read, PHP_INT_MAX );
			remove_filter( 'pre_site_option__site_transient_theme_roots', $read, PHP_INT_MAX );
			remove_filter( 'pre_set_site_transient_theme_roots', $capture, PHP_INT_MAX );
			remove_filter( 'pre_update_site_option__site_transient_theme_roots', $no_write, PHP_INT_MAX );
			remove_filter( 'pre_update_site_option__site_transient_timeout_theme_roots', $no_write, PHP_INT_MAX );
			remove_filter( 'wp_cache_themes_persistently', $fresh, PHP_INT_MAX );
		}
	}

	/**
	 * Validate a UTF-8 string against a byte limit.
	 *
	 * @param mixed $value Value.
	 * @param mixed $max Max.
	 * @throws \UnexpectedValueException Invalid UTF-8 or oversized metadata.
	 */
	private static function bounded( $value, $max ) {
		if ( ! is_string( $value ) || strlen( $value ) > $max || 1 !== preg_match( '//u', $value ) ) {
			throw new \UnexpectedValueException( 'Invalid bounded field.' );
		}
		return $value;
	}

	/**
	 * Validate a stable relative local component identity.
	 *
	 * @param mixed $value Value.
	 * @throws \UnexpectedValueException Unsafe relative component path.
	 */
	private static function identity( $value ) {
		$value = self::bounded( $value, 255 );
		if ( '' === $value || '/' === $value[0] || preg_match( '~(?:^|/)\.{1,2}(?:/|$)|[\\\\\x00-\x1f\x7f]~', $value ) ) {
			throw new \UnexpectedValueException( 'Invalid local identity.' );
		}
		return $value;
	}

	/**
	 * Slug.
	 *
	 * @param mixed $value Value.
	 */
	private static function slug( $value ) {
		return is_string( $value ) && strlen( $value ) <= 190 && preg_match( '/^[a-z0-9][a-z0-9._-]*$/D', $value ) ? $value : null;
	}

	/**
	 * Safe url.
	 *
	 * @param mixed $value Value.
	 */
	private static function safe_url( $value ) {
		if ( ! is_string( $value ) || strlen( $value ) > 2048 ) {
			return null;
		}
		$parts = wp_parse_url( $value );
		if ( ! is_array( $parts ) || 'https' !== ( $parts['scheme'] ?? '' ) || isset( $parts['user'] ) || isset( $parts['pass'] ) || isset( $parts['query'] ) || isset( $parts['fragment'] ) || ! isset( $parts['host'] ) ) {
			return null;
		}
		return $parts;
	}

	/**
	 * Export the official updater's cached slug, or flag an explicit custom Update URI.
	 *
	 * @param array  $hints Existing metadata hints.
	 * @param string $type Component type.
	 * @param string $identity Local plugin file or theme stylesheet.
	 * @param string $version Installed version.
	 * @param string $update_uri Declared Update URI.
	 * @param mixed  $updates Native update transient.
	 */
	private static function with_update_origin( $hints, $type, $identity, $version, $update_uri, $updates ) {
		$directory = 'plugin' === $type ? 'plugins' : 'themes';
		$declared  = null;
		if ( '' !== $update_uri ) {
			if ( ! preg_match( '~^(?:https://wordpress\.org/' . $directory . '/|w\.org/' . $type . '/)([a-z0-9][a-z0-9._-]*)/?$~D', $update_uri, $match ) ||
				! self::slug( $match[1] ) || ( 'theme' === $type && $identity !== $match[1] ) ) {
				$hints['wordpress_org_update_slug'] = null;
				return $hints;
			}
			$declared = $match[1];
		}
		if ( ! is_object( $updates ) || ! is_array( $updates->checked ?? null ) || ( $updates->checked[ $identity ] ?? null ) !== $version ) {
			return $hints;
		}
		$response  = is_array( $updates->response ?? null ) ? $updates->response : array();
		$no_update = is_array( $updates->no_update ?? null ) ? $updates->no_update : array();
		$record    = $response[ $identity ] ?? $no_update[ $identity ] ?? null;
		if ( ! is_array( $record ) && ! is_object( $record ) ) {
			return $hints;
		}
		$record = (array) $record;
		$slug   = 'plugin' === $type ? self::slug( $record['slug'] ?? null ) : self::slug( $identity );
		if ( ! $slug || ( $record[ $type ] ?? null ) !== $identity || ( $declared && $declared !== $slug ) ||
			( 'theme' === $type && isset( $record['slug'] ) && $record['slug'] !== $slug ) ) {
			return $hints;
		}
		if ( 'plugin' === $type && ! in_array( $record['id'] ?? null, array( 'w.org/plugins/' . $slug, 'w.org/plugin/' . $slug, 'https://wordpress.org/plugins/' . $slug . '/' ), true ) ) {
			return $hints;
		}
		if ( 'plugin' === $type ) {
			$directory = dirname( $identity );
			$local     = '.' === $directory ? basename( $identity, '.php' ) : $directory;
			if ( $local !== $slug && ! ( 'hello.php' === $identity && 'hello-dolly' === $slug ) ) {
				return $hints;
			}
		}
		$release = $record['new_version'] ?? null;
		$package = $record['package'] ?? null;
		$prefix  = 'https://downloads.wordpress.org/' . $type . '/' . $slug;
		if ( is_string( $release ) && preg_match( '/^[a-zA-Z0-9][a-zA-Z0-9._+-]{0,127}$/D', $release ) &&
			in_array( $package, array( $prefix . '.zip', $prefix . '.' . $release . '.zip' ), true ) ) {
			$hints['wordpress_org_update_slug'] = $slug;
		}
		return $hints;
	}

	/**
	 * Hints.
	 *
	 * @param mixed $product_uri Product uri.
	 * @param mixed $update_uri Update uri.
	 * @param mixed $type Type.
	 */
	private static function hints( $product_uri, $update_uri, $type ) {
		$product = self::safe_url( $product_uri );
		$update  = self::safe_url( $update_uri );
		$slug    = null;
		if ( $product && 'wordpress.org' === strtolower( $product['host'] ) && preg_match( '~^/' . ( 'plugin' === $type ? 'plugins' : 'themes' ) . '/([a-z0-9][a-z0-9._-]*)/?$~D', $product['path'] ?? '', $match ) ) {
			$slug = self::slug( $match[1] );
		}
		$host = $update ? strtolower( $update['host'] ) : null;
		if ( null !== $host && ( strlen( $host ) > 253 || ! preg_match( '/^[a-z0-9.-]+$/D', $host ) ) ) {
			$host = null;
		}
		return array(
			'wordpress_org_slug' => $slug,
			'update_uri_host'    => $host,
		);
	}

	/**
	 * Collect a complete single-site inventory or an explicit error.
	 *
	 * @throws \UnexpectedValueException Invalid component metadata; caught and returned as an inventory error.
	 */
	public static function collect() {
		global $wp_version;
		if ( is_multisite() ) {
			return new \WP_Error( 'unsupported_multisite', 'Single-site WordPress is required.', array( 'status' => 503 ) );
		}
		require_once ABSPATH . 'wp-admin/includes/plugin.php';
		try {
			$all_plugins = get_plugins();
			$all_themes  = self::themes();
			if ( count( $all_plugins ) > 2000 || count( $all_themes ) > 500 ) {
				throw new \UnexpectedValueException( 'Component count limit.' );
			}
			$plugins = array();
			$themes  = array();
			$updates = get_site_transient( 'update_plugins' );
			foreach ( $all_plugins as $file => $data ) {
				if ( ! is_array( $data ) || ! isset( $data['Name'], $data['Version'] ) || ! is_string( $data['Name'] ) || ! is_string( $data['Version'] ) ) {
					throw new \UnexpectedValueException( 'Invalid plugin metadata.' );
				}
				$available = null;
				$update    = null;
				if ( is_object( $updates ) && isset( $updates->response ) && is_array( $updates->response ) && isset( $updates->checked ) && is_array( $updates->checked ) && isset( $updates->checked[ $file ] ) && $updates->checked[ $file ] === $data['Version'] ) {
					$update = isset( $updates->response[ $file ] );
					if ( $update && isset( $updates->response[ $file ]->new_version ) ) {
						$available = self::bounded( $updates->response[ $file ]->new_version, 128 );
					}
				}
				$update_uri = $data['UpdateURI'] ?? '';
				$hints      = self::hints( $data['PluginURI'] ?? '', $update_uri, 'plugin' );
				$plugins[]  = array(
					'plugin_file'       => self::identity( $file ),
					'slug'              => self::slug( dirname( $file ) === '.' ? basename( $file, '.php' ) : dirname( $file ) ),
					'name'              => self::bounded( $data['Name'], 256 ),
					'version'           => self::bounded( $data['Version'], 128 ),
					'active'            => is_plugin_active( $file ),
					'update_available'  => $update,
					'available_version' => $available,
					'identity_hints'    => self::with_update_origin( $hints, 'plugin', $file, $data['Version'], $update_uri, $updates ),
				);
			}
			$theme_updates = get_site_transient( 'update_themes' );
			foreach ( $all_themes as $stylesheet => $theme ) {
				$parent     = $theme->get( 'Template' );
				$version    = self::bounded( $theme->get( 'Version' ), 128 );
				$update_uri = $theme->get( 'UpdateURI' );
				$hints      = self::hints( $theme->get( 'ThemeURI' ), $update_uri, 'theme' );
				$themes[]   = array(
					'stylesheet'     => self::identity( $stylesheet ),
					'slug'           => self::slug( $stylesheet ),
					'name'           => self::bounded( $theme->get( 'Name' ), 256 ),
					'version'        => $version,
					'active'         => get_stylesheet() === $stylesheet,
					'parent_theme'   => '' === $parent ? null : self::identity( $parent ),
					'identity_hints' => self::with_update_origin( $hints, 'theme', $stylesheet, $version, $update_uri, $theme_updates ),
				);
			}
			$settings = Credentials::settings();
			if ( ! Credentials::valid_id( $settings['site_id'] ?? null ) ) {
				throw new \UnexpectedValueException( 'Invalid site identity.' );
			}
			$payload = array(
				'schema_version'   => 2,
				'site_id'          => $settings['site_id'],
				'generated_at'     => gmdate( 'Y-m-d\TH:i:s\Z' ),
				'inventory_status' => 'complete',
				'core'             => array( 'version' => self::bounded( $wp_version, 128 ) ),
				'plugins'          => $plugins,
				'themes'           => $themes,
				'coverage'         => array(
					'mu_plugins_included' => false,
					'dropins_included'    => false,
					'multisite_supported' => false,
				),
			);
			$json    = wp_json_encode( $payload );
			if ( false === $json || strlen( $json ) > 1048576 ) {
				throw new \UnexpectedValueException( 'Inventory size limit.' );
			}
			return $payload;
		} catch ( \Throwable $error ) {
			return new \WP_Error( 'mc_security_reporter_inventory_incomplete', 'A complete inventory could not be produced.', array( 'status' => 503 ) );
		}
	}
}
