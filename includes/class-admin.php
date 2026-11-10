<?php
/**
 * Own-screen administration and one-time credential display.
 *
 * @package MediaComponents\SecurityReporter
 */

namespace MediaComponents\SecurityReporter;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/** Renders and authorizes the plugin settings screen and actions. */
final class Admin {
	const SCREEN = 'settings_page_mc-security-reporter';

	/**
	 * Register.
	 */
	public static function register() {
		add_action( 'admin_menu', array( self::class, 'menu' ) );
		add_action( 'admin_enqueue_scripts', array( self::class, 'assets' ) );
		add_action( 'wp_ajax_mc_security_reporter_manage', array( self::class, 'ajax' ) );
		add_action( 'wp_ajax_nopriv_mc_security_reporter_manage', array( self::class, 'ajax' ) );
	}

	/**
	 * Menu.
	 */
	public static function menu() {
		add_options_page( 'MC Security Monitor', 'MC Security Monitor', 'manage_options', 'mc-security-reporter', array( self::class, 'render' ) );
	}

	/**
	 * Assets.
	 *
	 * @param mixed $hook Hook.
	 */
	public static function assets( $hook ) {
		if ( self::SCREEN !== $hook || ! current_user_can( 'manage_options' ) ) {
			return;
		}
		wp_enqueue_style( 'mc_security_reporter_admin', plugins_url( 'assets/admin.css', MC_SECURITY_REPORTER_FILE ), array(), MC_SECURITY_REPORTER_VERSION );
		wp_enqueue_script( 'mc_security_reporter_admin', plugins_url( 'assets/admin.js', MC_SECURITY_REPORTER_FILE ), array(), MC_SECURITY_REPORTER_VERSION, true );
	}

	/**
	 * Also used by tests with real WP users/nonces/options; no alternate authorization path.
	 *
	 * @param mixed $method Method.
	 * @param mixed $post Post.
	 */
	public static function process( $method, $post ) {
		if ( 'POST' !== $method ) {
			return new \WP_Error( 'method_not_allowed', 'POST is required.', array( 'status' => 405 ) );
		}
		if ( ! current_user_can( 'manage_options' ) ) {
			return new \WP_Error( 'forbidden', 'Administrator permission is required.', array( 'status' => 403 ) );
		}
		if ( ! is_array( $post ) || ! isset( $post['nonce'], $post['operation'], $post['ticket'] ) || ! is_string( $post['nonce'] ) || strlen( $post['nonce'] ) > 64 || ! is_string( $post['operation'] ) || ! is_string( $post['ticket'] ) ) {
			return new \WP_Error( 'invalid_request', 'Invalid request.', array( 'status' => 400 ) );
		}
		if ( ! wp_verify_nonce( $post['nonce'], 'mc_security_reporter_manage' ) ) {
			return new \WP_Error( 'invalid_nonce', 'Reload settings and try again.', array( 'status' => 403 ) );
		}
		if ( ! in_array( $post['operation'], array( 'generate', 'rotate', 'disable', 'reset_identity' ), true ) ) {
			return new \WP_Error( 'invalid_operation', 'Invalid operation.', array( 'status' => 400 ) );
		}
		if ( ! Credentials::consume_ticket( $post['ticket'] ) ) {
			return new \WP_Error( 'ticket_expired', 'This action expired or was already used. Reload settings.', array( 'status' => 409 ) );
		}
		try {
			return Credentials::change( $post['operation'] );
		} catch ( \Exception $error ) {
			return new \WP_Error( 'credential_failure', 'Unable to complete the action. Reload settings.', array( 'status' => 500 ) );
		}
	}

	/**
	 * Ajax.
	 */
	public static function ajax() {
		// Older WordPress calls nocache_headers() again in wp_die() after JSON output.
		add_filter( 'nocache_headers', array( self::class, 'ajax_no_cache' ), PHP_INT_MAX );
		nocache_headers();
		header( 'Cache-Control: private, no-store, no-cache, must-revalidate, max-age=0', true );
		header( 'Referrer-Policy: no-referrer', true );
		$method = isset( $_SERVER['REQUEST_METHOD'] ) && is_string( $_SERVER['REQUEST_METHOD'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : '';
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- process() checks capability, nonce and one-use ticket before mutation.
		$result = self::process( $method, wp_unslash( $_POST ) );
		if ( is_wp_error( $result ) ) {
			wp_send_json_error( array( 'message' => $result->get_error_message() ), $result->get_error_data()['status'] ?? 400 );
		}
		wp_send_json_success( $result );
	}

	/**
	 * Preserve no-store through core AJAX termination, including anonymous errors.
	 *
	 * Registered only while serving this plugin's credential action.
	 *
	 * @param array $headers WordPress no-cache headers.
	 * @return array
	 */
	public static function ajax_no_cache( $headers ) {
		$headers['Cache-Control'] = 'private, no-store, no-cache, must-revalidate, max-age=0';
		return $headers;
	}

	/**
	 * Render.
	 */
	public static function render() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Administrator permission is required.', '', array( 'response' => 403 ) );
		}
		nocache_headers();
		if ( ! headers_sent() ) {
			header( 'Cache-Control: private, no-store, no-cache, must-revalidate, max-age=0', true );
		}
		$settings = Credentials::settings();
		$enabled  = true === ( $settings['enabled'] ?? false );
		$url      = rest_url( Rest_Controller::ROUTE );
		$secure   = is_ssl() && 'https' === wp_parse_url( $url, PHP_URL_SCHEME );
		$config   = array(
			'id'            => $settings['site_id'] ?? '',
			'name'          => 'Site name',
			'environment'   => wp_get_environment_type(),
			'inventory_url' => $url,
			'token_env'     => 'MC_SITE_TOKEN_REPLACE_ME',
			'enabled'       => false,
		);
		?>
		<div class="wrap mc-security-reporter">
			<header class="mc-reporter-header">
				<h1>MC Security Monitor</h1>
				<p class="mc-reporter-intro">Connect this site's inventory to your security monitor.</p>
			</header>
			<?php if ( is_multisite() ) : ?>
				<div class="mc-reporter-alert" role="alert">
					<strong>Single-site WordPress required</strong>
					<p>Multisite inventory and token management are not supported.</p>
				</div>
			<?php elseif ( ! $secure ) : ?>
				<div class="mc-reporter-alert" role="alert">
					<strong>HTTPS is required</strong>
					<p>Use HTTPS for this settings page and the inventory URL to generate or rotate a token. Keep TLS and hosting protections enabled.</p>
				</div>
			<?php endif; ?>
			<div class="mc-reporter-grid">
				<section class="mc-reporter-card" aria-labelledby="mc-reporter-connection-title">
					<div class="mc-reporter-card-heading">
						<h2 id="mc-reporter-connection-title">Site connection</h2>
						<strong id="mc-security-reporter-status" class="mc-reporter-status" data-state="<?php echo $enabled ? 'enabled' : 'disabled'; ?>"><?php echo $enabled ? 'Enabled' : 'Disabled'; ?></strong>
					</div>
					<p class="mc-reporter-description">Inventory API access for this site. Scanner connection is configured separately.</p>
					<label class="mc-reporter-label" for="mc-security-reporter-endpoint">Inventory URL</label>
					<div class="mc-reporter-copy-field">
						<input id="mc-security-reporter-endpoint" type="url" readonly value="<?php echo esc_attr( $url ); ?>" spellcheck="false">
						<button id="mc-security-reporter-copy-endpoint" type="button" class="button">Copy URL</button>
					</div>
					<span id="mc-security-reporter-endpoint-feedback" class="mc-reporter-copy-feedback" role="status" aria-live="polite"></span>
					<dl class="mc-reporter-facts">
						<div><dt>Site ID</dt><dd><code><?php echo esc_html( $settings['site_id'] ?? 'Not initialized' ); ?></code></dd></div>
						<div><dt>Transport</dt><dd><span class="mc-reporter-transport"><?php echo $secure ? 'HTTPS ready' : 'HTTPS required'; ?></span></dd></div>
						<div><dt>Last token change</dt><dd><?php echo esc_html( empty( $settings['rotated_at'] ) ? 'Never' : wp_date( 'M j, Y · H:i', strtotime( $settings['rotated_at'] ), new \DateTimeZone( 'UTC' ) ) . ' UTC' ); ?></dd></div>
					</dl>
				</section>
				<section class="mc-reporter-card" aria-labelledby="mc-reporter-token-title">
					<h2 id="mc-reporter-token-title">Access token</h2>
					<p class="mc-reporter-description"><?php echo $enabled ? 'Rotating creates a new token and immediately revokes the current one.' : 'Generate a token to enable this site\'s inventory API.'; ?></p>
					<form id="mc-security-reporter-form" action="<?php echo esc_url( admin_url( 'admin-ajax.php' ) ); ?>" method="post" autocomplete="off">
						<input type="hidden" name="action" value="mc_security_reporter_manage">
						<input type="hidden" name="nonce" value="<?php echo esc_attr( wp_create_nonce( 'mc_security_reporter_manage' ) ); ?>">
						<input type="hidden" name="ticket" value="<?php echo esc_attr( Credentials::issue_ticket() ); ?>">
						<?php if ( ! is_multisite() ) : ?>
							<div class="mc-reporter-actions">
								<button type="submit" class="button button-primary" name="operation" value="<?php echo $enabled ? 'rotate' : 'generate'; ?>" <?php disabled( ! $secure ); ?>><?php echo $enabled ? 'Rotate Token' : 'Generate Access Token'; ?></button>
								<button type="submit" class="button" name="operation" value="disable">Disable API</button>
							</div>
							<details class="mc-reporter-advanced">
								<summary>Cloned site? Reset identity</summary>
								<p>Use only on a copied database. Creates a new Site ID and disables API access. A domain change does not need a reset.</p>
								<button type="submit" class="button mc-reporter-danger" name="operation" value="reset_identity">Reset Clone Identity and Disable API</button>
							</details>
						<?php endif; ?>
					</form>
					<div id="mc-security-reporter-result" class="mc-reporter-feedback" role="status" aria-live="polite" hidden></div>
					<div id="mc-security-reporter-token-panel" class="mc-reporter-token-panel" hidden>
						<h3>Save your token now</h3>
						<p>Shown once. Save it in your secret manager and update the site's GitHub Secret.</p>
						<p id="mc-security-reporter-token" hidden></p>
						<button id="mc-security-reporter-copy-token" type="button" class="button">Copy token</button>
						<span id="mc-security-reporter-token-feedback" class="mc-reporter-copy-feedback" role="status" aria-live="polite"></span>
					</div>
					<button id="mc-security-reporter-reload" type="button" class="button mc-reporter-reload" hidden>Reload Settings</button>
				</section>
			</div>
			<details class="mc-reporter-card mc-reporter-configuration">
				<summary><span>Scanner configuration</span><span class="mc-reporter-summary-hint">JSON example for onboarding</span></summary>
				<div class="mc-reporter-details-body">
					<p>Replace the site name and token environment name. Add the token separately to GitHub Secrets; this example contains no token and starts disabled.</p>
					<label class="screen-reader-text" for="mc-security-reporter-config">Site configuration example</label>
					<textarea id="mc-security-reporter-config" readonly rows="9" spellcheck="false"><?php echo esc_textarea( wp_json_encode( $config, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES ) ); ?></textarea>
					<div class="mc-reporter-actions">
						<button id="mc-security-reporter-copy" type="button" class="button">Copy Configuration Example</button>
						<span id="mc-security-reporter-copy-feedback" class="mc-reporter-copy-feedback" role="status" aria-live="polite"></span>
					</div>
				</div>
			</details>
			<details class="mc-reporter-coverage">
				<summary>What does this plugin cover?</summary>
				<p>WordPress Core and all regular plugins and themes, including inactive components. Mu-plugins, drop-ins and multisite are excluded. Inventory and known vulnerability matches do not prove a site is secure.</p>
			</details>
			<noscript><p class="mc-reporter-alert">JavaScript is required to manage and display tokens.</p></noscript>
		</div>
		<?php
	}
}
