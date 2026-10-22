<?php
/** WordPress-only access gates, local backups and narrowly scoped loopback probes. */
if ( ! defined( 'ABSPATH' ) ) { exit; }

class IP_Blocker_WAF_Server {
	const BACKUPS = 'ipbw_backups';
	const LOCK = 'ipbw_write_lock';

	public static function path() {
		$software = $_SERVER['SERVER_SOFTWARE'] ?? '';
		$unsupported_version = preg_match( '/^Apache\/(\d+\.\d+)/i', $software, $version ) && version_compare( $version[1], '2.4', '<' );
		if ( is_multisite() || ( defined( 'DISALLOW_FILE_MODS' ) && DISALLOW_FILE_MODS ) || ( defined( 'DISALLOW_FILE_EDIT' ) && DISALLOW_FILE_EDIT ) || ! preg_match( '/^Apache(?:\/|$)/i', $software ) || $unsupported_version ) {
			return new WP_Error( 'environment', __( 'Editing requires Apache 2.4, a single-site installation, and enabled WordPress file modifications.', 'ip-blocker-with-waf' ) );
		}
		if ( ! function_exists( 'get_home_path' ) ) { require_once ABSPATH . 'wp-admin/includes/file.php'; }
		$root = realpath( get_home_path() );
		if ( false === $root || $root !== realpath( ABSPATH ) ) {
			return new WP_Error( 'root', __( 'WordPress and the site home must use the same directory in this version.', 'ip-blocker-with-waf' ) );
		}
		return $root . '/.htaccess';
	}

	public static function experiment_safe() {
		global $wpdb;
		if ( ! class_exists( 'Atshift_Semantic_Deterrence_Storage', false ) ) { return true; }
		$settings = Atshift_Semantic_Deterrence_Storage::get_settings();
		if ( in_array( $settings['mode'] ?? '', array( 'deter', 'deter_limit' ), true ) || ( 'experiment' === ( $settings['mode'] ?? '' ) && '1' === ( $settings['experiment_enabled'] ?? '' ) ) ) {
			return false;
		}
		$previous = $wpdb->suppress_errors( true );
		try {
			$pending = $wpdb->get_var( $wpdb->prepare( 'SELECT id FROM %i WHERE responded = 1 AND window_ends_at >= %s LIMIT 1', $wpdb->prefix . 'atsdn_events', current_time( 'mysql' ) ) );
			return null === $pending && '' === $wpdb->last_error;
		} finally { $wpdb->suppress_errors( $previous ); }
	}

	public static function probe() {
		$token = bin2hex( random_bytes( 32 ) );
		set_transient( 'ipbw_probe', $token, 90 );
		try {
			$response = wp_remote_get( add_query_arg( 'ipbw_probe', $token, home_url( '/' ) ), array( 'timeout' => 8, 'redirection' => 0, 'sslverify' => true, 'headers' => array( 'Cache-Control' => 'no-cache' ), 'limit_response_size' => 1024 ) );
			return ! is_wp_error( $response ) && 200 === wp_remote_retrieve_response_code( $response ) && hash_equals( 'ipbw-ok-' . $token, trim( wp_remote_retrieve_body( $response ) ) );
		} finally { delete_transient( 'ipbw_probe' ); }
	}

	public static function maybe_probe() {
		$token = $_GET['ipbw_probe'] ?? null;
		if ( 'GET' !== ( $_SERVER['REQUEST_METHOD'] ?? '' ) || ! is_string( $token ) || ! preg_match( '/^[a-f0-9]{64}$/', $token ) ) { return; }
		$active = get_transient( 'ipbw_probe' );
		if ( ! is_string( $active ) || ! hash_equals( $active, $token ) ) { return; }
		nocache_headers();
		status_header( 200 );
		header( 'Content-Type: text/plain; charset=UTF-8' );
		echo 'ipbw-ok-' . esc_html( $token );
		exit;
	}

	public static function backup( $content ) {
		$backups = get_option( self::BACKUPS, array() );
		$backups = is_array( $backups ) ? array_slice( $backups, -2 ) : array();
		$backups[] = array( 'id' => wp_generate_uuid4(), 'at' => time(), 'user' => get_current_user_id(), 'sha256' => hash( 'sha256', $content ), 'content' => $content );
		return update_option( self::BACKUPS, $backups, false );
	}

	private static function lock() {
		global $wpdb;
		$token = wp_generate_uuid4();
		$value = ( time() + 120 ) . ':' . $token;
		$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->options} WHERE option_name = %s AND CAST(option_value AS UNSIGNED) <= %d", self::LOCK, time() ) );
		wp_cache_delete( self::LOCK, 'options' );
		return add_option( self::LOCK, $value, '', false ) ? $value : false;
	}

	public static function apply_plan( $plan, $protected ) {
		global $wpdb;
		if ( ! current_user_can( 'manage_options' ) ) { return new WP_Error( 'forbidden', __( 'Administrator access is required.', 'ip-blocker-with-waf' ) ); }
		if ( ! is_array( $plan ) || ! isset( $plan['ips'], $plan['hash'], $plan['at'] ) || ! is_int( $plan['at'] ) || $plan['at'] < time() - 600 || $plan['at'] > time() ) {
			return new WP_Error( 'expired', __( 'The preview expired. Create a new preview.', 'ip-blocker-with-waf' ) );
		}
		$path = self::path();
		if ( is_wp_error( $path ) ) { return $path; }
		if ( ! self::experiment_safe() ) { return new WP_Error( 'experiment', __( 'Pause Semantic Deterrence responses and wait for active observation windows to finish before changing server blocks.', 'ip-blocker-with-waf' ) ); }
		$previous = $wpdb->suppress_errors( true );
		$lock = false;
		try {
			$lock = self::lock();
			if ( false === $lock ) { return new WP_Error( 'busy', __( 'Another change is in progress. Try again later.', 'ip-blocker-with-waf' ) ); }
			$before = IP_Blocker_WAF_Server_File::read( $path );
			if ( is_wp_error( $before ) ) { return $before; }
			$after = IP_Blocker_WAF_IP_Rules::compose( $before, $plan['ips'], $protected );
			if ( is_wp_error( $after ) ) { return $after; }
			return IP_Blocker_WAF_Server_File::apply( $path, $plan['hash'], $after, array( __CLASS__, 'backup' ), array( __CLASS__, 'probe' ) );
		} catch ( Throwable $error ) {
			return new WP_Error( 'failed', __( 'The change could not be completed. Review the current file and backups before retrying.', 'ip-blocker-with-waf' ) );
		} finally {
			if ( false !== $lock ) {
				$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->options} WHERE option_name = %s AND option_value = %s", self::LOCK, $lock ) );
				wp_cache_delete( self::LOCK, 'options' );
			}
			$wpdb->suppress_errors( $previous );
		}
	}
}
