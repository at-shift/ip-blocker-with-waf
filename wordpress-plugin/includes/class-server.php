<?php
/** WordPress-only access gates, local backups and narrowly scoped loopback probes. */
if ( ! defined( 'ABSPATH' ) ) { exit; }

class IP_Blocker_WAF_Server {
	const BACKUPS = 'ipbw_backups';
	const LOCK = 'ipbw_write_lock';

	public static function has_measurement_api() {
		return class_exists( 'Atshift_Semantic_Deterrence_Server_Blocks', false ) &&
			defined( 'Atshift_Semantic_Deterrence_Server_Blocks::API_VERSION' ) &&
			1 === Atshift_Semantic_Deterrence_Server_Blocks::API_VERSION &&
			is_callable( array( 'Atshift_Semantic_Deterrence_Server_Blocks', 'begin_change' ) ) &&
			is_callable( array( 'Atshift_Semantic_Deterrence_Server_Blocks', 'finish_change' ) ) &&
			is_callable( array( 'Atshift_Semantic_Deterrence_Server_Blocks', 'snapshot' ) );
	}

	public static function measurement_status() {
		if ( self::has_measurement_api() ) {
			$state = self::measurement_state();
			if ( is_wp_error( $state ) ) { return $state; }
			if ( $state['active'] ) { return new WP_Error( 'measurement_pending', __( 'A previous server change interrupted SDN measurement. Review the current file and resume measurement below before another change.', 'ip-blocker-with-waf' ) ); }
			return true;
		}
		return self::experiment_safe() ? true : new WP_Error( 'experiment', __( 'Update Semantic Deterrence to version 0.1.8 or later to change IP blocks while its responses or observation windows are active.', 'ip-blocker-with-waf' ) );
	}

	private static function measurement_state() {
		try { $state = Atshift_Semantic_Deterrence_Server_Blocks::snapshot(); }
		catch ( Throwable $error ) { $state = false; }
		if ( ! is_array( $state ) || ! is_bool( $state['active'] ?? null ) || ! is_string( $state['revision'] ?? null ) ||
			( '' !== $state['revision'] && ! preg_match( '/^[a-f0-9]{32}$/D', $state['revision'] ) ) ||
			( $state['active'] && '' === $state['revision'] ) ) {
			return new WP_Error( 'measurement_state', __( 'SDN measurement state is unavailable. Server changes are disabled until it can be read.', 'ip-blocker-with-waf' ) );
		}
		return $state;
	}

	public static function resume_measurement() {
		global $wpdb;
		if ( ! current_user_can( 'manage_options' ) || ! self::has_measurement_api() ) { return new WP_Error( 'forbidden', __( 'Compatible SDN measurement support and administrator access are required.', 'ip-blocker-with-waf' ) ); }
		$state = self::measurement_state();
		if ( is_wp_error( $state ) || ! $state['active'] ) { return new WP_Error( 'measurement_state', __( 'No interrupted SDN measurement is available to resume.', 'ip-blocker-with-waf' ) ); }
		$previous = $wpdb->suppress_errors( true );
		$lock = false;
		try {
			$lock = self::lock();
			if ( false === $lock ) { return new WP_Error( 'busy', __( 'Another change is in progress. Try again later.', 'ip-blocker-with-waf' ) ); }
			$path = self::path();
			$content = is_wp_error( $path ) ? $path : IP_Blocker_WAF_Server_File::read( $path );
			$inspection = is_wp_error( $content ) ? $content : IP_Blocker_WAF_IP_Rules::inspect( $content );
			if ( is_wp_error( $inspection ) ) { return $inspection; }
			if ( ! self::probe() ) { return new WP_Error( 'baseline', __( 'The site self-check failed. Measurement remains interrupted; review the server configuration and recovery access.', 'ip-blocker-with-waf' ) ); }
			$result = Atshift_Semantic_Deterrence_Server_Blocks::finish_change( $state['revision'] );
			return true === $result ? true : new WP_Error( 'measurement_finish', __( 'SDN measurement could not be resumed. No server file was changed by this recovery attempt.', 'ip-blocker-with-waf' ) );
		} finally {
			if ( false !== $lock ) {
				$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->options} WHERE option_name = %s AND option_value = %s", self::LOCK, $lock ) );
				wp_cache_delete( self::LOCK, 'options' );
			}
			$wpdb->suppress_errors( $previous );
		}
	}

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
		$measurement_status = self::measurement_status();
		if ( is_wp_error( $measurement_status ) ) { return $measurement_status; }
		$previous = $wpdb->suppress_errors( true );
		$lock = false;
		$measurement = false;
		$result = new WP_Error( 'failed', __( 'The change could not be completed. Review the current file and backups before retrying.', 'ip-blocker-with-waf' ) );
		try {
			$lock = self::lock();
			if ( false === $lock ) { return new WP_Error( 'busy', __( 'Another change is in progress. Try again later.', 'ip-blocker-with-waf' ) ); }
			$before = IP_Blocker_WAF_Server_File::read( $path );
			if ( is_wp_error( $before ) ) { return $before; }
			$after = IP_Blocker_WAF_IP_Rules::compose( $before, $plan['ips'], $protected );
			if ( is_wp_error( $after ) ) { return $after; }
			if ( ! hash_equals( hash( 'sha256', $before ), $plan['hash'] ) ) { return new WP_Error( 'changed', __( 'The server file changed. Create a new preview and download a fresh backup.', 'ip-blocker-with-waf' ) ); }
			if ( $after === $before ) { return true; }
			if ( self::has_measurement_api() ) {
				$token = Atshift_Semantic_Deterrence_Server_Blocks::begin_change();
				if ( ! is_string( $token ) || ! preg_match( '/^[a-f0-9]{32}$/D', $token ) ) { return new WP_Error( 'measurement_prepare', __( 'SDN measurement could not be protected. No server changes were started. Review the SDN measurement status before retrying.', 'ip-blocker-with-waf' ) ); }
				$measurement = $token;
			}
			$result = IP_Blocker_WAF_Server_File::apply( $path, $plan['hash'], $after, array( __CLASS__, 'backup' ), array( __CLASS__, 'probe' ) );
		} catch ( Throwable $error ) {
			$result = new WP_Error( 'failed', __( 'The change could not be completed. Review the current file and backups before retrying.', 'ip-blocker-with-waf' ) );
		} finally {
			if ( is_string( $measurement ) ) {
				try { $finished = Atshift_Semantic_Deterrence_Server_Blocks::finish_change( $measurement ); }
				catch ( Throwable $error ) { $finished = false; }
				if ( true !== $finished ) { $result = new WP_Error( 'measurement_finish', __( 'The file change attempt finished, but SDN measurement remains interrupted. Review the managed IP list and use Resume SDN measurement. Do not assume the file was unchanged.', 'ip-blocker-with-waf' ) ); }
			}
			if ( false !== $lock ) {
				$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->options} WHERE option_name = %s AND option_value = %s", self::LOCK, $lock ) );
				wp_cache_delete( self::LOCK, 'options' );
			}
			$wpdb->suppress_errors( $previous );
		}
		return $result;
	}
}
