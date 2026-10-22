<?php
/** GitHub distribution only; never include this file in the WordPress.org branch. */
if ( ! defined( 'ABSPATH' ) ) { exit; }

class IP_Blocker_WAF_Updater {
	const REPO = 'https://github.com/at-shift/ip-blocker-with-waf';
	const API = 'https://api.github.com/repos/at-shift/ip-blocker-with-waf/releases/latest';
	const ASSET = 'ip-blocker-with-waf.zip';
	const CACHE = 'ipbw_github_release_v1';

	public static function init() {
		add_filter( 'update_plugins_github.com', array( __CLASS__, 'update' ), 10, 4 );
		add_filter( 'plugins_api', array( __CLASS__, 'information' ), 10, 3 );
		add_filter( 'upgrader_pre_download', array( __CLASS__, 'download' ), 10, 4 );
	}

	public static function parse_release( $body ) {
		if ( ! is_array( $body ) || false !== ( $body['draft'] ?? null ) || false !== ( $body['prerelease'] ?? null ) || ! is_string( $body['tag_name'] ?? null ) || ! preg_match( '/^v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/D', $body['tag_name'] ) ) { return false; }
		$tag = $body['tag_name'];
		if ( self::REPO . '/releases/tag/' . $tag !== ( $body['html_url'] ?? '' ) || ! is_array( $body['assets'] ?? null ) || count( $body['assets'] ) > 100 ) { return false; }
		$found = array();
		foreach ( $body['assets'] as $asset ) {
			if ( ! is_array( $asset ) || ! is_string( $asset['name'] ?? null ) || ! in_array( $asset['name'], array( self::ASSET, self::ASSET . '.sha256' ), true ) ) { continue; }
			$name = $asset['name'];
			if ( isset( $found[$name] ) || self::REPO . '/releases/download/' . $tag . '/' . $name !== ( $asset['browser_download_url'] ?? '' ) ) { return false; }
			$found[$name] = $asset['browser_download_url'];
		}
		if ( ! isset( $found[self::ASSET], $found[self::ASSET . '.sha256'] ) ) { return false; }
		return array( 'version' => ltrim( $tag, 'v' ), 'url' => $body['html_url'], 'package' => $found[self::ASSET] );
	}

	private static function request_args( $timeout, $limit ) {
		return array( 'timeout' => $timeout, 'redirection' => 5, 'sslverify' => true, 'limit_response_size' => $limit, 'user-agent' => 'IP-Blocker-With-WAF/' . IP_BLOCKER_WAF_VERSION, 'headers' => array( 'Accept' => 'application/vnd.github+json' ) );
	}

	private static function release() {
		$cached = get_site_transient( self::CACHE );
		if ( is_array( $cached ) ) { return $cached ?: false; }
		$response = wp_safe_remote_get( self::API, self::request_args( 10, 262144 ) );
		$release = ! is_wp_error( $response ) && 200 === wp_remote_retrieve_response_code( $response ) ? self::parse_release( json_decode( wp_remote_retrieve_body( $response ), true, 16 ) ) : false;
		set_site_transient( self::CACHE, $release ?: array(), $release ? 6 * HOUR_IN_SECONDS : 15 * MINUTE_IN_SECONDS );
		return $release;
	}

	public static function update( $update, $plugin_data, $plugin_file, $locales ) {
		if ( plugin_basename( IP_BLOCKER_WAF_FILE ) !== $plugin_file ) { return $update; }
		$release = self::release();
		if ( ! $release || ! version_compare( $release['version'], IP_BLOCKER_WAF_VERSION, '>' ) ) { return false; }
		return array( 'id' => self::REPO, 'slug' => 'ip-blocker-with-waf', 'version' => $release['version'], 'url' => $release['url'], 'package' => $release['package'], 'requires' => '6.4', 'requires_php' => '7.4', 'autoupdate' => false );
	}

	public static function information( $result, $action, $args ) {
		if ( 'plugin_information' !== $action || 'ip-blocker-with-waf' !== ( $args->slug ?? '' ) ) { return $result; }
		$release = self::release();
		if ( ! $release ) { return $result; }
		return (object) array(
			'name' => 'IP Blocker with WAF', 'slug' => 'ip-blocker-with-waf', 'version' => $release['version'], 'author' => '@shift', 'homepage' => self::REPO, 'requires' => '6.4', 'requires_php' => '7.4', 'download_link' => $release['package'],
			'sections' => array( 'description' => esc_html__( 'Review repeated local WAF detections and manually manage server blocks with backups.', 'ip-blocker-with-waf' ), 'changelog' => '<p><a href="' . esc_url( $release['url'] ) . '" target="_blank" rel="noopener noreferrer">' . esc_html__( 'View release notes on GitHub.', 'ip-blocker-with-waf' ) . '</a></p>' ),
		);
	}

	private static function is_package( $url ) {
		return is_string( $url ) && 1 === preg_match( '~^' . preg_quote( self::REPO, '~' ) . '/releases/download/v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)/' . preg_quote( self::ASSET, '~' ) . '$~D', $url );
	}

	public static function download( $reply, $package, $upgrader, $hook_extra ) {
		if ( false !== $reply || ! self::is_package( $package ) ) { return $reply; }
		$response = wp_safe_remote_get( $package . '.sha256', self::request_args( 15, 4096 ) );
		$checksum = ! is_wp_error( $response ) && 200 === wp_remote_retrieve_response_code( $response ) ? trim( wp_remote_retrieve_body( $response ) ) : '';
		if ( ! preg_match( '/^([a-f0-9]{64})[ \t]+\*?' . preg_quote( self::ASSET, '/' ) . '$/iD', $checksum, $matches ) ) {
			return new WP_Error( 'ipbw_checksum_unavailable', __( 'The GitHub update checksum is unavailable. Please try again later.', 'ip-blocker-with-waf' ) );
		}
		if ( ! function_exists( 'wp_tempnam' ) ) { require_once ABSPATH . 'wp-admin/includes/file.php'; }
		$temp = wp_tempnam( self::ASSET );
		if ( ! $temp ) { return new WP_Error( 'ipbw_download_failed', __( 'The GitHub update package could not be downloaded.', 'ip-blocker-with-waf' ) ); }
		$args = self::request_args( 300, 25 * 1024 * 1024 );
		$args['stream'] = true;
		$args['filename'] = $temp;
		try {
			$download = wp_safe_remote_get( $package, $args );
			if ( is_wp_error( $download ) || 200 !== wp_remote_retrieve_response_code( $download ) ) {
				wp_delete_file( $temp );
				return new WP_Error( 'ipbw_download_failed', __( 'The GitHub update package could not be downloaded.', 'ip-blocker-with-waf' ) );
			}
			$actual = hash_file( 'sha256', $temp );
			if ( ! is_string( $actual ) || ! hash_equals( strtolower( $matches[1] ), $actual ) ) {
				wp_delete_file( $temp );
				return new WP_Error( 'ipbw_checksum_mismatch', __( 'The GitHub update package failed SHA-256 verification.', 'ip-blocker-with-waf' ) );
			}
			return $temp;
		} catch ( Throwable $error ) {
			wp_delete_file( $temp );
			return new WP_Error( 'ipbw_download_failed', __( 'The GitHub update package could not be downloaded.', 'ip-blocker-with-waf' ) );
		}
	}
}
