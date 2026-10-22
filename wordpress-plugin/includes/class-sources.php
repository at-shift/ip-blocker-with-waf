<?php
/** Bounded read-only access to existing provider logs. No request collection. */
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class IP_Blocker_WAF_Sources {
	const LIMIT = 10000;
	const MAX_RESULTS = 200;

	public static function providers() {
		return array( 'cloudsecure' => 'CloudSecure WP Security', 'wordfence' => 'Wordfence' );
	}

	public static function group_bursts( $rows, $provider, $minutes = 10, $threshold = 30 ) {
		$minutes = in_array( $minutes, array( 5, 10, 30 ), true ) ? $minutes : 10;
		$threshold = in_array( $threshold, array( 20, 30, 50, 100 ), true ) ? $threshold : 30;
		$categories = array( 'SQLインジェクション' => 'SQL injection', 'クロスサイトスクリプティング' => 'Cross-site scripting', 'OSコマンドインジェクション' => 'OS command injection', 'コードインジェクション' => 'Code injection', 'メールヘッダインジェクション' => 'Mail header injection' );
		$groups = array();
		foreach ( array_slice( $rows, 0, self::LIMIT ) as $row ) {
			$address = $row['address'] ?? '';
			if ( 'wordfence' === $provider ) { $address = is_string( $address ) && preg_match( '/^[a-f0-9]{32}$/i', $address ) ? inet_ntop( hex2bin( $address ) ) : ''; }
			$ip = IP_Blocker_WAF_IP_Rules::canonical( $address );
			$kind = $row['kind'] ?? '';
			if ( false === $ip || ! is_string( $kind ) ) { continue; }
			if ( 'cloudsecure' === $provider ) {
				if ( ! isset( $categories[$kind] ) ) { continue; }
				$kind = $categories[$kind];
			} elseif ( ! preg_match( '/^[a-z][a-z0-9_-]{0,39}$/', $kind ) || in_array( $kind, array( 'blocked', 'logged', 'unknown' ), true ) ) { continue; }
			$seen = $row['seen_at'] ?? null;
			if ( 'cloudsecure' === $provider ) {
				if ( ! is_string( $seen ) ) { continue; }
				$date = DateTimeImmutable::createFromFormat( '!Y-m-d H:i:s', $seen, wp_timezone() );
				if ( false === $date || $date->format( 'Y-m-d H:i:s' ) !== $seen ) { continue; }
				$seen = $date->getTimestamp();
			} elseif ( is_numeric( $seen ) ) { $seen = (int) $seen; } else { continue; }
			if ( $seen < 1 || $seen > time() ) { continue; }
			$key = $ip . '|' . $kind;
			if ( ! isset( $groups[$key] ) ) { $groups[$key] = array( 'ip' => $ip, 'kind' => $kind, 'times' => array() ); }
			$groups[$key]['times'][] = $seen;
		}
		$result = array();
		foreach ( $groups as $group ) {
			sort( $group['times'], SORT_NUMERIC );
			$left = 0; $peak = 0; $end = 0;
			foreach ( $group['times'] as $right => $at ) {
				while ( $at - $group['times'][$left] > $minutes * 60 ) { ++$left; }
				if ( $right - $left + 1 >= $peak ) { $peak = $right - $left + 1; $end = $at; }
			}
			$result[] = array( 'ip' => $group['ip'], 'kind' => $group['kind'], 'count' => count( $group['times'] ), 'burst_count' => $peak, 'candidate' => $peak >= $threshold, 'burst_end' => wp_date( 'Y-m-d H:i:s', $end ), 'last_seen' => wp_date( 'Y-m-d H:i:s', max( $group['times'] ) ) );
		}
		usort( $result, static function ( $a, $b ) { return $b['burst_count'] <=> $a['burst_count'] ?: strcmp( $b['last_seen'], $a['last_seen'] ); } );
		return array_slice( $result, 0, self::MAX_RESULTS );
	}

	public static function read( $provider, $hours = 24, $minutes = 10, $threshold = 30 ) {
		global $wpdb;
		if ( ! current_user_can( 'manage_options' ) || is_multisite() ) {
			return new WP_Error( 'forbidden', __( 'Administrator access on a single-site installation is required.', 'ip-blocker-with-waf' ) );
		}
		if ( ! array_key_exists( $provider, self::providers() ) ) {
			return new WP_Error( 'provider', __( 'Unsupported log source.', 'ip-blocker-with-waf' ) );
		}
		$hours = in_array( $hours, array( 24, 168, 720 ), true ) ? $hours : 24;
		if ( ( 'cloudsecure' === $provider && ! class_exists( 'CloudSecureWP_Waf', false ) ) || ( 'wordfence' === $provider && ! defined( 'WORDFENCE_VERSION' ) ) ) {
			return new WP_Error( 'inactive', __( 'The selected WAF is not active.', 'ip-blocker-with-waf' ) );
		}
		$previous = $wpdb->suppress_errors( true );
		try {
			$table = $wpdb->prefix . ( 'cloudsecure' === $provider ? 'cloudsecurewp_waf_log' : 'wfHits' );
			if ( $table !== $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $wpdb->esc_like( $table ) ) ) ) {
				return new WP_Error( 'unavailable', __( 'The provider log table is unavailable.', 'ip-blocker-with-waf' ) );
			}
			if ( 'cloudsecure' === $provider ) {
				$sql = $wpdb->prepare(
					'SELECT ip AS address, access_at AS seen_at, attack AS kind FROM (SELECT ip, access_at, attack FROM %i ORDER BY id DESC LIMIT 10000) AS recent WHERE access_at >= %s AND access_at <= %s',
					$table, wp_date( 'Y-m-d H:i:s', time() - $hours * HOUR_IN_SECONDS ), current_time( 'mysql' )
				);
			} else {
				$sql = $wpdb->prepare(
					"SELECT HEX(IP) AS address, ctime AS seen_at, LEFT(JSON_UNQUOTE(JSON_EXTRACT(CASE WHEN JSON_VALID(actionData) THEN actionData ELSE '{}' END, '$.category')), 41) AS kind FROM (SELECT IP, ctime, action, actionData FROM %i ORDER BY id DESC LIMIT 10000) AS recent WHERE ctime >= %d AND ctime <= %d AND action = %s",
					$table, time() - $hours * HOUR_IN_SECONDS, time(), 'blocked:waf'
				);
			}
			$rows = $wpdb->get_results( $sql, ARRAY_A );
			if ( '' !== $wpdb->last_error || ! is_array( $rows ) ) {
				return new WP_Error( 'unavailable', __( 'The provider log could not be read. No raw database details are shown.', 'ip-blocker-with-waf' ) );
			}
			return self::group_bursts( $rows, $provider, $minutes, $threshold );
		} catch ( Throwable $error ) {
			return new WP_Error( 'unavailable', __( 'The provider log could not be read. No raw database details are shown.', 'ip-blocker-with-waf' ) );
		} finally {
			$wpdb->suppress_errors( $previous );
		}
	}
}
