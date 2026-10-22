<?php
/** Exact-IP validation and side-effect-free Apache rule generation. */
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class IP_Blocker_WAF_IP_Rules {
	const MAX_IPS = 50;
	const BEGIN = '# BEGIN IP Blocker with WAF';
	const END = '# END IP Blocker with WAF';

	public static function canonical( $value ) {
		if ( ! is_string( $value ) || strlen( $value ) > 45 ) {
			return false;
		}
		$value = trim( $value );
		if ( false === filter_var( $value, FILTER_VALIDATE_IP ) ) {
			return false;
		}
		$packed = inet_pton( $value );
		if ( 16 === strlen( $packed ) && substr( $packed, 0, 12 ) === str_repeat( "\0", 10 ) . "\xff\xff" ) {
			$packed = substr( $packed, 12 );
		}
		return strtolower( inet_ntop( $packed ) );
	}

	private static function in_network( $ip, $network ) {
		list( $base, $bits ) = explode( '/', $network );
		$address = inet_pton( $ip );
		$base = inet_pton( $base );
		if ( strlen( $address ) !== strlen( $base ) ) {
			return false;
		}
		$bytes = intdiv( (int) $bits, 8 );
		$rest = (int) $bits % 8;
		return substr( $address, 0, $bytes ) === substr( $base, 0, $bytes ) &&
			( 0 === $rest || ( ord( $address[$bytes] ) & ( 255 << ( 8 - $rest ) ) ) === ( ord( $base[$bytes] ) & ( 255 << ( 8 - $rest ) ) ) );
	}

	public static function public_address( $value ) {
		$ip = self::canonical( $value );
		if ( false === $ip || false === filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) ) {
			return false;
		}
		foreach ( array( '0.0.0.0/8', '100.64.0.0/10', '192.0.0.0/24', '192.0.2.0/24', '198.18.0.0/15', '198.51.100.0/24', '203.0.113.0/24', '224.0.0.0/4', '240.0.0.0/4', '::/96', '100::/64', '2001:db8::/32', 'ff00::/8' ) as $network ) {
			if ( self::in_network( $ip, $network ) ) {
				return false;
			}
		}
		return $ip;
	}

	public static function protected_addresses( $extra = '' ) {
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Both unslashed server addresses pass strict canonical IP validation below, without lossy text rewriting.
		$values = array( wp_unslash( $_SERVER['REMOTE_ADDR'] ?? '' ), wp_unslash( $_SERVER['SERVER_ADDR'] ?? '' ) );
		if ( is_string( $extra ) ) {
			$values = array_merge( $values, preg_split( '/\R/', substr( $extra, 0, 6000 ) ) );
		}
		$ips = array();
		foreach ( $values as $value ) {
			$ip = self::canonical( $value );
			if ( false !== $ip ) {
				$ips[] = $ip;
			}
		}
		return array_values( array_unique( $ips ) );
	}

	public static function validate( $values, $protected = array() ) {
		if ( is_string( $values ) && strlen( $values ) <= 6000 ) {
			$values = preg_split( '/\R/', trim( $values ) );
		}
		if ( ! is_array( $values ) || count( $values ) > self::MAX_IPS ) {
			return new WP_Error( 'invalid_list', __( 'Enter no more than 50 exact public IP addresses, one per line.', 'ip-blocker-with-waf' ) );
		}
		$result = array();
		foreach ( $values as $value ) {
			if ( is_string( $value ) && '' === trim( $value ) ) {
				continue;
			}
			$ip = self::public_address( $value );
			if ( false === $ip ) {
				return new WP_Error( 'invalid_ip', __( 'Only exact public IPv4 or IPv6 addresses are accepted. Private, reserved, masked addresses, hostnames and ranges are not accepted.', 'ip-blocker-with-waf' ) );
			}
			if ( in_array( $ip, $protected, true ) ) {
				return new WP_Error( 'protected_ip', __( 'The list contains your current connection, the server address, or a protected IP. Remove it before continuing.', 'ip-blocker-with-waf' ) );
			}
			$result[] = $ip;
		}
		$result = array_values( array_unique( $result ) );
		sort( $result, SORT_STRING );
		return $result;
	}

	public static function generate( $values, $protected = array() ) {
		$ips = self::validate( $values, $protected );
		if ( is_wp_error( $ips ) ) {
			return $ips;
		}
		if ( empty( $ips ) ) {
			return '';
		}
		$conditions = array();
		foreach ( $ips as $ip ) {
			$conditions[] = "-R '" . $ip . "'";
		}
		// A conditional denial adds no blanket grant that could weaken existing auth.
		return self::BEGIN . "\n<If \"" . implode( ' || ', $conditions ) . "\">\n    Require all denied\n</If>\n" . self::END . "\n";
	}

	public static function inspect( $content ) {
		if ( ! is_string( $content ) || strlen( $content ) > 131072 ) {
			return new WP_Error( 'file_size', __( 'The settings file is unreadable or larger than 128 KiB.', 'ip-blocker-with-waf' ) );
		}
		$begin = substr_count( $content, self::BEGIN );
		$end = substr_count( $content, self::END );
		if ( 0 === $begin && 0 === $end ) {
			return array( 'ips' => array(), 'rest' => $content );
		}
		if ( 1 !== $begin || 1 !== $end || 0 !== strpos( $content, self::BEGIN . "\n" ) ) {
			return new WP_Error( 'markers', __( 'The managed section is ambiguous or was moved. Restore or review it manually.', 'ip-blocker-with-waf' ) );
		}
		$position = strpos( $content, self::END . "\n" );
		if ( false === $position ) {
			return new WP_Error( 'markers', __( 'The managed section is ambiguous or was moved. Restore or review it manually.', 'ip-blocker-with-waf' ) );
		}
		$length = $position + strlen( self::END ) + 1;
		$section = substr( $content, 0, $length );
		preg_match_all( "/-R '([0-9a-f:.]+)'/", $section, $matches );
		$ips = self::validate( $matches[1] );
		if ( is_wp_error( $ips ) || empty( $ips ) || self::generate( $ips ) !== $section ) {
			return new WP_Error( 'modified', __( 'The managed section was edited outside this plugin. No changes were made.', 'ip-blocker-with-waf' ) );
		}
		return array( 'ips' => $ips, 'rest' => substr( $content, $length ) );
	}

	public static function compose( $content, $ips, $protected = array() ) {
		$state = self::inspect( $content );
		if ( is_wp_error( $state ) ) {
			return $state;
		}
		$section = self::generate( $ips, $protected );
		return is_wp_error( $section ) ? $section : $section . $state['rest'];
	}
}
