<?php
/** Contract and failure tests for the SDN integration; no live WordPress/files. */
define( 'ABSPATH', __DIR__ . '/' );
$checks = 0; $capable = true; $content = 'original'; $calls = array(); $options = array();
class WP_Error { private $code; private $message; public function __construct( $code, $message = '' ) { $this->code = $code; $this->message = $message; } public function get_error_code() { return $this->code; } public function get_error_message() { return $this->message; } }
function is_wp_error( $v ) { return $v instanceof WP_Error; }
function __( $v, $domain = '' ) { return $v; }
function current_user_can( $cap ) { global $capable; return $capable && 'manage_options' === $cap; }
function is_multisite() { return false; }
function get_home_path() { return ABSPATH; }
function wp_generate_uuid4() { return bin2hex( random_bytes( 16 ) ); }
function wp_cache_delete() {}
function add_option( $key, $v, $deprecated = '', $autoload = false ) { global $options; if ( isset( $options[$key] ) ) { return false; } $options[$key] = $v; return true; }
function get_option( $key, $default = false ) { global $options; return $options[$key] ?? $default; }
function set_transient( $key, $v, $ttl ) {}
function delete_transient( $key ) {}
function add_query_arg( $key, $v, $url ) { return $url . '?' . $key . '=' . $v; }
function home_url( $path ) { return 'https://fixture.invalid/'; }
function wp_remote_get( $url, $args ) { global $calls; $calls[] = 'probe'; return $url; }
function wp_remote_retrieve_response_code( $response ) { return 200; }
function wp_remote_retrieve_body( $response ) { return 'ipbw-ok-' . substr( $response, strpos( $response, '=' ) + 1 ); }
class Measurement_DB {
	public $options = 'wp_options'; public $last_error = ''; public $prefix = 'wp_'; public $suppressed = false;
	public function prepare( $q, ...$args ) { return array( $q, $args ); }
	public function suppress_errors( $v ) { $old = $this->suppressed; $this->suppressed = $v; return $old; }
	public function query( $query ) { global $options; if ( false !== strpos( $query[0], 'option_value = %s' ) && ( $options[$query[1][0]] ?? '' ) === $query[1][1] ) { unset( $options[$query[1][0]] ); } return 1; }
}
$wpdb = new Measurement_DB();
class Atshift_Semantic_Deterrence_Server_Blocks {
	const API_VERSION = 1; public static $active = false; public static $begin_failure = false; public static $finish_failure = false; public static $state_failure = false;
	public static function snapshot() { return self::$state_failure ? new WP_Error( 'state' ) : array( 'active' => self::$active, 'revision' => str_repeat( 'a', 32 ) ); }
	public static function begin_change() { global $calls; $calls[] = 'begin'; if ( self::$begin_failure ) { return new WP_Error( 'begin' ); } self::$active = true; return str_repeat( 'a', 32 ); }
	public static function finish_change( $token ) { global $calls; $calls[] = 'finish'; if ( self::$finish_failure ) { return new WP_Error( 'finish' ); } self::$active = false; return true; }
}
class IP_Blocker_WAF_IP_Rules {
	public static function compose( $before, $ips, $protected = array() ) { return empty( $ips ) ? 'original' : 'blocked'; }
	public static function inspect( $file ) { return array( 'ips' => array() ); }
}
class IP_Blocker_WAF_Server_File {
	public static $fail = false; public static $throw = false;
	public static function read( $path ) { global $content; return $content; }
	public static function apply( $path, $hash, $after, $backup, $probe ) {
		global $calls, $content; $calls[] = 'file';
		if ( ! Atshift_Semantic_Deterrence_Server_Blocks::$active ) { throw new RuntimeException( 'unprotected file write' ); }
		if ( self::$throw ) { throw new RuntimeException( 'fixture failure' ); }
		if ( self::$fail ) { return new WP_Error( 'baseline' ); }
		$content = $after; return true;
	}
}
require dirname( __DIR__ ) . '/wordpress-plugin/includes/class-server.php';
$_SERVER['SERVER_SOFTWARE'] = 'Apache/2.4.66';
function measurement_check( $ok, $message ) { global $checks; ++$checks; if ( ! $ok ) { throw new RuntimeException( $message ); } }
function plan() { global $content; return array( 'at' => time(), 'hash' => hash( 'sha256', $content ), 'ips' => array( 'fixture' ) ); }
measurement_check( IP_Blocker_WAF_Server::has_measurement_api() && true === IP_Blocker_WAF_Server::measurement_status(), 'compatible API detected' );
$result = IP_Blocker_WAF_Server::apply_plan( plan(), array() );
measurement_check( true === $result && 'blocked' === $content, 'SDN-compatible change succeeds' );
measurement_check( array( 'begin', 'file', 'finish' ) === $calls, 'fence brackets file write' );
measurement_check( ! Atshift_Semantic_Deterrence_Server_Blocks::$active && ! isset( $options[IP_Blocker_WAF_Server::LOCK] ) && ! $wpdb->suppressed, 'successful cleanup' );
$calls = array(); measurement_check( true === IP_Blocker_WAF_Server::apply_plan( plan(), array() ) && array() === $calls, 'no-op does not censor experiments' );
$content = 'original'; $calls = array(); Atshift_Semantic_Deterrence_Server_Blocks::$begin_failure = true;
measurement_check( is_wp_error( IP_Blocker_WAF_Server::apply_plan( plan(), array() ) ) && array( 'begin' ) === $calls && 'original' === $content, 'begin failure prevents write' );
Atshift_Semantic_Deterrence_Server_Blocks::$begin_failure = false; IP_Blocker_WAF_Server_File::$fail = true; $calls = array();
measurement_check( 'baseline' === IP_Blocker_WAF_Server::apply_plan( plan(), array() )->get_error_code() && array( 'begin', 'file', 'finish' ) === $calls && 'original' === $content, 'file failure completes fence without write' );
IP_Blocker_WAF_Server_File::$fail = false; IP_Blocker_WAF_Server_File::$throw = true; $calls = array();
measurement_check( is_wp_error( IP_Blocker_WAF_Server::apply_plan( plan(), array() ) ) && array( 'begin', 'file', 'finish' ) === $calls, 'exception completes fence and releases lock' );
IP_Blocker_WAF_Server_File::$throw = false; Atshift_Semantic_Deterrence_Server_Blocks::$finish_failure = true;
measurement_check( 'measurement_finish' === IP_Blocker_WAF_Server::apply_plan( plan(), array() )->get_error_code() && 'blocked' === $content, 'completion failure does not falsely claim file unchanged' );
$calls = array(); measurement_check( 'measurement_pending' === IP_Blocker_WAF_Server::measurement_status()->get_error_code(), 'pending state visible' );
measurement_check( is_wp_error( IP_Blocker_WAF_Server::apply_plan( plan(), array() ) ) && array() === $calls, 'pending state prevents another write' );
Atshift_Semantic_Deterrence_Server_Blocks::$finish_failure = false;
measurement_check( true === IP_Blocker_WAF_Server::resume_measurement() && array( 'probe', 'finish' ) === $calls && 'blocked' === $content, 'explicit recovery verifies health without rewriting file' );
Atshift_Semantic_Deterrence_Server_Blocks::$state_failure = true;
measurement_check( is_wp_error( IP_Blocker_WAF_Server::measurement_status() ), 'unreadable state fails closed' ); Atshift_Semantic_Deterrence_Server_Blocks::$state_failure = false;
$capable = false;
measurement_check( is_wp_error( IP_Blocker_WAF_Server::resume_measurement() ) && is_wp_error( IP_Blocker_WAF_Server::apply_plan( plan(), array() ) ), 'non-admin cannot write or resume' );
$capable = true; $bad = plan(); $bad['hash'] = str_repeat( '0', 64 ); $calls = array();
measurement_check( 'changed' === IP_Blocker_WAF_Server::apply_plan( $bad, array() )->get_error_code() && array() === $calls, 'stale file rejected before fence' );
echo 'PASS ' . $checks . ' SDN integration contract and transaction checks' . PHP_EOL;
