<?php
/** Render retained observations against a real, disposable managed server file. */
define( 'ABSPATH', __DIR__ );
class WP_Error {
	private $message;
	public function __construct( $code, $message ) { $this->message = $message; }
	public function get_error_message() { return $this->message; }
}
function is_wp_error( $value ) { return $value instanceof WP_Error; }
function __( $value, $domain = '' ) { return $value; }
function esc_html( $value ) { return htmlspecialchars( (string) $value, ENT_QUOTES, 'UTF-8' ); }
function esc_attr( $value ) { return esc_html( $value ); }
function esc_url( $value ) { return esc_html( $value ); }
function esc_html_e( $value, $domain = '' ) { echo esc_html( $value ); }
function esc_attr_e( $value, $domain = '' ) { echo esc_attr( $value ); }
function wp_unslash( $value ) { return $value; }
function sanitize_key( $value ) { return preg_replace( '/[^a-z0-9_-]/', '', $value ); }
function absint( $value ) { return abs( (int) $value ); }
function selected( $a, $b ) { if ( $a === $b ) { echo 'selected="selected"'; } }
function checked( $value ) { if ( $value ) { echo 'checked="checked"'; } }
function disabled( $value ) { if ( $value ) { echo 'disabled="disabled"'; } }
function number_format_i18n( $value ) { return (string) $value; }
function wp_nonce_field( $action ) {}
function admin_url( $path ) { return 'https://fixture.invalid/wp-admin/' . $path; }
function add_query_arg( $args, $url ) { return $url . '?' . http_build_query( $args ); }
class IP_Blocker_WAF_Server {
	public static $path;
	public static function path() { return self::$path; }
}
class IP_Blocker_WAF_Sources {
	public static $rows = array();
	public static function providers() { return array( 'cloudsecure' => 'CloudSecure', 'wordfence' => 'Wordfence' ); }
	public static function read( $source, $hours, $minutes, $threshold ) { return self::$rows; }
}
require dirname( __DIR__ ) . '/wordpress-plugin/includes/class-ip-rules.php';
require dirname( __DIR__ ) . '/wordpress-plugin/includes/class-server-file.php';
require dirname( __DIR__ ) . '/wordpress-plugin/includes/class-admin.php';
$checks = 0;
function observation_check( $ok, $message ) {
	global $checks;
	++$checks;
	if ( ! $ok ) { throw new RuntimeException( $message ); }
}
function observation_render( $candidate = true, $protected = '', $ip = '8.8.8.8' ) {
	IP_Blocker_WAF_Sources::$rows = array( array( 'ip' => $ip, 'kind' => 'Code injection', 'count' => 40, 'burst_count' => 40, 'burst_end' => '2026-11-04 00:00:00', 'last_seen' => '2026-11-04 00:00:00', 'candidate' => $candidate ) );
	$method = new ReflectionMethod( IP_Blocker_WAF_Admin::class, 'observations' );
	if ( PHP_VERSION_ID < 80100 ) { $method->setAccessible( true ); }
	ob_start();
	$method->invoke( null, array( 'sources' => array( 'cloudsecure', 'wordfence' ), 'minutes' => 10, 'threshold' => 30, 'protected' => $protected ) );
	return ob_get_clean();
}
function observation_blocked( $html ) { return false !== strpos( $html, 'class="ipbw-badge is-blocked">Blocked</span>' ); }
$path = tempnam( sys_get_temp_dir(), 'ipbw-observation-' );
IP_Blocker_WAF_Server::$path = $path;
$_GET = array( 'show_all' => '1' );
try {
	file_put_contents( $path, IP_Blocker_WAF_IP_Rules::generate( array( '8.8.8.8' ) ) );
	$html = observation_render();
	observation_check( observation_blocked( $html ), 'managed IP displays Blocked' );
	observation_check( false !== strpos( $html, 'disabled="disabled"' ), 'managed IP cannot be selected for duplicate addition' );
	observation_check( observation_blocked( observation_render( false ) ), 'blocked status overrides below-threshold status' );
	observation_check( observation_blocked( observation_render( true, '8.8.8.8' ) ), 'existing block remains visible when IP becomes protected' );
	$_GET['source'] = 'wordfence';
	observation_check( observation_blocked( observation_render() ), 'Wordfence records use the same managed state' );
	$ipv6_rules = IP_Blocker_WAF_IP_Rules::generate( array( '2606:4700:4700::1111' ) );
	file_put_contents( $path, $ipv6_rules );
	observation_check( observation_blocked( observation_render( true, '', '2606:4700:4700:0:0:0:0:1111' ) ), 'equivalent IPv6 spelling matches the managed block' );
	observation_check( file_get_contents( $path ) === $ipv6_rules, 'rendering never changes the server file' );
	file_put_contents( $path, '' );
	$html = observation_render();
	observation_check( ! observation_blocked( $html ) && false !== strpos( $html, '>Review required</span>' ), 'removing the rule immediately restores review status' );
	observation_check( false === strpos( $html, 'disabled="disabled"' ), 'removed IP can be selected again' );
	observation_check( false !== strpos( observation_render( false ), '>Below threshold</span>' ), 'ordinary below-threshold status preserved' );
	observation_check( false !== strpos( observation_render( true, '8.8.8.8' ), '>Protected / non-public</span>' ), 'ordinary protected status preserved' );
	file_put_contents( $path, 'deny from 8.8.8.8' );
	observation_check( ! observation_blocked( observation_render() ), 'unmanaged manual rules are not claimed as verified managed blocks' );
	file_put_contents( $path, IP_Blocker_WAF_IP_Rules::BEGIN . "\ninvalid\n" );
	$html = observation_render();
	observation_check( ! observation_blocked( $html ) && false !== strpos( $html, 'is-error' ), 'malformed managed section exposes an error without claiming a block' );
	IP_Blocker_WAF_Server::$path = new WP_Error( 'fixture', 'Cannot read server settings.' );
	$html = observation_render();
	observation_check( ! observation_blocked( $html ) && false !== strpos( $html, 'Cannot read server settings.' ), 'unavailable server path does not claim a block' );
} finally {
	unlink( $path );
}
echo 'PASS ' . $checks . ' observation badge and current managed-file checks' . PHP_EOL;
