<?php
/** Exercise POST prerequisites independently of file writes or browser state. */
define( 'ABSPATH', __DIR__ );
$capable = true; $nonce_ok = true; $options = array( 'ipbw_settings' => array( 'editing' => '1' ) ); $transients = array(); $checks = 0;
class WP_Error { private $message; public function __construct( $code, $message ) { $this->message = $message; } public function get_error_message() { return $this->message; } }
class Admin_Flow_Redirect extends RuntimeException {}
function is_wp_error( $value ) { return $value instanceof WP_Error; }
function __( $value, $domain = '' ) { return $value; }
function esc_html__( $value, $domain = '' ) { return $value; }
function current_user_can( $cap ) { global $capable; return $capable; }
function is_multisite() { return false; }
function wp_die( $text = '', $title = '', $args = array() ) { throw new RuntimeException( 'denied' ); }
function check_admin_referer( $action ) { global $nonce_ok; if ( ! $nonce_ok ) { throw new RuntimeException( 'nonce' ); } }
function get_option( $key, $default = false ) { global $options; return $options[$key] ?? $default; }
function get_current_user_id() { return 1; }
function wp_get_session_token() { return 'fixture-session'; }
function get_transient( $key ) { global $transients; return $transients[$key] ?? false; }
function set_transient( $key, $value, $ttl ) { global $transients; $transients[$key] = $value; return true; }
function delete_transient( $key ) { global $transients; unset( $transients[$key] ); }
function admin_url( $path ) { return 'https://fixture.invalid/wp-admin/' . $path; }
function add_query_arg( $values, $url ) { return $url . '?' . http_build_query( $values ); }
function wp_safe_redirect( $url ) { throw new Admin_Flow_Redirect( $url ); }
class IP_Blocker_WAF_Sources { public static function providers() { return array( 'cloudsecure' => 'CloudSecure' ); } }
class IP_Blocker_WAF_IP_Rules { public static function protected_addresses( $value ) { return array(); } }
class IP_Blocker_WAF_Server {
	public static $calls = 0; public static $error = false;
	public static function apply_plan( $plan, $protected ) { ++self::$calls; return self::$error ? new WP_Error( 'fixture', 'Measurement guard refused the change.' ) : true; }
}
require dirname( __DIR__ ) . '/wordpress-plugin/includes/class-admin.php';
$suffix = substr( hash( 'sha256', '1|fixture-session' ), 0, 32 );
$plan_key = 'ipbw_plan_' . $suffix; $backup_key = 'ipbw_backup_ready_' . $suffix;
function admin_flow_check( $ok, $message ) { global $checks; ++$checks; if ( ! $ok ) { throw new RuntimeException( $message ); } }
function submit_fixture() { try { IP_Blocker_WAF_Admin::apply(); } catch ( Admin_Flow_Redirect $redirect ) { admin_flow_check( false !== strpos( $redirect->getMessage(), 'tab=rules' ), 'redirects to rules' ); return $GLOBALS['transients']['ipbw_notice_1']['text']; } throw new RuntimeException( 'missing redirect' ); }
$_SERVER['REQUEST_METHOD'] = 'POST';
$plan = array( 'hash' => hash( 'sha256', 'fixture-file' ), 'ips' => array(), 'at' => time() );
$transients[$plan_key] = $plan; $transients[$backup_key] = $plan['hash'];
$_POST = array( 'address_confirmed' => '1' );
admin_flow_check( false !== strpos( submit_fixture(), 'Both address' ), 'missing acknowledgement named explicitly' );
admin_flow_check( isset( $transients[$plan_key], $transients[$backup_key] ) && 0 === IP_Blocker_WAF_Server::$calls, 'failed confirmation does not consume preview or call writer' );
$_POST['recovery_confirmed'] = '1'; unset( $transients[$backup_key] );
admin_flow_check( false !== strpos( submit_fixture(), 'Download the current' ) && 0 === IP_Blocker_WAF_Server::$calls, 'both checks do not bypass required backup' );
$transients[$backup_key] = hash( 'sha256', 'different-file' );
admin_flow_check( false !== strpos( submit_fixture(), 'Download the current' ), 'mismatched backup refused' );
$transients[$backup_key] = $plan['hash'];
admin_flow_check( false !== strpos( submit_fixture(), 'Server settings updated' ) && 1 === IP_Blocker_WAF_Server::$calls, 'both checks and valid backup reach writer' );
admin_flow_check( ! isset( $transients[$plan_key], $transients[$backup_key] ), 'successful prerequisites consumed once' );
admin_flow_check( false !== strpos( submit_fixture(), 'preview expired' ) && 1 === IP_Blocker_WAF_Server::$calls, 'replay cannot call writer' );
$transients[$plan_key] = $plan; $transients[$backup_key] = $plan['hash']; IP_Blocker_WAF_Server::$error = true;
admin_flow_check( 'Measurement guard refused the change.' === submit_fixture(), 'measurement failure is not misreported as a missing checkbox' );
$nonce_ok = false;
try { submit_fixture(); admin_flow_check( false, 'nonce required' ); } catch ( RuntimeException $error ) { admin_flow_check( 'nonce' === $error->getMessage(), 'invalid nonce refused' ); }
$nonce_ok = true; $capable = false;
try { submit_fixture(); admin_flow_check( false, 'admin required' ); } catch ( RuntimeException $error ) { admin_flow_check( 'denied' === $error->getMessage(), 'non-admin refused' ); }
echo 'PASS ' . $checks . ' admin prerequisites, errors and replay checks' . PHP_EOL;
