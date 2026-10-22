<?php
/** Isolated fixtures only: never load a real WordPress configuration or WAF log. */
$root = sys_get_temp_dir() . '/ipbw-test-' . bin2hex( random_bytes( 8 ) );
mkdir( $root, 0700 );
$root = realpath( $root );
define( 'ABSPATH', $root . '/' );
define( 'HOUR_IN_SECONDS', 3600 );
define( 'ARRAY_A', 'ARRAY_A' );
$capable = true;
$multisite = false;
$options = array();
class WP_Error {
	public $code; public $message;
	public function __construct( $code, $message = '' ) { $this->code = $code; $this->message = $message; }
	public function get_error_message() { return $this->message; }
	public function get_error_code() { return $this->code; }
}
function is_wp_error( $value ) { return $value instanceof WP_Error; }
function __( $text, $domain = '' ) { return $text; }
function wp_unslash( $value ) { return is_array( $value ) ? array_map( 'wp_unslash', $value ) : stripslashes( (string) $value ); }
function sanitize_text_field( $value ) { return is_scalar( $value ) ? trim( strip_tags( (string) $value ) ) : ''; }
function sanitize_key( $value ) { return is_scalar( $value ) ? preg_replace( '/[^a-z0-9_\-]/', '', strtolower( (string) $value ) ) : ''; }
function esc_html__( $text, $domain = '' ) { return htmlspecialchars( $text, ENT_QUOTES ); }
function current_user_can( $cap ) { global $capable; return $capable && 'manage_options' === $cap; }
function is_multisite() { global $multisite; return $multisite; }
function absint( $value ) { return abs( (int) $value ); }
function wp_date( $format, $timestamp ) { return gmdate( $format, $timestamp ); }
function wp_timezone() { return new DateTimeZone( 'UTC' ); }
function current_time( $format ) { return gmdate( 'Y-m-d H:i:s' ); }
function get_home_path() { return ABSPATH; }
function wp_die( $text = '', $title = '', $options = array() ) { throw new RuntimeException( 'denied' ); }
function check_admin_referer() { throw new RuntimeException( 'nonce-reached' ); }
function get_option( $key, $default = false ) { global $options; return $options[$key] ?? $default; }
function add_option( $key, $value, $deprecated = '', $autoload = null ) { global $options; if ( isset( $options[$key] ) ) { return false; } $options[$key] = $value; return true; }
function update_option( $key, $value, $autoload = null ) { global $options; $options[$key] = $value; return true; }
function wp_generate_uuid4() { return bin2hex( random_bytes( 16 ) ); }
function get_current_user_id() { return 1; }
function wp_cache_delete() {}
class IPBW_Test_DB {
	public $prefix = 'wp_'; public $options = 'wp_options'; public $last_error = ''; public $calls = array(); public $suppressed = false; public $rows = array(); public $table = true; public $fail = false; public $pending = null;
	public function prepare( $sql, ...$arguments ) { return array( $sql, $arguments ); }
	public function esc_like( $value ) { return addcslashes( $value, '_%\\' ); }
	public function suppress_errors( $value ) { $old = $this->suppressed; $this->suppressed = $value; return $old; }
	public function get_var( $query ) { $this->calls[] = $query; return 0 === strpos( $query[0], 'SHOW' ) ? ( $this->table ? stripslashes( $query[1][0] ) : null ) : $this->pending; }
	public function get_results( $query, $format ) { $this->calls[] = $query; if ( $this->fail ) { $this->last_error = 'private-database-error'; return null; } return $this->rows; }
	public function query( $query ) { $this->calls[] = $query; return 1; }
}
$wpdb = new IPBW_Test_DB();
$base = dirname( __DIR__ ) . '/wordpress-plugin/includes/';
foreach ( array( 'ip-rules', 'sources', 'server-file', 'server', 'admin' ) as $file ) { require $base . 'class-' . $file . '.php'; }
$checks = 0;
function verify( $ok, $message ) { global $checks; ++$checks; if ( ! $ok ) { throw new RuntimeException( 'FAIL: ' . $message ); } }
function code_is( $value, $code ) { return is_wp_error( $value ) && $code === $value->get_error_code(); }
try {
	foreach ( array( '1.1.1.1' => '1.1.1.1', '2606:4700:4700:0:0:0:0:1111' => '2606:4700:4700::1111', '::ffff:1.1.1.1' => '1.1.1.1' ) as $input => $expected ) { verify( $expected === IP_Blocker_WAF_IP_Rules::canonical( $input ), 'canonical IP' ); }
	foreach ( array( '1.2.3.4/24', '127.1', 'example.com', '1.1.1.1\nRequire all granted', array(), 'fe80::1%lo0', '[::1]', '0x08080808' ) as $bad ) { verify( false === IP_Blocker_WAF_IP_Rules::canonical( $bad ), 'reject ambiguous or injected address' ); }
	foreach ( array( '127.0.0.1', '10.0.0.1', '172.16.0.1', '192.168.1.1', '100.64.1.1', '192.0.2.1', '198.51.100.1', '203.0.113.1', '224.0.0.1', '::', '::1', 'fc00::1', 'fe80::1', 'ff02::1', '2001:db8::1', '::ffff:127.0.0.1' ) as $bad ) { verify( false === IP_Blocker_WAF_IP_Rules::public_address( $bad ), 'reject non-public exact address' ); }
	$_SERVER = array( 'REMOTE_ADDR' => '8.8.8.8', 'SERVER_ADDR' => '1.1.1.1', 'HTTP_X_FORWARDED_FOR' => '9.9.9.9', 'SERVER_SOFTWARE' => 'Apache/2.4.66' );
	$protected = IP_Blocker_WAF_IP_Rules::protected_addresses( "208.67.222.222\n::ffff:8.8.8.8" );
	verify( 3 === count( $protected ) && ! in_array( '9.9.9.9', $protected, true ), 'ignore untrusted forwarding header and deduplicate protection' );
	verify( code_is( IP_Blocker_WAF_IP_Rules::validate( array( '8.8.8.8' ), $protected ), 'protected_ip' ), 'self block rejected' );
	verify( code_is( IP_Blocker_WAF_IP_Rules::validate( array_fill( 0, 51, '9.9.9.9' ) ), 'invalid_list' ), 'bound list size' );
	verify( array( '9.9.9.9' ) === IP_Blocker_WAF_IP_Rules::validate( "9.9.9.9\n9.9.9.9\n" ), 'deduplicate exact addresses' );
	$original = "# Original file\r\nDeny from 208.67.222.222\r\n# BEGIN WordPress\r\n# retained bytes\r\n# END WordPress";
	$after = IP_Blocker_WAF_IP_Rules::compose( $original, array( '9.9.9.9' ), $protected );
	verify( is_string( $after ) && false !== strpos( $after, "<If \"-R '9.9.9.9'\">" ), 'conditional denial generated' );
	verify( false === strpos( $after, 'Require all granted' ), 'no new blanket access grant' );
	verify( $original === IP_Blocker_WAF_IP_Rules::inspect( $after )['rest'], 'outside bytes preserved including CRLF and missing final newline' );
	verify( $original === IP_Blocker_WAF_IP_Rules::compose( $after, array() ), 'remove owned block only' );
	verify( code_is( IP_Blocker_WAF_IP_Rules::inspect( $after . '\n' . IP_Blocker_WAF_IP_Rules::BEGIN ), 'markers' ), 'duplicate markers rejected' );
	verify( code_is( IP_Blocker_WAF_IP_Rules::inspect( str_replace( 'Require all denied', 'Require all granted', $after ) ), 'modified' ), 'foreign modifications rejected' );
	verify( code_is( IP_Blocker_WAF_IP_Rules::inspect( '# prefix\n' . $after ), 'markers' ), 'moved section rejected' );
	verify( is_wp_error( IP_Blocker_WAF_IP_Rules::inspect( str_repeat( 'a', 131073 ) ) ), 'file size bound' );
	$path = $root . '/.htaccess'; file_put_contents( $path, $original ); chmod( $path, 0644 );
	$saved = array(); $backup = static function ( $content ) use ( &$saved ) { $saved[] = $content; return true; };
	$result = IP_Blocker_WAF_Server_File::apply( $path, hash( 'sha256', $original ), $after, $backup, static function () { return true; } );
	verify( true === $result && $after === file_get_contents( $path ) && array( $original ) === $saved, 'successful apply with original backup' );
	verify( 0644 === ( fileperms( $path ) & 0777 ), 'file mode preserved' );
	verify( fileowner( $path ) === fileowner( $root ) && filegroup( $path ) === filegroup( $root ), 'owner and group preserved' );
	verify( code_is( IP_Blocker_WAF_Server_File::apply( $path, hash( 'sha256', $original ), 'wrong', $backup, static function () { return true; } ), 'changed' ), 'stale preview does not overwrite file' );
	$count = 0;
	$result = IP_Blocker_WAF_Server_File::apply( $path, hash( 'sha256', $after ), $original, $backup, static function () use ( &$count ) { return 1 === ++$count; } );
	verify( code_is( $result, 'rolled_back' ) && $after === file_get_contents( $path ), 'postflight failure restores exact before image' );
	$result = IP_Blocker_WAF_Server_File::apply( $path, hash( 'sha256', $after ), $original, $backup, static function () { return false; } );
	verify( code_is( $result, 'baseline' ) && $after === file_get_contents( $path ), 'baseline failure never writes' );
	$result = IP_Blocker_WAF_Server_File::apply( $path, hash( 'sha256', $after ), $original, static function () { return false; }, static function () { return true; } );
	verify( code_is( $result, 'backup' ) && $after === file_get_contents( $path ), 'backup failure never writes' );
	$count = 0;
	$result = IP_Blocker_WAF_Server_File::apply( $path, hash( 'sha256', $after ), $original, $backup, static function () use ( &$count, $path ) { if ( 1 === ++$count ) { return true; } file_put_contents( $path, 'external change' ); return false; } );
	verify( code_is( $result, 'recovery' ) && 'external change' === file_get_contents( $path ), 'rollback will not clobber a concurrent external edit' );
	verify( array() === glob( $root . '/.htaccess.ipbw-*' ), 'temporary files cleaned' );
	file_put_contents( $root . '/target', 'untouched' ); symlink( $root . '/target', $root . '/linked' );
	verify( is_wp_error( IP_Blocker_WAF_Server_File::read( $root . '/linked' ) ), 'symlink refused' );
	verify( $path === IP_Blocker_WAF_Server::path(), 'fixed same-directory server path' );
	$_SERVER['SERVER_SOFTWARE'] = 'nginx'; verify( is_wp_error( IP_Blocker_WAF_Server::path() ), 'unsupported server refused' ); $_SERVER['SERVER_SOFTWARE'] = 'Apache/2.4.66';
	$_SERVER['SERVER_SOFTWARE'] = 'Apache/2.2.34'; verify( is_wp_error( IP_Blocker_WAF_Server::path() ), 'old Apache version refused' ); $_SERVER['SERVER_SOFTWARE'] = 'Apache/2.4.66';
	$multisite = true; verify( is_wp_error( IP_Blocker_WAF_Server::path() ), 'multisite file edits refused' );
	verify( code_is( IP_Blocker_WAF_Sources::read( 'cloudsecure' ), 'forbidden' ), 'multisite log reads refused' ); $multisite = false;
	verify( code_is( IP_Blocker_WAF_Server::apply_plan( array( 'ips' => array(), 'hash' => 'x', 'at' => time() - 601 ), array() ), 'expired' ), 'expired plan rejected' );
	verify( code_is( IP_Blocker_WAF_Sources::read( 'cloudsecure' ), 'inactive' ) && array() === $wpdb->calls, 'inactive provider never queried' );
	if ( ! class_exists( 'CloudSecureWP_Waf', false ) ) { class CloudSecureWP_Waf {} }
	$wpdb->rows = array_fill( 0, 17, array( 'address' => '9.9.9.9', 'kind' => 'コードインジェクション', 'seen_at' => gmdate( 'Y-m-d H:i:s', time() - 60 ) ) );
	$wpdb->rows[] = array( 'address' => '<script>', 'kind' => 'xss', 'seen_at' => '<script>' );
	$rows = IP_Blocker_WAF_Sources::read( 'cloudsecure' );
	verify( 1 === count( $rows ) && 17 === $rows[0]['count'], 'valid bounded IP-only rows' );
	$query = $wpdb->calls[1][0];
	verify( false !== strpos( $query, 'LIMIT 10000' ), 'bounded provider query' );
	verify( ! preg_match( '/\b(url|matched|cookie|user|payload)\b/i', $query ), 'sensitive request fields not selected' );
	$wpdb->fail = true; verify( code_is( IP_Blocker_WAF_Sources::read( 'cloudsecure' ), 'unavailable' ) && false === $wpdb->suppressed, 'provider DB failure stays private and restores state' ); $wpdb->fail = false; $wpdb->last_error = '';
	$before_calls = count( $wpdb->calls ); $capable = false;
	verify( code_is( IP_Blocker_WAF_Sources::read( 'cloudsecure' ), 'forbidden' ) && $before_calls === count( $wpdb->calls ), 'reader cannot read IPs' );
	foreach ( array( 'render', 'save', 'apply', 'download_backup' ) as $method ) {
		try { IP_Blocker_WAF_Admin::$method(); verify( false, 'must reject non-admin' ); } catch ( RuntimeException $error ) { verify( 'denied' === $error->getMessage(), 'capability before nonce/file work' ); }
	}
	$capable = true; $_SERVER['REQUEST_METHOD'] = 'POST';
	foreach ( array( 'save', 'apply', 'download_backup' ) as $method ) {
		try { IP_Blocker_WAF_Admin::$method(); } catch ( RuntimeException $error ) { verify( 'nonce-reached' === $error->getMessage(), 'actions require nonce' ); }
	}
	verify( array() === IP_Blocker_WAF_Admin::settings()['sources'] && false === IP_Blocker_WAF_Admin::settings()['editing'], 'all opt-ins default off' );
	verify( 30 === IP_Blocker_WAF_Admin::settings()['threshold'] && 10 === IP_Blocker_WAF_Admin::settings()['minutes'], 'default repeated-candidate policy is 30 per 10 minutes' );
	$events = array_fill( 0, 30, array( 'address' => '9.9.9.9', 'kind' => 'コードインジェクション', 'seen_at' => gmdate( 'Y-m-d H:i:s', time() - 60 ) ) );
	$burst = IP_Blocker_WAF_Sources::group_bursts( $events, 'cloudsecure' );
	verify( 30 === $burst[0]['burst_count'] && $burst[0]['candidate'], '30 repeated records qualify' );
	verify( ! IP_Blocker_WAF_Sources::group_bursts( array_slice( $events, 0, 29 ), 'cloudsecure' )[0]['candidate'], '29 records do not qualify' );
	$events = array_merge( array_slice( $events, 0, 20 ), array_fill( 0, 20, array( 'address' => '9.9.9.9', 'kind' => 'SQLインジェクション', 'seen_at' => gmdate( 'Y-m-d H:i:s', time() - 60 ) ) ) );
	$burst = IP_Blocker_WAF_Sources::group_bursts( $events, 'cloudsecure' );
	verify( 2 === count( $burst ) && ! $burst[0]['candidate'] && ! $burst[1]['candidate'], 'different categories never combine to cross threshold' );
	$spread = array();
	for ( $i = 0; $i < 30; ++$i ) { $spread[] = array( 'address' => '9.9.9.9', 'kind' => 'コードインジェクション', 'seen_at' => gmdate( 'Y-m-d H:i:s', time() - 60 - $i * 120 ) ); }
	$burst = IP_Blocker_WAF_Sources::group_bursts( $spread, 'cloudsecure' );
	verify( 6 === $burst[0]['burst_count'] && ! $burst[0]['candidate'], 'spread-out daily counts are not a short burst' );
	define( 'WORDFENCE_VERSION', 'fixture' );
	$wpdb->rows = array_fill( 0, 30, array( 'address' => bin2hex( inet_pton( '::ffff:9.9.9.9' ) ), 'kind' => 'rce', 'seen_at' => time() - 1 ) );
	$wf = IP_Blocker_WAF_Sources::read( 'wordfence' );
	verify( 1 === count( $wf ) && '9.9.9.9' === $wf[0]['ip'] && $wf[0]['candidate'], 'Wordfence binary address and categorical repeat grouping' );
	$wf_query = $wpdb->calls[count( $wpdb->calls ) - 1];
	verify( false !== strpos( $wf_query[0], 'JSON_VALID' ) && in_array( 'blocked:waf', $wf_query[1], true ) && false === strpos( $wf_query[0], 'paramValue' ), 'database-side category extraction without request payload transfer' );
	$bad = array( array( 'address' => bin2hex( inet_pton( '::ffff:9.9.9.9' ) ), 'kind' => str_repeat( 'a', 41 ), 'seen_at' => time() - 1 ) );
	verify( array() === IP_Blocker_WAF_Sources::group_bursts( $bad, 'wordfence' ), 'overlong category is rejected, not truncated into another category' );
	if ( ! class_exists( 'Atshift_Semantic_Deterrence_Storage', false ) ) { class Atshift_Semantic_Deterrence_Storage { public static $mode = 'observe'; public static function get_settings() { return array( 'mode' => self::$mode ); } } }
	Atshift_Semantic_Deterrence_Storage::$mode = 'deter'; verify( false === IP_Blocker_WAF_Server::experiment_safe(), 'semantic responses block server modifications' );
	Atshift_Semantic_Deterrence_Storage::$mode = 'observe'; $wpdb->pending = 1; verify( false === IP_Blocker_WAF_Server::experiment_safe(), 'open observation window blocks server modifications' );
	$wpdb->pending = null; verify( true === IP_Blocker_WAF_Server::experiment_safe(), 'no active responses or open windows permits modification' );
	echo 'PASS ' . $checks . ' rule, file transaction, privacy, opt-in and permission checks' . PHP_EOL;
} finally {
	foreach ( glob( $root . '/*' ) as $file ) { unlink( $file ); }
	foreach ( glob( $root . '/.htaccess*' ) as $file ) { unlink( $file ); }
	rmdir( $root );
}
