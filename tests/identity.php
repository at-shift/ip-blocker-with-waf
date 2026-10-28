<?php
/** Submission naming changes must not rename saved data or server markers. */
define( 'ABSPATH', __DIR__ );
define( 'IP_BLOCKER_WAF_FILE', dirname( __DIR__ ) . '/wordpress-plugin/atshift-ip-blocker.php' );
define( 'IP_BLOCKER_WAF_VERSION', '1.0.1' );
$menu = array(); $assets = array(); $checks = 0;
function add_menu_page( ...$args ) { $GLOBALS['menu'] = $args; }
function current_user_can( $cap ) { return 'manage_options' === $cap; }
function wp_enqueue_style( ...$args ) { $GLOBALS['assets'][] = $args; }
function wp_enqueue_script( ...$args ) { $GLOBALS['assets'][] = $args; }
function plugins_url( $path, $file ) { return 'https://fixture.invalid/wp-content/plugins/atshift-ip-blocker/' . $path; }
function admin_url( $path ) { return 'https://fixture.invalid/wp-admin/' . $path; }
function add_query_arg( $args, $url ) { return $url . '?' . http_build_query( $args ); }
function get_option( $key, $default = false ) { return 'ipbw_settings' === $key ? array( 'sources' => array( 'cloudsecure' ), 'editing' => '1', 'protected' => '9.9.9.9', 'threshold' => 50, 'minutes' => 30 ) : $default; }
require dirname( __DIR__ ) . '/wordpress-plugin/includes/class-admin.php';
require dirname( __DIR__ ) . '/wordpress-plugin/includes/class-sources.php';
require dirname( __DIR__ ) . '/wordpress-plugin/includes/class-ip-rules.php';
function identity_check( $ok, $message ) { ++$GLOBALS['checks']; if ( ! $ok ) { throw new RuntimeException( $message ); } }
IP_Blocker_WAF_Admin::menu();
identity_check( array( 'atshift IP Blocker', 'atshift IP Blocker', 'manage_options', 'atshift-ip-blocker' ) === array_slice( $menu, 0, 4 ), 'distinctive menu name and new slug' );
IP_Blocker_WAF_Admin::assets( 'toplevel_page_ip-blocker-with-waf' );
identity_check( array() === $assets, 'old menu hook does not enqueue assets' );
IP_Blocker_WAF_Admin::assets( 'toplevel_page_atshift-ip-blocker' );
identity_check( 2 === count( $assets ) && false !== strpos( $assets[0][1], '/atshift-ip-blocker/assets/' ), 'new menu hook loads matching assets' );
$url = new ReflectionMethod( 'IP_Blocker_WAF_Admin', 'url' ); $url->setAccessible( true );
identity_check( false !== strpos( $url->invoke( null, 'rules' ), 'page=atshift-ip-blocker&tab=rules' ), 'navigation uses new slug' );
$settings = IP_Blocker_WAF_Admin::settings();
identity_check( $settings['editing'] && 50 === $settings['threshold'] && 30 === $settings['minutes'] && '9.9.9.9' === $settings['protected'] && array( 'cloudsecure' ) === $settings['sources'], 'existing saved settings are retained' );
identity_check( '# BEGIN IP Blocker with WAF' === IP_Blocker_WAF_IP_Rules::BEGIN && '# END IP Blocker with WAF' === IP_Blocker_WAF_IP_Rules::END, 'legacy managed section remains recognizable' );
identity_check( is_file( IP_BLOCKER_WAF_FILE ) && ! is_file( dirname( IP_BLOCKER_WAF_FILE ) . '/ip-blocker-with-waf.php' ), 'only new entry filename exists' );
$entry = file_get_contents( IP_BLOCKER_WAF_FILE );
identity_check( false !== strpos( $entry, 'Plugin Name: atshift IP Blocker' ) && false !== strpos( $entry, 'Text Domain: atshift-ip-blocker' ), 'plugin headers match requested identity' );
identity_check( false === strpos( $entry, 'Update URI:' ) && false === strpos( $entry, 'class-updater' ), 'submission has no external updater' );
foreach ( glob( dirname( IP_BLOCKER_WAF_FILE ) . '/includes/*.php' ) as $file ) { identity_check( false === strpos( file_get_contents( $file ), "'ip-blocker-with-waf'" ), 'no old text domain or admin slug in ' . basename( $file ) ); }
echo 'PASS ' . $checks . ' submission identity and compatibility checks' . PHP_EOL;
