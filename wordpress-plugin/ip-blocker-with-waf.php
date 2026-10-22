<?php
/**
 * Plugin Name: IP Blocker with WAF
 * Description: Review local WAF IP observations and manually manage server-side IP blocks with backups and rollback checks.
 * Version: 0.1.2
 * Requires at least: 6.4
 * Requires PHP: 7.4
 * Author: @shift
 * License: GPL-2.0-or-later
 * Text Domain: ip-blocker-with-waf
 * Domain Path: /languages
 * Update URI: https://github.com/at-shift/ip-blocker-with-waf
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'IP_BLOCKER_WAF_VERSION', '0.1.2' );
define( 'IP_BLOCKER_WAF_FILE', __FILE__ );
require_once __DIR__ . '/includes/class-ip-rules.php';
require_once __DIR__ . '/includes/class-sources.php';
require_once __DIR__ . '/includes/class-server-file.php';
require_once __DIR__ . '/includes/class-server.php';
require_once __DIR__ . '/includes/class-admin.php';
require_once __DIR__ . '/includes/class-updater.php';
IP_Blocker_WAF_Updater::init();

add_action( 'plugins_loaded', array( 'IP_Blocker_WAF_Server', 'maybe_probe' ), 0 );
add_action( 'plugins_loaded', static function () {
	IP_Blocker_WAF_Admin::init();
} );
add_action( 'init', static function () {
	load_plugin_textdomain( 'ip-blocker-with-waf', false, dirname( plugin_basename( __FILE__ ) ) . '/languages' );
} );
