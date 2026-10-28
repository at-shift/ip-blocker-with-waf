<?php
/**
 * Plugin Name: atshift IP Blocker
 * Description: Review local WAF IP observations and manually manage server-side IP blocks with backups and rollback checks.
 * Version: 1.0.1
 * Requires at least: 6.4
 * Requires PHP: 7.4
 * Author: @shift
 * License: GPL-2.0-or-later
 * Text Domain: atshift-ip-blocker
 * Domain Path: /languages
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'IP_BLOCKER_WAF_VERSION', '1.0.1' );
define( 'IP_BLOCKER_WAF_FILE', __FILE__ );
require_once __DIR__ . '/includes/class-ip-rules.php';
require_once __DIR__ . '/includes/class-sources.php';
require_once __DIR__ . '/includes/class-server-file.php';
require_once __DIR__ . '/includes/class-server.php';
require_once __DIR__ . '/includes/class-admin.php';

add_action( 'plugins_loaded', array( 'IP_Blocker_WAF_Server', 'maybe_probe' ), 0 );
add_action( 'plugins_loaded', static function () {
	IP_Blocker_WAF_Admin::init();
} );
add_action( 'init', static function () {
	// phpcs:ignore PluginCheck.CodeAnalysis.DiscouragedFunctions.load_plugin_textdomainFound -- Register bundled translation fallbacks on the supported WordPress 6.4 baseline; official language packs still take priority.
	load_plugin_textdomain( 'atshift-ip-blocker', false, dirname( plugin_basename( __FILE__ ) ) . '/languages' );
} );
