<?php
/** Run only on an isolated install: wp eval-file tests/wordpress-release.php. */
if ( ! defined( 'WP_CLI' ) || ! WP_CLI || 'ipbw_release_20261028' !== DB_NAME ) {
	throw new RuntimeException( 'Use the isolated release fixture database.' );
}
$GLOBALS['ipbw_release_checks'] = 0;
$original = get_option( 'ipbw_settings', null );
function release_check( $ok, $label ) {
	++$GLOBALS['ipbw_release_checks'];
	if ( ! $ok ) { throw new RuntimeException( $label ); }
}
try {
	require_once ABSPATH . 'wp-admin/includes/plugin.php';
	$data = get_plugin_data( IP_BLOCKER_WAF_FILE, false, false );
	release_check( '1.0.0' === $data['Version'] && 'atshift IP Blocker' === $data['Name'] && 'atshift-ip-blocker' === $data['TextDomain'], 'WordPress plugin metadata' );
	release_check( empty( $data['UpdateURI'] ) && ! class_exists( 'IP_Blocker_WAF_Updater', false ), 'official update route only' );
	wp_set_current_user( 1 );
	$_SERVER['REQUEST_METHOD'] = 'GET';
	update_option( 'ipbw_settings', array( 'sources' => array(), 'editing' => '0', 'protected' => '9.9.9.9', 'threshold' => 50, 'minutes' => 30 ), false );
	release_check( '9.9.9.9' === IP_Blocker_WAF_Admin::settings()['protected'], 'legacy saved option key retained' );
	foreach ( array( 'en_US' => 'Connections &amp; safety', 'ja' => '接続と安全設定' ) as $locale => $label ) {
		if ( 'ja' === $locale ) { release_check( switch_to_locale( 'ja' ), 'Japanese locale available' ); }
		foreach ( array( 'observations', 'connections', 'rules' ) as $tab ) {
			$_GET = array( 'tab' => $tab );
			ob_start(); IP_Blocker_WAF_Admin::render(); $html = ob_get_clean();
			release_check( false !== strpos( $html, $label ) && false !== strpos( $html, 'v1.0.0' ), $locale . ' renders ' . $tab );
		}
	}
	release_check( '接続元IPの帰属と、独立した復旧手段の両方を確認してください。' === __( 'Both address attribution and independent recovery access must be confirmed.', 'atshift-ip-blocker' ), 'latest save-flow translation loaded' );
	release_check( 'SDNの測定を再開' === __( 'Resume SDN measurement', 'atshift-ip-blocker' ), 'latest measurement recovery translation loaded' );
	restore_previous_locale();
	add_filter( 'wp_redirect', static function () { throw new RuntimeException( 'release-saved' ); }, -100 );
	$_SERVER['REQUEST_METHOD'] = 'POST';
	$_POST = array( 'sources' => array( 'cloudsecure' => '1' ), 'protected' => '9.9.9.9', 'threshold' => '50', 'minutes' => '30', 'editing' => '0' );
	$_REQUEST['_wpnonce'] = wp_create_nonce( 'ipbw_save' );
	try { IP_Blocker_WAF_Admin::save(); } catch ( RuntimeException $e ) { release_check( 'release-saved' === $e->getMessage(), 'nonce-protected save completed' ); }
	$saved = IP_Blocker_WAF_Admin::settings();
	release_check( array( 'cloudsecure' ) === $saved['sources'] && ! $saved['editing'] && 50 === $saved['threshold'], 'independent opt-ins and thresholds saved' );
	add_filter( 'wp_die_handler', static function () { return static function () { throw new RuntimeException( 'release-denied' ); }; } );
	$_REQUEST['_wpnonce'] = 'invalid';
	try { IP_Blocker_WAF_Admin::save(); release_check( false, 'invalid nonce accepted' ); } catch ( RuntimeException $e ) { release_check( 'release-denied' === $e->getMessage(), 'invalid nonce denied' ); }
	wp_set_current_user( 0 );
	try { IP_Blocker_WAF_Admin::render(); release_check( false, 'anonymous access accepted' ); } catch ( RuntimeException $e ) { release_check( 'release-denied' === $e->getMessage(), 'anonymous access denied' ); }
	echo 'PASS ' . $GLOBALS['ipbw_release_checks'] . ' real WordPress metadata, locale, view, settings and access checks' . PHP_EOL;
} finally {
	if ( null === $original ) { delete_option( 'ipbw_settings' ); } else { update_option( 'ipbw_settings', $original, false ); }
	delete_transient( 'ipbw_notice_1' );
}
