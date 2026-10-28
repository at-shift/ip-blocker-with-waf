<?php
/** Run only on an isolated install: wp eval-file tests/wordpress-release.php. */
if ( ! defined( 'WP_CLI' ) || ! WP_CLI || 'ipbw_release_20261028' !== DB_NAME ) {
	throw new RuntimeException( 'Use the isolated release fixture database.' );
}
$GLOBALS['ipbw_release_checks'] = 0;
$original = get_option( 'ipbw_settings', null );
$original_locale = get_user_meta( 1, 'locale', true );
function release_check( $ok, $label ) {
	++$GLOBALS['ipbw_release_checks'];
	if ( ! $ok ) { throw new RuntimeException( $label ); }
}
try {
	require_once ABSPATH . 'wp-admin/includes/plugin.php';
	$data = get_plugin_data( IP_BLOCKER_WAF_FILE, false, false );
	release_check( '1.0.1' === $data['Version'] && 'atshift IP Blocker' === $data['Name'] && 'atshift-ip-blocker' === $data['TextDomain'], 'WordPress plugin metadata' );
	release_check( empty( $data['UpdateURI'] ) && ! class_exists( 'IP_Blocker_WAF_Updater', false ), 'official update route only' );
	wp_set_current_user( 1 );
	$_SERVER['REQUEST_METHOD'] = 'GET';
	update_option( 'ipbw_settings', array( 'sources' => array(), 'editing' => '0', 'protected' => '9.9.9.9', 'threshold' => 50, 'minutes' => 30 ), false );
	release_check( '9.9.9.9' === IP_Blocker_WAF_Admin::settings()['protected'], 'legacy saved option key retained' );
	$locales = array( 'en_US', 'ja', 'es_ES', 'de_DE', 'fr_FR', 'pt_BR', 'it_IT', 'ru_RU', 'nl_NL', 'zh_CN', 'pl_PL', 'tr_TR', 'id_ID', 'zh_TW', 'ko_KR' );
	foreach ( $locales as $locale ) {
		$label = esc_html( 'Connections & safety' );
		if ( 'en_US' !== $locale ) {
			release_check( switch_to_locale( $locale ), $locale . ' available' );
			$catalog = new MO();
			release_check( $catalog->import_from_file( dirname( IP_BLOCKER_WAF_FILE ) . '/languages/atshift-ip-blocker-' . $locale . '.mo' ), $locale . ' compiled catalog readable' );
			foreach ( $catalog->entries as $entry ) {
				release_check( $entry->translations[0] === __( $entry->singular, 'atshift-ip-blocker' ), $locale . ' WordPress translation: ' . $entry->singular );
			}
			$label = esc_html( $catalog->translate( 'Connections & safety' ) );
		}
		foreach ( array( 'observations', 'connections', 'rules' ) as $tab ) {
			$_GET = array( 'tab' => $tab );
			ob_start(); IP_Blocker_WAF_Admin::render(); $html = ob_get_clean();
			release_check( false !== strpos( $html, $label ) && false !== strpos( $html, 'v1.0.1' ), $locale . ' renders ' . $tab );
		}
		if ( 'en_US' !== $locale ) { restore_previous_locale(); }
	}
	switch_to_locale( 'ja' );
	release_check( '接続元IPの帰属と、独立した復旧手段の両方を確認してください。' === __( 'Both address attribution and independent recovery access must be confirmed.', 'atshift-ip-blocker' ), 'latest save-flow translation loaded' );
	release_check( 'SDNの測定を再開' === __( 'Resume SDN measurement', 'atshift-ip-blocker' ), 'latest measurement recovery translation loaded' );
	restore_previous_locale();
	update_user_meta( 1, 'locale', 'fr_FR' );
	release_check( switch_to_user_locale( 1 ) && 'fr_FR' === get_locale(), 'administrator locale can differ from site locale' );
	release_check( 'Connections & safety' !== __( 'Connections & safety', 'atshift-ip-blocker' ), 'administrator locale loads translated interface' );
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
	update_user_meta( 1, 'locale', $original_locale );
}
