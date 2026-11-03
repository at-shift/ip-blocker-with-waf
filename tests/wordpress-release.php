<?php
/** Run only on an isolated install: wp eval-file tests/wordpress-release.php. */
if ( ! defined( 'WP_CLI' ) || ! WP_CLI || ! in_array( DB_NAME, array( 'ipbw_release_20261028', 'ipbw_guidance_20261103' ), true ) ) {
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
	release_check( '1.0.3' === $data['Version'] && 'atshift IP Blocker' === $data['Name'] && 'atshift-ip-blocker' === $data['TextDomain'], 'WordPress plugin metadata' );
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
			release_check( false !== strpos( $html, $label ) && false !== strpos( $html, 'v1.0.3' ), $locale . ' renders ' . $tab );
		}
		$preview_method = new ReflectionMethod( IP_Blocker_WAF_Admin::class, 'render_preview' );
		if ( PHP_VERSION_ID < 80100 ) { $preview_method->setAccessible( true ); }
		ob_start(); $preview_method->invoke( null, array( 'current' => '', 'next' => 'fixture' ) ); $preview_html = ob_get_clean();
		release_check( 3 === substr_count( $preview_html, 'class="ipbw-required">' . esc_html( __( 'Required', 'atshift-ip-blocker' ) ) . '</span>' ), $locale . ' preview displays all required badges' );
		release_check( false !== strpos( $preview_html, esc_html( __( 'I can recover if WordPress becomes unreachable by replacing .htaccess with the backup file through my hosting control panel or SFTP.', 'atshift-ip-blocker' ) ) ), $locale . ' preview displays recovery capability confirmation' );
		$verify_at = strpos( $preview_html, esc_html( __( '1. Verify the IP addresses', 'atshift-ip-blocker' ) ) );
		$backup_at = strpos( $preview_html, esc_html( __( '2. Download a recovery backup', 'atshift-ip-blocker' ) ) );
		$apply_at = strpos( $preview_html, esc_html( __( '3. Confirm and apply', 'atshift-ip-blocker' ) ) );
		release_check( false !== $verify_at && false !== $backup_at && false !== $apply_at && $verify_at < $backup_at && $backup_at < $apply_at, $locale . ' preview preserves translated safety-step order' );
		if ( 'en_US' !== $locale ) { restore_previous_locale(); }
	}
	switch_to_locale( 'ja' );
	if ( ! class_exists( 'Atshift_Semantic_Deterrence_Storage', false ) ) {
		class Atshift_Semantic_Deterrence_Storage {
			public static $external = '0';
			public static function get_settings() { return array( 'external_waf_enabled' => self::$external, 'mode' => 'experiment', 'experiment_enabled' => '1' ); }
		}
	}
	update_option( 'ipbw_settings', array( 'sources' => array( 'cloudsecure' ), 'editing' => '0' ), false );
	$_GET = array( 'tab' => 'connections' );
	ob_start(); IP_Blocker_WAF_Admin::render(); $guidance_html = ob_get_clean();
	release_check( false !== strpos( $guidance_html, 'Semantic Deterrence → 設定 → 高度な設定 → 外部WAFの参考観測' ) && false !== strpos( $guidance_html, '外部WAF連携を有効にする' ), 'guidance names exact SD page, section and checkbox' );
	release_check( false !== strpos( $guidance_html, 'page=atshift-semantic-deterrence-settings' ), 'guidance links to SD settings' );
	release_check( false !== strpos( $guidance_html, 'IP遮断は独立して動作します' ) && '0' === Atshift_Semantic_Deterrence_Storage::$external, 'SD reference observation opt-in remains independent and unchanged' );
	Atshift_Semantic_Deterrence_Storage::$external = '1';
	ob_start(); IP_Blocker_WAF_Admin::render(); $enabled_html = ob_get_clean();
	release_check( false === strpos( $enabled_html, 'page=atshift-semantic-deterrence-settings' ), 'enabled SD reference observation does not repeat reminder' );
	Atshift_Semantic_Deterrence_Storage::$external = '0';
	update_option( 'ipbw_settings', array( 'sources' => array( 'wordfence' ), 'editing' => '0' ), false );
	ob_start(); IP_Blocker_WAF_Admin::render(); $wordfence_html = ob_get_clean();
	release_check( false === strpos( $wordfence_html, 'page=atshift-semantic-deterrence-settings' ), 'Wordfence-only source does not imply SD reference support' );
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
	$saved_notice = get_transient( 'ipbw_notice_1' );
	release_check( false !== strpos( $saved_notice['text'], 'Semantic Deterrence → Settings → Advanced Settings → External WAF Reference Observations' ), 'save reminder carries exact SD path' );
	release_check( ! $saved_notice['error'] && '0' === Atshift_Semantic_Deterrence_Storage::$external, 'successful save remains successful and does not enable SD integration' );
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
