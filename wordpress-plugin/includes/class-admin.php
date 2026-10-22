<?php
/** Administrator-only log review, preview and apply workflow. */
if ( ! defined( 'ABSPATH' ) ) { exit; }

class IP_Blocker_WAF_Admin {
	const SETTINGS = 'ipbw_settings';

	public static function init() {
		add_action( 'admin_menu', array( __CLASS__, 'menu' ) );
		add_action( 'admin_enqueue_scripts', array( __CLASS__, 'assets' ) );
		add_action( 'admin_post_ipbw_save', array( __CLASS__, 'save' ) );
		add_action( 'admin_post_ipbw_apply', array( __CLASS__, 'apply' ) );
		add_action( 'admin_post_ipbw_backup', array( __CLASS__, 'download_backup' ) );
	}

	public static function require_admin() {
		if ( ! current_user_can( 'manage_options' ) || is_multisite() ) {
			wp_die( esc_html__( 'Administrator access on a single-site installation is required.', 'ip-blocker-with-waf' ), '', array( 'response' => 403 ) );
		}
	}

	public static function settings() {
		$raw = get_option( self::SETTINGS, array() );
		$raw = is_array( $raw ) ? $raw : array();
		$sources = is_array( $raw['sources'] ?? null ) ? array_intersect( array_keys( IP_Blocker_WAF_Sources::providers() ), $raw['sources'] ) : array();
		return array( 'sources' => $sources, 'editing' => '1' === ( $raw['editing'] ?? '0' ), 'protected' => is_string( $raw['protected'] ?? null ) ? substr( $raw['protected'], 0, 6000 ) : '', 'threshold' => in_array( $raw['threshold'] ?? 0, array( 20, 30, 50, 100 ), true ) ? $raw['threshold'] : 30, 'minutes' => in_array( $raw['minutes'] ?? 0, array( 5, 10, 30 ), true ) ? $raw['minutes'] : 10 );
	}

	public static function menu() {
		add_menu_page( 'IP Blocker with WAF', 'IP Blocker with WAF', 'manage_options', 'ip-blocker-with-waf', array( __CLASS__, 'render' ), 'dashicons-shield', 82 );
	}

	public static function assets( $hook ) {
		if ( 'toplevel_page_ip-blocker-with-waf' !== $hook || ! current_user_can( 'manage_options' ) ) { return; }
		wp_enqueue_style( 'ipbw', plugins_url( 'assets/admin.css', IP_BLOCKER_WAF_FILE ), array( 'dashicons' ), IP_BLOCKER_WAF_VERSION );
		wp_enqueue_script( 'ipbw', plugins_url( 'assets/admin.js', IP_BLOCKER_WAF_FILE ), array(), IP_BLOCKER_WAF_VERSION, true );
	}

	private static function url( $tab ) { return add_query_arg( array( 'page' => 'ip-blocker-with-waf', 'tab' => $tab ), admin_url( 'admin.php' ) ); }
	private static function session_key( $kind ) { return 'ipbw_' . $kind . '_' . substr( hash( 'sha256', get_current_user_id() . '|' . wp_get_session_token() ), 0, 32 ); }
	private static function notice( $message, $error = false ) {
		set_transient( 'ipbw_notice_' . get_current_user_id(), array( 'text' => $message, 'error' => $error ), 60 );
	}
	private static function post( $action ) {
		self::require_admin();
		if ( 'POST' !== ( $_SERVER['REQUEST_METHOD'] ?? '' ) ) { wp_die( '', '', array( 'response' => 405 ) ); }
		check_admin_referer( $action );
	}

	public static function save() {
		self::post( 'ipbw_save' );
		$protected = isset( $_POST['protected'] ) && is_string( $_POST['protected'] ) ? wp_unslash( $_POST['protected'] ) : '';
		$lines = strlen( $protected ) <= 6000 ? preg_split( '/\R/', trim( $protected ) ) : array_fill( 0, 51, '' );
		$ips = array();
		foreach ( $lines as $line ) {
			if ( '' === trim( $line ) ) { continue; }
			$ip = IP_Blocker_WAF_IP_Rules::canonical( $line );
			if ( false === $ip || count( $lines ) > 50 ) { wp_die( esc_html__( 'Enter no more than 50 valid protected IP addresses.', 'ip-blocker-with-waf' ) ); }
			$ips[] = $ip;
		}
		if ( count( $lines ) > 50 ) { wp_die( esc_html__( 'Enter no more than 50 valid protected IP addresses.', 'ip-blocker-with-waf' ) ); }
		$sources = array();
		$posted = is_array( $_POST['sources'] ?? null ) ? $_POST['sources'] : array();
		foreach ( IP_Blocker_WAF_Sources::providers() as $key => $name ) {
			if ( '1' === ( $posted[$key] ?? '' ) ) { $sources[] = $key; }
		}
		$threshold = is_string( $_POST['threshold'] ?? null ) ? (int) $_POST['threshold'] : 30;
		$minutes = is_string( $_POST['minutes'] ?? null ) ? (int) $_POST['minutes'] : 10;
		update_option( self::SETTINGS, array( 'sources' => $sources, 'protected' => implode( "\n", array_unique( $ips ) ), 'editing' => '1' === ( $_POST['editing'] ?? '' ) ? '1' : '0', 'threshold' => in_array( $threshold, array( 20, 30, 50, 100 ), true ) ? $threshold : 30, 'minutes' => in_array( $minutes, array( 5, 10, 30 ), true ) ? $minutes : 10 ), false );
		delete_transient( self::session_key( 'plan' ) );
		self::notice( __( 'Settings saved.', 'ip-blocker-with-waf' ) );
		wp_safe_redirect( self::url( 'connections' ) ); exit;
	}

	public static function download_backup() {
		self::post( 'ipbw_backup' );
		$content = null;
		if ( isset( $_POST['backup_id'] ) ) {
			$id = is_string( $_POST['backup_id'] ) ? $_POST['backup_id'] : '';
			$backups = get_option( IP_Blocker_WAF_Server::BACKUPS, array() );
			foreach ( is_array( $backups ) ? array_slice( $backups, -3 ) : array() as $backup ) {
				if ( $id === ( $backup['id'] ?? null ) && is_string( $backup['content'] ?? null ) && strlen( $backup['content'] ) <= 131072 && hash_equals( $backup['sha256'] ?? '', hash( 'sha256', $backup['content'] ) ) ) { $content = $backup['content']; }
			}
			if ( null === $content ) { wp_die( esc_html__( 'Backup not found.', 'ip-blocker-with-waf' ) ); }
		} else {
			$path = IP_Blocker_WAF_Server::path();
			if ( is_wp_error( $path ) ) { wp_die( esc_html( $path->get_error_message() ) ); }
			$content = IP_Blocker_WAF_Server_File::read( $path );
			if ( is_wp_error( $content ) ) { wp_die( esc_html( $content->get_error_message() ) ); }
			set_transient( self::session_key( 'backup_ready' ), hash( 'sha256', $content ), 600 );
		}
		nocache_headers();
		header( 'Content-Type: text/plain; charset=UTF-8' );
		header( 'Content-Disposition: attachment; filename="htaccess-backup-' . gmdate( 'Ymd-His' ) . '.txt"' );
		header( 'X-Content-Type-Options: nosniff' );
		echo $content; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- exact administrator-requested attachment.
		exit;
	}

	public static function apply() {
		self::post( 'ipbw_apply' );
		$settings = self::settings();
		$plan = get_transient( self::session_key( 'plan' ) );
		delete_transient( self::session_key( 'plan' ) );
		$downloaded = get_transient( self::session_key( 'backup_ready' ) );
		delete_transient( self::session_key( 'backup_ready' ) );
		if ( ! $settings['editing'] || '1' !== ( $_POST['recovery_confirmed'] ?? '' ) || '1' !== ( $_POST['address_confirmed'] ?? '' ) || ! is_array( $plan ) || ! is_string( $downloaded ) || ! hash_equals( $plan['hash'] ?? '', $downloaded ) ) {
			self::notice( __( 'Enable editing, download the current backup, and confirm address attribution and recovery access before applying.', 'ip-blocker-with-waf' ), true );
		} else {
			$result = IP_Blocker_WAF_Server::apply_plan( $plan, IP_Blocker_WAF_IP_Rules::protected_addresses( $settings['protected'] ) );
			self::notice( is_wp_error( $result ) ? $result->get_error_message() : __( 'Server settings updated and the site self-check passed. This does not prove that a selected remote IP was blocked.', 'ip-blocker-with-waf' ), is_wp_error( $result ) );
		}
		wp_safe_redirect( self::url( 'rules' ) ); exit;
	}

	private static function preview( $before, $settings ) {
		self::post( 'ipbw_preview' );
		if ( ! $settings['editing'] ) { return new WP_Error( 'disabled', __( 'Enable server editing in Connections first.', 'ip-blocker-with-waf' ) ); }
		$state = IP_Blocker_WAF_IP_Rules::inspect( $before );
		if ( is_wp_error( $state ) ) { return $state; }
		$manual = isset( $_POST['manual_ips'] ) && is_string( $_POST['manual_ips'] ) ? wp_unslash( $_POST['manual_ips'] ) : '';
		$selected = is_array( $_POST['selected_ips'] ?? null ) ? wp_unslash( $_POST['selected_ips'] ) : array();
		if ( strlen( $manual ) > 6000 || count( $selected ) > 50 ) { return new WP_Error( 'limit', __( 'Enter no more than 50 exact public IP addresses, one per line.', 'ip-blocker-with-waf' ) ); }
		$values = array_merge( $selected, '' === trim( $manual ) ? array() : preg_split( '/\R/', trim( $manual ) ) );
		if ( 'add' === ( $_POST['intent'] ?? '' ) && empty( $values ) ) { return new WP_Error( 'empty', __( 'Select at least one repeated candidate.', 'ip-blocker-with-waf' ) ); }
		if ( 'add' === ( $_POST['intent'] ?? '' ) ) { $values = array_values( array_unique( array_merge( $state['ips'], $values ), SORT_REGULAR ) ); }
		$ips = IP_Blocker_WAF_IP_Rules::validate( $values, IP_Blocker_WAF_IP_Rules::protected_addresses( $settings['protected'] ) );
		if ( is_wp_error( $ips ) ) { return $ips; }
		$after = IP_Blocker_WAF_IP_Rules::compose( $before, $ips );
		if ( is_wp_error( $after ) ) { return $after; }
		$plan = array( 'hash' => hash( 'sha256', $before ), 'ips' => $ips, 'at' => time() );
		if ( ! set_transient( self::session_key( 'plan' ), $plan, 600 ) ) { return new WP_Error( 'plan', __( 'The preview could not be saved.', 'ip-blocker-with-waf' ) ); }
		return array( 'current' => IP_Blocker_WAF_IP_Rules::generate( $state['ips'] ), 'next' => IP_Blocker_WAF_IP_Rules::generate( $ips ), 'count' => count( $ips ) );
	}

	public static function render() {
		self::require_admin();
		nocache_headers();
		$tab = isset( $_GET['tab'] ) && is_string( $_GET['tab'] ) && in_array( $_GET['tab'], array( 'observations', 'rules', 'connections' ), true ) ? $_GET['tab'] : 'observations';
		$settings = self::settings();
		?><div class="wrap ipbw-wrap">
			<header class="ipbw-header"><h1><span class="dashicons dashicons-shield" aria-hidden="true"></span> IP Blocker with WAF</h1><span class="ipbw-badge">v<?php echo esc_html( IP_BLOCKER_WAF_VERSION ); ?></span></header>
			<nav class="ipbw-nav" aria-label="<?php esc_attr_e( 'Plugin views', 'ip-blocker-with-waf' ); ?>">
				<?php foreach ( array( 'observations' => __( 'WAF observations', 'ip-blocker-with-waf' ), 'rules' => __( 'Server blocks', 'ip-blocker-with-waf' ), 'connections' => __( 'Connections & safety', 'ip-blocker-with-waf' ) ) as $key => $label ) : ?>
					<a href="<?php echo esc_url( self::url( $key ) ); ?>" <?php if ( $tab === $key ) { echo 'aria-current="page"'; } ?>><?php echo esc_html( $label ); ?></a>
				<?php endforeach; ?>
			</nav>
			<?php
			$notice = get_transient( 'ipbw_notice_' . get_current_user_id() );
			delete_transient( 'ipbw_notice_' . get_current_user_id() );
			if ( is_array( $notice ) ) { self::message( $notice['text'], $notice['error'] ); }
			if ( 'connections' === $tab ) { self::connections( $settings ); }
			elseif ( 'rules' === $tab ) { self::rules( $settings ); }
			else { self::observations( $settings ); }
			?>
		</div><?php
	}

	private static function message( $text, $error = false ) { ?><p role="status" class="ipbw-message<?php echo $error ? ' is-error' : ''; ?>"><?php echo esc_html( $text ); ?></p><?php }
	private static function classification( $kind ) {
		$labels = array( 'SQL injection' => __( 'SQL injection', 'ip-blocker-with-waf' ), 'Cross-site scripting' => __( 'Cross-site scripting', 'ip-blocker-with-waf' ), 'OS command injection' => __( 'OS command injection', 'ip-blocker-with-waf' ), 'Code injection' => __( 'Code injection', 'ip-blocker-with-waf' ), 'Mail header injection' => __( 'Mail header injection', 'ip-blocker-with-waf' ) );
		return $labels[$kind] ?? $kind;
	}
	private static function button( $label, $icon = 'arrow-right-alt2', $name = '' ) { ?><button class="button button-primary" type="submit" <?php if ( $name ) { echo 'name="' . esc_attr( $name ) . '" value="1"'; } ?>><span class="dashicons dashicons-<?php echo esc_attr( $icon ); ?>" aria-hidden="true"></span> <?php echo esc_html( $label ); ?></button><?php }

	private static function observations( $settings ) {
		$providers = IP_Blocker_WAF_Sources::providers();
		$source = isset( $_GET['source'] ) && is_string( $_GET['source'] ) && isset( $providers[$_GET['source']] ) ? $_GET['source'] : ( $settings['sources'][0] ?? 'cloudsecure' );
		$hours = isset( $_GET['hours'] ) && is_string( $_GET['hours'] ) ? absint( $_GET['hours'] ) : 24;
		$hours = in_array( $hours, array( 24, 168, 720 ), true ) ? $hours : 24;
		?><section class="ipbw-section"><h2><?php esc_html_e( 'Local WAF records', 'ip-blocker-with-waf' ); ?></h2>
		<form method="get" class="ipbw-toolbar"><input type="hidden" name="page" value="ip-blocker-with-waf"><input type="hidden" name="tab" value="observations">
		<label><?php esc_html_e( 'Source', 'ip-blocker-with-waf' ); ?> <select name="source"><?php foreach ( $providers as $key => $name ) : ?><option value="<?php echo esc_attr( $key ); ?>" <?php selected( $source, $key ); ?>><?php echo esc_html( $name ); ?></option><?php endforeach; ?></select></label>
		<label><?php esc_html_e( 'Period', 'ip-blocker-with-waf' ); ?> <select name="hours"><?php foreach ( array( 24 => __( '24 hours', 'ip-blocker-with-waf' ), 168 => __( '7 days', 'ip-blocker-with-waf' ), 720 => __( '30 days', 'ip-blocker-with-waf' ) ) as $key => $label ) : ?><option value="<?php echo esc_attr( $key ); ?>" <?php selected( $hours, $key ); ?>><?php echo esc_html( $label ); ?></option><?php endforeach; ?></select></label>
		<label><input type="checkbox" name="show_all" value="1" <?php checked( '1' === ( $_GET['show_all'] ?? '' ) ); ?>> <?php esc_html_e( 'Include below-threshold groups', 'ip-blocker-with-waf' ); ?></label>
		<?php self::button( __( 'Read logs', 'ip-blocker-with-waf' ), 'update' ); ?></form>
		<p class="ipbw-meta"><?php esc_html_e( 'Up to 10,000 retained rows and 200 IP/classification groups. Counts are source-specific records, not confirmed attacks. No automatic polling or external sharing.', 'ip-blocker-with-waf' ); ?></p>
		<?php
		if ( ! in_array( $source, $settings['sources'], true ) ) { self::message( __( 'This source is disabled. Enable it in Connections & safety to read its IP records.', 'ip-blocker-with-waf' ) ); echo '</section>'; return; }
		$rows = IP_Blocker_WAF_Sources::read( $source, $hours, $settings['minutes'], $settings['threshold'] );
		if ( is_wp_error( $rows ) ) { self::message( $rows->get_error_message(), true ); echo '</section>'; return; }
		if ( '1' !== ( $_GET['show_all'] ?? '' ) ) { $rows = array_filter( $rows, static function ( $row ) { return $row['candidate']; } ); }
		self::message( sprintf( __( 'Candidate threshold: %1$d records of the same classification from the same IP within any %2$d-minute window in this period. This is not proof of identical payloads or an attack.', 'ip-blocker-with-waf' ), $settings['threshold'], $settings['minutes'] ) );
		self::message( 'cloudsecure' === $source ? __( 'CloudSecure retained detections may include records that were not blocked.', 'ip-blocker-with-waf' ) : __( 'Wordfence uses retained blocked:waf records with a valid category. Generic blocks, learning-mode logs and unknown categories are not combined into candidates.', 'ip-blocker-with-waf' ) );
		$protected = IP_Blocker_WAF_IP_Rules::protected_addresses( $settings['protected'] );
		?><form method="post" action="<?php echo esc_url( self::url( 'rules' ) ); ?>"><?php wp_nonce_field( 'ipbw_preview' ); ?><input type="hidden" name="ipbw_preview" value="1"><input type="hidden" name="intent" value="add">
		<table class="widefat ipbw-table"><thead><tr><th><?php esc_html_e( 'Select', 'ip-blocker-with-waf' ); ?></th><th>IP</th><th><?php esc_html_e( 'Classification', 'ip-blocker-with-waf' ); ?></th><th><?php esc_html_e( 'Records', 'ip-blocker-with-waf' ); ?></th><th><?php esc_html_e( 'Peak in window', 'ip-blocker-with-waf' ); ?></th><th><?php esc_html_e( 'Last seen', 'ip-blocker-with-waf' ); ?></th><th><?php esc_html_e( 'Eligibility', 'ip-blocker-with-waf' ); ?></th></tr></thead><tbody>
		<?php foreach ( $rows as $row ) : $public = false !== IP_Blocker_WAF_IP_Rules::public_address( $row['ip'] ) && ! in_array( $row['ip'], $protected, true ); $eligible = $public && $row['candidate']; ?>
		<tr><td data-label="<?php esc_attr_e( 'Select', 'ip-blocker-with-waf' ); ?>"><input type="checkbox" name="selected_ips[]" value="<?php echo esc_attr( $row['ip'] ); ?>" aria-label="<?php echo esc_attr( sprintf( __( 'Select %s', 'ip-blocker-with-waf' ), $row['ip'] ) ); ?>" <?php disabled( ! $eligible ); ?>></td><td data-label="IP"><code><?php echo esc_html( $row['ip'] ); ?></code></td><td data-label="<?php esc_attr_e( 'Classification', 'ip-blocker-with-waf' ); ?>"><?php echo esc_html( self::classification( $row['kind'] ) ); ?></td><td data-label="<?php esc_attr_e( 'Records', 'ip-blocker-with-waf' ); ?>"><?php echo esc_html( number_format_i18n( $row['count'] ) ); ?></td><td data-label="<?php esc_attr_e( 'Peak in window', 'ip-blocker-with-waf' ); ?>"><strong><?php echo esc_html( number_format_i18n( $row['burst_count'] ) ); ?></strong><br><small><?php echo esc_html( $row['burst_end'] ); ?></small></td><td data-label="<?php esc_attr_e( 'Last seen', 'ip-blocker-with-waf' ); ?>"><?php echo esc_html( $row['last_seen'] ); ?></td><td data-label="<?php esc_attr_e( 'Eligibility', 'ip-blocker-with-waf' ); ?>"><span class="ipbw-badge<?php echo $eligible ? '' : ' is-protected'; ?>"><?php echo esc_html( $eligible ? __( 'Review required', 'ip-blocker-with-waf' ) : ( $public ? __( 'Below threshold', 'ip-blocker-with-waf' ) : __( 'Protected / non-public', 'ip-blocker-with-waf' ) ) ); ?></span></td></tr>
		<?php endforeach; ?>
		<?php if ( empty( $rows ) ) : ?><tr><td colspan="7"><?php esc_html_e( 'No matching groups for this period and threshold.', 'ip-blocker-with-waf' ); ?></td></tr><?php endif; ?>
		</tbody></table><div class="ipbw-actions"><?php self::button( __( 'Preview selected IP blocks', 'ip-blocker-with-waf' ) ); ?></div></form></section><?php
	}

	private static function rules( $settings ) {
		?><section class="ipbw-section"><h2><?php esc_html_e( 'Managed server blocks', 'ip-blocker-with-waf' ); ?></h2><?php
		$path = IP_Blocker_WAF_Server::path();
		$content = is_wp_error( $path ) ? $path : IP_Blocker_WAF_Server_File::read( $path );
		$state = is_wp_error( $content ) ? $content : IP_Blocker_WAF_IP_Rules::inspect( $content );
		if ( is_wp_error( $state ) ) { self::message( $state->get_error_message(), true ); echo '</section>'; self::recovery_history(); return; }
		if ( ! $settings['editing'] ) { self::message( __( 'Server editing is disabled. Viewing does not change the file.', 'ip-blocker-with-waf' ) ); }
		self::message( __( 'Only this plugin\'s managed section is edited. Existing manual deny rules remain outside its control. Blocks remain after deactivation or uninstall.', 'ip-blocker-with-waf' ) );
		if ( isset( $_POST['ipbw_preview'] ) ) {
			$preview = self::preview( $content, $settings );
			if ( is_wp_error( $preview ) ) { self::message( $preview->get_error_message(), true ); }
			else { self::render_preview( $preview ); }
		}
		?><form method="post" action="<?php echo esc_url( self::url( 'rules' ) ); ?>"><?php wp_nonce_field( 'ipbw_preview' ); ?><input type="hidden" name="ipbw_preview" value="1"><input type="hidden" name="intent" value="replace">
		<label class="ipbw-label" for="ipbw-addresses"><?php esc_html_e( 'Managed IP list', 'ip-blocker-with-waf' ); ?></label><textarea id="ipbw-addresses" name="manual_ips" rows="7" spellcheck="false" placeholder="IPv4 / IPv6"><?php echo esc_textarea( implode( "\n", $state['ips'] ) ); ?></textarea>
		<div class="ipbw-actions"><?php self::button( __( 'Preview replacement list', 'ip-blocker-with-waf' ) ); ?></div></form></section><?php
		self::recovery_history();
	}

	private static function recovery_history() {
		$backups = get_option( IP_Blocker_WAF_Server::BACKUPS, array() );
		if ( is_array( $backups ) && $backups ) { ?><section class="ipbw-section"><h2><?php esc_html_e( 'Recovery history', 'ip-blocker-with-waf' ); ?></h2><ul><?php foreach ( array_reverse( array_slice( $backups, -3 ) ) as $backup ) : ?><li><time><?php echo esc_html( wp_date( 'Y-m-d H:i:s', (int) $backup['at'] ) ); ?></time> <code><?php echo esc_html( substr( $backup['sha256'], 0, 16 ) ); ?></code><form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>"><input type="hidden" name="action" value="ipbw_backup"><input type="hidden" name="backup_id" value="<?php echo esc_attr( $backup['id'] ); ?>"><?php wp_nonce_field( 'ipbw_backup' ); ?><?php self::button( __( 'Download backup', 'ip-blocker-with-waf' ), 'download' ); ?></form></li><?php endforeach; ?></ul></section><?php }
	}

	private static function render_preview( $preview ) {
		?><div class="ipbw-preview"><h3><?php esc_html_e( 'Change preview', 'ip-blocker-with-waf' ); ?></h3><div class="ipbw-diff"><div><h4><?php esc_html_e( 'Current managed section', 'ip-blocker-with-waf' ); ?></h4><pre><?php echo esc_html( $preview['current'] ?: __( '(empty)', 'ip-blocker-with-waf' ) ); ?></pre></div><div><h4><?php esc_html_e( 'Proposed managed section', 'ip-blocker-with-waf' ); ?></h4><pre><?php echo esc_html( $preview['next'] ?: __( '(remove managed section)', 'ip-blocker-with-waf' ) ); ?></pre></div></div>
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>"><input type="hidden" name="action" value="ipbw_backup"><?php wp_nonce_field( 'ipbw_backup' ); ?><?php self::button( __( 'Download current .htaccess backup', 'ip-blocker-with-waf' ), 'download' ); ?></form>
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>"><input type="hidden" name="action" value="ipbw_apply"><?php wp_nonce_field( 'ipbw_apply' ); ?>
		<label class="ipbw-check"><input type="checkbox" name="address_confirmed" value="1" required> <?php esc_html_e( 'I verified that these are client IPs, not CDN/proxy or shared-service addresses.', 'ip-blocker-with-waf' ); ?></label>
		<label class="ipbw-check"><input type="checkbox" name="recovery_confirmed" value="1" required> <?php esc_html_e( 'I saved the backup and can restore .htaccess through hosting or SFTP if WordPress becomes unreachable.', 'ip-blocker-with-waf' ); ?></label>
		<?php self::button( __( 'Apply server changes', 'ip-blocker-with-waf' ), 'lock' ); ?></form></div><?php
	}

	private static function connections( $settings ) {
		?><section class="ipbw-section"><h2><?php esc_html_e( 'Connections & safety', 'ip-blocker-with-waf' ); ?></h2><form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>"><input type="hidden" name="action" value="ipbw_save"><?php wp_nonce_field( 'ipbw_save' ); ?>
		<fieldset><legend><?php esc_html_e( 'Read existing WAF logs', 'ip-blocker-with-waf' ); ?></legend><?php foreach ( IP_Blocker_WAF_Sources::providers() as $key => $name ) : ?><label class="ipbw-check"><input type="checkbox" name="sources[<?php echo esc_attr( $key ); ?>]" value="1" <?php checked( in_array( $key, $settings['sources'], true ) ); ?>> <?php echo esc_html( $name ); ?></label><?php endforeach; ?></fieldset>
		<p class="ipbw-meta"><?php esc_html_e( 'Raw IPs are read locally only when an administrator views the records. Provider logs are never modified. URLs, payloads, cookies and user accounts are not read.', 'ip-blocker-with-waf' ); ?></p>
		<div class="ipbw-toolbar"><label><?php esc_html_e( 'Minimum repeat count', 'ip-blocker-with-waf' ); ?> <select name="threshold"><?php foreach ( array( 20, 30, 50, 100 ) as $count ) : ?><option value="<?php echo esc_attr( $count ); ?>" <?php selected( $settings['threshold'], $count ); ?>><?php echo esc_html( $count ); ?></option><?php endforeach; ?></select></label><label><?php esc_html_e( 'Window (minutes)', 'ip-blocker-with-waf' ); ?> <select name="minutes"><?php foreach ( array( 5, 10, 30 ) as $minutes ) : ?><option value="<?php echo esc_attr( $minutes ); ?>" <?php selected( $settings['minutes'], $minutes ); ?>><?php echo esc_html( $minutes ); ?></option><?php endforeach; ?></select></label></div>
		<label class="ipbw-label" for="ipbw-protected"><?php esc_html_e( 'Protected IP addresses', 'ip-blocker-with-waf' ); ?></label><textarea id="ipbw-protected" name="protected" rows="4" spellcheck="false"><?php echo esc_textarea( $settings['protected'] ); ?></textarea>
		<p class="ipbw-meta"><?php esc_html_e( 'Your current REMOTE_ADDR and SERVER_ADDR are protected automatically. Forwarded IP headers are not trusted by this plugin. Add monitoring, proxy and administrator IPs here.', 'ip-blocker-with-waf' ); ?></p>
		<label class="ipbw-check"><input type="checkbox" name="editing" value="1" <?php checked( $settings['editing'] ); ?>> <?php esc_html_e( 'Enable manual .htaccess editing with backup and self-check', 'ip-blocker-with-waf' ); ?></label>
		<p class="ipbw-message is-warning"><?php esc_html_e( 'Apache 2.4 and same-directory, single-site WordPress only. Self-checks cannot guarantee recovery after process termination or hosting failures. Keep independent hosting/SFTP access. No background or automatic IP blocking.', 'ip-blocker-with-waf' ); ?></p>
		<p class="ipbw-meta"><?php esc_html_e( 'Up to three full configuration backups and configured IPs remain in the local database. Preview and probe tokens expire. There is no Hub, telemetry, geolocation lookup or remote block list. Uninstall does not remove server blocks or recovery data.', 'ip-blocker-with-waf' ); ?></p>
		<?php self::button( __( 'Save settings', 'ip-blocker-with-waf' ), 'saved' ); ?></form></section><?php
	}
}
