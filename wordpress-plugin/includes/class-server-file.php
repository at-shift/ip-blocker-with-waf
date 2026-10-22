<?php
/**
 * Bounded, hash-checked replacement and rollback of a fixed local settings file.
 * Native stream operations are intentional here: exclusive creation, fsync and
 * atomic same-directory rename must not fall back to FTP or copy-and-delete.
 */
if ( ! defined( 'ABSPATH' ) ) { exit; }

class IP_Blocker_WAF_Server_File {
	public static function read( $path ) {
		clearstatcache( true, $path );
		if ( is_link( $path ) || ! is_file( $path ) || filesize( $path ) > 131072 ) {
			return new WP_Error( 'file', __( 'An existing, regular .htaccess file of at most 128 KiB is required. Symbolic links are not supported.', 'ip-blocker-with-waf' ) );
		}
		$content = @file_get_contents( $path );
		return false === $content ? new WP_Error( 'file', __( 'The settings file could not be read.', 'ip-blocker-with-waf' ) ) : $content;
	}

	private static function replace( $path, $expected, $content ) {
		$before = self::read( $path );
		if ( is_wp_error( $before ) || ! hash_equals( $expected, hash( 'sha256', $before ) ) ) {
			return new WP_Error( 'changed', __( 'The settings file changed. Create a fresh preview before applying.', 'ip-blocker-with-waf' ) );
		}
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_is_writable -- Check the fixed local file and its parent before an atomic local transaction.
		if ( ! is_writable( $path ) || ! is_writable( dirname( $path ) ) || strlen( $content ) > 131072 ) {
			return new WP_Error( 'write', __( 'The file or its directory is not writable, or the result exceeds 128 KiB.', 'ip-blocker-with-waf' ) );
		}
		$original_stat = stat( $path );
		if ( false === $original_stat ) { return new WP_Error( 'file', __( 'The settings file could not be read.', 'ip-blocker-with-waf' ) ); }
		$mode = $original_stat['mode'] & 0777;
		if ( 0 !== ( $mode & 0022 ) || 0 !== ( $mode & 0111 ) ) {
			return new WP_Error( 'permissions', __( 'Use non-executable file permissions without group or world write access before editing.', 'ip-blocker-with-waf' ) );
		}
		$temp = dirname( $path ) . '/.htaccess.ipbw-' . bin2hex( random_bytes( 16 ) );
		$old_mask = umask( 0077 );
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- Exclusive creation under umask 0077; WP_Filesystem cannot provide this stream invariant.
		try { $handle = @fopen( $temp, 'x+b' ); } finally { umask( $old_mask ); }
		if ( false === $handle ) {
			return new WP_Error( 'write', __( 'A private temporary file could not be created.', 'ip-blocker-with-waf' ) );
		}
		try {
			// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_chmod -- Keep the owned temporary configuration private until it is ready for atomic replacement.
			if ( ! @chmod( $temp, 0600 ) ) { throw new RuntimeException( 'chmod' ); }
			$temp_stat = fstat( $handle );
			if ( false === $temp_stat ) { throw new RuntimeException( 'stat' ); }
			// Preserve ownership as well as mode; otherwise a rename can break Apache access.
			// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_chown -- Preserve the validated original file's numeric owner, not a submitted username.
			if ( $temp_stat['uid'] !== $original_stat['uid'] && ! @chown( $temp, $original_stat['uid'] ) ) { throw new RuntimeException( 'owner' ); }
			// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_chgrp -- Preserve the validated original group before the atomic rename.
			if ( $temp_stat['gid'] !== $original_stat['gid'] && ! @chgrp( $temp, $original_stat['gid'] ) ) { throw new RuntimeException( 'group' ); }
			$offset = 0;
			while ( $offset < strlen( $content ) ) {
				// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite -- Write only through the exclusively created stream, handling partial writes and fsync before rename.
				$written = fwrite( $handle, substr( $content, $offset ) );
				if ( false === $written || 0 === $written ) { throw new RuntimeException( 'write' ); }
				$offset += $written;
			}
			if ( ! fflush( $handle ) ) { throw new RuntimeException( 'flush' ); }
			if ( function_exists( 'fsync' ) && ! fsync( $handle ) ) { throw new RuntimeException( 'sync' ); }
			// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_chmod -- Restore original mode before making the new configuration visible to Apache.
			if ( ! @chmod( $temp, $mode ) ) { throw new RuntimeException( 'chmod' ); }
			$latest = self::read( $path );
			if ( is_wp_error( $latest ) || ! hash_equals( $expected, hash( 'sha256', $latest ) ) ) {
				return new WP_Error( 'changed', __( 'The settings file changed. Create a fresh preview before applying.', 'ip-blocker-with-waf' ) );
			}
			// phpcs:ignore WordPress.WP.AlternativeFunctions.rename_rename -- Atomic same-filesystem replacement is required; WP_Filesystem::move can fall back to non-atomic copy-and-delete.
			if ( ! @rename( $temp, $path ) ) { throw new RuntimeException( 'rename' ); }
			return true;
		} catch ( Throwable $error ) {
			return new WP_Error( 'write', __( 'The settings file could not be replaced. No partial file was installed.', 'ip-blocker-with-waf' ) );
		} finally {
			// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- Close the owned exclusive stream in every success/error path.
			fclose( $handle );
			// phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink -- Remove only the exact random temporary path created here; cleanup must not allow filtered paths or leave configuration fragments behind.
			if ( is_file( $temp ) ) { @unlink( $temp ); }
		}
	}

	public static function apply( $path, $expected, $after, $backup, $probe ) {
		$before = self::read( $path );
		if ( is_wp_error( $before ) || ! hash_equals( $expected, hash( 'sha256', $before ) ) ) {
			return new WP_Error( 'changed', __( 'The settings file changed. Create a fresh preview before applying.', 'ip-blocker-with-waf' ) );
		}
		if ( $after === $before ) { return new WP_Error( 'unchanged', __( 'No changes to apply.', 'ip-blocker-with-waf' ) ); }
		try {
			if ( ! $probe() ) { return new WP_Error( 'baseline', __( 'The preflight site check failed. The settings file was not changed.', 'ip-blocker-with-waf' ) ); }
			if ( ! $backup( $before ) ) { return new WP_Error( 'backup', __( 'The database backup could not be saved. The settings file was not changed.', 'ip-blocker-with-waf' ) ); }
		} catch ( Throwable $error ) {
			return new WP_Error( 'preflight', __( 'Preflight or backup failed. The settings file was not changed.', 'ip-blocker-with-waf' ) );
		}
		$write = self::replace( $path, $expected, $after );
		if ( is_wp_error( $write ) ) { return $write; }
		try { $healthy = $probe(); } catch ( Throwable $error ) { $healthy = false; }
		if ( $healthy ) {
			$latest = self::read( $path );
			return ! is_wp_error( $latest ) && hash_equals( hash( 'sha256', $after ), hash( 'sha256', $latest ) )
				? true : new WP_Error( 'changed', __( 'The file changed again during verification. Review its current contents before retrying.', 'ip-blocker-with-waf' ) );
		}
		$rollback = self::replace( $path, hash( 'sha256', $after ), $before );
		return is_wp_error( $rollback )
			? new WP_Error( 'recovery', __( 'The site check failed and automatic rollback could not safely complete. Restore the downloaded backup through your hosting panel or SFTP immediately.', 'ip-blocker-with-waf' ) )
			: new WP_Error( 'rolled_back', __( 'The site check failed. The previous file was restored automatically.', 'ip-blocker-with-waf' ) );
	}
}
