<?php
/**
 * Plugin Name:       HHH Members Gate
 * Description:       Makes the whole site members-only: pages, feeds, the REST API and every uploaded file need a login. Keeps an allowlist so AI connectors (Novamira OAuth / MCP) keep working, and checks hourly that photos are not leaking.
 * Version:           1.2.0
 * Requires at least: 6.0
 * Requires PHP:      7.4
 * Author:            HHH Consulting
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       hhh-members-gate
 *
 * Why: a private family archive should not depend on a third-party plugin whose
 * blanket REST block breaks the AI connection and whose upload rule outlives it.
 * This plugin owns its upload rule (written on activation, removed on deactivation)
 * and allowlists only the routes the AI connector needs to sign in.
 */

defined( 'ABSPATH' ) || exit;

const HMG_VERSION = '1.2.0';
const HMG_OPTION  = 'hmg_settings';
const HMG_LOG     = 'hmg_log';
const HMG_MARKER  = 'HHH Members Gate';
const HMG_TOKEN   = 'HMG-CANARY-OK';
const HMG_DIR     = 'hhh-members-gate';  // under uploads/: canary.txt here (gated), public/ is the one carve-out

/* --------------------------------------------------------------------------
 * Settings and log
 * ------------------------------------------------------------------------ */

function hmg_defaults() {
	return array(
		// REST routes reachable without login. They must do their own auth (OAuth / MCP do).
		'rest_allow' => "novamira/v1/oauth\nmcp/novamira-oauth\nmcp/novamira",
		// admin-ajax actions reachable without login (e.g. Wordfence 2FA at the login form).
		'ajax_allow' => 'wordfence_ls_authenticate',
		'gate_ajax'  => 1,
	);
}

function hmg_settings() {
	return wp_parse_args( (array) get_option( HMG_OPTION, array() ), hmg_defaults() );
}

function hmg_list( $key ) {
	return array_values( array_filter( array_map( function ( $s ) {
		return trim( $s, " \t/" );
	}, preg_split( '/[\s,]+/', (string) hmg_settings()[ $key ] ) ) ) );
}

/** Keep the last 50 events, newest first. */
function hmg_log( $message ) {
	$log = (array) get_option( HMG_LOG, array() );
	array_unshift( $log, array( 'time' => time(), 'message' => $message ) );
	update_option( HMG_LOG, array_slice( $log, 0, 50 ), false );
}

/* --------------------------------------------------------------------------
 * 1) Pages: logged-out visitors go to the login screen
 * ------------------------------------------------------------------------ */

add_action( 'template_redirect', function () {
	if ( is_user_logged_in() || is_robots() ) {
		return;
	}
	$req = isset( $_SERVER['REQUEST_URI'] ) ? wp_unslash( $_SERVER['REQUEST_URI'] ) : '/'; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
	nocache_headers();
	wp_safe_redirect( wp_login_url( home_url( $req ) ) );
	exit;
}, 1 );

/* --------------------------------------------------------------------------
 * 2) REST API: members only, except the allowlisted sign-in routes
 * ------------------------------------------------------------------------ */

function hmg_rest_route() {
	if ( ! empty( $GLOBALS['wp']->query_vars['rest_route'] ) ) {
		return trim( (string) $GLOBALS['wp']->query_vars['rest_route'], '/' );
	}
	$path   = (string) wp_parse_url( isset( $_SERVER['REQUEST_URI'] ) ? wp_unslash( $_SERVER['REQUEST_URI'] ) : '', PHP_URL_PATH ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
	$prefix = '/' . trim( (string) wp_parse_url( rest_url(), PHP_URL_PATH ), '/' ) . '/';
	return 0 === strpos( $path, $prefix ) ? trim( substr( $path, strlen( $prefix ) ), '/' ) : '';
}

function hmg_rest_allowed( $route ) {
	foreach ( hmg_list( 'rest_allow' ) as $allow ) {
		if ( $route === $allow || 0 === strpos( $route, $allow . '/' ) ) {
			return true;
		}
	}
	return false;
}

// Late priority: authentication plugins (application passwords, OAuth) have already run.
add_filter( 'rest_authentication_errors', function ( $result ) {
	if ( is_wp_error( $result ) || is_user_logged_in() || hmg_rest_allowed( hmg_rest_route() ) ) {
		return $result;
	}
	return new WP_Error( 'hmg_members_only', __( 'Members only.', 'hhh-members-gate' ), array( 'status' => 401 ) );
}, 99 );

/* --------------------------------------------------------------------------
 * 3) Feeds, XML-RPC, sitemaps, indexing, logged-out admin-ajax
 * ------------------------------------------------------------------------ */

foreach ( array( 'do_feed', 'do_feed_rdf', 'do_feed_rss', 'do_feed_rss2', 'do_feed_atom', 'do_feed_rss2_comments', 'do_feed_atom_comments' ) as $hmg_feed ) {
	add_action( $hmg_feed, function () {
		if ( ! is_user_logged_in() ) {
			wp_safe_redirect( wp_login_url() );
			exit;
		}
	}, 1 );
}
add_filter( 'xmlrpc_enabled', '__return_false' );
add_filter( 'wp_headers', function ( $h ) {
	unset( $h['X-Pingback'] );
	return $h;
} );
add_filter( 'wp_sitemaps_enabled', '__return_false' );
add_filter( 'wp_robots', 'wp_robots_no_robots' );
add_filter( 'robots_txt', function () {
	return "User-agent: *\nDisallow: /\n";
}, 99 );

add_action( 'init', function () {
	if ( ! wp_doing_ajax() || is_user_logged_in() || ! hmg_settings()['gate_ajax'] ) {
		return;
	}
	$action = isset( $_REQUEST['action'] ) ? sanitize_key( wp_unslash( $_REQUEST['action'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification
	if ( in_array( $action, hmg_list( 'ajax_allow' ), true ) ) {
		return;
	}
	wp_die( esc_html__( 'Members only.', 'hhh-members-gate' ), '', array( 'response' => 403 ) );
}, 0 );

/* --------------------------------------------------------------------------
 * 4) Uploaded files: every request is routed through WordPress and checked
 *
 * Two folders hold copies of members' photos: uploads/ itself, and the WebP copies
 * that WebP Express keeps in wp-content/webp-express/webp-images/uploads/ (it also
 * converts missing ones on request). Both get a rewrite block at the TOP of their
 * .htaccess, so no other rule can serve a file before the gate sees it.
 * ------------------------------------------------------------------------ */

function hmg_uploads() {
	$up = wp_get_upload_dir();
	return empty( $up['basedir'] ) ? array() : array( 'path' => untrailingslashit( $up['basedir'] ), 'url' => untrailingslashit( $up['baseurl'] ) );
}

/** The gated folders: query var => [ folder whose files are served, .htaccess that routes them, rewrite rules ]. */
function hmg_roots() {
	$up = hmg_uploads();
	if ( ! $up ) {
		return array();
	}
	$home  = '/' . ltrim( trailingslashit( (string) wp_parse_url( home_url( '/' ), PHP_URL_PATH ) ), '/' );
	$ubase = '/' . trim( (string) wp_parse_url( $up['url'], PHP_URL_PATH ), '/' ) . '/';
	$roots = array(
		'hmg_file' => array(
			'path'     => $up['path'],
			'htaccess' => $up['path'] . '/.htaccess',
			'rules'    => array(
				'<IfModule mod_rewrite.c>',
				'RewriteEngine On',
				'RewriteBase ' . $ubase,
				'RewriteCond %{REQUEST_URI} !^' . $ubase . HMG_DIR . '/public/',
				'RewriteRule ^(.+)$ ' . $home . 'index.php?hmg_file=$1 [L,QSA]',
				'</IfModule>',
			),
		),
	);
	$webp = WP_CONTENT_DIR . '/webp-express/webp-images';
	if ( is_dir( $webp ) ) {
		$roots['hmg_webp'] = array(
			'path'     => $webp . '/uploads',
			'htaccess' => $webp . '/.htaccess',
			'rules'    => array(
				'<IfModule mod_rewrite.c>',
				'RewriteEngine On',
				'RewriteRule ^uploads/(.+)$ ' . $home . 'index.php?hmg_webp=$1 [L,QSA]',
				'</IfModule>',
			),
		);
	}
	return $roots;
}

/** Put our marker block at the top of an .htaccess file (or remove it when $lines is empty). */
function hmg_write_block( $file, $lines ) {
	$current = file_exists( $file ) ? (string) file_get_contents( $file ) : ''; // phpcs:ignore WordPress.WP.AlternativeFunctions
	$pattern = '/# BEGIN ' . preg_quote( HMG_MARKER, '/' ) . '.*?# END ' . preg_quote( HMG_MARKER, '/' ) . "\\R*/s";
	$rest    = preg_replace( $pattern, '', $current );
	$block   = $lines ? '# BEGIN ' . HMG_MARKER . "\n" . implode( "\n", $lines ) . "\n# END " . HMG_MARKER . "\n\n" : '';
	$new     = $block . ltrim( $rest );
	if ( $new === $current ) {
		return true;
	}
	if ( '' === trim( $new ) ) {
		return ! file_exists( $file ) || @unlink( $file ); // phpcs:ignore WordPress.WP.AlternativeFunctions,WordPress.PHP.NoSilencedErrors
	}
	return false !== @file_put_contents( $file, $new, LOCK_EX ); // phpcs:ignore WordPress.WP.AlternativeFunctions,WordPress.PHP.NoSilencedErrors
}

/** Install ($on) or remove every block. Returns false if any write failed. */
function hmg_write_rules( $on ) {
	$ok = true;
	foreach ( hmg_roots() as $root ) {
		$ok = hmg_write_block( $root['htaccess'], $on ? $root['rules'] : array() ) && $ok;
	}
	return $ok;
}

/** True when every gated folder has its block in place. */
function hmg_rules_installed() {
	$roots = hmg_roots();
	foreach ( $roots as $root ) {
		if ( false === strpos( (string) @file_get_contents( $root['htaccess'] ), '# BEGIN ' . HMG_MARKER ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions,WordPress.PHP.NoSilencedErrors
			return false;
		}
	}
	return (bool) $roots;
}

/** Own folder: canaries (gated) and public/ (login-screen assets only). */
function hmg_prepare_dir() {
	$up = hmg_uploads();
	if ( ! $up ) {
		return;
	}
	$dir = $up['path'] . '/' . HMG_DIR;
	wp_mkdir_p( $dir . '/public' );
	foreach ( array( $dir, $dir . '/public' ) as $d ) {
		if ( ! file_exists( $d . '/index.php' ) ) {
			@file_put_contents( $d . '/index.php', "<?php\n// Silence is golden.\n" ); // phpcs:ignore WordPress.WP.AlternativeFunctions,WordPress.PHP.NoSilencedErrors
		}
	}
	if ( ! file_exists( $dir . '/public/.htaccess' ) ) {
		@file_put_contents( $dir . '/public/.htaccess', "Options -Indexes\n<FilesMatch \"\\.(?i:php\\d?|phtml|phps)$\">\nRequire all denied\n</FilesMatch>\n" ); // phpcs:ignore WordPress.WP.AlternativeFunctions,WordPress.PHP.NoSilencedErrors
	}
	foreach ( hmg_roots() as $root ) {
		$canary = $root['path'] . '/' . HMG_DIR . '/canary.txt';
		if ( ! file_exists( $canary ) ) {
			wp_mkdir_p( dirname( $canary ) );
			@file_put_contents( $canary, HMG_TOKEN ); // phpcs:ignore WordPress.WP.AlternativeFunctions,WordPress.PHP.NoSilencedErrors
		}
	}
}

add_action( 'init', 'hmg_serve_file', 0 );
function hmg_serve_file() {
	$roots = hmg_roots();
	$var   = isset( $_GET['hmg_file'] ) ? 'hmg_file' : ( isset( $_GET['hmg_webp'] ) ? 'hmg_webp' : '' ); // phpcs:ignore WordPress.Security.NonceVerification
	if ( ! $var || empty( $roots[ $var ] ) ) {
		return;
	}
	$base = realpath( $roots[ $var ]['path'] );
	$rel  = ltrim( str_replace( '\\', '/', (string) wp_unslash( $_GET[ $var ] ) ), '/' ); // phpcs:ignore WordPress.Security.NonceVerification,WordPress.Security.ValidatedSanitizedInput
	$path = $base ? realpath( $base . '/' . $rel ) : false;
	$in   = $path && 0 === strpos( $path, $base . DIRECTORY_SEPARATOR ) && is_file( $path );

	$public = 'hmg_file' === $var ? realpath( $base . '/' . HMG_DIR . '/public' ) : false;
	if ( ! is_user_logged_in() && ! ( $in && $public && 0 === strpos( $path, $public . DIRECTORY_SEPARATOR ) ) ) {
		nocache_headers();
		wp_safe_redirect( wp_login_url() );
		exit;
	}

	// A WebP copy that doesn't exist yet: send the member to the original instead of
	// letting WebP Express convert it (its converter would also serve logged-out visitors).
	if ( ! $in && 'hmg_webp' === $var && preg_match( '/^(.+\.(?:jpe?g|png))\.webp$/i', $rel, $m ) && false === strpos( $m[1], '..' ) ) {
		wp_safe_redirect( hmg_uploads()['url'] . '/' . $m[1] );
		exit;
	}

	// Only real files inside the folder (realpath defeats ../ tricks); never .htaccess or PHP.
	if ( ! $in || preg_match( '/(^|\/)\.ht|\.(php\d?|phtml|phps)$/i', $path ) ) {
		status_header( 404 );
		nocache_headers();
		exit;
	}

	/**
	 * Lets other code send a different file for this member (since 1.2.0), e.g. a copy of a
	 * photo with a face pixelated. Only a real file is accepted; otherwise the request 404s.
	 */
	$swap = apply_filters( 'hmg_serve_path', $path, $rel, $var );
	if ( $swap !== $path ) {
		if ( ! is_string( $swap ) || ! is_file( $swap ) ) {
			status_header( 404 );
			nocache_headers();
			exit;
		}
		$path = $swap;
	}

	hmg_stream( $path, (string) apply_filters( 'hmg_cache_control', 'private, max-age=86400', $rel, $var ) );
}

/** Send a file with browser caching (private) and single-range support for video. */
function hmg_stream( $path, $cache_control = 'private, max-age=86400' ) {
	$size  = (int) filesize( $path );
	$mtime = (int) filemtime( $path );
	$etag  = '"' . md5( $path . $size . $mtime ) . '"';
	$ft    = wp_check_filetype( $path );
	$type  = $ft['type'] ? $ft['type'] : 'application/octet-stream';

	while ( ob_get_level() ) {
		ob_end_clean();
	}
	header_remove( 'Pragma' );
	header_remove( 'Expires' );
	header( 'Cache-Control: ' . $cache_control );
	header( 'Vary: Cookie' );
	header( 'ETag: ' . $etag );
	header( 'Last-Modified: ' . gmdate( 'D, d M Y H:i:s', $mtime ) . ' GMT' );
	header( 'X-Content-Type-Options: nosniff' );
	header( 'X-Robots-Tag: noindex, nofollow' );

	$inm = isset( $_SERVER['HTTP_IF_NONE_MATCH'] ) ? trim( wp_unslash( $_SERVER['HTTP_IF_NONE_MATCH'] ) ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
	$ims = isset( $_SERVER['HTTP_IF_MODIFIED_SINCE'] ) ? strtotime( wp_unslash( $_SERVER['HTTP_IF_MODIFIED_SINCE'] ) ) : false; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
	// Proxies may weaken the ETag (W/"…") or suffix it (…-gzip), so compare loosely.
	$norm = function ( $t ) {
		return preg_replace( '/-gzip$/', '', str_replace( array( 'W/', '"' ), '', trim( $t ) ) );
	};
	$hit = $inm && in_array( $norm( $etag ), array_map( $norm, explode( ',', $inm ) ), true );
	if ( $hit || ( ! $inm && $ims && $ims >= $mtime ) ) {
		status_header( 304 );
		exit;
	}

	$inline = (bool) preg_match( '#^(image/|video/|audio/|text/plain$|application/pdf$)#', $type );
	header( 'Content-Type: ' . $type );
	header( 'Content-Disposition: ' . ( $inline ? 'inline' : 'attachment' ) . '; filename="' . str_replace( '"', '', basename( $path ) ) . '"' );
	header( 'Accept-Ranges: bytes' );

	$start = 0;
	$end   = $size - 1;
	$range = isset( $_SERVER['HTTP_RANGE'] ) ? (string) wp_unslash( $_SERVER['HTTP_RANGE'] ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
	if ( $size > 0 && preg_match( '/^bytes=(\d*)-(\d*)$/', $range, $m ) && ( '' !== $m[1] || '' !== $m[2] ) ) {
		if ( '' === $m[1] ) {
			$start = max( 0, $size - (int) $m[2] );
		} else {
			$start = (int) $m[1];
			$end   = '' === $m[2] ? $end : min( $end, (int) $m[2] );
		}
		if ( $start > $end || $start >= $size ) {
			status_header( 416 );
			header( 'Content-Range: bytes */' . $size );
			exit;
		}
		status_header( 206 );
		header( 'Content-Range: bytes ' . $start . '-' . $end . '/' . $size );
	} else {
		status_header( 200 );
	}
	header( 'Content-Length: ' . ( $end - $start + 1 ) );

	$fh = fopen( $path, 'rb' ); // phpcs:ignore WordPress.WP.AlternativeFunctions
	if ( $fh ) {
		fseek( $fh, $start );
		$left = $end - $start + 1;
		while ( $left > 0 && ! feof( $fh ) ) {
			$chunk = fread( $fh, (int) min( 1048576, $left ) ); // phpcs:ignore WordPress.WP.AlternativeFunctions
			echo $chunk; // phpcs:ignore WordPress.Security.EscapeOutput
			$left -= strlen( $chunk );
			flush();
		}
		fclose( $fh ); // phpcs:ignore WordPress.WP.AlternativeFunctions
	}
	exit;
}

/* --------------------------------------------------------------------------
 * 5) Leak self-test: a logged-out request for the canary must not get it
 * ------------------------------------------------------------------------ */

function hmg_self_test() {
	$up = hmg_uploads();
	if ( ! $up ) {
		return '';
	}
	hmg_prepare_dir();
	$urls = array( $up['url'] . '/' . HMG_DIR . '/canary.txt' );
	if ( isset( hmg_roots()['hmg_webp'] ) ) {
		$urls[] = content_url( '/webp-express/webp-images/uploads/' . HMG_DIR . '/canary.txt' );
	}
	$leak = false;
	foreach ( $urls as $url ) {
		$res = wp_remote_get( $url . '?t=' . time(), array( 'cookies' => array(), 'timeout' => 10, 'redirection' => 0 ) );
		if ( is_wp_error( $res ) ) {
			return '';
		}
		$leak = $leak || ( 200 === (int) wp_remote_retrieve_response_code( $res ) && false !== strpos( wp_remote_retrieve_body( $res ), HMG_TOKEN ) );
	}
	$result = $leak ? 'leak' : 'sealed';
	if ( get_option( 'hmg_test' ) !== $result ) {
		hmg_log( $leak ? __( 'Self-test: an uploaded file could be opened without logging in!', 'hhh-members-gate' ) : __( 'Self-test: uploaded files are sealed.', 'hhh-members-gate' ) );
	}
	update_option( 'hmg_test', $result, false );
	update_option( 'hmg_test_time', time(), false );
	return $result;
}

add_action( 'hmg_hourly', 'hmg_hourly_check' );
function hmg_hourly_check() {
	// Re-install the rule if something (a host tool, another plugin) stripped it.
	// e.g. WebP Express rewrites its .htaccess whenever its settings are saved.
	if ( ! hmg_rules_installed() && hmg_write_rules( true ) ) {
		hmg_log( __( 'An upload rule was missing and has been restored.', 'hhh-members-gate' ) );
	}
	hmg_self_test();
}

add_action( 'admin_notices', function () {
	if ( ! current_user_can( 'activate_plugins' ) ) {
		return;
	}
	if ( 'leak' === get_option( 'hmg_test' ) ) {
		echo '<div class="notice notice-error"><p><strong>' . esc_html__( 'HHH Members Gate:', 'hhh-members-gate' ) . '</strong> '
			. esc_html__( 'uploaded files can be opened without logging in. Open Settings > Members Gate.', 'hhh-members-gate' ) . '</p></div>';
	} elseif ( ! hmg_rules_installed() ) {
		echo '<div class="notice notice-error"><p><strong>' . esc_html__( 'HHH Members Gate:', 'hhh-members-gate' ) . '</strong> '
			. esc_html__( 'an upload protection rule is not installed (an .htaccess file may not be writable).', 'hhh-members-gate' ) . '</p></div>';
	}
} );

/* --------------------------------------------------------------------------
 * Activation / deactivation: the upload rule lives and dies with the plugin
 * ------------------------------------------------------------------------ */

register_activation_hook( __FILE__, function () {
	hmg_prepare_dir();
	hmg_log( hmg_write_rules( true ) ? __( 'Activated: upload rules installed.', 'hhh-members-gate' ) : __( 'Activated, but an upload rule could not be written.', 'hhh-members-gate' ) );
	if ( ! wp_next_scheduled( 'hmg_hourly' ) ) {
		wp_schedule_event( time() + 60, 'hourly', 'hmg_hourly' );
	}
} );

register_deactivation_hook( __FILE__, function () {
	hmg_write_rules( false ); // without the plugin the rules would break every image
	wp_clear_scheduled_hook( 'hmg_hourly' );
	delete_option( 'hmg_test' );
	hmg_log( __( 'Deactivated: upload rules removed. The site is public.', 'hhh-members-gate' ) );
} );

/* --------------------------------------------------------------------------
 * Settings page (Settings > Members Gate)
 * ------------------------------------------------------------------------ */

add_action( 'admin_menu', function () {
	add_options_page( __( 'Members Gate', 'hhh-members-gate' ), __( 'Members Gate', 'hhh-members-gate' ), 'activate_plugins', 'hhh-members-gate', 'hmg_render_settings' );
} );

add_action( 'admin_init', function () {
	register_setting( 'hmg', HMG_OPTION, array( 'sanitize_callback' => 'hmg_sanitize' ) );
} );

function hmg_sanitize( $input ) {
	$input = (array) $input;
	$clean = function ( $v ) {
		return implode( "\n", array_filter( array_map( function ( $s ) {
			return preg_replace( '#[^a-z0-9_\-/.]#i', '', trim( $s, " \t/" ) );
		}, preg_split( '/[\s,]+/', (string) $v ) ) ) );
	};
	return array(
		'rest_allow' => $clean( $input['rest_allow'] ?? '' ),
		'ajax_allow' => $clean( $input['ajax_allow'] ?? '' ),
		'gate_ajax'  => empty( $input['gate_ajax'] ) ? 0 : 1,
	);
}

add_action( 'admin_post_hmg_test', function () {
	check_admin_referer( 'hmg_test' );
	if ( current_user_can( 'activate_plugins' ) ) {
		hmg_hourly_check();
	}
	wp_safe_redirect( admin_url( 'options-general.php?page=hhh-members-gate' ) );
	exit;
} );

function hmg_render_settings() {
	if ( ! current_user_can( 'activate_plugins' ) ) {
		return;
	}
	$s    = hmg_settings();
	$test = get_option( 'hmg_test' );
	$when = (int) get_option( 'hmg_test_time' );
	$fmt  = get_option( 'date_format' ) . ' ' . get_option( 'time_format' );
	?>
	<div class="wrap">
		<h1><?php esc_html_e( 'HHH Members Gate', 'hhh-members-gate' ); ?></h1>
		<p><?php esc_html_e( 'Every page, feed, REST request and uploaded file needs a login, apart from the routes listed below.', 'hhh-members-gate' ); ?></p>

		<table class="widefat striped" style="max-width:720px">
			<tbody>
				<tr><td style="width:14em"><?php esc_html_e( 'Upload protection rules', 'hhh-members-gate' ); ?></td>
					<td><?php echo hmg_rules_installed() ? '<span style="color:#1a7f37">' . esc_html__( 'Installed', 'hhh-members-gate' ) . '</span>' : '<span style="color:#b32d2e">' . esc_html__( 'Missing', 'hhh-members-gate' ) . '</span>'; ?></td></tr>
				<tr><td><?php esc_html_e( 'Leak self-test', 'hhh-members-gate' ); ?></td>
					<td><?php
					if ( 'sealed' === $test ) {
						echo '<span style="color:#1a7f37">' . esc_html__( 'Sealed', 'hhh-members-gate' ) . '</span>';
					} elseif ( 'leak' === $test ) {
						echo '<span style="color:#b32d2e">' . esc_html__( 'LEAKING', 'hhh-members-gate' ) . '</span>';
					} else {
						esc_html_e( 'Not run yet', 'hhh-members-gate' );
					}
					echo $when ? ' &middot; ' . esc_html( wp_date( $fmt, $when ) ) : '';
					?>
					<a class="button button-small" style="margin-left:8px" href="<?php echo esc_url( wp_nonce_url( admin_url( 'admin-post.php?action=hmg_test' ), 'hmg_test' ) ); ?>"><?php esc_html_e( 'Run now', 'hhh-members-gate' ); ?></a></td></tr>
			</tbody>
		</table>

		<form method="post" action="options.php">
			<?php settings_fields( 'hmg' ); ?>
			<table class="form-table" role="presentation">
				<tr>
					<th scope="row"><?php esc_html_e( 'REST routes open without login', 'hhh-members-gate' ); ?></th>
					<td><textarea name="<?php echo esc_attr( HMG_OPTION ); ?>[rest_allow]" rows="4" class="large-text code"><?php echo esc_textarea( $s['rest_allow'] ); ?></textarea>
						<p class="description"><?php esc_html_e( 'One route prefix per line, without /wp-json/. Only list routes that check their own authentication, such as the AI connector sign-in (novamira/v1/oauth, mcp/novamira-oauth).', 'hhh-members-gate' ); ?></p></td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Logged-out admin-ajax', 'hhh-members-gate' ); ?></th>
					<td><label><input type="checkbox" name="<?php echo esc_attr( HMG_OPTION ); ?>[gate_ajax]" value="1" <?php checked( $s['gate_ajax'] ); ?>> <?php esc_html_e( 'Block admin-ajax.php for visitors who are not logged in', 'hhh-members-gate' ); ?></label>
						<p><input type="text" class="regular-text code" name="<?php echo esc_attr( HMG_OPTION ); ?>[ajax_allow]" value="<?php echo esc_attr( str_replace( "\n", ', ', $s['ajax_allow'] ) ); ?>"></p>
						<p class="description"><?php esc_html_e( 'Actions still allowed, comma-separated (for example the Wordfence two-factor login step).', 'hhh-members-gate' ); ?></p></td>
				</tr>
			</table>
			<?php submit_button(); ?>
		</form>

		<h2><?php esc_html_e( 'Recent events', 'hhh-members-gate' ); ?></h2>
		<table class="widefat striped" style="max-width:720px">
			<tbody>
			<?php $log = (array) get_option( HMG_LOG, array() ); if ( ! $log ) : ?>
				<tr><td><?php esc_html_e( 'Nothing yet.', 'hhh-members-gate' ); ?></td></tr>
			<?php else : foreach ( $log as $row ) : ?>
				<tr><td style="width:13em"><?php echo esc_html( wp_date( $fmt, (int) $row['time'] ) ); ?></td><td><?php echo esc_html( $row['message'] ); ?></td></tr>
			<?php endforeach; endif; ?>
			</tbody>
		</table>
	</div>
	<?php
}

add_filter( 'plugin_action_links_' . plugin_basename( __FILE__ ), function ( $links ) {
	array_unshift( $links, '<a href="' . esc_url( admin_url( 'options-general.php?page=hhh-members-gate' ) ) . '">' . esc_html__( 'Settings', 'hhh-members-gate' ) . '</a>' );
	return $links;
} );
