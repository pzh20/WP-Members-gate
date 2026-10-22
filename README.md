# WP-Members-gate 

A WordPress plugin that makes a whole site members-only. Pages, feeds, the REST API and every uploaded file need a login. An allowlist keeps the AI connectors (Novamira OAuth / MCP) working, and an hourly self-test checks that uploads are not leaking.

## Install
1. Put `hhh-members-gate.php` and `uninstall.php` in a folder called `hhh-members-gate` and zip that folder.
2. In WordPress, go to Plugins > Add New > Upload Plugin, choose the zip and activate it.
3. Settings are under Settings > Members Gate.

Requires WordPress 6.0+ and PHP 7.4+.

## For developers: filters
Since 1.2.0, other code (for example a WPCodeBox snippet) can change what a member is sent for a protected upload.

- `hmg_serve_path( $path, $rel, $var )` returns the file to send instead of `$path`. `$rel` is the path inside uploads and `$var` is `hmg_file` or `hmg_webp`. If you return anything other than an existing file, the request gets a 404, so the original is never sent by mistake.
- `hmg_cache_control( $value, $rel, $var )` sets the Cache-Control header. The default is `private, max-age=86400`. Return `private, no-cache` for files whose content can change per viewer.

Example: The Harrison Family site uses both filters to send a copy of a photo with a child's face pixelated to everyone except the child's parents.

## Changelog
- **1.2.0** Added the `hmg_serve_path` and `hmg_cache_control` filters.
- **1.1.0** First public release.

## License
GPL-2.0-or-later
