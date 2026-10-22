# WP-Members-gate 

A WordPress plugin that makes a whole site members-only. Pages, feeds, the REST API and every uploaded file need a login. An allowlist keeps the AI connectors (Novamira OAuth / MCP) working, and an hourly self-test checks that uploads are not leaking.

## Install
1. Put `hhh-members-gate.php` and `uninstall.php` in a folder called `hhh-members-gate` and zip that folder.
2. In WordPress, go to Plugins > Add New > Upload Plugin, choose the zip and activate it.
3. Settings are under Settings > Members Gate.

Requires WordPress 6.0+ and PHP 7.4+.

## Changelog
- **1.2.0** Added two developer hooks (`hmg_serve_path`, `hmg_cache_control`) for sending a different copy of a protected file. Nothing changes unless your own code uses them.
- **1.1.0** First public release.

## License
GPL-2.0-or-later
