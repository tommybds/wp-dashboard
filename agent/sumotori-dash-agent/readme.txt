=== Sumotori Dash Agent ===
Contributors: tommybordas
Tags: maintenance, monitoring, management, inventory, multisite
Requires at least: 5.2
Tested up to: 7.1
Requires PHP: 7.0
Stable tag: 1.6.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Connects this site to a monitoring dashboard you choose: reports administration events and answers signed, read-only inventory requests.

== Description ==

Sumotori Dash Agent is a connector. It links a WordPress site to the monitoring
dashboard of your choice — the one you use to keep an eye on the sites you
maintain.

**The plugin ships with no service address.** You enter the dashboard URL
yourself when pairing, and **nothing is transmitted until the site is paired**.
See the "External services" section below for the exhaustive list of the data
exchanged.

= What the agent does =

* **Pairing by code**: you paste a short code displayed by your dashboard into
  the settings screen; the agent then obtains the endpoint and the shared secret
  by itself. No secret has to be copied by hand. The same pairing can be
  triggered from WP-CLI, or by an administrator through this site's own REST API
  — useful when the plugin was installed remotely and nobody is going to open
  wp-admin to copy a code.
* **Administration event reporting**: creation or promotion of an administrator
  account, administrator login, plugin activation or deactivation, completed
  update, theme switch, account deletion. Every message is signed (HMAC-SHA256)
  and sent non-blocking: a slow or unreachable dashboard never slows the site
  down.
* **Read-only inventory**: the agent exposes two REST routes that *answer*
  requests signed by your dashboard. They only write a response: no option is
  modified, no task is scheduled, no command is executed.
* **Multisite**: a single link for the whole network, managed from the network
  administration. The inventory can target any sub-site.

= Privacy =

The agent never transmits passwords, password hashes, file contents, post
contents, or backup destination credentials (S3 keys, SFTP passwords, Google
Drive tokens and the like). It does however transmit personal data about your
administrator accounts: see "External services".

== External services ==

This plugin communicates with **a third-party monitoring dashboard**, separate
from this WordPress site.

**Which service?** There is no default service: no address is hardcoded in the
plugin. The service contacted is the one whose **URL you enter yourself** in the
"Settings → Dash Agent" screen when pairing (a `SUMOTORI_DASH_AGENT_URL`
constant may also be defined in `wp-config.php` to enforce that address). The
endpoint actually used for subsequent messages is the one that service returns
in its pairing response. The operator of that service is the person or company
hosting it, and that operator publishes its own terms of use and privacy policy.

The dashboard this plugin was written against is a self-hosted, open-source
application; you can run your own instance.

Reference implementation: https://github.com/tommybds/wp-dashboard
Terms of use: https://github.com/tommybds/wp-dashboard/blob/master/TERMS.md
Privacy policy: https://github.com/tommybds/wp-dashboard/blob/master/PRIVACY.md

**No data is transmitted until the site is paired.** Before pairing the plugin
makes no outbound request whatsoever, and its inventory REST routes answer 403 to
every call. The one route that answers before pairing is the pairing route
itself (`/wp-json/sumotori-dash/v1/pair`), and only to a logged-in administrator
of this site: it is how the pairing is started, and it reports no site data — it
returns nothing but the resulting link status.

Exchanges happen in exactly three situations.

= 1. Pairing (one request, manually triggered) =

When: only when an administrator submits a pairing code from the settings
screen, runs `wp dash-agent pair`, or triggers the pairing through this site's
own REST API (`POST /wp-json/sumotori-dash/v1/pair`, reserved to the same
capability as the settings screen — see the FAQ). Whichever of the three routes
is used, the request below is the very first thing the plugin ever sends: **no
data leaves the site before it**.
Where: `POST <dashboard URL>/api/pair`.
Data transmitted:

* the pairing code you entered;
* the URL of this site (`home_url()`, or `network_site_url()` on multisite);
* the agent version number;
* a boolean telling whether the installation is a multisite.

In return, the service sends back the event endpoint and a shared secret, which
are stored in this site's database.

= 2. Administration events (one request per event) =

When: on each event listed below, for as long as the site is paired.
Where: `POST <endpoint returned at pairing>`, sent non-blocking, 2-second
timeout, signed with the `X-Viz-Site`, `X-Viz-Timestamp` and `X-Viz-Signature`
headers.
Every message contains the site URL, the event name, a timestamp and, on
multisite, the ID and URL of the sub-site concerned. Depending on the event, it
also contains:

* **Administrator account created / promoted to administrator**: numeric ID,
  **login name**, **email address** and role list of the account concerned.
* **Administrator login**: numeric ID, **login name**, **email address** and the
  **IP address** the login came from.
* **Promotion to super administrator** (multisite): numeric ID, login name and
  email address.
* **Plugin activated / deactivated**: plugin file path and scope (network or
  site).
* **Update completed**: type (plugin, theme, core), action, and the list of
  updated items.
* **Theme switched**: new theme name, incoming and outgoing stylesheets.
* **Account deleted**: numeric ID and login name of the deleted account, ID of
  the reassignment account.
* **Sub-site created** (multisite): ID, URL and name of the sub-site.

= 3. Answers to inventory requests (no outbound request) =

When: when the dashboard queries this site at
`GET /wp-json/sumotori-dash/v1/inventory` or
`GET /wp-json/sumotori-dash/v1/sites`. These requests must carry a valid HMAC
signature, computed with the shared secret and timestamped (300-second window);
any other request gets a 403. The plugin contacts nobody in this case: it merely
answers.
Data transmitted in the response:

* WordPress version and pending core update where applicable;
* site URL and name, PHP version;
* **inventory of installed plugins**: slug, activation state, installed version,
  whether an update is pending and the target version;
* **inventory of installed themes**: directory slug, display name, state (active,
  parent theme of the active child theme, or inactive), installed version,
  whether an update is pending and the target version, and the slug of the parent
  theme for a child theme;
* number of themes with a pending update;
* **administrator accounts**: numeric ID, **login name**, **email address** and
  registration date;
* **UpdraftPlus backup settings** when it is installed: file and database backup
  frequency, retention rules (including additional weekly or monthly rules),
  **names** of the configured destinations and the timestamp of the last backup;
* number of plugins set to auto-update;
* if the VizProof Timeline plugin is active on the site: its version, the number
  of pages it watches, a boolean telling whether it is connected to its own
  service (its API token is never transmitted, only its *presence* is reported),
  and the ID, state and date of its last check;
* on multisite: number of sub-sites, network-activated plugins, **super
  administrators** (login name, numeric ID, email address) and the list of
  sub-sites (ID, URL, name).

= Never transmitted =

Passwords, password hashes, file contents, post contents, third-party service
API keys, and backup destination credentials (only the destination *names* are
reported).

== Installation ==

1. Install and activate the plugin.
2. Open "Settings → Dash Agent" (on multisite: "Settings" in the network
   administration).
3. Enter the https URL of your dashboard and the pairing code it shows you, then
   submit.
4. The site is paired: administration events are reported and the dashboard can
   query the inventory.

To unlink the site, return to the same screen and click "Disconnect this site":
no further data is transmitted.

= Command-line installation =

    wp plugin activate sumotori-dash-agent
    wp dash-agent pair --url=https://your-dashboard.example --code=XXXXXX
    wp dash-agent status
    wp dash-agent disconnect

= Pairing without opening wp-admin =

If you have no shell access to the site, an administrator can start the same
pairing over this site's REST API. See "Can a dashboard pair the site without
opening wp-admin?" in the FAQ below.

== Frequently Asked Questions ==

= Does the plugin send anything before pairing? =

No. As long as the site is not paired, no event hook is even registered and the
inventory REST routes answer 403. The only thing that starts an exchange is an
administrator deliberately pairing the site, from the settings screen, from
WP-CLI, or through the `/pair` REST route.

= Where is the dashboard address set? =

You enter it when pairing. No address is hardcoded in the plugin. If you manage
a fleet of sites, you can also enforce it in `wp-config.php`:

    define( 'SUMOTORI_DASH_AGENT_URL', 'https://your-dashboard.example' );

The settings screen field then displays that value instead of being editable.

= What is left in the database after uninstalling? =

Nothing. Deleting the plugin erases the configuration option: the site option,
the network option, and any options left on sub-sites.

= Can a dashboard pair the site without opening wp-admin? =

Yes, since version 1.4.0. An administrator of the site — in practice a dashboard
authenticating with an administrator application password the site owner issued
to it — can call this site's own REST API:

    POST /wp-json/sumotori-dash/v1/pair
    {"url": "https://your-dashboard.example", "code": "XXXX-XXXX"}

The agent then performs exactly the same exchange as the settings form: it calls
`<url>/api/pair` and stores the endpoint and secret it gets back. The second
accepted body registers the link directly, as `wp dash-agent connect` does:

    POST /wp-json/sumotori-dash/v1/pair
    {"endpoint": "https://your-dashboard.example/api/ingest", "secret": "…"}

Send one form or the other, never both. The endpoint must be an https URL and
the secret 16 to 512 printable characters with no space.

Both forms require the `manage_options` capability (`manage_network_options` on
a multisite network) — exactly the capability the settings screen already
requires. The route therefore grants its caller nothing they could not already do
by hand in wp-admin; anyone else gets a 403.

A site that is already paired answers 409 and keeps its current link, unless the
body also carries `"force": true`.

The answer to a successful call is:

    {"paired": true, "endpoint": "…", "paired_at": "…", "site_url": "…",
     "agent_version": "…", "message": "…"}

**The shared secret is never returned**, never logged, and never quoted in an
error message. An invalid body gives a 400, a dashboard that cannot be reached or
whose answer cannot be read gives a 502.

Finally, `DELETE /wp-json/sumotori-dash/v1/pair`, with the same capability,
clears the link: it is the REST equivalent of the "Disconnect this site" button,
so a dashboard can withdraw cleanly from a site it no longer manages.

= Can the inventory modify my site? =

No. Both inventory routes (`/inventory` and `/sites`) are read-only: they write
no option, schedule no task, execute no command, and include no file whose path
would come from the request.

The only route that writes anything is `/pair`, and all it ever writes is the
link itself — the dashboard endpoint and the shared secret, the same single
option the settings screen saves. It is reserved to administrators of the site,
and it touches nothing else.

= Does the plugin work on multisite? =

Yes. The link is unique for the whole network and is configured from the network
administration (`manage_network_options` capability). The inventory can target
any sub-site through the `blog_id` parameter.

== Changelog ==

= 1.6.0 =

* New signed endpoint `GET /wp-json/sumotori-dash/v1/scan`: structural checks
  that **only WordPress can perform**. A dashboard scanning files over SSH sees
  the disk, including what sits outside the document root, and cannot be lied to
  by code running inside the site; it does not see the database, the scheduler,
  or the plugin list as WordPress actually renders it. This endpoint covers that
  second half, and nothing else — it deliberately does not scan files.
* Six checks, all read-only: a scheduled `wp-cron` hook with no registered
  callback (a backdoor can live in the scheduler with no file at all); an option
  over 20 KB whose value contains PHP source, a call to `eval()` or a long
  encoded block (a payload that rewrites a theme file on every visit leaves no
  suspicious file to find); a plugin directory carrying a valid plugin header
  that `get_plugins()` does not return, which means it removes itself through the
  `all_plugins` filter; a plugin marked active whose file is missing; the
  effective `auto_prepend_file` and `auto_append_file` as PHP applies them; and
  the list of must-use plugins, which run without ever being activated.
* Nothing is written, changed or deleted: the endpoint only describes. Deciding
  what is legitimate is left to the dashboard, which keeps a per-site reference
  of what was already there — without one, a perfectly healthy site would report
  the same findings on every pass.
* Transients are excluded from the option check: they regenerate, and including
  them would fill the answer with entries that no longer exist the next day.

= 1.5.0 =

* The inventory answer now carries the **list of installed themes**, not only a
  count of the ones awaiting an update: for each theme its directory slug,
  display name, state (active, parent theme of the active child theme, or
  inactive), installed version, whether an update is pending and the target
  version, and the parent theme of a child theme. A dashboard can therefore
  show the themes of a site and cross-check them against a public vulnerability
  database, as it already does for plugins. At most 100 themes are listed.
* On multisite, the state of each theme is reported for the sub-site being
  inventoried, exactly as the plugin inventory already does.
* The existing `themes_updates` count is unchanged, so dashboards written
  against an earlier version keep working.
* Nothing else moves: the inventory stays strictly read-only, no personal data
  is added — a theme name and a version number are not personal data — and no
  outbound request is made.

= 1.4.0 =

* The site can now be paired without anyone opening wp-admin, through a new REST
  route `POST /wp-json/sumotori-dash/v1/pair`. The body carries either
  `url` + `code`, which runs exactly the same exchange as the settings form, or
  `endpoint` + `secret`, the equivalent of `wp dash-agent connect`. This closes
  the last gap for a dashboard that installed the agent remotely and has no shell
  access to the site: until now a human had to copy a code by hand.
* The route requires `manage_options` (`manage_network_options` on multisite) —
  the very capability the settings screen already requires — so it grants its
  caller nothing they could not already do from wp-admin. Every other request
  gets a 403.
* An already paired site answers 409 and keeps its link unless the body carries
  `"force": true`. An invalid body gives a 400, an unreachable or unreadable
  dashboard a 502.
* The shared secret is never included in the answer, in an error message, or in
  any log.
* New `DELETE /wp-json/sumotori-dash/v1/pair`, same capability, clearing the
  link: the REST equivalent of the "Disconnect this site" button.
* The shared secret is now validated on every path — settings screen, WP-CLI and
  REST alike: 16 to 512 printable characters, no space and no control character.

= 1.3.0 =

* Removed the "Protect the agent against deactivation" option, which copied the
  agent file into `wp-content/mu-plugins/`. Plugins are not meant to write
  executable code outside their own directory, so the feature has been dropped
  entirely rather than kept behind a checkbox. The agent is now an ordinary
  plugin that is activated, deactivated and uninstalled like any other.
* `uninstall.php` no longer touches the `mu-plugins` directory.
* Internal version constant realigned with the plugin header.

= 1.2.1 =

* Plugin URI corrected to a page that actually resolves.
* Translation files removed from the package: translations are now handled by
  translate.wordpress.org, which generates and delivers them automatically.
* `load_plugin_textdomain()` removed — WordPress has loaded translations by
  itself for plugins hosted on WordPress.org since version 4.6.

= 1.2.0 =

* The `mu-plugins` copy becomes an explicit option, disabled by default, with a
  "Remove from mu-plugins" button. It is no longer performed automatically on
  activation: the plugin stays normally deactivatable and uninstallable.
* The dashboard URL is now entered by the administrator when pairing: no service
  address is embedded in the plugin any more.
* Added `uninstall.php`: uninstalling erases all options and the mu-plugins copy.
* All visible strings go through the translation functions (text domain
  `sumotori-dash-agent`) and a `.pot` template is provided.
* Compliance review: output escaping, input sanitising, nonce and capability
  check on every action, unique prefix, removal of error-log writes.

= 1.1.0 =

* Pairing by code from the settings screen and from WP-CLI.
* Multisite support: single network link, network block in the inventory,
  `/sites` route, `blog_id` parameter.

= 1.0.0 =

* First release: administration event reporting and read-only REST inventory.

== Upgrade Notice ==

= 1.3.0 =

The deactivation-protection option is gone. If you had enabled it in an earlier
version, delete `wp-content/mu-plugins/sumotori-dash-agent.php` by hand over FTP
or SSH: that leftover file keeps loading the old code and prevents the updated
plugin from running.
