=== Sumotori Dash Agent ===
Contributors: tommybordas
Tags: maintenance, monitoring, management, inventory, multisite
Requires at least: 5.2
Tested up to: 7.1
Requires PHP: 7.0
Stable tag: 1.2.0
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
  by itself. No secret has to be copied by hand.
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

Reference implementation: <!-- TO FILL IN BEFORE SUBMISSION: public URL of the dashboard source code. -->
Terms of use: <!-- TO FILL IN BEFORE SUBMISSION: public terms-of-use URL. -->
Privacy policy: <!-- TO FILL IN BEFORE SUBMISSION: public privacy-policy URL. -->

**No data is transmitted until the site is paired.** Before pairing the plugin
makes no outbound request whatsoever, and its REST routes answer 403 to every
call.

Exchanges happen in exactly three situations.

= 1. Pairing (one request, manually triggered) =

When: only when an administrator submits a pairing code from the settings
screen, or runs `wp dash-agent pair`.
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

== Frequently Asked Questions ==

= Does the plugin send anything before pairing? =

No. As long as the site is not paired, no event hook is even registered and the
REST routes answer 403.

= Where is the dashboard address set? =

You enter it when pairing. No address is hardcoded in the plugin. If you manage
a fleet of sites, you can also enforce it in `wp-config.php`:

    define( 'SUMOTORI_DASH_AGENT_URL', 'https://your-dashboard.example' );

The settings screen field then displays that value instead of being editable.

= What is the "Protect the agent against deactivation" option for? =

It is **disabled by default**. If you check it, a copy of the agent file is
placed in `wp-content/mu-plugins/`. Files in that directory are loaded
automatically by WordPress and do not appear in the plugins list, so the agent
can no longer be deactivated from wp-admin. This option only makes sense on
sites you administer yourself and monitor on a client's behalf.

= How do I undo that protection? =

Three ways, whichever you prefer:

1. uncheck the box and save: the copy is deleted;
2. click the "Remove from mu-plugins" button shown under the option;
3. manually delete `wp-content/mu-plugins/sumotori-dash-agent.php` over FTP or
   SSH.

Uninstalling the plugin also removes that copy.

= What is left in the database after uninstalling? =

Nothing. Deleting the plugin erases the configuration option (site option and
network option, plus any sub-site options) and the mu-plugins copy.

= Can the inventory modify my site? =

No. Both REST routes are read-only: they write no option, schedule no task,
execute no command, and include no file whose path would come from the request.

= Does the plugin work on multisite? =

Yes. The link is unique for the whole network and is configured from the network
administration (`manage_network_options` capability). The inventory can target
any sub-site through the `blog_id` parameter.

== Changelog ==

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

= 1.2.0 =

The agent no longer copies itself into mu-plugins on its own: if you relied on
that behaviour, check the matching option under "Settings → Dash Agent". The
dashboard URL is now requested when pairing.
