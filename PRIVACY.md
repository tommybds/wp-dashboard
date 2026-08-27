# Privacy Policy — Sumotori Dash Agent / WP Dashboard

This policy describes the data handled by the **Sumotori Dash Agent** WordPress
plugin and the self-hosted **WP Dashboard** it connects to.

## Self-hosted model — who is the controller

WP Dashboard is **self-hosted software**. There is no central service operated by
the author. Whoever installs and runs a dashboard instance is the **data
controller** for the data that instance receives, and is responsible for
informing the administrators of the connected sites and for complying with
applicable law (including the GDPR where relevant).

The plugin ships with **no service address**: the dashboard URL is entered by the
site administrator at pairing time. Nothing is transmitted until a site is
paired.

## What the agent transmits

Once a site is paired, the agent sends the following to the dashboard instance
whose URL was configured, over HTTPS, signed with HMAC-SHA256:

- **Administration events**: administrator account created or promoted
  (numeric id, **login name**, **email address**, roles); administrator login
  (numeric id, **login name**, **email address**, **IP address**); plugin
  activation/deactivation; completed updates; theme switch; account deletion.
- **Inventory, on signed request from the dashboard**: WordPress and PHP
  versions, pending updates, installed plugins (slug, version, status),
  **administrator accounts** (numeric id, **login name**, **email address**,
  registration date), UpdraftPlus backup settings (including destination
  **names**, never their credentials), and on multisite the list of sub-sites
  and super administrators.

The personal data involved is limited to **administrator account identifiers**
(login, email) and, for logins, the **originating IP address**. This is the
minimum needed to detect a site compromise (for example an unexpected new
administrator).

## What is never transmitted

Passwords, password hashes, file contents, post contents, third-party API keys,
and backup destination credentials (S3 keys, SFTP passwords, Google Drive
tokens). Only destination *names* are reported.

## Purpose and legal basis

The data is used solely to **supervise and maintain** the connected sites
(inventory, update tracking, security monitoring). For an agency maintaining
client sites under contract, the legal basis is typically the legitimate
interest in securing and maintaining those sites, or the maintenance contract
itself.

## Retention

Data lives in the operator's dashboard instance for as long as that operator
keeps it. Unpairing a site (from the plugin's settings screen or
`wp dash-agent disconnect`) stops all transmission immediately.

## Contact

Because each dashboard is self-hosted, requests regarding personal data must be
addressed to **the operator of the specific dashboard instance** a site is paired
with, not to the software author.
