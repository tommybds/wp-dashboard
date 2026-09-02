<?php
/**
 * Plugin Name: Sumotori Dash Agent
 * Plugin URI: https://github.com/tommybds/wp-dashboard
 * Description: Connects this site to a monitoring dashboard of your choice: reports sensitive administration events and answers signed, read-only inventory requests.
 * Version: 1.3.0
 * Requires at least: 5.2
 * Requires PHP: 7.0
 * Author: Tommy Bordas
 * Author URI: https://sumotori.fr/
 * License: GPLv2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: sumotori-dash-agent
 * Domain Path: /languages
 * Network: true
 *
 * @package Sumotori_Dash_Agent
 */

/*
Sumotori Dash Agent
Copyright (C) 2026 Tommy Bordas

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
*/

defined( 'ABSPATH' ) || exit;

if ( ! class_exists( 'Sumotori_Dash_Agent' ) ) {

	/**
	 * Agent de supervision.
	 *
	 * Le plugin ne contacte aucun service tant que l'administrateur ne l'a pas
	 * appairé : l'URL du tableau de bord est saisie par l'utilisateur au moment
	 * de l'appairage (ou imposée par la constante SUMOTORI_DASH_AGENT_URL dans
	 * wp-config.php). Aucune adresse de service n'est embarquée dans le code.
	 *
	 * Trois capacités :
	 *  1. Appairage : un code court est échangé contre {endpoint, secret}.
	 *  2. Événements sortants : POST signé et non bloquant à chaque événement
	 *     d'administration sensible.
	 *  3. Inventaire REST : GET sumotori-dash/v1/inventory et /sites, protégés
	 *     par signature HMAC, strictement en lecture seule.
	 *
	 * Configuration : option `sumotori_dash_agent`
	 *   array( 'enabled', 'endpoint', 'secret', 'paired_at' )
	 * stockée en option de réseau sur un multisite (une seule liaison pour tout
	 * le réseau) et en option de site sinon.
	 *
	 * Aucun mot de passe, aucun hash de mot de passe et aucun contenu de fichier
	 * ne sort jamais de ce site.
	 */
	final class Sumotori_Dash_Agent {

		const OPTION_KEY       = 'sumotori_dash_agent';
		const REST_NAMESPACE   = 'sumotori-dash/v1';
		const ROUTE_INVENTORY  = '/inventory';
		const ROUTE_SITES      = '/sites';
		const MENU_SLUG        = 'sumotori-dash-agent';
		const NONCE_ACTION     = 'sumotori_dash_agent_admin';
		const URL_CONSTANT     = 'SUMOTORI_DASH_AGENT_URL';
		const MAX_TIMESTAMP_SKEW = 300;
		const REQUEST_TIMEOUT  = 2;
		const PAIR_TIMEOUT     = 10;
		const MAX_EVENT_ITEMS  = 25;
		const MAX_SITES_LISTED = 500;
		const VERSION          = '1.3.0';

		/**
		 * Instance unique.
		 *
		 * @var Sumotori_Dash_Agent|null
		 */
		private static $instance = null;

		/**
		 * Configuration mémorisée pour la requête courante.
		 *
		 * @var array|null
		 */
		private $config_cache = null;

		/**
		 * Message à afficher dans l'écran de réglages.
		 *
		 * @var array|null
		 */
		private $notice = null;

		/**
		 * Sous-sites déjà annoncés pendant cette requête.
		 *
		 * @var array
		 */
		private $announced_blog_ids = array();

		/**
		 * Retourne l'instance unique.
		 *
		 * @return Sumotori_Dash_Agent
		 */
		public static function instance() {
			if ( null === self::$instance ) {
				self::$instance = new self();
			}

			return self::$instance;
		}

		/**
		 * Enregistre les accroches WordPress.
		 */
		private function __construct() {

			add_action( 'rest_api_init', array( $this, 'register_rest_routes' ) );

			if ( is_multisite() ) {
				add_action( 'network_admin_menu', array( $this, 'register_network_admin_menu' ) );
			} else {
				add_action( 'admin_menu', array( $this, 'register_admin_menu' ) );
			}

			$this->register_event_hooks();
		}

		// ── Configuration ────────────────────────────────────────────────────

		/**
		 * URL du tableau de bord imposée par wp-config.php, si l'administrateur
		 * en a défini une. Aucune valeur par défaut n'est embarquée.
		 *
		 * @return string URL normalisée, ou chaîne vide.
		 */
		public function get_configured_dashboard_url() {
			if ( ! defined( self::URL_CONSTANT ) ) {
				return '';
			}

			$url = untrailingslashit( esc_url_raw( trim( (string) constant( self::URL_CONSTANT ) ) ) );

			return ( '' !== $url ) ? $url : '';
		}

		/**
		 * Configuration courante.
		 *
		 * @return array
		 */
		public function get_config() {
			if ( is_array( $this->config_cache ) ) {
				return $this->config_cache;
			}

			// get_site_option() retombe sur get_option() hors multisite.
			$saved = get_site_option( self::OPTION_KEY, array() );
			if ( ! is_array( $saved ) ) {
				$saved = array();
			}

			$this->config_cache = array(
				'enabled'    => ! empty( $saved['enabled'] ),
				'endpoint'   => isset( $saved['endpoint'] ) ? esc_url_raw( (string) $saved['endpoint'] ) : '',
				'secret'     => isset( $saved['secret'] ) ? (string) $saved['secret'] : '',
				'paired_at'  => isset( $saved['paired_at'] ) ? absint( $saved['paired_at'] ) : 0,
			);

			return $this->config_cache;
		}

		/**
		 * Secret partagé.
		 *
		 * @return string
		 */
		public function get_secret() {
			$config = $this->get_config();

			return (string) $config['secret'];
		}

		/**
		 * Le site est-il appairé ?
		 *
		 * @return bool
		 */
		public function is_connected() {
			$config = $this->get_config();

			return ! empty( $config['enabled'] )
				&& '' !== (string) $config['endpoint']
				&& '' !== (string) $config['secret'];
		}

		/**
		 * Capacité requise : réseau sur un multisite, site sinon.
		 *
		 * @return string
		 */
		public function get_required_capability() {
			return is_multisite() ? 'manage_network_options' : 'manage_options';
		}

		/**
		 * Écrit la configuration en conservant les clés non fournies.
		 *
		 * @param array $changes Clés à mettre à jour.
		 */
		private function save_config( array $changes ) {
			$config = array_merge( $this->get_config(), $changes );

			update_site_option(
				self::OPTION_KEY,
				array(
					'enabled'    => ! empty( $config['enabled'] ),
					'endpoint'   => esc_url_raw( (string) $config['endpoint'] ),
					'secret'     => (string) $config['secret'],
					'paired_at'  => absint( $config['paired_at'] ),
				)
			);

			$this->config_cache = null;
		}

		/**
		 * Un endpoint doit être en https. Seule dérogation, explicite : un
		 * endpoint http dont l'hôte est exactement celui de la constante définie
		 * par l'administrateur dans wp-config.php (environnement de test).
		 *
		 * @param string $endpoint URL à valider.
		 * @return bool
		 */
		private function is_endpoint_acceptable( $endpoint ) {
			$parts  = wp_parse_url( (string) $endpoint );
			$scheme = ( is_array( $parts ) && ! empty( $parts['scheme'] ) ) ? strtolower( (string) $parts['scheme'] ) : '';
			$host   = ( is_array( $parts ) && ! empty( $parts['host'] ) ) ? strtolower( (string) $parts['host'] ) : '';

			if ( '' === $host ) {
				return false;
			}
			if ( 'https' === $scheme ) {
				return true;
			}
			if ( 'http' !== $scheme ) {
				return false;
			}

			$configured = $this->get_configured_dashboard_url();
			if ( '' === $configured ) {
				return false;
			}

			$override      = wp_parse_url( $configured );
			$override_host = ( is_array( $override ) && ! empty( $override['host'] ) ) ? strtolower( (string) $override['host'] ) : '';

			return ( '' !== $override_host && $override_host === $host );
		}

		/**
		 * Détermine l'URL du tableau de bord à interroger pour l'appairage.
		 *
		 * @param string $provided URL saisie par l'utilisateur.
		 * @return string|WP_Error
		 */
		private function resolve_dashboard_url( $provided ) {
			$configured = $this->get_configured_dashboard_url();
			if ( '' !== $configured ) {
				return $configured;
			}

			$provided = untrailingslashit( trim( (string) $provided ) );
			if ( '' === $provided ) {
				return new WP_Error(
					'sumotori_dash_missing_url',
					__( 'Please provide the dashboard URL.', 'sumotori-dash-agent' )
				);
			}

			if ( ! $this->is_endpoint_acceptable( $provided ) ) {
				return new WP_Error(
					'sumotori_dash_insecure_url',
					__( 'The dashboard URL must be a valid https URL.', 'sumotori-dash-agent' )
				);
			}

			$sanitized = untrailingslashit( esc_url_raw( $provided ) );
			if ( '' === $sanitized ) {
				return new WP_Error(
					'sumotori_dash_invalid_url',
					__( 'The dashboard URL is invalid.', 'sumotori-dash-agent' )
				);
			}

			return $sanitized;
		}

		/**
		 * Enregistre la liaison.
		 *
		 * @param string $endpoint URL de réception des événements.
		 * @param string $secret   Secret partagé.
		 * @return true|WP_Error
		 */
		public function connect( $endpoint, $secret ) {
			$endpoint = trim( (string) $endpoint );
			$secret   = trim( (string) $secret );

			if ( '' === $endpoint ) {
				return new WP_Error(
					'sumotori_dash_missing_endpoint',
					__( 'Please provide the receiving endpoint.', 'sumotori-dash-agent' )
				);
			}

			if ( ! $this->is_endpoint_acceptable( $endpoint ) ) {
				return new WP_Error(
					'sumotori_dash_insecure_endpoint',
					__( 'The endpoint must be a valid https URL.', 'sumotori-dash-agent' )
				);
			}

			$sanitized_endpoint = esc_url_raw( $endpoint );
			if ( '' === $sanitized_endpoint ) {
				return new WP_Error(
					'sumotori_dash_invalid_endpoint',
					__( 'The endpoint is invalid.', 'sumotori-dash-agent' )
				);
			}

			if ( '' === $secret ) {
				return new WP_Error(
					'sumotori_dash_missing_secret',
					__( 'Please provide the shared secret.', 'sumotori-dash-agent' )
				);
			}

			$this->save_config(
				array(
					'enabled'   => true,
					'endpoint'  => $sanitized_endpoint,
					'secret'    => $secret,
					'paired_at' => time(),
				)
			);

			return true;
		}

		/**
		 * Efface la liaison : plus aucune donnée ne sort du site.
		 *
		 * @return true
		 */
		public function disconnect() {
			$this->save_config(
				array(
					'enabled'   => false,
					'endpoint'  => '',
					'secret'    => '',
					'paired_at' => 0,
				)
			);

			return true;
		}

		// ── Appairage par code ───────────────────────────────────────────────

		/**
		 * Échange un code court contre {endpoint, secret} auprès du tableau de
		 * bord indiqué, puis enregistre la liaison. Rien n'est stocké si la
		 * réponse n'est pas exploitable.
		 *
		 * @param string $dashboard_url URL du tableau de bord saisie par l'utilisateur.
		 * @param string $code          Code d'appairage.
		 * @return true|WP_Error
		 */
		public function pair( $dashboard_url, $code ) {
			$code = trim( (string) $code );
			if ( '' === $code ) {
				return new WP_Error(
					'sumotori_dash_missing_code',
					__( 'Please provide the pairing code.', 'sumotori-dash-agent' )
				);
			}

			$base = $this->resolve_dashboard_url( $dashboard_url );
			if ( is_wp_error( $base ) ) {
				return $base;
			}

			if ( ! function_exists( 'wp_remote_post' ) ) {
				return new WP_Error(
					'sumotori_dash_http_unavailable',
					__( 'The WordPress HTTP API is unavailable.', 'sumotori-dash-agent' )
				);
			}

			$body = wp_json_encode(
				array(
					'code'          => $code,
					'site_url'      => is_multisite() ? network_site_url() : home_url(),
					'agent_version' => self::VERSION,
					'multisite'     => is_multisite(),
				)
			);
			if ( ! is_string( $body ) || '' === $body ) {
				return new WP_Error(
					'sumotori_dash_encode_failed',
					__( 'Could not prepare the pairing request.', 'sumotori-dash-agent' )
				);
			}

			$response = wp_remote_post(
				$base . '/api/pair',
				array(
					'timeout'     => self::PAIR_TIMEOUT,
					'redirection' => 2,
					'sslverify'   => true,
					'headers'     => array(
						'Content-Type' => 'application/json; charset=utf-8',
						'Accept'       => 'application/json',
					),
					'body'        => $body,
					'user-agent'  => 'Sumotori-Dash-Agent/' . self::VERSION,
				)
			);

			if ( is_wp_error( $response ) ) {
				return new WP_Error(
					'sumotori_dash_pair_unreachable',
					sprintf(
						/* translators: %s: error message returned by the HTTP API. */
						__( 'Dashboard unreachable: %s', 'sumotori-dash-agent' ),
						$response->get_error_message()
					)
				);
			}

			$status = (int) wp_remote_retrieve_response_code( $response );
			$raw    = (string) wp_remote_retrieve_body( $response );
			$data   = json_decode( $raw, true );

			if ( ! is_array( $data ) ) {
				return new WP_Error(
					'sumotori_dash_pair_bad_response',
					sprintf(
						/* translators: %d: HTTP status code. */
						__( 'Unreadable response from the dashboard (HTTP %d).', 'sumotori-dash-agent' ),
						$status
					)
				);
			}

			if ( 200 !== $status || empty( $data['ok'] ) ) {
				return new WP_Error( 'sumotori_dash_pair_refused', $this->describe_pair_error( $data, $status ) );
			}

			$secret   = isset( $data['secret'] ) ? trim( (string) $data['secret'] ) : '';
			$endpoint = isset( $data['endpoint'] ) ? trim( (string) $data['endpoint'] ) : '';
			if ( '' === $secret || '' === $endpoint ) {
				return new WP_Error(
					'sumotori_dash_pair_incomplete',
					__( 'The dashboard did not return a usable endpoint and secret.', 'sumotori-dash-agent' )
				);
			}

			return $this->connect( $endpoint, $secret );
		}

		/**
		 * Traduit un refus d'appairage en message lisible.
		 *
		 * @param array $data   Réponse décodée.
		 * @param int   $status Code HTTP.
		 * @return string
		 */
		private function describe_pair_error( $data, $status ) {
			if ( ! empty( $data['message'] ) ) {
				return sanitize_text_field( (string) $data['message'] );
			}

			$error = ! empty( $data['error'] ) ? sanitize_key( (string) $data['error'] ) : '';
			$known = array(
				'invalid_code'   => __( 'Invalid pairing code.', 'sumotori-dash-agent' ),
				'expired_code'   => __( 'Pairing code expired: generate a new one from the dashboard.', 'sumotori-dash-agent' ),
				'code_expired'   => __( 'Pairing code expired: generate a new one from the dashboard.', 'sumotori-dash-agent' ),
				'used_code'      => __( 'Pairing code already used.', 'sumotori-dash-agent' ),
				'code_used'      => __( 'Pairing code already used.', 'sumotori-dash-agent' ),
				'already_paired' => __( 'This code has already been used to pair a site.', 'sumotori-dash-agent' ),
			);
			if ( '' !== $error && isset( $known[ $error ] ) ) {
				return $known[ $error ];
			}

			if ( 401 === (int) $status || 403 === (int) $status ) {
				return __( 'Pairing code rejected (invalid, expired or already used).', 'sumotori-dash-agent' );
			}

			return sprintf(
				/* translators: %d: HTTP status code. */
				__( 'Pairing rejected by the dashboard (HTTP %d).', 'sumotori-dash-agent' ),
				(int) $status
			);
		}

		// ── Écran d'administration ───────────────────────────────────────────

		/**
		 * Menu de réglages sur un site simple.
		 */
		public function register_admin_menu() {
			add_options_page(
				__( 'Dash Agent', 'sumotori-dash-agent' ),
				__( 'Dash Agent', 'sumotori-dash-agent' ),
				'manage_options',
				self::MENU_SLUG,
				array( $this, 'render_admin_page' )
			);
		}

		/**
		 * Menu de réglages réseau sur un multisite.
		 */
		public function register_network_admin_menu() {
			add_submenu_page(
				'settings.php',
				__( 'Dash Agent', 'sumotori-dash-agent' ),
				__( 'Dash Agent', 'sumotori-dash-agent' ),
				'manage_network_options',
				self::MENU_SLUG,
				array( $this, 'render_admin_page' )
			);
		}

		/**
		 * Écran de réglages.
		 */
		public function render_admin_page() {
			$capability = $this->get_required_capability();
			if ( ! current_user_can( $capability ) ) {
				wp_die( esc_html__( 'Insufficient permissions.', 'sumotori-dash-agent' ) );
			}

			$this->handle_admin_request( $capability );

			$config     = $this->get_config();
			$connected  = $this->is_connected();
			$configured = $this->get_configured_dashboard_url();
			?>
			<div class="wrap">
				<h1><?php esc_html_e( 'Sumotori Dash Agent', 'sumotori-dash-agent' ); ?></h1>

				<?php if ( is_array( $this->notice ) ) : ?>
					<div class="notice notice-<?php echo esc_attr( $this->notice['type'] ); ?>">
						<p><?php echo esc_html( $this->notice['message'] ); ?></p>
					</div>
				<?php endif; ?>

				<table class="form-table" role="presentation">
					<tr>
						<th scope="row"><?php esc_html_e( 'Status', 'sumotori-dash-agent' ); ?></th>
						<td>
							<?php if ( $connected ) : ?>
								<strong><?php esc_html_e( 'Paired', 'sumotori-dash-agent' ); ?></strong>
								&mdash; <code><?php echo esc_html( $config['endpoint'] ); ?></code>
								<?php if ( ! empty( $config['paired_at'] ) ) : ?>
									<br />
									<span class="description">
										<?php
										printf(
											/* translators: %s: formatted date. */
											esc_html__( 'Paired on %s', 'sumotori-dash-agent' ),
											esc_html( $this->format_date( $config['paired_at'] ) )
										);
										?>
									</span>
								<?php endif; ?>
							<?php else : ?>
								<strong><?php esc_html_e( 'Not paired', 'sumotori-dash-agent' ); ?></strong>
								<p class="description">
									<?php esc_html_e( 'No data is transmitted until the site is paired.', 'sumotori-dash-agent' ); ?>
								</p>
							<?php endif; ?>
						</td>
					</tr>
					<?php if ( is_multisite() ) : ?>
						<tr>
							<th scope="row"><?php esc_html_e( 'Scope', 'sumotori-dash-agent' ); ?></th>
							<td><?php esc_html_e( 'Multisite network: a single link for the whole network.', 'sumotori-dash-agent' ); ?></td>
						</tr>
					<?php endif; ?>
				</table>

				<?php if ( $connected ) : ?>
					<form method="post">
						<?php wp_nonce_field( self::NONCE_ACTION ); ?>
						<input type="hidden" name="sumotori_dash_action" value="unpair" />
						<?php submit_button( __( 'Disconnect this site', 'sumotori-dash-agent' ), 'delete', 'submit', true ); ?>
					</form>
				<?php else : ?>
					<h2><?php esc_html_e( 'Pair this site', 'sumotori-dash-agent' ); ?></h2>
					<form method="post">
						<?php wp_nonce_field( self::NONCE_ACTION ); ?>
						<input type="hidden" name="sumotori_dash_action" value="pair" />
						<table class="form-table" role="presentation">
							<tr>
								<th scope="row">
									<label for="sumotori_dash_url"><?php esc_html_e( 'Dashboard URL', 'sumotori-dash-agent' ); ?></label>
								</th>
								<td>
									<?php if ( '' !== $configured ) : ?>
										<code><?php echo esc_html( $configured ); ?></code>
										<p class="description">
											<?php
											printf(
												/* translators: %s: PHP constant name. */
												esc_html__( 'Enforced by the %s constant defined in wp-config.php.', 'sumotori-dash-agent' ),
												esc_html( self::URL_CONSTANT )
											);
											?>
										</p>
									<?php else : ?>
										<input
											type="url"
											id="sumotori_dash_url"
											name="sumotori_dash_url"
											class="regular-text"
											value=""
											placeholder="https://"
											autocomplete="off"
											spellcheck="false"
											required
										/>
										<p class="description">
											<?php esc_html_e( 'The https address of the dashboard this site should connect to.', 'sumotori-dash-agent' ); ?>
										</p>
									<?php endif; ?>
								</td>
							</tr>
							<tr>
								<th scope="row">
									<label for="sumotori_dash_code"><?php esc_html_e( 'Pairing code', 'sumotori-dash-agent' ); ?></label>
								</th>
								<td>
									<input
										type="text"
										id="sumotori_dash_code"
										name="sumotori_dash_code"
										class="regular-text"
										value=""
										autocomplete="off"
										spellcheck="false"
										required
									/>
									<p class="description">
										<?php esc_html_e( 'Paste the code shown by your dashboard here. No secret has to be copied by hand: the agent retrieves it itself.', 'sumotori-dash-agent' ); ?>
									</p>
								</td>
							</tr>
						</table>
						<?php submit_button( __( 'Pair this site', 'sumotori-dash-agent' ) ); ?>
					</form>
				<?php endif; ?>

			</div>
			<?php
		}

		/**
		 * Traite les soumissions de l'écran de réglages.
		 *
		 * @param string $capability Capacité requise.
		 */
		private function handle_admin_request( $capability ) {
			// phpcs:ignore WordPress.Security.NonceVerification.Missing -- le nonce est vérifié dès que l'action est identifiée, juste en dessous.
			$action = isset( $_POST['sumotori_dash_action'] ) ? sanitize_key( wp_unslash( $_POST['sumotori_dash_action'] ) ) : '';
			if ( '' === $action ) {
				return;
			}

			if ( ! in_array( $action, array( 'pair', 'unpair' ), true ) ) {
				return;
			}

			if ( ! current_user_can( $capability ) ) {
				wp_die( esc_html__( 'Insufficient permissions.', 'sumotori-dash-agent' ) );
			}
			check_admin_referer( self::NONCE_ACTION );

			switch ( $action ) {
				case 'pair':
					$this->handle_pair_action();
					break;

				case 'unpair':
					$this->disconnect();
					$this->notice = array(
						'type'    => 'success',
						'message' => __( 'Site disconnected: no more data is transmitted.', 'sumotori-dash-agent' ),
					);
					break;
			}
		}

		/**
		 * Appairage depuis le formulaire.
		 */
		private function handle_pair_action() {
			// Nonce déjà vérifié par handle_admin_request() avant l'aiguillage.
			// phpcs:disable WordPress.Security.NonceVerification.Missing
			$url  = isset( $_POST['sumotori_dash_url'] ) ? esc_url_raw( wp_unslash( $_POST['sumotori_dash_url'] ) ) : '';
			$code = isset( $_POST['sumotori_dash_code'] ) ? sanitize_text_field( wp_unslash( $_POST['sumotori_dash_code'] ) ) : '';
			// phpcs:enable WordPress.Security.NonceVerification.Missing

			$result = $this->pair( $url, $code );
			if ( is_wp_error( $result ) ) {
				$this->notice = array(
					'type'    => 'error',
					'message' => $result->get_error_message(),
				);

				return;
			}

			$config       = $this->get_config();
			$this->notice = array(
				'type'    => 'success',
				'message' => sprintf(
					/* translators: %s: endpoint URL. */
					__( 'Site paired with the dashboard (%s).', 'sumotori-dash-agent' ),
					$config['endpoint']
				),
			);
		}

		/**
		 * Formate une date selon les réglages du site.
		 *
		 * @param int $timestamp Horodatage Unix.
		 * @return string
		 */
		private function format_date( $timestamp ) {
			$timestamp = absint( $timestamp );
			if ( $timestamp <= 0 ) {
				return '';
			}

			$format = get_option( 'date_format' ) . ' ' . get_option( 'time_format' );

			if ( function_exists( 'wp_date' ) ) {
				return (string) wp_date( $format, $timestamp );
			}

			return (string) date_i18n( $format, $timestamp );
		}

		// ── Événements sortants ──────────────────────────────────────────────

		/**
		 * Rien n'est accroché tant que la liaison est absente ou incomplète : un
		 * site non appairé ne paie qu'une lecture d'option autoloadée.
		 */
		public function register_event_hooks() {
			if ( ! $this->is_connected() ) {
				return;
			}

			add_action( 'user_register', array( $this, 'on_user_register' ), 10, 1 );
			add_action( 'set_user_role', array( $this, 'on_set_user_role' ), 10, 3 );
			add_action( 'wp_login', array( $this, 'on_wp_login' ), 10, 2 );
			add_action( 'activated_plugin', array( $this, 'on_activated_plugin' ), 10, 2 );
			add_action( 'deactivated_plugin', array( $this, 'on_deactivated_plugin' ), 10, 2 );
			add_action( 'upgrader_process_complete', array( $this, 'on_upgrader_process_complete' ), 20, 2 );
			add_action( 'switch_theme', array( $this, 'on_switch_theme' ), 10, 3 );
			add_action( 'deleted_user', array( $this, 'on_deleted_user' ), 10, 3 );

			if ( is_multisite() ) {
				// wp_initialize_site (WP 5.1+) et wpmu_new_blog (historique) peuvent
				// se déclencher tous les deux : announced_blog_ids dédoublonne.
				add_action( 'wp_initialize_site', array( $this, 'on_initialize_site' ), 20, 2 );
				add_action( 'wpmu_new_blog', array( $this, 'on_new_blog' ), 20, 1 );
				add_action( 'grant_super_admin', array( $this, 'on_grant_super_admin' ), 10, 1 );
			}
		}

		/**
		 * Nouvel utilisateur administrateur.
		 *
		 * @param int $user_id Identifiant.
		 */
		public function on_user_register( $user_id ) {
			try {
				$user = $this->get_user( $user_id );
				if ( ! $user || ! $this->user_is_administrator( $user ) ) {
					return;
				}

				$this->send_event(
					'user_register',
					array(
						'userId' => (int) $user->ID,
						'login'  => sanitize_user( (string) $user->user_login, true ),
						'email'  => sanitize_email( (string) $user->user_email ),
						'roles'  => $this->sanitize_string_list( is_array( $user->roles ) ? $user->roles : array() ),
					)
				);
			} catch ( Throwable $throwable ) {
				return;
			}
		}

		/**
		 * Promotion d'un compte au rôle administrateur.
		 *
		 * @param int    $user_id   Identifiant.
		 * @param string $role      Nouveau rôle.
		 * @param array  $old_roles Rôles précédents.
		 */
		public function on_set_user_role( $user_id, $role = '', $old_roles = array() ) {
			try {
				if ( 'administrator' !== sanitize_key( (string) $role ) ) {
					return;
				}

				$user = $this->get_user( $user_id );
				if ( ! $user ) {
					return;
				}

				$this->send_event(
					'set_user_role',
					array(
						'userId'   => (int) $user->ID,
						'login'    => sanitize_user( (string) $user->user_login, true ),
						'email'    => sanitize_email( (string) $user->user_email ),
						'role'     => 'administrator',
						'oldRoles' => $this->sanitize_string_list( $old_roles ),
					)
				);
			} catch ( Throwable $throwable ) {
				return;
			}
		}

		/**
		 * Connexion d'un administrateur.
		 *
		 * @param string       $user_login Identifiant de connexion.
		 * @param WP_User|null $user       Utilisateur.
		 */
		public function on_wp_login( $user_login = '', $user = null ) {
			try {
				if ( ! ( $user instanceof WP_User ) ) {
					$user = get_user_by( 'login', (string) $user_login );
				}
				if ( ! ( $user instanceof WP_User ) || ! $this->user_is_administrator( $user ) ) {
					return;
				}

				$this->send_event(
					'wp_login',
					array(
						'userId' => (int) $user->ID,
						'login'  => sanitize_user( (string) $user->user_login, true ),
						'email'  => sanitize_email( (string) $user->user_email ),
						'ip'     => $this->get_request_ip(),
					)
				);
			} catch ( Throwable $throwable ) {
				return;
			}
		}

		/**
		 * Activation d'une extension.
		 *
		 * @param string $plugin       Fichier de l'extension.
		 * @param bool   $network_wide Activation réseau.
		 */
		public function on_activated_plugin( $plugin = '', $network_wide = false ) {
			try {
				$this->send_event(
					'activated_plugin',
					array(
						'plugin'      => $this->sanitize_plugin_file( $plugin ),
						'networkWide' => (bool) $network_wide,
					)
				);
			} catch ( Throwable $throwable ) {
				return;
			}
		}

		/**
		 * Désactivation d'une extension.
		 *
		 * @param string $plugin       Fichier de l'extension.
		 * @param bool   $network_wide Désactivation réseau.
		 */
		public function on_deactivated_plugin( $plugin = '', $network_wide = false ) {
			try {
				$this->send_event(
					'deactivated_plugin',
					array(
						'plugin'      => $this->sanitize_plugin_file( $plugin ),
						'networkWide' => (bool) $network_wide,
					)
				);
			} catch ( Throwable $throwable ) {
				return;
			}
		}

		/**
		 * Fin d'une mise à jour.
		 *
		 * @param mixed $upgrader_object Objet upgrader.
		 * @param array $hook_extra      Contexte de la mise à jour.
		 */
		public function on_upgrader_process_complete( $upgrader_object = null, $hook_extra = array() ) {
			try {
				unset( $upgrader_object );
				$hook_extra = is_array( $hook_extra ) ? $hook_extra : array();

				$items = array();
				if ( ! empty( $hook_extra['plugins'] ) && is_array( $hook_extra['plugins'] ) ) {
					$items = $hook_extra['plugins'];
				} elseif ( ! empty( $hook_extra['themes'] ) && is_array( $hook_extra['themes'] ) ) {
					$items = $hook_extra['themes'];
				} elseif ( ! empty( $hook_extra['plugin'] ) ) {
					$items = array( $hook_extra['plugin'] );
				} elseif ( ! empty( $hook_extra['theme'] ) ) {
					$items = array( $hook_extra['theme'] );
				}

				$this->send_event(
					'upgrader_process_complete',
					array(
						'type'   => isset( $hook_extra['type'] ) ? sanitize_key( (string) $hook_extra['type'] ) : '',
						'action' => isset( $hook_extra['action'] ) ? sanitize_key( (string) $hook_extra['action'] ) : '',
						'items'  => $this->sanitize_string_list( $items ),
					)
				);
			} catch ( Throwable $throwable ) {
				return;
			}
		}

		/**
		 * Changement de thème.
		 *
		 * @param string        $new_name  Nom du nouveau thème.
		 * @param WP_Theme|null $new_theme Nouveau thème.
		 * @param WP_Theme|null $old_theme Ancien thème.
		 */
		public function on_switch_theme( $new_name = '', $new_theme = null, $old_theme = null ) {
			try {
				$this->send_event(
					'switch_theme',
					array(
						'newName'       => sanitize_text_field( (string) $new_name ),
						'newStylesheet' => ( $new_theme instanceof WP_Theme ) ? sanitize_text_field( (string) $new_theme->get_stylesheet() ) : '',
						'oldStylesheet' => ( $old_theme instanceof WP_Theme ) ? sanitize_text_field( (string) $old_theme->get_stylesheet() ) : '',
					)
				);
			} catch ( Throwable $throwable ) {
				return;
			}
		}

		/**
		 * Suppression d'un compte.
		 *
		 * @param int          $user_id  Identifiant supprimé.
		 * @param int|null     $reassign Identifiant de réattribution.
		 * @param WP_User|null $user     Utilisateur supprimé.
		 */
		public function on_deleted_user( $user_id = 0, $reassign = null, $user = null ) {
			try {
				$this->send_event(
					'deleted_user',
					array(
						'userId'   => absint( $user_id ),
						'login'    => ( $user instanceof WP_User ) ? sanitize_user( (string) $user->user_login, true ) : '',
						'reassign' => ( null === $reassign || '' === $reassign ) ? 0 : absint( $reassign ),
					)
				);
			} catch ( Throwable $throwable ) {
				return;
			}
		}

		/**
		 * Création d'un sous-site (WP 5.1+).
		 *
		 * @param WP_Site|null $new_site Nouveau site.
		 * @param array        $args     Arguments.
		 */
		public function on_initialize_site( $new_site = null, $args = array() ) {
			try {
				unset( $args );
				if ( ! ( $new_site instanceof WP_Site ) ) {
					return;
				}
				$this->announce_new_blog( (int) $new_site->blog_id );
			} catch ( Throwable $throwable ) {
				return;
			}
		}

		/**
		 * Création d'un sous-site (accroche historique).
		 *
		 * @param int $blog_id Identifiant du sous-site.
		 */
		public function on_new_blog( $blog_id = 0 ) {
			try {
				$this->announce_new_blog( absint( $blog_id ) );
			} catch ( Throwable $throwable ) {
				return;
			}
		}

		/**
		 * Émet l'événement de création de sous-site, une seule fois.
		 *
		 * @param int $blog_id Identifiant du sous-site.
		 */
		private function announce_new_blog( $blog_id ) {
			$blog_id = absint( $blog_id );
			if ( $blog_id <= 0 || isset( $this->announced_blog_ids[ $blog_id ] ) ) {
				return;
			}
			$this->announced_blog_ids[ $blog_id ] = true;

			$this->send_event(
				'new_site',
				array(
					'newBlogId'   => $blog_id,
					'newBlogUrl'  => esc_url_raw( (string) get_site_url( $blog_id ) ),
					'newBlogName' => sanitize_text_field( (string) get_blog_option( $blog_id, 'blogname', '' ) ),
				)
			);
		}

		/**
		 * Promotion d'un super administrateur.
		 *
		 * @param int $user_id Identifiant.
		 */
		public function on_grant_super_admin( $user_id = 0 ) {
			try {
				$user = $this->get_user( $user_id );

				$this->send_event(
					'grant_super_admin',
					array(
						'userId' => absint( $user_id ),
						'login'  => ( $user instanceof WP_User ) ? sanitize_user( (string) $user->user_login, true ) : '',
						'email'  => ( $user instanceof WP_User ) ? sanitize_email( (string) $user->user_email ) : '',
					)
				);
			} catch ( Throwable $throwable ) {
				return;
			}
		}

		/**
		 * HMAC-SHA256 sur "<timestamp>.<matière>" — même formule dans les deux
		 * sens (événements sortants et requêtes d'inventaire entrantes).
		 *
		 * @param int|string  $timestamp Horodatage.
		 * @param string      $material  Matière signée.
		 * @param string|null $secret    Secret, celui de la configuration par défaut.
		 * @return string
		 */
		public function sign( $timestamp, $material, $secret = null ) {
			$secret = ( null === $secret ) ? $this->get_secret() : (string) $secret;
			if ( '' === $secret ) {
				return '';
			}

			return hash_hmac( 'sha256', (string) $timestamp . '.' . (string) $material, $secret );
		}

		/**
		 * Envoi « fire and forget » : jamais bloquant, jamais d'exception
		 * remontée à WordPress, jamais de donnée sensible dans le corps.
		 *
		 * @param string $event  Nom de l'événement.
		 * @param array  $detail Détail de l'événement.
		 * @return bool
		 */
		public function send_event( $event, $detail = array() ) {
			try {
				if ( ! $this->is_connected() || ! function_exists( 'wp_remote_post' ) ) {
					return false;
				}

				$event = sanitize_key( (string) $event );
				if ( '' === $event ) {
					return false;
				}

				$detail = is_array( $detail ) ? $detail : array();
				if ( is_multisite() ) {
					$detail['blog_id']  = (int) get_current_blog_id();
					$detail['blog_url'] = esc_url_raw( home_url() );
				}

				$config    = $this->get_config();
				$timestamp = time();
				$body      = wp_json_encode(
					array(
						'site'   => home_url(),
						'event'  => $event,
						'detail' => $detail,
						'at'     => $timestamp,
					)
				);
				if ( ! is_string( $body ) || '' === $body ) {
					return false;
				}

				$signature = $this->sign( $timestamp, $body, $config['secret'] );
				if ( '' === $signature ) {
					return false;
				}

				wp_remote_post(
					$config['endpoint'],
					array(
						'blocking'    => false,
						'timeout'     => self::REQUEST_TIMEOUT,
						'redirection' => 0,
						'sslverify'   => true,
						'headers'     => array(
							'Content-Type'     => 'application/json; charset=utf-8',
							'Accept'           => 'application/json',
							'X-Viz-Site'       => home_url(),
							'X-Viz-Timestamp'  => (string) $timestamp,
							'X-Viz-Signature'  => $signature,
						),
						'body'        => $body,
						'user-agent'  => 'Sumotori-Dash-Agent/' . self::VERSION,
					)
				);

				return true;
			} catch ( Throwable $throwable ) {
				return false;
			}
		}

		// ── Routes REST (lecture seule) ──────────────────────────────────────

		/**
		 * Déclare les routes REST.
		 */
		public function register_rest_routes() {
			register_rest_route(
				self::REST_NAMESPACE,
				self::ROUTE_INVENTORY,
				array(
					array(
						'methods'             => 'GET',
						'permission_callback' => array( $this, 'can_read_inventory' ),
						'callback'            => array( $this, 'rest_get_inventory' ),
						'args'                => array(
							'blog_id' => array(
								'required'          => false,
								'default'           => 0,
								'sanitize_callback' => 'absint',
							),
						),
					),
				)
			);

			register_rest_route(
				self::REST_NAMESPACE,
				self::ROUTE_SITES,
				array(
					array(
						'methods'             => 'GET',
						'permission_callback' => array( $this, 'can_read_sites' ),
						'callback'            => array( $this, 'rest_get_sites' ),
						'args'                => array(),
					),
				)
			);
		}

		/**
		 * Contrôle d'accès de /inventory.
		 *
		 * @param WP_REST_Request $request Requête.
		 * @return true|WP_Error
		 */
		public function can_read_inventory( $request ) {
			return $this->verify_signature( $request, self::ROUTE_INVENTORY );
		}

		/**
		 * Contrôle d'accès de /sites.
		 *
		 * @param WP_REST_Request $request Requête.
		 * @return true|WP_Error
		 */
		public function can_read_sites( $request ) {
			return $this->verify_signature( $request, self::ROUTE_SITES );
		}

		/**
		 * Contrôle HMAC : X-Viz-Signature doit valoir
		 * hash_hmac('sha256', "<X-Viz-Timestamp>.<route>", <secret>), avec une
		 * fenêtre de MAX_TIMESTAMP_SKEW secondes (anti-rejeu) et une comparaison
		 * en temps constant.
		 *
		 * @param WP_REST_Request $request Requête.
		 * @param string          $route   Route signée.
		 * @return true|WP_Error
		 */
		private function verify_signature( $request, $route ) {
			$secret = $this->get_secret();
			if ( '' === $secret ) {
				return $this->forbidden(
					'sumotori_dash_not_configured',
					__( 'Agent not paired.', 'sumotori-dash-agent' )
				);
			}

			$timestamp = '';
			$signature = '';
			if ( $request instanceof WP_REST_Request ) {
				$timestamp = trim( (string) $request->get_header( 'x-viz-timestamp' ) );
				$signature = trim( (string) $request->get_header( 'x-viz-signature' ) );
			}

			if ( '' === $timestamp || '' === $signature ) {
				return $this->forbidden(
					'sumotori_dash_missing_signature',
					__( 'Missing signature.', 'sumotori-dash-agent' )
				);
			}

			if ( ! preg_match( '/^\d{1,20}$/', $timestamp ) ) {
				return $this->forbidden(
					'sumotori_dash_invalid_timestamp',
					__( 'Invalid timestamp.', 'sumotori-dash-agent' )
				);
			}

			if ( abs( time() - (int) $timestamp ) > self::MAX_TIMESTAMP_SKEW ) {
				return $this->forbidden(
					'sumotori_dash_stale_timestamp',
					__( 'Expired timestamp.', 'sumotori-dash-agent' )
				);
			}

			$expected = hash_hmac( 'sha256', $timestamp . '.' . (string) $route, $secret );
			if ( '' === $expected || ! hash_equals( $expected, $signature ) ) {
				return $this->forbidden(
					'sumotori_dash_invalid_signature',
					__( 'Invalid signature.', 'sumotori-dash-agent' )
				);
			}

			return true;
		}

		/**
		 * Construit une erreur 403.
		 *
		 * @param string $code    Code d'erreur.
		 * @param string $message Message.
		 * @return WP_Error
		 */
		private function forbidden( $code, $message ) {
			return new WP_Error(
				sanitize_key( (string) $code ),
				sanitize_text_field( (string) $message ),
				array( 'status' => 403 )
			);
		}

		/**
		 * Inventaire. Lecture seule absolue : aucune écriture d'option, aucune
		 * planification, aucune exécution, aucune inclusion de chemin venant de
		 * la requête, et aucun secret dans la réponse.
		 *
		 * @param WP_REST_Request|null $request Requête.
		 * @return WP_REST_Response|WP_Error
		 */
		public function rest_get_inventory( $request = null ) {
			$requested_blog_id = 0;
			if ( $request instanceof WP_REST_Request ) {
				$requested_blog_id = absint( $request->get_param( 'blog_id' ) );
			}

			$target_blog_id = 0;
			if ( is_multisite() ) {
				$target_blog_id = ( $requested_blog_id > 0 ) ? $requested_blog_id : $this->get_main_blog_id();
				if ( ! $this->blog_exists( $target_blog_id ) ) {
					return new WP_Error(
						'sumotori_dash_unknown_blog',
						__( 'Sub-site not found.', 'sumotori-dash-agent' ),
						array( 'status' => 404 )
					);
				}
			}

			$switched = false;
			if ( is_multisite() && $target_blog_id > 0 && $target_blog_id !== (int) get_current_blog_id() ) {
				switch_to_blog( $target_blog_id );
				$switched = true;
			}

			try {
				$payload = $this->build_site_inventory();
			} finally {
				// Toute sortie de ce bloc restaure le contexte, exception comprise.
				if ( $switched ) {
					restore_current_blog();
				}
			}

			$payload['multisite'] = is_multisite();
			$payload['blog_id']   = is_multisite() ? (int) $target_blog_id : (int) get_current_blog_id();
			$payload['network']   = is_multisite() ? $this->build_network_inventory() : null;

			return new WP_REST_Response( $payload, 200 );
		}

		/**
		 * Liste les sous-sites. Hors multisite, renvoie l'unique site courant.
		 *
		 * @param WP_REST_Request|null $request Requête.
		 * @return WP_REST_Response
		 */
		public function rest_get_sites( $request = null ) {
			unset( $request );

			if ( ! is_multisite() ) {
				return new WP_REST_Response(
					array(
						array(
							'blog_id' => (int) get_current_blog_id(),
							'url'     => esc_url_raw( get_site_url() ),
							'name'    => sanitize_text_field( (string) get_option( 'blogname' ) ),
							'is_main' => true,
						),
					),
					200
				);
			}

			$main_blog_id = $this->get_main_blog_id();
			$sites        = get_sites( array( 'number' => self::MAX_SITES_LISTED ) );
			if ( ! is_array( $sites ) ) {
				$sites = array();
			}

			$list = array();
			foreach ( $sites as $site ) {
				$blog_id = 0;
				if ( $site instanceof WP_Site ) {
					$blog_id = (int) $site->blog_id;
				} elseif ( is_object( $site ) && isset( $site->blog_id ) ) {
					$blog_id = (int) $site->blog_id;
				}
				if ( $blog_id <= 0 ) {
					continue;
				}

				$list[] = array(
					'blog_id' => $blog_id,
					'url'     => esc_url_raw( (string) get_site_url( $blog_id ) ),
					'name'    => sanitize_text_field( (string) get_blog_option( $blog_id, 'blogname', '' ) ),
					'is_main' => ( $blog_id === $main_blog_id ),
				);
			}

			return new WP_REST_Response( $list, 200 );
		}

		/**
		 * Identifiant du site principal.
		 *
		 * @return int
		 */
		private function get_main_blog_id() {
			if ( function_exists( 'get_main_site_id' ) ) {
				return (int) get_main_site_id();
			}
			if ( defined( 'BLOG_ID_CURRENT_SITE' ) ) {
				return (int) BLOG_ID_CURRENT_SITE;
			}

			return 1;
		}

		/**
		 * Le sous-site existe-t-il ?
		 *
		 * @param int $blog_id Identifiant.
		 * @return bool
		 */
		private function blog_exists( $blog_id ) {
			$blog_id = absint( $blog_id );
			if ( $blog_id <= 0 ) {
				return false;
			}
			if ( function_exists( 'get_site' ) ) {
				return ( null !== get_site( $blog_id ) );
			}
			if ( function_exists( 'get_blog_details' ) ) {
				return ( false !== get_blog_details( $blog_id ) );
			}

			return true;
		}

		/**
		 * Inventaire du site couramment sélectionné.
		 *
		 * @return array
		 */
		private function build_site_inventory() {
			return array(
				'core_version'        => $this->get_core_version(),
				'core_update'         => $this->get_core_update(),
				'siteurl'             => esc_url_raw( get_site_url() ),
				'blogname'            => sanitize_text_field( (string) get_option( 'blogname' ) ),
				'php_version'         => PHP_VERSION,
				'plugins'             => $this->get_plugins_inventory(),
				'themes_updates'      => $this->get_themes_updates_count(),
				'admins'              => $this->get_admins_inventory(),
				'updraft'             => $this->get_updraft_inventory(),
				'plugins_auto_update' => $this->get_plugins_auto_update_count(),
				'vizproof'            => $this->get_vizproof_inventory(),
			);
		}

		/**
		 * Bloc VizProof Timeline, renseigné seulement si cette extension est
		 * active sur le site. Tout est déduit de lectures d'options : le jeton
		 * d'API n'est jamais renvoyé, seule sa présence est rapportée sous forme
		 * de booléen.
		 *
		 * @return array|null
		 */
		private function get_vizproof_inventory() {
			if ( ! class_exists( 'VizProof_Timeline_Plugin' ) ) {
				return null;
			}

			$version = defined( 'VizProof_Timeline_Plugin::VERSION' )
				? (string) constant( 'VizProof_Timeline_Plugin::VERSION' )
				: '';

			$options = get_option( 'vizproof_timeline_options', array() );
			if ( ( ! is_array( $options ) || empty( $options ) ) && is_multisite() ) {
				$options = get_site_option( 'vizproof_timeline_network_options', array() );
			}
			if ( ! is_array( $options ) ) {
				$options = array();
			}

			$has_token = ! empty( $options['api_token'] ) || ! empty( $options['api_token_encrypted'] );
			$connected = ! empty( $options['api_base_url'] ) && $has_token && ! empty( $options['site_id'] );

			$pages = array();
			if ( ! empty( $options['selected_wordpress_page_ids'] ) && is_array( $options['selected_wordpress_page_ids'] ) ) {
				$pages = $options['selected_wordpress_page_ids'];
			}

			return array(
				'version'     => sanitize_text_field( $version ),
				'connected'   => (bool) $connected,
				'pages_count' => count( $pages ),
				'last_run'    => $this->get_vizproof_last_run(),
			);
		}

		/**
		 * Dernier scan VizProof terminé, lu dans l'historique local.
		 *
		 * @return array|null
		 */
		private function get_vizproof_last_run() {
			$history = get_option( 'vizproof_timeline_history', array() );
			if ( ! is_array( $history ) || empty( $history ) ) {
				return null;
			}

			foreach ( $history as $entry ) {
				if ( ! is_array( $entry ) ) {
					continue;
				}

				$status = isset( $entry['status'] ) ? sanitize_key( (string) $entry['status'] ) : '';
				if ( in_array( $status, array( 'queued', 'running', 'pending', 'requested' ), true ) ) {
					continue;
				}

				$run_ids = ( ! empty( $entry['runIds'] ) && is_array( $entry['runIds'] ) ) ? array_values( $entry['runIds'] ) : array();
				if ( empty( $run_ids ) ) {
					continue;
				}

				$run_id = sanitize_text_field( (string) $run_ids[0] );

				return array(
					'id'     => ( '' !== $run_id ) ? $run_id : ( isset( $entry['eventId'] ) ? sanitize_text_field( (string) $entry['eventId'] ) : '' ),
					'status' => ( '' !== $status ) ? $status : 'unknown',
					'at'     => isset( $entry['createdAt'] ) ? sanitize_text_field( (string) $entry['createdAt'] ) : '',
				);
			}

			return null;
		}

		/**
		 * Bloc réseau : données globales, indépendantes du sous-site courant.
		 *
		 * @return array
		 */
		private function build_network_inventory() {
			return array(
				'sites_count'     => $this->get_sites_count(),
				'network_plugins' => $this->get_network_plugins(),
				'super_admins'    => $this->get_super_admins_inventory(),
			);
		}

		/**
		 * Nombre de sous-sites.
		 *
		 * @return int
		 */
		private function get_sites_count() {
			$count = get_sites(
				array(
					'count'  => true,
					'number' => 0,
				)
			);
			if ( is_numeric( $count ) ) {
				return (int) $count;
			}
			if ( function_exists( 'get_blog_count' ) ) {
				return (int) get_blog_count();
			}

			return 0;
		}

		/**
		 * Extensions activées sur tout le réseau.
		 *
		 * @return array
		 */
		private function get_network_plugins() {
			$active = get_site_option( 'active_sitewide_plugins', array() );
			if ( ! is_array( $active ) || empty( $active ) ) {
				return array();
			}

			$all_plugins = $this->ensure_plugin_api() ? get_plugins() : array();
			if ( ! is_array( $all_plugins ) ) {
				$all_plugins = array();
			}

			$list = array();
			foreach ( $active as $plugin_file => $activated_at ) {
				$plugin_file = (string) $plugin_file;
				$data        = ( isset( $all_plugins[ $plugin_file ] ) && is_array( $all_plugins[ $plugin_file ] ) )
					? $all_plugins[ $plugin_file ]
					: array();

				$list[] = array(
					'name'         => $this->get_plugin_slug( $plugin_file ),
					'file'         => $this->sanitize_plugin_file( $plugin_file ),
					'version'      => isset( $data['Version'] ) ? sanitize_text_field( (string) $data['Version'] ) : '',
					'activated_at' => absint( $activated_at ),
				);
			}

			return $list;
		}

		/**
		 * Super administrateurs du réseau.
		 *
		 * @return array
		 */
		private function get_super_admins_inventory() {
			if ( ! function_exists( 'get_super_admins' ) ) {
				return array();
			}

			$logins = get_super_admins();
			if ( ! is_array( $logins ) ) {
				return array();
			}

			$list = array();
			foreach ( $logins as $login ) {
				if ( is_array( $login ) || is_object( $login ) ) {
					continue;
				}
				$login = sanitize_user( (string) $login, true );
				if ( '' === $login ) {
					continue;
				}

				$entry = array(
					'login' => $login,
					'id'    => 0,
					'email' => '',
				);
				$user  = function_exists( 'get_user_by' ) ? get_user_by( 'login', $login ) : null;
				if ( $user instanceof WP_User ) {
					$entry['id']    = (int) $user->ID;
					$entry['email'] = sanitize_email( (string) $user->user_email );
				}
				$list[] = $entry;
			}

			return $list;
		}

		/**
		 * Version du cœur.
		 *
		 * @return string
		 */
		private function get_core_version() {
			global $wp_version;

			if ( isset( $wp_version ) && is_string( $wp_version ) && '' !== $wp_version ) {
				return sanitize_text_field( $wp_version );
			}

			return sanitize_text_field( (string) get_bloginfo( 'version' ) );
		}

		/**
		 * Mise à jour du cœur en attente, lue dans le transient `update_core`
		 * que WordPress entretient déjà (aucun appel réseau déclenché ici).
		 *
		 * @return array|null
		 */
		private function get_core_update() {
			if ( ! function_exists( 'get_core_updates' ) ) {
				$update_file = ABSPATH . 'wp-admin/includes/update.php';
				if ( ! file_exists( $update_file ) ) {
					return null;
				}
				require_once $update_file;
			}

			if ( ! function_exists( 'get_core_updates' ) ) {
				return null;
			}

			$updates = get_core_updates( array( 'dismissed' => false ) );
			if ( ! is_array( $updates ) || empty( $updates ) ) {
				return null;
			}

			foreach ( $updates as $update ) {
				if ( ! is_object( $update ) ) {
					continue;
				}

				$response = isset( $update->response ) ? sanitize_key( (string) $update->response ) : '';
				if ( 'upgrade' !== $response ) {
					continue;
				}

				return array(
					'response' => $response,
					'version'  => isset( $update->version ) ? sanitize_text_field( (string) $update->version ) : '',
					'locale'   => isset( $update->locale ) ? sanitize_text_field( (string) $update->locale ) : '',
				);
			}

			return null;
		}

		/**
		 * Charge l'API d'inspection des extensions si besoin.
		 *
		 * @return bool
		 */
		private function ensure_plugin_api() {
			if ( function_exists( 'get_plugins' ) && function_exists( 'is_plugin_active' ) ) {
				return true;
			}

			$plugin_file = ABSPATH . 'wp-admin/includes/plugin.php';
			if ( ! file_exists( $plugin_file ) ) {
				return false;
			}
			require_once $plugin_file;

			return function_exists( 'get_plugins' );
		}

		/**
		 * Inventaire des extensions installées.
		 *
		 * @return array
		 */
		private function get_plugins_inventory() {
			if ( ! $this->ensure_plugin_api() ) {
				return array();
			}

			$all_plugins = get_plugins();
			if ( ! is_array( $all_plugins ) ) {
				return array();
			}

			$update_plugins = get_site_transient( 'update_plugins' );
			$pending        = ( is_object( $update_plugins ) && ! empty( $update_plugins->response ) && is_array( $update_plugins->response ) )
				? $update_plugins->response
				: array();

			$inventory = array();
			foreach ( $all_plugins as $plugin_file => $plugin_data ) {
				$plugin_file = (string) $plugin_file;
				$plugin_data = is_array( $plugin_data ) ? $plugin_data : array();

				$has_update  = isset( $pending[ $plugin_file ] );
				$new_version = '';
				if ( $has_update && is_object( $pending[ $plugin_file ] ) && ! empty( $pending[ $plugin_file ]->new_version ) ) {
					$new_version = sanitize_text_field( (string) $pending[ $plugin_file ]->new_version );
				}

				$inventory[] = array(
					'name'    => $this->get_plugin_slug( $plugin_file ),
					'status'  => $this->get_plugin_status( $plugin_file ),
					'version' => isset( $plugin_data['Version'] ) ? sanitize_text_field( (string) $plugin_data['Version'] ) : '',
					'update'  => (bool) $has_update,
					'to'      => ( '' !== $new_version ) ? $new_version : null,
				);
			}

			return $inventory;
		}

		/**
		 * Slug d'une extension.
		 *
		 * @param string $plugin_file Fichier de l'extension.
		 * @return string
		 */
		private function get_plugin_slug( $plugin_file ) {
			$slug = dirname( (string) $plugin_file );
			if ( '.' === $slug || '' === $slug || '/' === $slug ) {
				$slug = basename( (string) $plugin_file, '.php' );
			}

			return sanitize_text_field( $slug );
		}

		/**
		 * État d'activation d'une extension.
		 *
		 * @param string $plugin_file Fichier de l'extension.
		 * @return string
		 */
		private function get_plugin_status( $plugin_file ) {
			if ( is_multisite() && function_exists( 'is_plugin_active_for_network' ) && is_plugin_active_for_network( $plugin_file ) ) {
				return 'network-active';
			}
			if ( function_exists( 'is_plugin_active' ) && is_plugin_active( $plugin_file ) ) {
				return 'active';
			}

			return 'inactive';
		}

		/**
		 * Nombre de thèmes à mettre à jour.
		 *
		 * @return int
		 */
		private function get_themes_updates_count() {
			$update_themes = get_site_transient( 'update_themes' );
			if ( ! is_object( $update_themes ) || empty( $update_themes->response ) || ! is_array( $update_themes->response ) ) {
				return 0;
			}

			return count( $update_themes->response );
		}

		/**
		 * Comptes administrateurs du site.
		 *
		 * @return array
		 */
		private function get_admins_inventory() {
			if ( ! function_exists( 'get_users' ) ) {
				return array();
			}

			$users = get_users(
				array(
					'role'    => 'administrator',
					'orderby' => 'ID',
					'order'   => 'ASC',
					'number'  => 200,
				)
			);
			if ( ! is_array( $users ) ) {
				return array();
			}

			$admins = array();
			foreach ( $users as $user ) {
				if ( ! ( $user instanceof WP_User ) ) {
					continue;
				}

				$admins[] = array(
					'id'         => (int) $user->ID,
					'login'      => sanitize_user( (string) $user->user_login, true ),
					'email'      => sanitize_email( (string) $user->user_email ),
					'registered' => sanitize_text_field( (string) $user->user_registered ),
				);
			}

			return $admins;
		}

		/**
		 * Planification UpdraftPlus, lue dans ses propres options. Seules les
		 * métadonnées de planification sortent : jamais un identifiant de
		 * destination distante.
		 *
		 * @return array|null
		 */
		private function get_updraft_inventory() {
			if ( ! $this->is_updraftplus_present() ) {
				return null;
			}

			$last_backup    = get_option( 'updraft_last_backup', array() );
			$last_backup_ts = null;
			if ( is_array( $last_backup ) ) {
				if ( ! empty( $last_backup['backup_time'] ) ) {
					$last_backup_ts = absint( $last_backup['backup_time'] );
				} elseif ( ! empty( $last_backup['backup_time_ms'] ) ) {
					$last_backup_ts = (int) round( absint( $last_backup['backup_time_ms'] ) / 1000 );
				}
			}

			return array(
				'interval'       => $this->sanitize_scalar_option( get_option( 'updraft_interval', '' ) ),
				'interval_db'    => $this->sanitize_scalar_option( get_option( 'updraft_interval_database', '' ) ),
				'retain'         => $this->sanitize_scalar_option( get_option( 'updraft_retain', '' ) ),
				'retain_db'      => $this->sanitize_scalar_option( get_option( 'updraft_retain_db', '' ) ),
				'service'        => $this->sanitize_service_option( get_option( 'updraft_service', '' ) ),
				'last_backup_ts' => $last_backup_ts,
				'extrarules'     => $this->sanitize_extra_rules( get_option( 'updraft_retain_extrarules', array() ) ),
			);
		}

		/**
		 * UpdraftPlus est-il présent ?
		 *
		 * @return bool
		 */
		private function is_updraftplus_present() {
			if ( class_exists( 'UpdraftPlus' ) || defined( 'UPDRAFTPLUS_DIR' ) ) {
				return true;
			}

			// UpdraftPlus désactivé mais installé : la planification existe encore.
			return false !== get_option( 'updraft_interval', false );
		}

		/**
		 * Normalise une valeur d'option scalaire.
		 *
		 * @param mixed $value Valeur.
		 * @return string
		 */
		private function sanitize_scalar_option( $value ) {
			if ( is_array( $value ) || is_object( $value ) ) {
				return '';
			}
			if ( is_bool( $value ) ) {
				return $value ? '1' : '0';
			}

			return sanitize_text_field( (string) $value );
		}

		/**
		 * Normalise la liste des destinations de sauvegarde (noms seulement).
		 *
		 * @param mixed $value Valeur.
		 * @return array|string
		 */
		private function sanitize_service_option( $value ) {
			if ( ! is_array( $value ) ) {
				return $this->sanitize_scalar_option( $value );
			}

			$services = array();
			foreach ( $value as $service ) {
				if ( is_array( $service ) || is_object( $service ) ) {
					continue;
				}
				$service = sanitize_text_field( (string) $service );
				if ( '' !== $service ) {
					$services[] = $service;
				}
			}

			return array_values( $services );
		}

		/**
		 * Normalise les règles de rétention supplémentaires.
		 *
		 * @param mixed $rules Valeur.
		 * @return array
		 */
		private function sanitize_extra_rules( $rules ) {
			if ( ! is_array( $rules ) ) {
				return array();
			}

			$clean = array();
			foreach ( $rules as $key => $rule ) {
				$key = sanitize_key( (string) $key );
				if ( '' === $key ) {
					continue;
				}

				if ( is_array( $rule ) ) {
					$entry = array();
					foreach ( $rule as $rule_key => $rule_value ) {
						$rule_key = sanitize_key( (string) $rule_key );
						if ( '' === $rule_key || is_array( $rule_value ) || is_object( $rule_value ) ) {
							continue;
						}
						$entry[ $rule_key ] = $this->sanitize_scalar_option( $rule_value );
					}
					$clean[ $key ] = $entry;
					continue;
				}

				$clean[ $key ] = $this->sanitize_scalar_option( $rule );
			}

			return $clean;
		}

		/**
		 * Nombre d'extensions en mise à jour automatique.
		 *
		 * @return int
		 */
		private function get_plugins_auto_update_count() {
			$auto_update_plugins = get_option( 'auto_update_plugins', array() );
			if ( ! is_array( $auto_update_plugins ) ) {
				return 0;
			}

			return count( $auto_update_plugins );
		}

		// ── Utilitaires ──────────────────────────────────────────────────────

		/**
		 * État de l'agent, sans jamais exposer le secret.
		 *
		 * @return array
		 */
		public function describe_state() {
			$config = $this->get_config();

			return array(
				'ok'              => true,
				'enabled'         => (bool) $config['enabled'],
				'connected'       => (bool) $this->is_connected(),
				'endpoint'        => (string) $config['endpoint'],
				'secret_set'      => ( '' !== (string) $config['secret'] ),
				'paired_at'       => (int) $config['paired_at'],
				'site'            => is_multisite() ? network_site_url() : home_url(),
				'multisite'       => is_multisite(),
				'sites_count'     => is_multisite() ? $this->get_sites_count() : 1,
				'dashboard_url'   => $this->get_configured_dashboard_url(),
				'inventory_route' => esc_url_raw( rest_url( self::REST_NAMESPACE . self::ROUTE_INVENTORY ) ),
				'sites_route'     => esc_url_raw( rest_url( self::REST_NAMESPACE . self::ROUTE_SITES ) ),
				'agent_version'   => self::VERSION,
				'php_version'     => PHP_VERSION,
				'wp_version'      => (string) get_bloginfo( 'version' ),
			);
		}

		/**
		 * Récupère un utilisateur.
		 *
		 * @param int $user_id Identifiant.
		 * @return WP_User|null
		 */
		private function get_user( $user_id ) {
			$user_id = absint( $user_id );
			if ( $user_id <= 0 || ! function_exists( 'get_userdata' ) ) {
				return null;
			}

			$user = get_userdata( $user_id );

			return ( $user instanceof WP_User ) ? $user : null;
		}

		/**
		 * L'utilisateur a-t-il une portée d'administrateur ?
		 *
		 * @param WP_User|null $user Utilisateur.
		 * @return bool
		 */
		private function user_is_administrator( $user ) {
			if ( ! ( $user instanceof WP_User ) ) {
				return false;
			}

			if ( in_array( 'administrator', (array) $user->roles, true ) ) {
				return true;
			}

			// Un super admin réseau a la portée d'un administrateur sans forcément
			// porter le rôle sur le site courant.
			return is_multisite() && function_exists( 'is_super_admin' ) && is_super_admin( (int) $user->ID );
		}

		/**
		 * IP cliente au mieux. REMOTE_ADDR fait foi ; X-Forwarded-For n'est
		 * qu'une indication (en-tête fourni par l'appelant, falsifiable sauf
		 * reverse proxy de confiance). Toute valeur doit passer une validation
		 * d'IP stricte avant de quitter le site.
		 *
		 * @return string
		 */
		private function get_request_ip() {
			$candidates = array();

			// phpcs:disable WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- chaque candidat est validé par FILTER_VALIDATE_IP ci-dessous.
			if ( isset( $_SERVER['HTTP_X_FORWARDED_FOR'] ) && is_string( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
				$forwarded = explode( ',', (string) wp_unslash( $_SERVER['HTTP_X_FORWARDED_FOR'] ) );
				foreach ( $forwarded as $forwarded_candidate ) {
					$candidates[] = trim( (string) $forwarded_candidate );
				}
			}
			if ( isset( $_SERVER['REMOTE_ADDR'] ) && is_string( $_SERVER['REMOTE_ADDR'] ) ) {
				$candidates[] = trim( (string) wp_unslash( $_SERVER['REMOTE_ADDR'] ) );
			}
			// phpcs:enable

			foreach ( $candidates as $candidate ) {
				if ( '' === $candidate ) {
					continue;
				}
				if ( filter_var( $candidate, FILTER_VALIDATE_IP ) ) {
					return $candidate;
				}
			}

			return '';
		}

		/**
		 * Normalise un chemin d'extension.
		 *
		 * @param string $plugin Fichier de l'extension.
		 * @return string
		 */
		private function sanitize_plugin_file( $plugin ) {
			$plugin = sanitize_text_field( (string) $plugin );

			return ltrim( str_replace( '\\', '/', $plugin ), '/' );
		}

		/**
		 * Normalise une liste de chaînes, bornée.
		 *
		 * @param mixed $items Liste.
		 * @return array
		 */
		private function sanitize_string_list( $items ) {
			if ( ! is_array( $items ) ) {
				return array();
			}

			$clean = array();
			foreach ( $items as $item ) {
				if ( is_array( $item ) || is_object( $item ) ) {
					continue;
				}
				$value = sanitize_text_field( (string) $item );
				if ( '' === $value ) {
					continue;
				}
				$clean[] = $value;
				if ( count( $clean ) >= self::MAX_EVENT_ITEMS ) {
					break;
				}
			}

			return array_values( $clean );
		}
	}
}

if ( ! function_exists( 'sumotori_dash_agent' ) ) {
	/**
	 * Accès à l'instance de l'agent.
	 *
	 * @return Sumotori_Dash_Agent
	 */
	function sumotori_dash_agent() {
		return Sumotori_Dash_Agent::instance();
	}
}

sumotori_dash_agent();

if ( defined( 'WP_CLI' ) && WP_CLI && class_exists( 'WP_CLI' ) && ! class_exists( 'Sumotori_Dash_Agent_CLI' ) ) {

	/**
	 * Pilote l'agent de supervision.
	 */
	final class Sumotori_Dash_Agent_CLI {

		/**
		 * Pairs this site with a dashboard using a short code.
		 *
		 * ## OPTIONS
		 *
		 * --code=<code>
		 * : Pairing code supplied by the dashboard.
		 *
		 * [--url=<url>]
		 * : The https URL of the dashboard. Not needed when the
		 * SUMOTORI_DASH_AGENT_URL constant is defined in wp-config.php.
		 *
		 * [--format=<format>]
		 * : json (default) or table.
		 *
		 * @param array $args       Positional arguments.
		 * @param array $assoc_args Associative arguments.
		 */
		public function pair( $args = array(), $assoc_args = array() ) {
			unset( $args );

			$code = isset( $assoc_args['code'] ) ? (string) $assoc_args['code'] : '';
			$url  = isset( $assoc_args['url'] ) ? (string) $assoc_args['url'] : '';

			$result = sumotori_dash_agent()->pair( $url, $code );
			if ( is_wp_error( $result ) ) {
				$this->render(
					array(
						'ok'      => false,
						'message' => $result->get_error_message(),
					),
					$assoc_args
				);
				$this->halt( 1 );

				return;
			}

			$config = sumotori_dash_agent()->get_config();
			$this->render(
				array(
					'ok'       => true,
					'endpoint' => $config['endpoint'],
				),
				$assoc_args
			);
			$this->halt( 0 );
		}

		/**
		 * Connects this site by supplying the endpoint and secret directly.
		 *
		 * ## OPTIONS
		 *
		 * --endpoint=<url>
		 * : The https URL that receives the events.
		 *
		 * --secret=<secret>
		 * : Shared secret used to sign the exchanges.
		 *
		 * [--format=<format>]
		 * : json (default) or table.
		 *
		 * @param array $args       Positional arguments.
		 * @param array $assoc_args Associative arguments.
		 */
		public function connect( $args = array(), $assoc_args = array() ) {
			unset( $args );

			$endpoint = isset( $assoc_args['endpoint'] ) ? (string) $assoc_args['endpoint'] : '';
			$secret   = isset( $assoc_args['secret'] ) ? (string) $assoc_args['secret'] : '';

			$result = sumotori_dash_agent()->connect( $endpoint, $secret );
			if ( is_wp_error( $result ) ) {
				$this->render(
					array(
						'ok'      => false,
						'message' => $result->get_error_message(),
					),
					$assoc_args
				);
				$this->halt( 1 );

				return;
			}

			$this->render( array( 'ok' => true ), $assoc_args );
			$this->halt( 0 );
		}

		/**
		 * Disconnects this site from the dashboard and clears the local link.
		 *
		 * ## OPTIONS
		 *
		 * [--format=<format>]
		 * : json (default) or table.
		 *
		 * @param array $args       Positional arguments.
		 * @param array $assoc_args Associative arguments.
		 */
		public function disconnect( $args = array(), $assoc_args = array() ) {
			unset( $args );

			sumotori_dash_agent()->disconnect();
			$this->render( array( 'ok' => true ), $assoc_args );
			$this->halt( 0 );
		}

		/**
		 * Displays the agent state. The secret is never displayed.
		 *
		 * ## OPTIONS
		 *
		 * [--format=<format>]
		 * : json (default) or table.
		 *
		 * @param array $args       Positional arguments.
		 * @param array $assoc_args Associative arguments.
		 */
		public function status( $args = array(), $assoc_args = array() ) {
			unset( $args );

			$this->render( sumotori_dash_agent()->describe_state(), $assoc_args );
			$this->halt( 0 );
		}

		/**
		 * Renders the payload in the requested format.
		 *
		 * @param array $payload    Payload.
		 * @param array $assoc_args Associative arguments.
		 */
		private function render( $payload, $assoc_args ) {
			$format = isset( $assoc_args['format'] ) ? strtolower( (string) $assoc_args['format'] ) : 'json';

			if ( 'table' !== $format ) {
				WP_CLI::line( (string) wp_json_encode( $payload ) );

				return;
			}

			foreach ( $this->flatten( $payload, '' ) as $row ) {
				WP_CLI::line( $row['field'] . "\t" . $row['value'] );
			}
		}

		/**
		 * Flattens a structure for table display.
		 *
		 * @param array  $payload Payload.
		 * @param string $prefix  Key prefix.
		 * @return array
		 */
		private function flatten( $payload, $prefix ) {
			$rows = array();
			if ( ! is_array( $payload ) ) {
				return $rows;
			}

			foreach ( $payload as $key => $value ) {
				$field = ( '' === $prefix ) ? (string) $key : $prefix . '.' . (string) $key;

				if ( is_array( $value ) ) {
					if ( empty( $value ) ) {
						$rows[] = array(
							'field' => $field,
							'value' => '',
						);
						continue;
					}
					$rows = array_merge( $rows, $this->flatten( $value, $field ) );
					continue;
				}

				if ( null === $value ) {
					$rows[] = array(
						'field' => $field,
						'value' => '',
					);
					continue;
				}
				if ( is_bool( $value ) ) {
					$rows[] = array(
						'field' => $field,
						'value' => $value ? 'true' : 'false',
					);
					continue;
				}

				$rows[] = array(
					'field' => $field,
					'value' => (string) $value,
				);
			}

			return $rows;
		}

		/**
		 * Ends the command with an exit code.
		 *
		 * @param int $exit_code Code de sortie.
		 */
		private function halt( $exit_code ) {
			$exit_code = (int) $exit_code;

			if ( method_exists( 'WP_CLI', 'halt' ) ) {
				WP_CLI::halt( $exit_code );

				return;
			}

			// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- $exit_code is a cast integer used as the process exit status, not printed output.
			exit( $exit_code );
		}
	}

	WP_CLI::add_command( 'dash-agent', 'Sumotori_Dash_Agent_CLI' );
}
