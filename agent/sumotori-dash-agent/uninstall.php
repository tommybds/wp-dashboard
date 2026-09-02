<?php
/**
 * Désinstallation de Sumotori Dash Agent.
 *
 * Supprime toutes les traces du plugin : la liaison au tableau de bord (option
 * de site et option de réseau) et les éventuelles options laissées sur chaque
 * sous-site d'un multisite.
 *
 * @package Sumotori_Dash_Agent
 */

defined( 'WP_UNINSTALL_PLUGIN' ) || exit;

/**
 * Clé d'option unique du plugin.
 */
if ( ! defined( 'SUMOTORI_DASH_AGENT_UNINSTALL_OPTION' ) ) {
	define( 'SUMOTORI_DASH_AGENT_UNINSTALL_OPTION', 'sumotori_dash_agent' );
}

// Option de réseau (multisite) et option de site : delete_site_option() retombe
// sur delete_option() hors multisite.
delete_site_option( SUMOTORI_DASH_AGENT_UNINSTALL_OPTION );
delete_option( SUMOTORI_DASH_AGENT_UNINSTALL_OPTION );

if ( is_multisite() ) {
	$sumotori_dash_agent_site_ids = get_sites(
		array(
			'fields' => 'ids',
			'number' => 0,
		)
	);

	if ( is_array( $sumotori_dash_agent_site_ids ) ) {
		foreach ( $sumotori_dash_agent_site_ids as $sumotori_dash_agent_site_id ) {
			switch_to_blog( (int) $sumotori_dash_agent_site_id );
			delete_option( SUMOTORI_DASH_AGENT_UNINSTALL_OPTION );
			restore_current_blog();
		}
	}

	unset( $sumotori_dash_agent_site_ids, $sumotori_dash_agent_site_id );
}
