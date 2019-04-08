/* \\/ Westermo - Teamd snmpsubagent - dot3adAggTable.
 *
 * Copyright (C) 2019 Westermo Network Technologies AB
 *
 * Author(s): Johan Askerin <johan.askein@westermo.se>
 *
 * Description:
 */

#include <netinet/ether.h>
#include <teamdctl.h>
#include "teamdagentd.h"


#define MIN_COLUMN 1
#define MAX_COLUMN 11

#define ELEMENT_SIZE(s,e) sizeof(((s*)0)->e)
#define ARRAY_ELEMENTS(arr) ((sizeof(arr)/sizeof(0[arr])) / ((size_t)(!(sizeof(arr) % sizeof(0[arr])))))

typedef struct table_data_t table_data_t;

struct table_data_t
{
	uint32_t		dot3ad_agg_index;
	u_char 			dot3ad_agg_mac_address[ETHER_ADDR_LEN];
	uint32_t 		dot3ad_agg_actor_system_priority;
	u_char 			dot3ad_agg_actor_systemID[ETHER_ADDR_LEN];
	u_char 			dot3ad_agg_aggregate_or_individual;
	uint32_t 		dot3ad_agg_actor_admin_key;
	uint32_t 		dot3ad_agg_actor_oper_key;
	u_char 			dot3ad_agg_partner_systemID[ETHER_ADDR_LEN];
	uint32_t 		dot3ad_agg_partner_system_priority;
	uint32_t 		dot3ad_agg_partner_oper_key;
	uint32_t 		dot3ad_agg_collector_max_delay;
	table_data_t	*next;
};

static struct table_data_t *table_head = NULL;

static NetsnmpCacheLoad table_load;
static NetsnmpCacheFree table_free;
static Netsnmp_First_Data_Point table_get_first;
static Netsnmp_Next_Data_Point table_get_next;
static Netsnmp_Node_Handler table_handler;

static nsh_table_index_t idx[] = {
	NSH_TABLE_INDEX (ASN_INTEGER, table_data_t, dot3ad_agg_index, 0),
};

nsh_table_free(table_free, table_data_t, table_head)
nsh_table_get_first(table_get_first, table_get_next, table_head)
nsh_table_get_next(table_get_next, table_data_t, idx, 1)

static int table_handler (netsnmp_mib_handler *handler,
						  netsnmp_handler_registration *reginfo,
						  netsnmp_agent_request_info *reqinfo,
						  netsnmp_request_info *requests)
{
	nsh_table_entry_t table[] = {
	NSH_TABLE_ENTRY_RO (ASN_INTEGER,	table_data_t, dot3ad_agg_index, 					0),
	NSH_TABLE_ENTRY_RO (ASN_OCTET_STR, 	table_data_t, dot3ad_agg_mac_address, 				0),
	NSH_TABLE_ENTRY_RO (ASN_INTEGER, 	table_data_t, dot3ad_agg_actor_system_priority, 	0),
	NSH_TABLE_ENTRY_RO (ASN_OCTET_STR,	table_data_t, dot3ad_agg_actor_systemID, 			0),
	NSH_TABLE_ENTRY_RO (ASN_INTEGER, 	table_data_t, dot3ad_agg_aggregate_or_individual, 	0),
	NSH_TABLE_ENTRY_NOTSUPPORTED (		table_data_t, dot3ad_agg_actor_admin_key     		),
	NSH_TABLE_ENTRY_RO (ASN_INTEGER, 	table_data_t, dot3ad_agg_actor_oper_key, 			0),
	NSH_TABLE_ENTRY_RO (ASN_OCTET_STR, 	table_data_t, dot3ad_agg_partner_systemID, 			0),
	NSH_TABLE_ENTRY_RO (ASN_INTEGER, 	table_data_t, dot3ad_agg_partner_system_priority, 	0),
	NSH_TABLE_ENTRY_RO (ASN_INTEGER, 	table_data_t, dot3ad_agg_partner_oper_key, 			0),
	NSH_TABLE_ENTRY_NOTSUPPORTED (table_data_t, dot3ad_agg_collector_max_delay),
	};

	return nsh_handle_table (reqinfo, requests, table, ARRAY_ELEMENTS(table));
}


static void table_create_entry (long agg_index,
								u_char *mac_address,
								long actor_system_priority,
								u_char *actor_systemID,
								u_char aggregate_or_individual,
								long actor_admin_key,
								long actor_oper_key,
								u_char *partner_systemID,
								long partner_system_priority,
								long partner_oper_key,
								long collector_max_delay)
{
	table_data_t *entry;

	entry = SNMP_MALLOC_TYPEDEF(table_data_t);
	if (!entry)
		return;

	entry->dot3ad_agg_index = agg_index;
	memcpy (entry->dot3ad_agg_mac_address, mac_address, ELEMENT_SIZE(table_data_t, dot3ad_agg_mac_address));
	entry->dot3ad_agg_actor_system_priority = actor_system_priority;
	memcpy (entry->dot3ad_agg_actor_systemID, actor_systemID, ELEMENT_SIZE(table_data_t, dot3ad_agg_actor_systemID));
	entry->dot3ad_agg_aggregate_or_individual = aggregate_or_individual;
	entry->dot3ad_agg_actor_admin_key = actor_admin_key;
	entry->dot3ad_agg_actor_oper_key = actor_oper_key;
	memcpy (entry->dot3ad_agg_partner_systemID, partner_systemID,
		ELEMENT_SIZE(table_data_t, dot3ad_agg_partner_systemID));
	entry->dot3ad_agg_partner_system_priority = partner_system_priority;
	entry->dot3ad_agg_partner_oper_key = partner_oper_key;
	entry->dot3ad_agg_collector_max_delay = collector_max_delay;
	entry->next = table_head;
	table_head = entry;
}

static int parse_jason (json_t *dump_json)
{
	json_t *ports_json;
	json_t *iter;
	json_t *actor_json;
	json_t *partner_json;
	char *runner_name;
	char *dev_addr;

	uint32_t ifindex;

	char *actor_system, *partner_system;
	uint32_t actor_key = 0, actor_port = 0, actor_state = 0, actor_prio = 0;
	uint32_t partner_key = 0, partner_port = 0, partner_state = 0, partner_prio = 0;

	unsigned char mac[6] = { 0 }, actor_mac[6] = { 0 }, partner_mac[6] = { 0 };

	if (json_unpack (dump_json, "{s:{s:{s:s, s:i}}}", "team_device", "ifinfo",
		"dev_addr",	&dev_addr,
		"ifindex",	&ifindex
		))
		return -1;

	ether_aton_r (dev_addr, (struct ether_addr *) mac);

	if (json_unpack (dump_json, "{s:{s:s}}", "setup", "runner_name", &runner_name))
			return -1;

	if (strncmp (runner_name, "lacp", sizeof("lacp")) == 0) {
		if (json_unpack (dump_json, "{s:o}", "ports", &ports_json))
			return -1;

		iter = json_object_iter (ports_json); /* Extract actor info from first port */

		json_t *port_json = json_object_iter_value (iter);

		if (json_unpack (port_json,
			"{s:{s:o, s:o}}",
			"runner",
			"actor_lacpdu_info", &actor_json,
			"partner_lacpdu_info", &partner_json))
			return -1;

		if (json_unpack (actor_json, "{s:i, s:i, s:i, s:s, s:i}",
			"key", &actor_key,
			"port", &actor_port,
			"state", &actor_state,
			"system", &actor_system,
			"system_priority", &actor_prio))
			return -1;

		ether_aton_r (actor_system, (struct ether_addr *) actor_mac);

		if (json_unpack (partner_json, "{s:i, s:i, s:i, s:s, s:i}",
			"key", &partner_key,
			"port", &partner_port,
			"state", &partner_state,
			"system", &partner_system,
			"system_priority", &partner_prio))
			return -1;

		ether_aton_r (partner_system, (struct ether_addr *) partner_mac);
	}
	table_create_entry (ifindex, mac, actor_prio, actor_mac, 1, actor_key, actor_key, partner_mac, partner_prio,
		partner_key, 0);
	return 0;
}

static int table_load (netsnmp_cache *cache, void* vmagic)
{
	return parse_status_dir (parse_jason);
}

void snmp_init_mib_dot3adAggTable_table (void)
{
	oid table_oid[] = { oid_dot3adAggTable };
	int index[] = { ASN_INTEGER };

	nsh_register_table ("dot3adAggTable",
		table_oid,
		OID_LENGTH(table_oid),
		MIN_COLUMN,
		MAX_COLUMN,
		index,
		ARRAY_ELEMENTS(index),
		table_handler,
		table_get_first,
		table_get_next,
		table_load,
		table_free,
		HANDLER_CAN_RWRITE);
}

