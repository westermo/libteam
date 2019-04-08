/* \\/ Westermo - Teamd snmpsubagent - dot3adAggPortTable.
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
#define MAX_COLUMN 25

#define ELEMENT_SIZE(s,e) sizeof(((s*)0)->e)
#define ARRAY_ELEMENTS(arr) ((sizeof(arr)/sizeof(0[arr])) / ((size_t)(!(sizeof(arr) % sizeof(0[arr])))))

typedef struct table_data_t table_data_t;

struct table_data_t
{
	uint32_t		dot3ad_agg_port_index;
	uint32_t 		dot3ad_agg_port_actor_system_priority;
	uint8_t 		dot3ad_agg_port_actor_system_id[6];
	uint32_t 		dot3ad_agg_port_actor_admin_key;
	uint32_t 		dot3ad_agg_port_actor_oper_key;
	uint32_t 		dot3ad_agg_port_partner_admin_system_priority;
	uint32_t 		dot3ad_agg_port_partner_oper_system_priority;
	uint8_t 		dot3ad_agg_port_partner_admin_system_id[6];
	uint8_t 		dot3ad_agg_port_partner_oper_system_id[6];
	uint32_t 		dot3ad_agg_port_partner_admin_key;
	uint32_t 		dot3ad_agg_port_partner_oper_key;
	uint32_t 		dot3ad_agg_port_selected_agg_id;
	uint32_t 		dot3ad_agg_port_attached_agg_id;
	uint32_t 		dot3ad_agg_port_actor_port;
	uint32_t 		dot3ad_agg_port_actor_port_priority;
	uint32_t 		dot3ad_agg_port_partner_admin_port;
	uint32_t 		dot3ad_agg_port_partner_oper_port;
	uint32_t 		dot3ad_agg_port_partner_admin_port_priority;
	uint32_t 		dot3ad_agg_port_partner_oper_port_priority;
	uint8_t 		dot3ad_agg_port_actor_admin_state[1];
	uint8_t 		dot3ad_agg_port_actor_oper_state[1];
	uint8_t 		dot3ad_agg_port_partner_admin_state[1];
	uint8_t 		dot3ad_agg_port_partner_oper_state[1];
	uint32_t 		dot3ad_agg_port_aggregate_or_individual;
	table_data_t	*next;
};

static struct table_data_t *table_head = NULL;

static NetsnmpCacheLoad table_load;
static NetsnmpCacheFree table_free;
static Netsnmp_First_Data_Point table_get_first;
static Netsnmp_Next_Data_Point table_get_next;
static Netsnmp_Node_Handler table_handler;

static nsh_table_index_t idx[] = {
	NSH_TABLE_INDEX (ASN_INTEGER, table_data_t, dot3ad_agg_port_index, 0),
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
	NSH_TABLE_ENTRY_RO (ASN_INTEGER,	table_data_t, dot3ad_agg_port_index,						0),
	NSH_TABLE_ENTRY_RO (ASN_INTEGER,	table_data_t, dot3ad_agg_port_actor_system_priority,		0),
	NSH_TABLE_ENTRY_RO (ASN_OCTET_STR,	table_data_t, dot3ad_agg_port_actor_system_id,				0),
	NSH_TABLE_ENTRY_NOTSUPPORTED (		table_data_t, dot3ad_agg_port_actor_admin_key				),
	NSH_TABLE_ENTRY_RO (ASN_INTEGER,	table_data_t, dot3ad_agg_port_actor_oper_key,				0),
	NSH_TABLE_ENTRY_NOTSUPPORTED (		table_data_t, dot3ad_agg_port_partner_admin_system_priority	),
	NSH_TABLE_ENTRY_RO (ASN_INTEGER,	table_data_t, dot3ad_agg_port_partner_oper_system_priority,	0),
	NSH_TABLE_ENTRY_NOTSUPPORTED (		table_data_t, dot3ad_agg_port_partner_admin_system_id		),
	NSH_TABLE_ENTRY_RO (ASN_OCTET_STR,	table_data_t, dot3ad_agg_port_partner_oper_system_id,		0),
	NSH_TABLE_ENTRY_NOTSUPPORTED (		table_data_t, dot3ad_agg_port_partner_admin_key				),
	NSH_TABLE_ENTRY_RO (ASN_INTEGER,	table_data_t, dot3ad_agg_port_partner_oper_key,				0),
	NSH_TABLE_ENTRY_RO (ASN_INTEGER,	table_data_t, dot3ad_agg_port_selected_agg_id,				0),
	NSH_TABLE_ENTRY_RO (ASN_INTEGER,	table_data_t, dot3ad_agg_port_attached_agg_id,				0),
	NSH_TABLE_ENTRY_RO (ASN_INTEGER,	table_data_t, dot3ad_agg_port_actor_port,					0),
	NSH_TABLE_ENTRY_RO (ASN_INTEGER,	table_data_t, dot3ad_agg_port_actor_port_priority,			0),
	NSH_TABLE_ENTRY_NOTSUPPORTED (		table_data_t, dot3ad_agg_port_partner_admin_port			),
	NSH_TABLE_ENTRY_RO (ASN_INTEGER,	table_data_t, dot3ad_agg_port_partner_oper_port,			0),
	NSH_TABLE_ENTRY_NOTSUPPORTED (		table_data_t, dot3ad_agg_port_partner_admin_port_priority	),
	NSH_TABLE_ENTRY_RO (ASN_INTEGER,	table_data_t, dot3ad_agg_port_partner_oper_port_priority,	0),
	NSH_TABLE_ENTRY_NOTSUPPORTED (		table_data_t, dot3ad_agg_port_actor_admin_state				),
	NSH_TABLE_ENTRY_RO (ASN_OCTET_STR,	table_data_t, dot3ad_agg_port_actor_oper_state,				0),
	NSH_TABLE_ENTRY_NOTSUPPORTED (		table_data_t, dot3ad_agg_port_partner_admin_state			),
	NSH_TABLE_ENTRY_RO (ASN_OCTET_STR,	table_data_t, dot3ad_agg_port_partner_oper_state,			0),
	NSH_TABLE_ENTRY_RO (ASN_INTEGER,	table_data_t, dot3ad_agg_port_aggregate_or_individual,		0),
	};

	return nsh_handle_table (reqinfo, requests, table, ARRAY_ELEMENTS(table));
}

static void table_create_entry (uint32_t index,
								uint32_t actor_system_priority,
								uint8_t *actor_system_id,
								uint32_t actor_oper_key,
								uint32_t partner_oper_system_priority,
								u_char *partner_oper_system_id,
								uint32_t partner_oper_key,
								uint32_t selected_agg_id,
								uint32_t attached_agg_id,
								uint32_t actor_port,
								uint32_t actor_port_priority,
								uint32_t partner_oper_port,
								uint32_t partner_oper_port_priority,
								uint8_t actor_oper_state,
								uint8_t partner_oper_state,
								uint32_t aggregate_or_individual)
{
	table_data_t *entry;
	entry = SNMP_MALLOC_TYPEDEF(table_data_t);
	if (!entry)

		return;
	entry->dot3ad_agg_port_index = index;
	entry->dot3ad_agg_port_actor_system_priority = actor_system_priority;
	memcpy (entry->dot3ad_agg_port_actor_system_id, actor_system_id,
		ELEMENT_SIZE(table_data_t, dot3ad_agg_port_actor_system_id));
	entry->dot3ad_agg_port_actor_oper_key = actor_oper_key;
	entry->dot3ad_agg_port_partner_oper_system_priority = partner_oper_system_priority;
	memcpy (entry->dot3ad_agg_port_partner_oper_system_id, partner_oper_system_id,
		ELEMENT_SIZE(table_data_t, dot3ad_agg_port_partner_oper_system_id));
	entry->dot3ad_agg_port_partner_oper_key = partner_oper_key;
	entry->dot3ad_agg_port_selected_agg_id = selected_agg_id;
	entry->dot3ad_agg_port_attached_agg_id = attached_agg_id;
	entry->dot3ad_agg_port_actor_port = actor_port;
	entry->dot3ad_agg_port_actor_port_priority = actor_port_priority;
	entry->dot3ad_agg_port_partner_oper_port = partner_oper_port;
	entry->dot3ad_agg_port_partner_oper_port_priority = partner_oper_port_priority;
	entry->dot3ad_agg_port_actor_oper_state[0] = actor_oper_state;
	entry->dot3ad_agg_port_partner_oper_state[0] = partner_oper_state;
	entry->dot3ad_agg_port_aggregate_or_individual = aggregate_or_individual;
	entry->next = table_head;

	table_head = entry;
}

static int parse_jason (json_t *dump_json)
{
	json_t *ports_json;
	json_t *iter;
	json_t *actor_json;
	json_t *aggregator_json;
	json_t *partner_json;
	char *runner_name;
	char *ifname = "0";

	uint32_t ifindex;

	char *actor_system, *partner_system;
	uint32_t actor_key = 0, actor_port = 0, actor_port_prio = 0, actor_state = 0, actor_prio = 0;
	uint32_t partner_key = 0, partner_port = 0, partner_port_prio = 0, partner_state = 0, partner_prio = 0;
	uint32_t selected, id;

	unsigned char actor_mac[6] = { 0 }, partner_mac[6] = { 0 };

	if (json_unpack (dump_json, "{s:{s:s}}", "setup", "runner_name", &runner_name))
			return -1;

	if (json_unpack (dump_json, "{s:o}", "ports", &ports_json))
				return -1;

	for (iter = json_object_iter (ports_json); iter; iter = json_object_iter_next (ports_json, iter)) {

		json_t *port_json = json_object_iter_value (iter);

		if (json_unpack (port_json, "{s:{s:i, s:s}}", "ifinfo",
				"ifindex",	&ifindex,
				"ifname",	&ifname
				))
				return -1;

		if (strncmp (runner_name, "lacp", sizeof("lacp")) == 0) {

			if (json_unpack (port_json,
				"{s:{s:o, s:o, s:o}}",
				"runner",
				"actor_lacpdu_info", &actor_json,
				"aggregator", &aggregator_json,
				"partner_lacpdu_info", &partner_json))
				return -1;

			if (json_unpack (actor_json, "{s:i, s:i, s:i, s:i, s:s, s:i}",
				"key", &actor_key,
				"port", &actor_port,
				"port_priority", &actor_port_prio,
				"state", &actor_state,
				"system", &actor_system,
				"system_priority", &actor_prio))
				return -1;

			ether_aton_r (actor_system, (struct ether_addr *) actor_mac);

			if (json_unpack (aggregator_json, "{s:i, s:b}",
				"id", &id,
				"selected", &selected))
				return -1;


			if (json_unpack (partner_json, "{s:i, s:i, s:i, s:i, s:s, s:i}",
				"key", &partner_key,
				"port", &partner_port,
				"port_priority", &partner_port_prio,
				"state", &partner_state,
				"system", &partner_system,
				"system_priority", &partner_prio))
				return -1;

			ether_aton_r (partner_system, (struct ether_addr *) partner_mac);


		}

		table_create_entry (ifindex,
							actor_prio,
							actor_mac,
							actor_key,
							partner_prio,
							partner_mac,
							partner_key,
							id,
							id,
							actor_port,
							actor_port_prio,
							partner_port,
							partner_port_prio,
							actor_state,
							partner_state,
							1);
	}
	return 0;
}

static int table_load (netsnmp_cache *cache, void* vmagic)
{
	return parse_status_dir (parse_jason);
}

void snmp_init_mib_dot3adAggtPortTable_table (void)
{
	oid table_oid[] = { oid_dot3adAggPortTable };
	int index[] = { ASN_INTEGER };

	nsh_register_table ("dot3adAggPortTable",
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

