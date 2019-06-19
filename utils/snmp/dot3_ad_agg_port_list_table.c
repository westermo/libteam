/* \\/ Westermo - Teamd snmpsubagent - dot3adAggPortListTable.
 *
 * Copyright (C) 2019 Westermo Network Technologies AB
 *
 * Author(s): Johan Askerin <johan.askein@westermo.se>
 *
 * Description:
 */

#include <teamdctl.h>
#include "teamdagentd.h"

#define MIN_COLUMN 1
#define MAX_COLUMN 1

#define ELEMENT_SIZE(s,e) sizeof(((s*)0)->e)
#define ARRAY_ELEMENTS(arr) ((sizeof(arr)/sizeof(0[arr])) / ((size_t)(!(sizeof(arr) % sizeof(0[arr])))))

typedef struct table_data_t table_data_t;

struct table_data_t
{
	uint32_t		dot3ad_agg_port_list_index;
	u_char 			dot3ad_agg_port_list_ports[4];
	table_data_t	*next;
};

static struct table_data_t *table_head = NULL;

static NetsnmpCacheLoad table_load;
static NetsnmpCacheFree table_free;
static Netsnmp_First_Data_Point table_get_first;
static Netsnmp_Next_Data_Point table_get_next;
static Netsnmp_Node_Handler table_handler;

static nsh_table_index_t idx[] = {
	NSH_TABLE_INDEX (ASN_INTEGER, table_data_t, dot3ad_agg_port_list_index, 0),
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
	NSH_TABLE_ENTRY_RO (ASN_OCTET_STR, 	table_data_t, dot3ad_agg_port_list_ports, 			0),
	};

	return nsh_handle_table (reqinfo, requests, table, ARRAY_ELEMENTS(table));
}


static void table_create_entry (long agg_index,
								u_char *ports)
{
	table_data_t *entry;
	entry = SNMP_MALLOC_TYPEDEF(table_data_t);
	if (!entry)
		return;

	entry->dot3ad_agg_port_list_index = agg_index;
	memcpy (entry->dot3ad_agg_port_list_ports, ports, ELEMENT_SIZE(table_data_t, dot3ad_agg_port_list_ports));
	entry->next = table_head;

	table_head = entry;
}


static int portname_to_num (const char *port_name)
{
	FILE *fp;
	char buf[64];
	snprintf (buf, sizeof(buf), "/var/run/swport/%s/index", port_name);
	int swindex = 0;

	fp = fopen (buf, "r");
	if (fp) {
		fgets (buf, sizeof(buf), fp);
		swindex = strtoul (buf, NULL, 0);
		fclose (fp);
	}
	return swindex;
}

static u_char *set_bit (u_char *ports, const char *port_name)
{
	uint32_t bits = 0;
	uint8_t  num_bit = portname_to_num (port_name);
	bits = bits | 1 << num_bit;
	ports[0] |= (bits >> 24) & 0xFF;
	ports[1] |= (bits >> 16) & 0xFF;
	ports[2] |= (bits >> 8) & 0xFF;
	ports[3] |= bits & 0xFF;
	return ports;
}


static int parse_jason (json_t *dump_json)
{
	json_t *ports_json;
	json_t *iter;
	u_char ports[4] = { 0 };

	uint32_t ifindex;

	if (json_unpack (dump_json, "{s:{s:{s:i}}}", "team_device", "ifinfo", "ifindex", &ifindex))
		return -1;

	if (json_unpack (dump_json, "{s:o}", "ports", &ports_json))
		return -1;

	for (iter = json_object_iter (ports_json); iter; iter = json_object_iter_next (ports_json, iter)) {
		const char *port_name = json_object_iter_key (iter);
		set_bit (ports, port_name);

	}
	table_create_entry (ifindex, ports);
	return 0;
}

static int table_load (netsnmp_cache *cache, void* vmagic)
{
	return parse_status_dir (parse_jason);
}

void snmp_init_mib_dot3adAggListPortTable_table (void)
{
	oid table_oid[] = { oid_dot3adAggPortListTable };
	int index[] = { ASN_INTEGER };

	nsh_register_table ("dot3adAggListPortTable",
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

