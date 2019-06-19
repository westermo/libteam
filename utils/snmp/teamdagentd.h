/* \\/ Westermo - Teamd snmpsubagent - dot3adAggPortListTable.
 *
 * Copyright (C) 2019 Westermo Network Technologies AB
 *
 * Author(s): Johan Askerin <johan.askein@westermo.se>
 *
 * Description:
 */

#ifndef TEAMD_SNMP_AGENT_H
#define TEAMD_SNMP_AGENT_H

#include <stddef.h> /* Needed by libnsh*/
#include <jansson.h>

#include <libnsh/table.h>
#include <libnsh/scalar.h>

#define oid_iso					1						/* 1 */
#define oid_member_body			oid_iso, 2				/* 1.2 */
#define oid_us					oid_member_body, 840	/* 1.2.840 */
#define oid_ieee802dot3			oid_us, 10006			/* 1.2.840.10006 */
#define oid_snmpmibs			oid_ieee802dot3, 300	/* 1.2.840.10006.300 */
#define oid_lagMIB				oid_snmpmibs, 43		/* 1.2.840.10006.300.43 */
#define oid_lagMIBObjects		oid_lagMIB, 1			/* 1.2.840.10006.300.43.1 */
#define oid_dot3adAgg			oid_lagMIBObjects, 1	/* 1.2.840.10006.300.43.1.1 */
#define oid_dot3adAggPort		oid_lagMIBObjects, 2	/* 1.2.840.10006.300.43.1.2 */
#define oid_dot3adAggTable		oid_dot3adAgg, 1		/* 1.2.840.10006.300.43.1.1.1 */
#define oid_dot3adAggPortTable	oid_dot3adAggPort, 1	/* 1.2.840.10006.300.43.1.2.1 */

#define oid_dot3adAggEntry					oid_dot3adAggTable, 1	/* 1.2.840.10006.300.43.1.1.1.1 */
#define oid_dot3adAggIndex					oid_dot3adAggEntry, 1	/* 1.2.840.10006.300.43.1.1.1.1.1 */
#define oid_dot3adAggMACAddress				oid_dot3adAggEntry, 2	/* 1.2.840.10006.300.43.1.1.1.1.2 */
#define oid_dot3adAggActorSystemPriority	oid_dot3adAggEntry, 3	/* 1.2.840.10006.300.43.1.1.1.1.3 */
#define oid_dot3adAggActorSystemID			oid_dot3adAggEntry, 4	/* 1.2.840.10006.300.43.1.1.1.1.4 */
#define oid_dot3adAggAggregateOrIndividual	oid_dot3adAggEntry, 5	/* 1.2.840.10006.300.43.1.1.1.1.5 */
#define oid_dot3adAggActorAdminKey			oid_dot3adAggEntry, 6	/* 1.2.840.10006.300.43.1.1.1.1.6 */
#define oid_dot3adAggActorOperKey			oid_dot3adAggEntry, 7	/* 1.2.840.10006.300.43.1.1.1.1.7 */
#define oid_dot3adAggPartnerSystemID		oid_dot3adAggEntry, 8	/* 1.2.840.10006.300.43.1.1.1.1.8 */
#define oid_dot3adAggPartnerSystemPriority	oid_dot3adAggEntry, 9	/* 1.2.840.10006.300.43.1.1.1.1.9 */
#define oid_dot3adAggPartnerOperKey			oid_dot3adAggEntry, 10	/* 1.2.840.10006.300.43.1.1.1.1.10 */
#define oid_dot3adAggCollectorMaxDelay		oid_dot3adAggEntry, 11	/* 1.2.840.10006.300.43.1.1.1.1.11 */

#define oid_dot3adAggPortListTable 	oid_dot3adAgg, 2				/* 1.2.840.10006.300.43.1.1.2 */
#define oid_dot3adAggPortListEntry 	oid_dot3adAggPortListTable, 1	/* 1.2.840.10006.300.43.1.1.2.1 */

#define oid_dot3adAggPortEntry		oid_dot3adAggPort, 1	/* 1.2.840.10006.300.43.1.2.1.1 */


void snmp_init_mib_dot3adAggTable_table (void);
void snmp_init_mib_dot3adAggListPortTable_table(void);
void snmp_init_mib_dot3adAggtPortTable_table (void);

int parse_status_dir (int (*parse_json) (json_t *json_obj));

#endif /* TEAMD_SNMP_AGENT_H */
