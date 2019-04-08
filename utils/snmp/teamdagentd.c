/* \\/ Westermo - Teamd snmpsubagent.
 *
 * Copyright (C) 2019 Westermo Network Technologies AB
 *
 * Author(s): Johan Askerin <johan.askein@westermo.se>
 *
 * Description:
 */

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <net-snmp/agent/snmp_vars.h>
#include <sys/types.h>
#include <dirent.h>
#include "../../teamd/teamd.h"
#include "teamdctl.h"
#include "teamdagentd.h"
#include <private/misc.h>
#include <ctype.h>

static int run = 1;

#ifndef FS_SW_VER
#define FS_SW_VER "0.0"
#endif

static const char *program_version = "teamdagentd v" FS_SW_VER;

/**************************************************************************/
static int usage (char *progname)
{
	fprintf (stderr, "\n"
		"------------------------------------------------------------------------------\n"
		"Usage: %s [OPTIONS]\n"
		" -v, --version                      Display version\n"
		" -?, --help                         This help text\n"
		"------------------------------------------------------------------------------\n"
		"\n", progname);

	return 1;
}

int main (int argc, char **argv)
{
	int c;
	struct option long_options[] = {
		{ "version", 0, NULL, 'v' },
		{ "help", 0, NULL, '?' },
		{ NULL, 0, NULL, 0 }
	};

	while ((c = getopt_long (argc, argv, "h?vf:", long_options, NULL)) != EOF)
	{
		switch (c)
		{
			case 'v':
				printf ("%s\n", program_version);
				return 0;
			case ':': /* Missing parameter for option. */
			case '?': /* Unknown option. */
			case 'h':
				default:
				return usage (argv[0]);
		}
	}

	netsnmp_enable_subagent ();
	snmp_disable_log ();
	netsnmp_ds_set_boolean (NETSNMP_DS_LIBRARY_ID,	NETSNMP_DS_LIB_DONT_PERSIST_STATE, TRUE);
	netsnmp_ds_set_boolean (NETSNMP_DS_APPLICATION_ID, NETSNMP_DS_AGENT_NO_CONNECTION_WARNINGS, TRUE);

	snmp_enable_stderrlog ();
	init_agent ("teamdagentd");
	init_snmp ("teamdagentd");

	snmp_init_mib_dot3adAggTable_table ();
	snmp_init_mib_dot3adAggListPortTable_table ();
	snmp_init_mib_dot3adAggtPortTable_table ();

	while (run)
	{
		agent_check_and_process (1);
	}
	return 0;
}

static int __jsonload (json_t **pjson, char *inputstrjson)
{
	json_t *json;
	json_error_t jerror;

	json = json_loads (inputstrjson, JSON_REJECT_DUPLICATES, &jerror);
	if (!json) {
		return -EINVAL;
	}
	*pjson = json;
	return 0;
}

int parse_status_dir (int (*parse_json) (json_t *json_obj))
{
	int err = 0;
	uint32_t ifindex;
	char *ifname;
	DIR * dir;
	struct dirent *dir_ent;
	json_t *dump_json;

	struct teamdctl *tdc;
	tdc = teamdctl_alloc ();
	if (!tdc)
		return -1;

	dir = opendir (TEAMD_RUN_DIR);
	if (dir) {
		while ((dir_ent = readdir (dir)) != NULL) {
			if (dir_ent->d_type == DT_REG) {
				if (strstr (dir_ent->d_name, ".pid")) {
					ifname = strtok (dir_ent->d_name, ".");
					err = ifname2ifindex (&ifindex, ifname);
					if (!err) {
						err = teamdctl_connect (tdc, ifname, NULL, NULL);
						if (!err) {
							char *dump = teamdctl_state_get_raw (tdc);
							err = __jsonload (&dump_json, dump);
								if (!err) {
								err = parse_json (dump_json);
								json_decref (dump_json);
							}
							teamdctl_disconnect (tdc);
						}
					}
				}
			}
		}
		closedir (dir);
	}
	teamdctl_free (tdc);
	return err;
}

