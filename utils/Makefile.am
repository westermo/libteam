MAINTAINERCLEANFILES = Makefile.in

ACLOCAL_AMFLAGS = -I m4

AM_CFLAGS = -I${top_srcdir}/include

teamnl_CFLAGS= -I${top_srcdir}/include -D_GNU_SOURCE
teamnl_LDADD = $(LIBNL_LIBS) $(top_builddir)/libteam/libteam.la
teamdctl_CFLAGS= $(JANSSON_CFLAGS) -I${top_srcdir}/include -D_GNU_SOURCE
teamdctl_LDADD = $(top_builddir)/libteamdctl/libteamdctl.la $(JANSSON_LIBS)

teamdagentd_CFLAGS= $(JANSSON_CFLAGS) -I${top_srcdir}/include -D_GNU_SOURCE
teamdagentd_LDADD = $(top_builddir)/libteamdctl/libteamdctl.la $(JANSSON_LIBS) -lnetsnmpmibs -lnetsnmpagent -lnetsnmp -lnsh

bin_PROGRAMS=teamnl teamdctl teamdagentd
teamnl_SOURCES=teamnl.c
teamdctl_SOURCES=teamdctl.c

teamdagentd_SOURCES=snmp/teamdagentd.c snmp/dot3_ad_agg_table.c \
	      snmp/dot3_ad_agg_port_list_table.c snmp/dot3_ad_agg_port_table.c

bin_SCRIPTS = bond2team
EXTRA_DIST = bond2team
