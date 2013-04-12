/*
 * mod_clamav - ClamAV virus scanning module for ProFTPD
 * Copyright (c) 2005, Joseph Benden <joe@thrallingpenguin.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307, USA.
 *
 * Furthermore, Joseph Benden gives permission to link this program with
 * ClamAV, and distribute the resulting executable, without including the
 * source code for ClamAV in the source distribution.
 *
 * ClamAV is available at http://www.clamav.net/
 * Non-official SuSE RPM packages for both ClamAV and ProFTPD are available 
 *  at http://www.ispservices.com/
 * 
 * Thanks to TJ Saunders for his helpful comments and suggestions!
 *
 * DO NOT EDIT THE LINE BELOW
 * $Libraries: -lclamav $
 */
#include "conf.h"
#include "clamav.h"

#define MOD_CLAMAV_VERSION "mod_clamav/0.3"

static void clamav_restart_ev(const void *event_data, void *user_data);
static int reload_av_database(void);
module clamav_module;

/* This works through the fork process on Linux. YMMV. If it doesn't work, ie.
 * seg. faults. A simple solution is to move the clamav database loader into
 * the session init handler.  This will definately slow things down, though.
 */
struct cl_node		*clamav_root = NULL;
struct cl_stat		dbstat;
static int     		patcount = 0;

MODRET clamav_scan(cmd_rec *cmd) {
	config_rec *        c = NULL;
	struct cl_limits    limits;
	const char *        virname;
	unsigned long int	size;
	int                 ret;
	mode_t              prevmask;

	c = find_config(CURRENT_CONF, CONF_PARAM, "ClamAV", FALSE);

	if(!c || !*(int*)(c->argv[0]))
		return DECLINED(cmd);
	
	/* pr_log_pri(PR_LOG_INFO, MOD_CLAMAV_VERSION ": info: scanning file: %s",cmd->arg); */
	memset(&limits, 0, sizeof(struct cl_limits));
	limits.maxfiles = 1000;
	limits.maxfilesize = 20 * 1048576;
	limits.maxreclevel = 5;
	limits.maxratio = 200;
	limits.archivememlim = 0;
	/* cl_settempdir("",1); */

	/* clamav insists on a tmp directory for handling archives */
	prevmask = umask(0);
	if(pr_fsio_mkdir("tmp",S_IREAD|S_IWRITE|S_IEXEC)!=0) {
		if(errno != EEXIST)
		pr_log_pri(PR_LOG_ERR, MOD_CLAMAV_VERSION ": notice: mkdir() failed: %d",errno);
	}
	umask(prevmask);

	/* hold on to the ClamWarn configuration option */
	c = find_config(CURRENT_CONF, CONF_PARAM, "ClamWarn", TRUE);

	/* scan it! */
	if((ret=cl_scanfile(cmd->arg,&virname,&size,clamav_root,&limits,CL_ARCHIVE|CL_MAIL|CL_OLE2)) == CL_VIRUS) {
		pr_log_pri(PR_LOG_ERR, MOD_CLAMAV_VERSION ": warning: file '%s' contains the virus '%s'. File was deleted.", cmd->arg, virname);
        if(c && *(int*)(c->argv[0]))
    		pr_response_add_err(R_DUP,"File contains the %s virus.", virname);
		if((ret=pr_fsio_unlink(cmd->arg))!=0) {
			pr_log_pri(PR_LOG_ERR, MOD_CLAMAV_VERSION ": notice: unlink() failed: %d",errno);
		}
		return ERROR(cmd);
	}
	if(ret != CL_CLEAN) {
		pr_log_pri(PR_LOG_ERR, MOD_CLAMAV_VERSION ": error: clamav returned the error message: %s", cl_strerror(ret));
	}
	if(c && *(int*)(c->argv[0])) 
		pr_response_add(R_226,"File passed ClamAV virus scanner containing %d patterns.", patcount);

	return DECLINED(cmd);
}

MODRET set_clamav(cmd_rec *cmd) {
	int bool = -1;
	config_rec *c = NULL;

	CHECK_ARGS(cmd, 1);
	CHECK_CONF(cmd, CONF_ROOT|CONF_ANON|CONF_LIMIT|CONF_VIRTUAL);
	if((bool = get_boolean(cmd,1)) == -1)
		CONF_ERROR(cmd, "requires a boolean value");

	c = add_config_param(cmd->argv[0], 1, NULL);
	c->argv[0] = pcalloc(c->pool, sizeof(int));
	*((int *) c->argv[0]) = bool;
	c->flags |= CF_MERGEDOWN;
	return HANDLED(cmd);
}

static int clamav_init(void) {
	int		ret = 0;

	patcount = 0;
	if((ret=cl_loaddbdir(cl_retdbdir(), &clamav_root, &patcount))) {
		pr_log_pri(PR_LOG_ERR, MOD_CLAMAV_VERSION ": error: cl_loaddbdir(): %s", cl_strerror(ret));
	}
	if((ret=cl_buildtrie(clamav_root))) {
		pr_log_pri(PR_LOG_ERR, MOD_CLAMAV_VERSION ": error: cl_buildtrie(): %s", cl_strerror(ret));
	}
	memset(&dbstat, 0, sizeof(struct cl_stat));
	cl_statinidir(cl_retdbdir(), &dbstat);
	pr_log_pri(PR_LOG_INFO, MOD_CLAMAV_VERSION ": info: loaded %d virus patterns", patcount);
	pr_event_register(&clamav_module, "core.restart", clamav_restart_ev, NULL);
	return 0;
}

static void clamav_restart_ev(const void *event_data, void *user_data) {
	reload_av_database();
}

static int clamav_session_init(void) {
	return reload_av_database();
}

static int reload_av_database(void) {
	int ret;

	/* check for updated virus defs */
	pr_log_pri(PR_LOG_INFO, MOD_CLAMAV_VERSION ": info: checking for newer antivirus defs");
	if(cl_statchkdir(&dbstat) == 1) {
		/* reload virus definitions */
		cl_free(clamav_root);
		clamav_root = NULL;
		patcount = 0;
		if((ret=cl_loaddbdir(cl_retdbdir(), &clamav_root, &patcount))) {
			pr_log_pri(PR_LOG_ERR, MOD_CLAMAV_VERSION ": error: cl_loaddbdir(): %s", cl_strerror(ret));
		}
		if((ret=cl_buildtrie(clamav_root))) {
			pr_log_pri(PR_LOG_ERR, MOD_CLAMAV_VERSION ": error: cl_buildtrie(): %s", cl_strerror(ret));
		}
		pr_log_pri(PR_LOG_INFO, MOD_CLAMAV_VERSION ": info: loaded %d virus patterns", patcount);
		cl_statfree(&dbstat);
		memset(&dbstat, 0, sizeof(struct cl_stat));
		cl_statinidir(cl_retdbdir(), &dbstat);
	}
	return 0;
}

static conftable clamav_conftab[] = {
	{ "ClamAV", set_clamav, NULL },
	{ "ClamWarn", set_clamav, NULL },
	{ NULL }
};

static cmdtable clamav_cmdtab[] = {
	{ POST_CMD, C_STOR, G_NONE, clamav_scan, TRUE, FALSE },
	{ POST_CMD, C_STOU, G_NONE, clamav_scan, TRUE, FALSE },
	{ POST_CMD, C_APPE, G_NONE, clamav_scan, TRUE, FALSE },
	{ 0, NULL }
};

module clamav_module = {
	NULL,
	NULL,
	0x20,			/* api ver */
	"clamav",
	clamav_conftab,
	clamav_cmdtab,
	NULL, 			/* auth function table */
	clamav_init, 		/* init function */
	clamav_session_init	/* session init function */
};

