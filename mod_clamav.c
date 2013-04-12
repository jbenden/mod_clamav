/*
 * mod_clamav - ClamAV virus scanning module for ProFTPD
 * Copyright (c) 2005-2006, Joseph Benden <joe@thrallingpenguin.com>
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
 */
#include "conf.h"
#include "privs.h"
#include "clamav.h"

#define MOD_CLAMAV_VERSION "mod_clamav/0.5"
module clamav_module;
static int clamd_sockd = 0;
int clamavd_session_start(int sockd);

/**
 * Read the returned information from Clamavd.
 */
int clamavd_result(int sockd, int warnClient, const char *filename) {
	int infected = 0, waserror = 0, ret;
	char buff[4096], *pt;
	FILE *fd = 0;
	
	if((fd=fdopen(dup(sockd), "r")) == NULL) {
		pr_log_pri(PR_LOG_ERR, MOD_CLAMAV_VERSION ": error: Cant open descriptor for reading: %d", errno);
		return -1;
	}
	
	if(fgets(buff, sizeof(buff), fd)) {
		if(strstr(buff, "FOUND\n")) {
			++infected;
			pr_log_pri(PR_LOG_ERR, MOD_CLAMAV_VERSION ": warning: %s", buff);
			/* Delete the upload */
			if(warnClient)
				pr_response_add_err(R_DUP,"%s", buff);
			pt = strrchr(buff, ':');
			*pt = 0;
			if((ret=pr_fsio_unlink(filename))!=0) {
				pr_log_pri(PR_LOG_ERR, MOD_CLAMAV_VERSION ": notice: unlink() failed: %d", errno);
			}
		} else if(strstr(buff, "ERROR\n")) {
			pr_log_pri(PR_LOG_ERR, MOD_CLAMAV_VERSION ": error: %s", buff);
			waserror = 1;
		}
	}
	fclose(fd);
	return infected ? infected : (waserror ? -1 : 0);
}

/**
 * Start a session with Clamavd.
 */
int clamavd_session_start(int sockd) {
	if(write(sockd, "SESSION\n", 8) <= 0) {
		pr_log_pri(PR_LOG_ERR, MOD_CLAMAV_VERSION ": error: Clamd didn't accept the session request.");
		return -1;
	}
	return 0;
}

/**
 * End session.
 */
int clamavd_session_stop(int sockd) {
	if(write(sockd, "END\n", 4) <= 0) {
		pr_log_pri(PR_LOG_ERR, MOD_CLAMAV_VERSION ": error: Clamd didn't accept the session end request.");
		return -1;
	}
	return 0;
}
 
/**
 * Request Clamavd to perform a scan.
 */
int clamavd_scan(int sockd, const char *fullpath, int warnClient, const char *filename) {
	char *scancmd = NULL;
	
	scancmd = calloc(strlen(fullpath) + 20, sizeof(char));
	sprintf(scancmd, "SCAN %s\n", fullpath);
	
	if(write(sockd, scancmd, strlen(scancmd)) <= 0) {
		pr_log_pri(PR_LOG_ERR, MOD_CLAMAV_VERSION ": error: Cant write to the ClamAVd socket: %d", errno);
		free(scancmd);
		return -1;
	}
	
	free(scancmd);
	return clamavd_result(sockd, warnClient, filename);	
} 

/**
 * Connect a socket to ClamAVd.
 */
int clamavd_connect(char *clamhost) {
	struct sockaddr_un server;
	int sockd;

	PRIVS_ROOT;	
	memset((char*)&server, 0, sizeof(server));
	
	/* Local Socket */
	server.sun_family = AF_UNIX;
	strncpy(server.sun_path, clamhost, sizeof(server.sun_path));
	
	if((sockd=socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
		PRIVS_RELINQUISH;
		pr_log_pri(PR_LOG_ERR, MOD_CLAMAV_VERSION ": error: Cannot create socket connection to ClamAVd: %d", errno);
		return -1;
	}
	
	if(connect(sockd, (struct sockaddr *)&server, sizeof(struct sockaddr_un)) < 0) {
		close(sockd);
		PRIVS_RELINQUISH;
		pr_log_pri(PR_LOG_ERR, MOD_CLAMAV_VERSION ": error: Cannot connect to ClamAVd: (%d) %s", errno, clamhost);
		return -1;
	}
	PRIVS_RELINQUISH;

	return sockd;
} 

MODRET clamav_scan(cmd_rec *cmd) {
	config_rec          *c = NULL;
	int                 ret, infected = 0;
	char				fullpath[4096];

	c = find_config(CURRENT_CONF, CONF_PARAM, "ClamAV", FALSE);
	
	if(!c || !*(int*)(c->argv[0]))
		return DECLINED(cmd);
	
	/* hold on to the ClamWarn configuration option */
	c = find_config(CURRENT_CONF, CONF_PARAM, "ClamWarn", TRUE);

	/* Figure out the full path */
	if(session.chroot_path) {
		sstrncpy(fullpath, strcmp(pr_fs_getvwd(), "/") ?
          pdircat(cmd->tmp_pool, session.chroot_path, pr_fs_getvwd(), NULL) :
          session.chroot_path, 4096);
	} else {
		sstrncpy(fullpath, pr_fs_getcwd(), 4096);
	}
	sstrcat(fullpath, "/", 4096 - strlen(fullpath));
	sstrcat(fullpath, cmd->arg, 4096 - strlen(fullpath));

	/* scan it! */
	if((ret=clamavd_scan(clamd_sockd, fullpath, (c ? *(int*)(c->argv[0]) : 0), cmd->arg)) >= 0) {
		infected += ret;
	}
	
	if(infected) {
		return ERROR(cmd);
	}

	if(c && *(int*)(c->argv[0])) 
		pr_response_add(R_226,"File passed ClamAV virus scanner.");

	return DECLINED(cmd);
}

MODRET set_clamav(cmd_rec *cmd) {
	int bool = -1;
	config_rec *c = NULL;

	CHECK_ARGS(cmd, 1);
	CHECK_CONF(cmd, CONF_ROOT|CONF_ANON|CONF_LIMIT|CONF_VIRTUAL|CONF_GLOBAL);
	if((bool = get_boolean(cmd,1)) == -1)
		CONF_ERROR(cmd, "requires a boolean value");

	c = add_config_param(cmd->argv[0], 1, NULL);
	c->argv[0] = pcalloc(c->pool, sizeof(int));
	*((int *) c->argv[0]) = bool;
	c->flags |= CF_MERGEDOWN;
	return HANDLED(cmd);
}

MODRET set_clamavd_local_socket(cmd_rec *cmd) {
	CHECK_ARGS(cmd, 1);
	CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);
	
	add_config_param_str("ClamLocalSocket", 1, cmd->argv[1]);
	return HANDLED(cmd);
}

static void clamav_shutdown(const void *event_data, void *user_data) {
	pr_log_pri(PR_LOG_INFO, MOD_CLAMAV_VERSION ": info: disconnected from Clamd.");
	if(clamd_sockd) {
		clamavd_session_stop(clamd_sockd);
		close(clamd_sockd);
	}
}

static int clamav_sess_init(void) {
	char *local_socket = NULL;

	clamd_sockd = 0;

	local_socket = (char*)get_param_ptr(main_server->conf, "ClamLocalSocket", FALSE);
	if(!local_socket) {
		pr_log_pri(PR_LOG_INFO, MOD_CLAMAV_VERSION ": warning: No local socket was specified.");
		return 0;
	}

    if((clamd_sockd = clamavd_connect(local_socket)) < 0) {
        pr_log_pri(PR_LOG_ERR, MOD_CLAMAV_VERSION ": Cannot connect to ClamAVd.");
        return 0;
    }

	clamavd_session_start(clamd_sockd);

	pr_event_register(&clamav_module, "core.exit", clamav_shutdown, NULL);

	return 0;
}

static conftable clamav_conftab[] = {
	{ "ClamAV", set_clamav, NULL },
	{ "ClamWarn", set_clamav, NULL },
	{ "ClamLocalSocket", set_clamavd_local_socket, NULL },
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
	0x20,				/* api ver */
	"clamav",
	clamav_conftab,
	clamav_cmdtab,
	NULL, 				/* auth function table */
	NULL, 		/* init function */
	clamav_sess_init	/* session init function */
};

