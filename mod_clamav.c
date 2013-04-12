/*
 * mod_clamav - ClamAV virus scanning module for ProFTPD
 * Copyright (c) 2005-2008, Joseph Benden <joe@thrallingpenguin.com>
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
 * 
 * Thanks to TJ Saunders for his helpful comments and suggestions!
 *
 * DO NOT EDIT THE LINE BELOW
 */
#include "conf.h"
#include "privs.h"
#include <libgen.h>

#define MOD_CLAMAV_VERSION "mod_clamav/0.7"
module clamav_module;
static int clamd_sockd = 0, is_remote = 0;
static char *clamd_host = NULL;
static int clamd_port = 0;
int clamavd_session_start(int sockd);

/**
 * Read the returned information from Clamavd.
 */
int clamavd_result(int sockd, const char *fullpath, const char *filename) {
	int infected = 0, waserror = 0, ret;
	char buff[4096], *pt, *pt1;
	FILE *fd = 0;
	
	if ((fd=fdopen(dup(sockd), "r")) == NULL) {
		pr_log_pri(PR_LOG_ERR, MOD_CLAMAV_VERSION ": error: Cant open descriptor for reading: %d", errno);
		return -1;
	}
	
	if (fgets(buff, sizeof(buff), fd)) {
		if (strstr(buff, "FOUND\n")) {
			++infected;
			
			pt = strrchr(buff, ':');
			if (pt)
				*pt = 0;
			/* Delete the infected upload */
			if ((ret=pr_fsio_unlink(fullpath))!=0) {
				if ((ret=pr_fsio_unlink(filename))!=0) {
					pr_log_pri(PR_LOG_ERR, MOD_CLAMAV_VERSION ": notice: unlink() failed (%d): %s", errno, strerror(errno));
				}
			}
			/* clean up the response */
			pt += 2;
			pt1 = strstr(pt, " FOUND");
			if (pt1) {
				*pt1 = 0;
			}
			
			/* Inform the client the file contained a virus */
			pr_response_add_err(R_550, "Virus Detected and Removed: %s", pt);
			
			/* Log the fact */
			pr_log_pri(PR_LOG_ERR, MOD_CLAMAV_VERSION ": Virus '%s' found in '%s'", pt, filename);
		} else if (strstr(buff, "ERROR\n")) {
			pr_log_pri(PR_LOG_ERR, MOD_CLAMAV_VERSION ": Clamd Error: %s", buff);
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
	if (write(sockd, "SESSION\n", 8) <= 0) {
		pr_log_pri(PR_LOG_ERR, MOD_CLAMAV_VERSION ": error: Clamd didn't accept the session request.");
		return -1;
	}
	return 0;
}

/**
 * End session.
 */
int clamavd_session_stop(int sockd) {
	if (write(sockd, "END\n", 4) <= 0) {
		pr_log_pri(PR_LOG_INFO, MOD_CLAMAV_VERSION ": info: Clamd didn't accept the session end request.");
		return -1;
	}
	return 0;
}

/**
 * Request Clamavd to perform a scan.
 */
int clamavd_scan(int sockd, const char *fullpath, const char *filename) {
	char *scancmd = NULL;

	scancmd = calloc(strlen(fullpath) + 20, sizeof(char));
	if (!scancmd) {
		pr_log_pri(PR_LOG_ERR, MOD_CLAMAV_VERSION ": error: Cannot allocate memory.");
		return -1;
	}
	
	sprintf(scancmd, "SCAN %s\n", fullpath);
	
	if (write(sockd, scancmd, strlen(scancmd)) <= 0) {
		pr_log_pri(PR_LOG_ERR, MOD_CLAMAV_VERSION ": error: Cannot write to the Clamd socket: %d", errno);
		free(scancmd);
		scancmd = NULL;
		return -1;
	}
	
	free(scancmd);
	scancmd = NULL;
	return clamavd_result(sockd, fullpath, filename);	
} 

/**
 * Connect a socket to ClamAVd.
 */
int clamavd_connect(void) {
	struct sockaddr_un server;
	struct sockaddr_in server2;
	struct hostent *he;
	int sockd;
	
	PRIVS_ROOT;	
	
	memset((char*)&server, 0, sizeof(server));
	memset((char*)&server2, 0, sizeof(server2));
	
	if (is_remote == 0) {
		/* Local Socket */
		server.sun_family = AF_UNIX;
		strncpy(server.sun_path, clamd_host, sizeof(server.sun_path));
		
		if ((sockd=socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
			PRIVS_RELINQUISH;
			pr_log_pri(PR_LOG_ERR, MOD_CLAMAV_VERSION ": error: Cannot create socket connection to Clamd (%d): %s", errno, strerror(errno));
			return -1;
		}
		
		if (connect(sockd, (struct sockaddr *)&server, sizeof(struct sockaddr_un)) < 0) {
			close(sockd);
			PRIVS_RELINQUISH;
			pr_log_pri(PR_LOG_ERR, MOD_CLAMAV_VERSION ": error: Cannot connect to Clamd (%d): %s", errno, strerror(errno));
			return -1;
		}
	} else {
		/* Remote Socket */
		server2.sin_family = AF_INET;
		server2.sin_port = htons(clamd_port);
		
		if ((sockd=socket(AF_INET, SOCK_STREAM, 0)) < 0) {
			PRIVS_RELINQUISH;
			pr_log_pri(PR_LOG_ERR, MOD_CLAMAV_VERSION ": error: Cannot create socket connection Clamd (%d): %s", errno, strerror(errno));
			return -1;
		}
		
		if ((he=gethostbyname(clamd_host)) == 0) {
			close(sockd);
			PRIVS_RELINQUISH;
			pr_log_pri(PR_LOG_ERR, MOD_CLAMAV_VERSION ": error: Cannot resolve hostname '%s'", clamd_host);
			return -1;
		}
		server2.sin_addr = *(struct in_addr *) he->h_addr_list[0];
		
		if (connect(sockd, (struct sockaddr *)&server2, sizeof(struct sockaddr_in)) < 0) {
			close(sockd);
			PRIVS_RELINQUISH;
			pr_log_pri(PR_LOG_ERR, MOD_CLAMAV_VERSION ": error: Cannot connect to Clamd (%d): %s", errno, strerror(errno));
			return -1;
		}
	}
	
	PRIVS_RELINQUISH;
	
	return sockd;
} 

int clamav_scan(cmd_rec *cmd) {
	config_rec *c = NULL;
	char fullpath[4096];
	char virtpath[4096];
	
	c = find_config(CURRENT_CONF, CONF_PARAM, "ClamAV", FALSE);
	
	if (!c || !*(int*)(c->argv[0]))
		return 0;
	
	if (session.chroot_path) {
		sstrncpy(fullpath, strcmp(pr_fs_getvwd(), "/") ?
			pdircat(cmd->tmp_pool, session.chroot_path, pr_fs_getvwd(), NULL) :
			session.chroot_path, 4096);
		sstrncpy(virtpath, strcmp(pr_fs_getvwd(), "/") ?
			pr_fs_getvwd() :
			"", 4096);
	} else {
		sstrncpy(fullpath, pr_fs_getcwd(), 4096);
		sstrncpy(virtpath, pr_fs_getcwd(), 4096);
	}
	if (session.xfer.path && session.xfer.path_hidden) {
		sstrcat(fullpath, "/", 4096 - strlen(fullpath));
		sstrcat(fullpath, basename(session.xfer.path_hidden), 4096 - strlen(fullpath));
		sstrcat(virtpath, "/", 4096 - strlen(virtpath));
		sstrcat(virtpath, basename(session.xfer.path_hidden), 4096 - strlen(virtpath));
	} else {
		sstrcat(fullpath, "/", 4096 - strlen(fullpath));
		sstrcat(fullpath, cmd->arg, 4096 - strlen(fullpath));
		sstrcat(virtpath, "/", 4096 - strlen(virtpath));
		sstrcat(virtpath, cmd->arg, 4096 - strlen(virtpath));
	}
	
	pr_log_debug(DEBUG4, "full filename to scan: %s", fullpath);
	pr_log_debug(DEBUG4, "virtual filename to scan: %s", virtpath);
	
	if (clamavd_scan(clamd_sockd, fullpath, virtpath) > 0) {
		return 1;
	}
	
	return 0;
}

MODRET set_clamav(cmd_rec *cmd) {
	int bool = -1;
	config_rec *c = NULL;
	
	CHECK_ARGS(cmd, 1);
	CHECK_CONF(cmd, CONF_ROOT|CONF_ANON|CONF_LIMIT|CONF_VIRTUAL|CONF_GLOBAL);
	if ((bool = get_boolean(cmd,1)) == -1)
		CONF_ERROR(cmd, "expected Boolean parameter");
	
	c = add_config_param(cmd->argv[0], 1, NULL);
	c->argv[0] = pcalloc(c->pool, sizeof(unsigned char));
	*((unsigned char *) c->argv[0]) = bool;
	c->flags |= CF_MERGEDOWN;
	
	return PR_HANDLED(cmd);
}

MODRET set_clamavd_local_socket(cmd_rec *cmd) {
	config_rec *c = NULL;
	
	CHECK_ARGS(cmd, 1);
	CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);
	
	c = add_config_param_str("ClamLocalSocket", 1, (void *) cmd->argv[1]);
	c->flags |= CF_MERGEDOWN;
	
	return PR_HANDLED(cmd);
}

MODRET set_clamavd_server(cmd_rec *cmd) {
	config_rec *c = NULL;
	
	CHECK_ARGS(cmd, 1);
	CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);
	
	c = add_config_param_str("ClamServer", 1, (void *) cmd->argv[1]);
	c->flags |= CF_MERGEDOWN;
	
	return PR_HANDLED(cmd);
}

MODRET set_clamavd_port(cmd_rec *cmd) {
	config_rec *c = NULL;
	
	CHECK_ARGS(cmd, 1);
	CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);
	
	c = add_config_param(cmd->argv[0], 1, NULL);
	c->argv[0] = pcalloc(c->pool, sizeof(int));
	*((int *) c->argv[0]) = (int) atol(cmd->argv[1]);
	c->flags |= CF_MERGEDOWN;
	
	return PR_HANDLED(cmd);
}

static void clamav_shutdown(const void *event_data, void *user_data) {
	pr_log_debug(DEBUG4, MOD_CLAMAV_VERSION ": debug: disconnected from Clamd");
	if (clamd_sockd) {
		clamavd_session_stop(clamd_sockd);
		close(clamd_sockd);
	}
}

static int clamav_sess_init(void) {
	int *port = NULL;
	config_rec *c = NULL;
	
	is_remote = clamd_sockd = 0;
	
	c = find_config(CURRENT_CONF, CONF_PARAM, "ClamAV", FALSE);
	
	if (!c || !*(int*)(c->argv[0]))
		return 0;
		
	clamd_host = (char *) get_param_ptr(main_server->conf, "ClamLocalSocket", FALSE);
	if (!clamd_host) {
		clamd_host = (char *) get_param_ptr(main_server->conf, "ClamServer", FALSE);
		if (!clamd_host) {
			pr_log_pri(PR_LOG_INFO, MOD_CLAMAV_VERSION ": warning: No local socket or server was specified.");
			return 0;
		}
		is_remote = 1;
		if ((port = (int *) get_param_ptr(main_server->conf, "ClamPort", FALSE)) <= 0)
			clamd_port = 3310;
		else
			clamd_port = *port;
		pr_log_debug(DEBUG4, MOD_CLAMAV_VERSION ": Connecting to remote Clamd host '%s' on port %d", clamd_host, clamd_port);
	} else {
		pr_log_debug(DEBUG4, MOD_CLAMAV_VERSION ": Connecting to local Clamd socket '%s'", clamd_host);
	}
	
	if ((clamd_sockd = clamavd_connect()) < 0) {
		pr_log_pri(PR_LOG_ERR, MOD_CLAMAV_VERSION ": Cannot connect to ClamAVd.");
		return 0;
	}
	
	clamavd_session_start(clamd_sockd);
	
	pr_event_register(&clamav_module, "core.exit", clamav_shutdown, NULL);
	
	return 0;
	}

static conftable clamav_conftab[] = {
	{ "ClamAV", set_clamav, NULL },
	{ "ClamLocalSocket", set_clamavd_local_socket, NULL },
	{ "ClamServer", set_clamavd_server, NULL },
	{ "ClamPort", set_clamavd_port, NULL },
	{ NULL }
};

module clamav_module = {
	NULL,
	NULL,
	0x20,				/* api ver */
	"clamav",
	clamav_conftab,
	NULL,
	NULL, 				/* auth function table */
	NULL, 				/* init function */
	clamav_sess_init	/* session init function */
};

