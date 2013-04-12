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

/**
 * Module version and declaration
 */
#define MOD_CLAMAV_VERSION "mod_clamav/0.8"
module clamav_module;

/**
 * Global variables
 */
static int clamd_sockd = 0, is_remote = 0;
static char *clamd_host = NULL;
static int clamd_port = 0, clamd_minsize = 0, clamd_maxsize = -1;

/**
 * Forward declarations
 */
int clamavd_result(int sockd, const char *abs_filename, const char *rel_filename);
int clamavd_session_start(int sockd);
int clamavd_session_stop(int sockd);
int clamavd_connect_check(int sockd);
int clamavd_scan(int sockd, const char *abs_filename, const char *rel_filename);
int clamavd_connect(void);
int clamav_scan(cmd_rec *cmd);

/**
 * Read the returned information from Clamavd.
 */
int clamavd_result(int sockd, const char *abs_filename, const char *rel_filename) {
	int infected = 0, waserror = 0, ret;
	char buff[4096], *pt, *pt1;
	FILE *fd = 0;
	
	if ((fd=fdopen(dup(sockd), "r")) == NULL) {
		pr_log_pri(PR_LOG_ERR, 
				MOD_CLAMAV_VERSION ": error: Cant open descriptor for reading: %d", 
				errno);
		return -1;
	}
	
	if (fgets(buff, sizeof(buff), fd)) {
		if (strstr(buff, "FOUND\n")) {
			++infected;
			
			pt = strrchr(buff, ':');
			if (pt)
				*pt = 0;
			
			/* Delete the infected upload */
			if ((ret=pr_fsio_unlink(rel_filename))!=0) {
				pr_log_pri(PR_LOG_ERR, 
						MOD_CLAMAV_VERSION ": notice: unlink() failed (%d): %s", 
						errno, strerror(errno));
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
			pr_log_pri(PR_LOG_ERR, 
					MOD_CLAMAV_VERSION ": Virus '%s' found in '%s'", pt, abs_filename);
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
	if (sockd != -1 && write(sockd, "SESSION\n", 8) <= 0) {
		pr_log_pri(PR_LOG_ERR, 
				MOD_CLAMAV_VERSION ": error: Clamd didn't accept the session request.");
		return -1;
	}
	return 0;
}

/**
 * End session.
 */
int clamavd_session_stop(int sockd) {
	if (sockd != -1 && write(sockd, "END\n", 4) <= 0) {
		pr_log_pri(PR_LOG_INFO, 
				MOD_CLAMAV_VERSION ": info: Clamd didn't accept the session end request.");
		return -1;
	}
	return 0;
}

/**
 * Test the connection with Clamd.
 */
int clamavd_connect_check(int sockd) {
	FILE *fd = NULL;
	char buff[32];

	if (sockd == -1)
		return 0;
	
	if (write(sockd, "PING\n", 5) <= 0) {
		pr_log_debug(DEBUG4, "Clamd did not accept PING (%d): %s", 
				errno, strerror(errno));
		close(sockd);
		clamd_sockd = -1;
		return 0;
	}
			
	if ((fd = fdopen(dup(sockd), "r")) == NULL) {
		pr_log_debug(DEBUG4, "Clamd can not open descriptor for reading (%d): %s", 
				errno, strerror(errno));
		close(sockd);
		clamd_sockd = -1;
		return 0;
	}

	if (fgets(buff, sizeof(buff), fd)) {
		if (strstr(buff, "PONG")) {
			fclose(fd);
			return 1;
		}
		pr_log_debug(DEBUG4, "Clamd return unknown response to PING: '%s'", buff);
	}
	
	pr_log_debug(DEBUG4, "Clamd did not respond to fgets (%d): %s", errno, strerror(errno));
	fclose(fd);
	close(sockd);
	clamd_sockd = -1;
	return 0;
}

/**
 * Request Clamavd to perform a scan.
 */
int clamavd_scan(int sockd, const char *abs_filename, const char *rel_filename) {
	char *scancmd = NULL;

	scancmd = calloc(strlen(abs_filename) + 20, sizeof(char));
	if (!scancmd) {
		pr_log_pri(PR_LOG_ERR, MOD_CLAMAV_VERSION ": error: Cannot allocate memory.");
		return -1;
	}
	
	sprintf(scancmd, "SCAN %s\n", abs_filename);
	
	if (!clamavd_connect_check(sockd)) {
		if ((clamd_sockd = clamavd_connect()) < 0) {
			pr_log_pri(PR_LOG_ERR, 
					MOD_CLAMAV_VERSION ": error: Cannot re-connect to Clamd (%d): %s", 
					errno, strerror(errno));
			return -1;
		}
		clamavd_session_start(clamd_sockd);
		sockd = clamd_sockd;
		pr_log_debug(DEBUG4, "Successfully reconnected to Clamd.");
	}
	
	if (write(sockd, scancmd, strlen(scancmd)) <= 0) {
		pr_log_pri(PR_LOG_ERR, 
				MOD_CLAMAV_VERSION ": error: Cannot write to the Clamd socket: %d", errno);
		free(scancmd);
		scancmd = NULL;
		return -1;
	}
	
	free(scancmd);
	scancmd = NULL;
	return clamavd_result(sockd, abs_filename, rel_filename);	
} 

/**
 * Connect a socket to ClamAVd.
 */
int clamavd_connect(void) {
	struct sockaddr_un server;
	struct sockaddr_in server2;
	struct hostent *he;
	int sockd;
	
	/**
	 * We will set the global socket to non-connected, just in-case.
	 */
	clamd_sockd = -1;
	
	memset((char*)&server, 0, sizeof(server));
	memset((char*)&server2, 0, sizeof(server2));
	
	PRIVS_ROOT;	
	
	if (is_remote == 0) {
		/* Local Socket */
		server.sun_family = AF_UNIX;
		strncpy(server.sun_path, clamd_host, sizeof(server.sun_path));
		
		if ((sockd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
			PRIVS_RELINQUISH;
			pr_log_pri(PR_LOG_ERR, 
					MOD_CLAMAV_VERSION ": error: Cannot create socket connection to Clamd (%d): %s", 
					errno, strerror(errno));
			return -1;
		}
		
		if (connect(sockd, (struct sockaddr *)&server, sizeof(struct sockaddr_un)) < 0) {
			close(sockd);
			PRIVS_RELINQUISH;
			pr_log_pri(PR_LOG_ERR, 
					MOD_CLAMAV_VERSION ": error: Cannot connect to Clamd (%d): %s", errno, strerror(errno));
			return -1;
		}
	} else {
		/* Remote Socket */
		server2.sin_family = AF_INET;
		server2.sin_port = htons(clamd_port);
		
		if ((sockd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
			PRIVS_RELINQUISH;
			pr_log_pri(PR_LOG_ERR, 
					MOD_CLAMAV_VERSION ": error: Cannot create socket connection Clamd (%d): %s", 
					errno, strerror(errno));
			return -1;
		}
		
		if ((he = gethostbyname(clamd_host)) == 0) {
			close(sockd);
			PRIVS_RELINQUISH;
			pr_log_pri(PR_LOG_ERR, MOD_CLAMAV_VERSION ": error: Cannot resolve hostname '%s'", clamd_host);
			return -1;
		}
		server2.sin_addr = *(struct in_addr *) he->h_addr_list[0];
		
		if (connect(sockd, (struct sockaddr *)&server2, sizeof(struct sockaddr_in)) < 0) {
			close(sockd);
			PRIVS_RELINQUISH;
			pr_log_pri(PR_LOG_ERR, 
					MOD_CLAMAV_VERSION ": error: Cannot connect to Clamd (%d): %s", 
					errno, strerror(errno));
			return -1;
		}
	}
	
	PRIVS_RELINQUISH;
	
	return sockd;
} 

/**
 * Entry point of mod_xfer during an upload
 */
int clamav_scan(cmd_rec *cmd) {
	char absolutepath[4096];
	char *file, *rel_file;
	struct stat st;
	
	if (clamd_sockd < 0)
		return 0;
	
	/**
	 * Figure out the absolute path of our directory
	 */
	if (session.xfer.path && session.xfer.path_hidden) {
		
		/* Hidden Store Condition */
		if (session.chroot_path) {
			sstrncpy(absolutepath, 
					pdircat(cmd->tmp_pool, session.chroot_path, session.xfer.path_hidden, NULL), 
					sizeof(absolutepath) - 1);
			pr_log_debug(DEBUG4, "session.chroot_path is '%s'.", session.chroot_path);
		} else {
			sstrncpy(absolutepath, session.xfer.path_hidden, sizeof(absolutepath) - 1);
		}
		file = absolutepath;
		rel_file = session.xfer.path_hidden;
		
		pr_log_debug(DEBUG4, "session.xfer.path_hidden is '%s'.", session.xfer.path_hidden);
	} else if (session.xfer.path) {
		
		/* Default Condition */
		if (session.chroot_path) {
			sstrncpy(absolutepath, pdircat(cmd->tmp_pool, session.chroot_path, session.xfer.path, NULL), 
					sizeof(absolutepath) - 1);
			pr_log_debug(DEBUG4, "session.chroot_path is '%s'.", session.chroot_path);
		} else {
			sstrncpy(absolutepath, session.xfer.path, sizeof(absolutepath) - 1);
		}
		file = absolutepath;
		rel_file = session.xfer.path;
		
		pr_log_debug(DEBUG4, "session.xfer.path is '%s'.", session.xfer.path);
	} else {
		
		/* Error! */
		pr_log_pri(PR_LOG_ERR, 
				MOD_CLAMAV_VERSION ": error: 'session.xfer.path' does not contain a valid filename.");
		pr_response_add_err(R_500, "'session.xfer.path' does not contain a valid filename.");
		return 1;
	}
	
	if (clamd_minsize > 0 || clamd_maxsize != -1) {
		/* Stat the file to acquire the size */
		if (pr_fsio_stat(rel_file, &st) == -1) {
			pr_log_pri(PR_LOG_ERR, MOD_CLAMAV_VERSION ": error: Can not stat file (%d): %s", errno,
					strerror(errno));
			return 1;
		}
	}
	
	if (clamd_minsize > 0) {
		/* test the minimum size */
		if (st.st_size < clamd_minsize) {
			pr_log_debug(DEBUG4, "File is too small, skipping virus scan. min = %d size = %ld", 
					clamd_minsize, st.st_size);
			return 0;
		}
	}
	
	if (clamd_maxsize != -1) {
		/* test the maximum size */
		if (st.st_size > clamd_maxsize) {
			pr_log_debug(DEBUG4, "File is too large, skipping virus scan. max = %d size = %ld",
					clamd_maxsize, st.st_size);
			return 0;
		}
	}
	
	pr_log_debug(DEBUG4, 
			"Going to virus scan absolute filename = '%s' with relative filename = '%s'.", file, rel_file);
	
	if (clamavd_scan(clamd_sockd, file, rel_file) > 0) {
		return 1;
	}
	
	pr_log_debug(DEBUG4, "No virus detected in filename = '%s'.", file);
	return 0;
}

/**
 * Configuration setter: ClamAV
 */
MODRET set_clamav(cmd_rec *cmd) {
	int bool = -1;
	config_rec *c = NULL;
	
	CHECK_ARGS(cmd, 1);
	CHECK_CONF(cmd, CONF_ROOT|CONF_LIMIT|CONF_VIRTUAL|CONF_GLOBAL|CONF_DIR);
	
	if ((bool = get_boolean(cmd,1)) == -1)
		CONF_ERROR(cmd, "expected Boolean parameter");
	
	c = add_config_param(cmd->argv[0], 1, NULL);
	c->argv[0] = pcalloc(c->pool, sizeof(unsigned char));
	*((unsigned char *) c->argv[0]) = bool;
	c->flags |= CF_MERGEDOWN;
	
	return PR_HANDLED(cmd);
}

/**
 * Configuration setter: ClamLocalSocket
 */

MODRET set_clamavd_local_socket(cmd_rec *cmd) {
	config_rec *c = NULL;
	
	CHECK_ARGS(cmd, 1);
	CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL|CONF_DIR);
	
	c = add_config_param_str("ClamLocalSocket", 1, (void *) cmd->argv[1]);
	c->flags |= CF_MERGEDOWN;
	
	return PR_HANDLED(cmd);
}

/**
 * Configuration setter: ClamServer
 */

MODRET set_clamavd_server(cmd_rec *cmd) {
	config_rec *c = NULL;
	
	CHECK_ARGS(cmd, 1);
	CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL|CONF_DIR);
	
	c = add_config_param_str("ClamServer", 1, (void *) cmd->argv[1]);
	c->flags |= CF_MERGEDOWN;
	
	return PR_HANDLED(cmd);
}

/**
 * Configuration setter: ClamPort
 */

MODRET set_clamavd_port(cmd_rec *cmd) {
	config_rec *c = NULL;
	
	CHECK_ARGS(cmd, 1);
	CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL|CONF_DIR);
	
	c = add_config_param(cmd->argv[0], 1, NULL);
	c->argv[0] = pcalloc(c->pool, sizeof(int));
	*((int *) c->argv[0]) = (int) atol(cmd->argv[1]);
	c->flags |= CF_MERGEDOWN;
	
	return PR_HANDLED(cmd);
}

/**
 * Configuration setter: ClamMinSize
 */

MODRET set_clamavd_minsize(cmd_rec *cmd) {
	config_rec *c = NULL;
	
	CHECK_ARGS(cmd, 1);
	CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL|CONF_DIR);
	
	c = add_config_param(cmd->argv[0], 1, NULL);
	c->argv[0] = pcalloc(c->pool, sizeof(int));
	*((int *) c->argv[0]) = (int) atol(cmd->argv[1]);
	c->flags |= CF_MERGEDOWN;
	
	return PR_HANDLED(cmd);
}

/**
 * Configuration setter: ClamMaxSize
 */

MODRET set_clamavd_maxsize(cmd_rec *cmd) {
	config_rec *c = NULL;
	
	CHECK_ARGS(cmd, 1);
	CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL|CONF_DIR);
	
	c = add_config_param(cmd->argv[0], 1, NULL);
	c->argv[0] = pcalloc(c->pool, sizeof(int));
	*((int *) c->argv[0]) = (int) atol(cmd->argv[1]);
	c->flags |= CF_MERGEDOWN;
	
	return PR_HANDLED(cmd);
}

/**
 * End FTP Session
 */
static void clamav_shutdown(const void *event_data, void *user_data) {
	pr_log_debug(DEBUG4, MOD_CLAMAV_VERSION ": debug: disconnected from Clamd");
	
	if (clamd_sockd != -1) {
		clamavd_session_stop(clamd_sockd);
		close(clamd_sockd);
		clamd_sockd = -1;
	}
}

/**
 * Start FTP Session
 */
static int clamav_sess_init(void) {
	int *port = NULL, *minsize = NULL, *maxsize = NULL;
	config_rec *c = NULL;
	
	is_remote = 0;
	clamd_sockd = -1;
	
	c = find_config(CURRENT_CONF, CONF_PARAM, "ClamAV", TRUE);
	if (!c || !*(int*)(c->argv[0]))
		return 0;
		
	clamd_host = (char *) get_param_ptr(main_server->conf, "ClamLocalSocket", TRUE);
	if (!clamd_host) {
		clamd_host = (char *) get_param_ptr(main_server->conf, "ClamServer", TRUE);
		if (!clamd_host) {
			pr_log_pri(PR_LOG_INFO, 
					MOD_CLAMAV_VERSION ": warning: No local socket or server was specified.");
			return 0;
		}
		is_remote = 1;
		if ((port = (int *) get_param_ptr(main_server->conf, "ClamPort", TRUE)) <= 0)
			clamd_port = 3310;
		else
			clamd_port = *port;
		pr_log_debug(DEBUG4, 
				MOD_CLAMAV_VERSION ": Connecting to remote Clamd host '%s' on port %d", clamd_host, clamd_port);
	} else {
		pr_log_debug(DEBUG4, MOD_CLAMAV_VERSION ": Connecting to local Clamd socket '%s'", clamd_host);
	}
	
	if ((clamd_sockd = clamavd_connect()) < 0) {
		pr_log_pri(PR_LOG_ERR, MOD_CLAMAV_VERSION ": Cannot connect to ClamAVd.");
		return 0;
	}
	
	clamavd_session_start(clamd_sockd);
	
	pr_event_register(&clamav_module, "core.exit", clamav_shutdown, NULL);
	
	if ((minsize = (int *) get_param_ptr(main_server->conf, "ClamMinSize", TRUE)) <= 0)
		clamd_minsize = 0;
	else
		clamd_minsize = *minsize;
	
	if ((maxsize = (int *) get_param_ptr(main_server->conf, "ClamMaxSize", TRUE)) <= 0)
		clamd_maxsize = -1;
	else
		clamd_maxsize = *maxsize;
	
	return 0;
}

static conftable clamav_conftab[] = {
	{ "ClamAV", set_clamav, NULL },
	{ "ClamLocalSocket", set_clamavd_local_socket, NULL },
	{ "ClamServer", set_clamavd_server, NULL },
	{ "ClamPort", set_clamavd_port, NULL },
	{ "ClamMinSize", set_clamavd_minsize, NULL },
	{ "ClamMaxSize", set_clamavd_maxsize, NULL },
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

