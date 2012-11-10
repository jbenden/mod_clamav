/*
 * mod_clamav - ClamAV virus scanning module for ProFTPD
 * Copyright (c) 2005-2008, Joseph Benden <joe@thrallingpenguin.com>
 * Copyright (c) 2012, TJ Saunders <tj@castaglia.org>
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
#define MOD_CLAMAV_VERSION "mod_clamav/0.10b"

module clamav_module;

/**
 * Global variables
 */
static int clamd_sockd = 0, is_remote = 0;
static char *clamd_host = NULL;
static int clamd_port = 0;
static unsigned long clamd_minsize = 0, clamd_maxsize = 0;
static int clam_errno;

/**
 * Local declarations
 */
static unsigned long parse_nbytes(char *nbytes_str, char *units_str);
static int clamavd_connect(void);
static int clamavd_scan(int, const char *, const char *);

/**
 * Read the returned information from Clamavd.
 */
static int clamavd_result(int sockd, const char *abs_filename, const char *rel_filename) {
	int infected = 0, waserror = 0, ret;
	char buff[4096], *pt, *pt1;
	FILE *fd = 0;
	
	if ((fd=fdopen(dup(sockd), "r")) == NULL) {
		pr_log_pri(PR_LOG_ERR, 
				MOD_CLAMAV_VERSION ": error: Cant open descriptor for reading: %d", 
				errno);
		return -1;
	}

	memset(buff, '\0', sizeof(buff));
	if (fgets(buff, sizeof(buff)-1, fd)) {
		if (strstr(buff, "FOUND\n")) {
                        const char *proto;

			++infected;
		
			/* Advance past the <id> portion of the response,
			 * and the path name, and the colon and space that
			 * follow the path name.
			 */	
			pt = strchr(buff, ':');
			pt++;
			pt += strlen(abs_filename);
			pt += 3;

			pt1 = strchr(pt, '(');
			if (pt1 != NULL) {
				*pt1 = '\0';
			}

			/* Delete the infected upload */
			if ((ret=pr_fsio_unlink(rel_filename))!=0) {
				pr_log_pri(PR_LOG_ERR, 
						MOD_CLAMAV_VERSION ": notice: unlink() failed (%d): %s", 
						errno, strerror(errno));
			}

                        /* Generate a custom event for any listeners (e.g.
                         * mod_ban) which might be listening.  Pass in the
                         * string containing the virus information.
                         */
                        pr_event_generate("mod_clamav.virus-found", pt);

			/* Inform the client the file contained a virus (only
                         * for FTP/FTPS connections).
                         */
                        proto = pr_session_get_protocol(0);
                        if (strncmp(proto, "ftp", 4) == 0 ||
                            strncmp(proto, "ftps", 5) == 0) {
                          pr_response_add_err(R_550, "Virus Detected and Removed: %s", pt);
                        }
			
			/* Log the fact */
			pr_log_pri(PR_LOG_ERR, 
					MOD_CLAMAV_VERSION ": Virus '%s' found in '%s'", pt, abs_filename);
		} else if (strstr(buff, "ERROR\n") != NULL ||
			   strstr(buff, "UNKNOWN COMMAND") != NULL) {
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
static int clamavd_session_start(int sockd) {
	if (sockd != -1 && write(sockd, "nIDSESSION\n", 11) <= 0) {
		pr_log_pri(PR_LOG_ERR, 
				MOD_CLAMAV_VERSION ": error: Clamd didn't accept the session request.");
		return -1;
	}
	return 0;
}

/**
 * End session.
 */
static int clamavd_session_stop(int sockd) {
	if (sockd != -1 && write(sockd, "nEND\n", 5) <= 0) {
		pr_log_pri(PR_LOG_INFO, 
				MOD_CLAMAV_VERSION ": info: Clamd didn't accept the session end request.");
		return -1;
	}
	return 0;
}

/**
 * Test the connection with Clamd.
 */
static int clamavd_connect_check(int sockd) {
	FILE *fd = NULL;
	char buff[32];

	if (sockd == -1)
		return 0;
	
	if (write(sockd, "PING\n", 5) <= 0) {
		pr_log_debug(DEBUG4, MOD_CLAMAV_VERSION
			": Clamd did not accept PING (%d): %s", errno, strerror(errno));
		close(sockd);
		clamd_sockd = -1;
		clam_errno = errno;
		return 0;
	}
			
	if ((fd = fdopen(dup(sockd), "r")) == NULL) {
		pr_log_debug(DEBUG4, MOD_CLAMAV_VERSION ": Clamd can not open descriptor for reading (%d): %s", 
				errno, strerror(errno));
		close(sockd);
		clamd_sockd = -1;
		clam_errno = errno;
		return 0;
	}

	if (fgets(buff, sizeof(buff), fd)) {
		if (strstr(buff, "PONG")) {
			fclose(fd);
			return 1;
		}
		pr_log_debug(DEBUG4, MOD_CLAMAV_VERSION ": Clamd return unknown response to PING: '%s'", buff);
	}
	
	pr_log_debug(DEBUG4, MOD_CLAMAV_VERSION ": Clamd did not respond to fgets (%d): %s", errno, strerror(errno));
	fclose(fd);
	close(sockd);
	clamd_sockd = -1;
	clam_errno = errno;
	return 0;
}

/**
 * Request Clamavd to perform a scan.
 */
static int clamavd_scan(int sockd, const char *abs_filename, const char *rel_filename) {
	char *scancmd = NULL;

	scancmd = calloc(strlen(abs_filename) + 20, sizeof(char));
	if (!scancmd) {
		pr_log_pri(PR_LOG_ERR, MOD_CLAMAV_VERSION ": error: Cannot allocate memory.");
		return -1;
	}
	
	sprintf(scancmd, "nSCAN %s\n", abs_filename);
	
	if (!clamavd_connect_check(sockd)) {
		if ((clamd_sockd = clamavd_connect()) < 0) {
			pr_log_pri(PR_LOG_ERR, 
					MOD_CLAMAV_VERSION ": error: Cannot re-connect to Clamd (%d): %s", 
					errno, strerror(errno));
			free(scancmd);
			scancmd = NULL;
			clam_errno = errno;
			return -1;
		}
		clamavd_session_start(clamd_sockd);
		sockd = clamd_sockd;
		pr_log_debug(DEBUG4, MOD_CLAMAV_VERSION ": Successfully reconnected to Clamd");
		clam_errno = 0;
	}

	if (write(sockd, scancmd, strlen(scancmd)) <= 0) {
		pr_log_pri(PR_LOG_ERR, 
				MOD_CLAMAV_VERSION ": error: Cannot write to the Clamd socket: %d", errno);
		free(scancmd);
		scancmd = NULL;
		clam_errno = errno;
		return -1;
	}
	
	free(scancmd);
	scancmd = NULL;
	return clamavd_result(sockd, abs_filename, rel_filename);	
} 

/**
 * Connect a socket to ClamAVd.
 */
static int clamavd_connect(void) {
	struct sockaddr_un server;
	struct sockaddr_in server2;
	struct hostent *he;
	int sockd, *port;
	
	/**
	 * We will set the global socket to non-connected, just in-case.
	 */
	clamd_sockd = -1;
	
	memset((char*)&server, 0, sizeof(server));
	memset((char*)&server2, 0, sizeof(server2));
	
	clamd_host = (char *) get_param_ptr(CURRENT_CONF, "ClamLocalSocket", TRUE);
	if (!clamd_host) {
		clamd_host = (char *) get_param_ptr(CURRENT_CONF, "ClamServer", TRUE);
		if (!clamd_host) {
			pr_log_pri(PR_LOG_INFO, 
					MOD_CLAMAV_VERSION ": warning: No local socket or server was specified.");
			return -1;
		}
		is_remote = 1;
		if ((port = (int *) get_param_ptr(CURRENT_CONF, "ClamPort", TRUE)) <= 0)
			clamd_port = 3310;
		else
			clamd_port = *port;
		pr_log_debug(DEBUG4, 
				MOD_CLAMAV_VERSION ": Connecting to remote Clamd host '%s' on port %d", clamd_host, clamd_port);
	} else {
		pr_log_debug(DEBUG4, MOD_CLAMAV_VERSION ": Connecting to local Clamd socket '%s'", clamd_host);
	}
	
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
			clam_errno = errno;
			return -1;
		}
		
		if (connect(sockd, (struct sockaddr *)&server, sizeof(struct sockaddr_un)) < 0) {
			close(sockd);
			PRIVS_RELINQUISH;
			pr_log_pri(PR_LOG_ERR, 
					MOD_CLAMAV_VERSION ": error: Cannot connect to Clamd (%d): %s", errno, strerror(errno));
			clam_errno = errno;
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
			clam_errno = errno;
			return -1;
		}
		
		if ((he = gethostbyname(clamd_host)) == 0) {
			close(sockd);
			PRIVS_RELINQUISH;
			pr_log_pri(PR_LOG_ERR, MOD_CLAMAV_VERSION ": error: Cannot resolve hostname '%s'", clamd_host);
			clam_errno = errno;
			return -1;
		}
		server2.sin_addr = *(struct in_addr *) he->h_addr_list[0];
		
		if (connect(sockd, (struct sockaddr *)&server2, sizeof(struct sockaddr_in)) < 0) {
			close(sockd);
			PRIVS_RELINQUISH;
			pr_log_pri(PR_LOG_ERR, 
					MOD_CLAMAV_VERSION ": error: Cannot connect to Clamd (%d): %s", 
					errno, strerror(errno));
			clam_errno = errno;
			return -1;
		}
	}
	
	PRIVS_RELINQUISH;
	
	clam_errno = 0;
	
	return sockd;
} 

static int clamav_fsio_close(pr_fh_t *fh, int fd) {
	char *abs_path, *rel_path;
	struct stat st;
	int do_scan = FALSE;
	config_rec *c = NULL;
	unsigned long *minsize, *maxsize;	

	/* We're only interested in STOR, APPE, and maybe STOU commands. */
	if (session.curr_cmd) {
	  if (strcmp(session.curr_cmd, C_STOR) == 0 ||
 	      strcmp(session.curr_cmd, C_APPE) == 0 ||
	      strcmp(session.curr_cmd, C_STOU) == 0) {
		do_scan = TRUE;
	  }
	}

	if (!do_scan) {
		return close(fd);
	}

	/* Make sure the data is written to disk, so that the fstat(2) picks
	 * up the size properly.
	 */
	if (fsync(fd) < 0) {
		return -1;
	}

	pr_fs_clear_cache();
	if (pr_fsio_fstat(fh, &st) < 0) {
		return -1;
	}

	if (close(fd) < 0) {
		return -1;
	}

	c = find_config(CURRENT_CONF, CONF_PARAM, "ClamAV", FALSE);
	if (!c || !*(int*)(c->argv[0]))
		return 0;

	/**
	 * Figure out the absolute path of our directory
	 */
		
	if (session.chroot_path) {
		abs_path = pdircat(fh->fh_pool, session.chroot_path, fh->fh_path, NULL);
	} else {
		abs_path = pstrdup(fh->fh_pool, fh->fh_path);
	}

	rel_path = pstrdup(fh->fh_pool, fh->fh_path);
		
	pr_log_debug(DEBUG4, MOD_CLAMAV_VERSION ": absolute path is '%s', relative path is '%s'", abs_path, rel_path);

	/**
	 * Handle min/max settings
	 */
	if ((minsize = (unsigned long *) get_param_ptr(CURRENT_CONF, "ClamMinSize", TRUE)) == 0UL)
		clamd_minsize = 0;
	else
		clamd_minsize = *minsize;
	
	if ((maxsize = (unsigned long *) get_param_ptr(CURRENT_CONF, "ClamMaxSize", TRUE)) == 0UL)
		clamd_maxsize = 0;
	else
		clamd_maxsize = *maxsize;
	
	if (clamd_minsize > 0 || clamd_maxsize > 0) {
		/* Stat the file to acquire the size */
		pr_fs_clear_cache();
		if (pr_fsio_fstat(fh, &st) == -1) {
			pr_log_pri(PR_LOG_ERR, MOD_CLAMAV_VERSION ": error: Can not stat file (%d): %s", errno,
					strerror(errno));
			return -1;
		}
		pr_log_debug(DEBUG4, MOD_CLAMAV_VERSION ": ClamMinSize=%lu ClamMaxSize=%lu Filesize=%" PR_LU, clamd_minsize, clamd_maxsize, (pr_off_t) st.st_size);
	}
	
	if (clamd_minsize > 0) {
		/* test the minimum size */
		if (st.st_size < clamd_minsize) {
			pr_log_debug(DEBUG4, MOD_CLAMAV_VERSION ": File is too small, skipping virus scan. min = %lu size = %" PR_LU, 
					clamd_minsize, (pr_off_t) st.st_size);
			return 0;
		}
	}
	
	if (clamd_maxsize > 0) {
		/* test the maximum size */
		if (st.st_size > clamd_maxsize) {
			pr_log_debug(DEBUG4, MOD_CLAMAV_VERSION ": File is too large, skipping virus scan. max = %lu size = %" PR_LU,
					clamd_maxsize, (pr_off_t) st.st_size);
			return 0;
		}
	}
	
	pr_log_debug(DEBUG4, MOD_CLAMAV_VERSION
			": Going to virus scan absolute filename = '%s' with relative filename = '%s'.", abs_path, rel_path);
	
	clam_errno = 0;
	if (clamavd_scan(clamd_sockd, abs_path, rel_path) > 0) {
		errno = EPERM;
		return -1;
	}
	
	if (clam_errno == 0)
		pr_log_debug(DEBUG4, MOD_CLAMAV_VERSION ": No virus detected in filename = '%s'.", abs_path);
	else
		pr_log_debug(DEBUG4, MOD_CLAMAV_VERSION ": Skipped virus scan due to errno = %d", clam_errno);
	
	return 0;
}

/**
 * Parse string size description and return value.
 */
static unsigned long parse_nbytes(char *nbytes_str, char *units_str) {
	long res;
	unsigned long nbytes;
	char *endp = NULL;
	float units_factor = 0.0;

	/* clear any previous local errors */
	clam_errno = 0;

	/* first, check the given units to determine the correct multiplier
	 */
	if (!strcasecmp("Gb", units_str)) {
		units_factor = 1024.0 * 1024.0 * 1024.0;

	} else if (!strcasecmp("Mb", units_str)) {
		units_factor = 1024.0 * 1024.0;

	} else if (!strcasecmp("Kb", units_str)) {
		units_factor = 1024.0;

	} else if (!strcasecmp("b", units_str)) {
		units_factor = 1.0;

	} else {
		clam_errno = EINVAL;
		return 0;
	}

	/* make sure a number was given */
	if (!isdigit((int) *nbytes_str)) {
		clam_errno = EINVAL;
		return 0;
	}

	/* knowing the factor, now convert the given number string to a real
	 * number
	 */
	res = strtol(nbytes_str, &endp, 10);

	if (errno == ERANGE) {
		clam_errno = ERANGE;
		return 0;
	}

	if (endp && *endp) {
		clam_errno = EINVAL;
		return 0;
	}

	/* don't bother to apply the factor if that will cause the number to
	 * overflow
	 */
	if (res > (ULONG_MAX / units_factor)) {
		clam_errno = ERANGE;
		return 0;
	}

	nbytes = (unsigned long) res * units_factor;
	return nbytes;
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
	unsigned long nbytes = 0;
	
	CHECK_ARGS(cmd, 2);
	CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL|CONF_DIR);
	
	if ((nbytes = parse_nbytes(cmd->argv[1], cmd->argv[2])) == 0) {
		char ulong_max[80] = {'\0'};
		sprintf(ulong_max, "%lu", (unsigned long) ULONG_MAX);

		if (clam_errno == EINVAL)
			CONF_ERROR(cmd, "invalid parameters");

		if (clam_errno == ERANGE)
			CONF_ERROR(cmd, pstrcat(cmd->tmp_pool,
					"number of bytes must be between 0 and ", ulong_max, NULL));
	}

    c = add_config_param(cmd->argv[0], 1, NULL);
    c->argv[0] = pcalloc(c->pool, sizeof(unsigned long));
    *((unsigned long *) c->argv[0]) = nbytes;
	c->flags |= CF_MERGEDOWN;
	
	return PR_HANDLED(cmd);
}

/**
 * Configuration setter: ClamMaxSize
 */
MODRET set_clamavd_maxsize(cmd_rec *cmd) {
	config_rec *c = NULL;
	unsigned long nbytes = 0;
	
	CHECK_ARGS(cmd, 2);
	CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL|CONF_DIR);
	
	if ((nbytes = parse_nbytes(cmd->argv[1], cmd->argv[2])) == 0) {
		char ulong_max[80] = {'\0'};
		sprintf(ulong_max, "%lu", (unsigned long) ULONG_MAX);

		if (clam_errno == EINVAL)
			CONF_ERROR(cmd, "invalid parameters");

		if (clam_errno == ERANGE)
			CONF_ERROR(cmd, pstrcat(cmd->tmp_pool,
					"number of bytes must be between 0 and ", ulong_max, NULL));
	}

    c = add_config_param(cmd->argv[0], 1, NULL);
    c->argv[0] = pcalloc(c->pool, sizeof(unsigned long));
    *((unsigned long *) c->argv[0]) = nbytes;
	c->flags |= CF_MERGEDOWN;
	
	return PR_HANDLED(cmd);
}

/**
 * End FTP Session
 */
static void clamav_shutdown(const void *event_data, void *user_data) {
	if (clamd_sockd != -1) {
		clamavd_session_stop(clamd_sockd);
		close(clamd_sockd);
		clamd_sockd = -1;
		pr_log_debug(DEBUG4, MOD_CLAMAV_VERSION ": debug: disconnected from Clamd");
	}
}

/**
 * Start FTP Session
 */
static int clamav_sess_init(void) {
	pr_fs_t *fs;

	is_remote = 0; clamd_sockd = -1;
	
	pr_event_register(&clamav_module, "core.exit", clamav_shutdown, NULL);

	fs = pr_register_fs(session.pool, "clamav", "/");
	if (fs) {
		fs->close = clamav_fsio_close;
	}

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
	clamav_sess_init,		/* session init function */
        MOD_CLAMAV_VERSION
};

