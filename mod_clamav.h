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
 
#if !defined(MOD_CLAMAV_H)
#define MOD_CLAMAV_H

/**
 * Function declarations
 */
int clamavd_result(int sockd, const char *abs_filename, const char *rel_filename);
int clamavd_session_start(int sockd);
int clamavd_session_stop(int sockd);
int clamavd_connect_check(int sockd);
int clamavd_scan(int sockd, const char *abs_filename, const char *rel_filename);
int clamavd_connect(void);
int clamav_scan(cmd_rec *cmd);

#endif
