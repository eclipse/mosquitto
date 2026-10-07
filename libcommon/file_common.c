/*
Copyright (c) 2009-2021 Roger Light <roger@atchoo.org>

All rights reserved. This program and the accompanying materials
are made available under the terms of the Eclipse Public License 2.0
and Eclipse Distribution License v1.0 which accompany this distribution.

The Eclipse Public License is available at
   https://www.eclipse.org/legal/epl-2.0/
and the Eclipse Distribution License is available at
  http://www.eclipse.org/org/documents/edl-v10.php.

SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause

Contributors:
   Roger Light - initial implementation and documentation.
*/

/* This contains general purpose utility functions that are not specific to
 * Mosquitto/MQTT features. */

#include "config.h"

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef WIN32
#  include <winsock2.h>
#  include <aclapi.h>
#  include <io.h>
#  include <lmcons.h>
#  include <fcntl.h>
#else
#  include <sys/stat.h>
#  include <pwd.h>
#  include <grp.h>
#  include <unistd.h>
#  include <fcntl.h>
#endif

#include "mosquitto.h"

#ifndef PATH_MAX
#  define PATH_MAX MAX_PATH
#endif

void (*libcommon_vprintf)(const char *fmt, va_list va) = NULL;


void libcommon_printf(const char *fmt, ...)
{
	va_list va;

	va_start(va, fmt);

	if(libcommon_vprintf){
		libcommon_vprintf(fmt, va);
	}else{
		vfprintf(stderr, fmt, va);
	}

	va_end(va);
}


FILE *mosquitto_fopen(const char *path, const char *mode, bool restrict_read)
{
#ifdef WIN32
	char buf[4096];
	int rc;
	int flags = 0;

	rc = ExpandEnvironmentStringsA(path, buf, 4096);
	if(rc == 0 || rc > 4096){
		return NULL;
	}else{
		if(restrict_read){
			HANDLE hfile;
			SECURITY_ATTRIBUTES sec;
			EXPLICIT_ACCESS_A ea;
			PACL pacl = NULL;
			char username[UNLEN + 1];
			DWORD ulen = UNLEN;
			SECURITY_DESCRIPTOR sd;
			DWORD dwCreationDisposition;
			DWORD dwShareMode;
			int fd;
			FILE *fptr;

			switch(mode[0]){
				case 'a':
					dwCreationDisposition = OPEN_ALWAYS;
					dwShareMode = GENERIC_WRITE;
					flags = _O_APPEND;
					break;
				case 'r':
					dwCreationDisposition = OPEN_EXISTING;
					dwShareMode = GENERIC_READ;
					flags = _O_RDONLY;
					break;
				case 'w':
					dwCreationDisposition = CREATE_ALWAYS;
					dwShareMode = GENERIC_WRITE;
					break;
				default:
					return NULL;
			}
			if(mode[1] == '+'){
				dwShareMode = GENERIC_READ | GENERIC_WRITE;
			}

			GetUserNameA(username, &ulen);
			if(!InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION)){
				return NULL;
			}
			BuildExplicitAccessWithNameA(&ea, username, GENERIC_ALL, SET_ACCESS, NO_INHERITANCE);
			if(SetEntriesInAclA(1, &ea, NULL, &pacl) != ERROR_SUCCESS){
				return NULL;
			}
			if(!SetSecurityDescriptorDacl(&sd, TRUE, pacl, FALSE)){
				LocalFree(pacl);
				return NULL;
			}

			memset(&sec, 0, sizeof(sec));
			sec.nLength = sizeof(SECURITY_ATTRIBUTES);
			sec.bInheritHandle = FALSE;
			sec.lpSecurityDescriptor = &sd;

			hfile = CreateFileA(buf, dwShareMode, FILE_SHARE_READ,
					&sec,
					dwCreationDisposition,
					FILE_ATTRIBUTE_NORMAL,
					NULL);

			LocalFree(pacl);

			fd = _open_osfhandle((intptr_t)hfile, flags);
			if(fd < 0){
				return NULL;
			}

			fptr = _fdopen(fd, mode);
			if(!fptr){
				_close(fd);
				return NULL;
			}
			if(mode[0] == 'a'){
				fseek(fptr, 0, SEEK_END);
			}
			return fptr;

		}else{
			return fopen(buf, mode);
		}
	}
#else
	FILE *fptr;
	struct stat statbuf;

	if(restrict_read){
		mode_t old_mask;

		old_mask = umask(0077);

		int open_flags = 0;
		if(!getenv("MOSQUITTO_UNSAFE_ALLOW_SYMLINKS")){
			open_flags |= O_NOFOLLOW;
		}
		for(size_t i = 0; i<strlen(mode); i++){
			if(mode[i] == 'r'){
				open_flags |= O_RDONLY;
			}else if(mode[i] == 'w'){
				open_flags |= O_WRONLY;
				open_flags |= (O_TRUNC | O_CREAT | O_EXCL);

			}else if(mode[i] == 'a'){
				open_flags |= O_WRONLY;
				open_flags |= (O_APPEND | O_CREAT);
			}else if(mode[i] == 't'){
			}else if(mode[i] == 'b'){
			}else if(mode[i] == '+'){
				open_flags |= O_RDWR;
			}
		}
		int fd = open(path, open_flags, 0600);
		if(fd < 0){
			return NULL;
		}
		fptr = fdopen(fd, mode);

		umask(old_mask);
	}else{
		fptr = fopen(path, mode);
	}
	if(!fptr){
		return NULL;
	}

	if(fstat(fileno(fptr), &statbuf) < 0){
		fclose(fptr);
		return NULL;
	}

	if(restrict_read){
		if(statbuf.st_mode & S_IRWXO){
			libcommon_printf(
					"Warning: File %s has world readable permissions. Future versions will refuse to load this file.\n"
					"To fix this, use `chmod 0700 %s`.\n",
					path, path);
#if 0
			return NULL;
#endif
		}
		if(statbuf.st_uid != getuid()){
			char buf[4096];
			struct passwd pw, *result;

			getpwuid_r(getuid(), &pw, buf, sizeof(buf), &result);
			if(result){
				libcommon_printf(
						"Warning: File %s owner is not %s. Future versions will refuse to load this file."
						"To fix this, use `chown %s %s`.\n",
						path, result->pw_name, result->pw_name, path);
			}
#if 0
			// Future version
			return NULL;
#endif
		}
		if(statbuf.st_gid != getgid()){
			char buf[4096];
			struct group grp, *result;

			if(getgrgid_r(getgid(), &grp, buf, sizeof(buf), &result) == 0 && result){
				libcommon_printf(
						"Warning: File %s group is not %s. Future versions will refuse to load this file.\n",
						path, result->gr_name);
			}
#if 0
			// Future version
			return NULL
#endif
		}
	}

	if(!S_ISREG(statbuf.st_mode)){
		libcommon_printf("Error: %s is not a file.", path);
		fclose(fptr);
		return NULL;
	}
	return fptr;
#endif
}


char *mosquitto_trimblanks(char *str)
{
	char *endptr;

	if(str == NULL){
		return NULL;
	}

	while(isspace((unsigned char)str[0])){
		str++;
	}
	endptr = &str[strlen(str)-1];
	while(endptr > str && isspace((unsigned char)endptr[0])){
		endptr[0] = '\0';
		endptr--;
	}
	return str;
}


char *mosquitto_fgets(char **buf, int *buflen, FILE *stream)
{
	char *rc;
	char endchar;
	int offset = 0;
	char *newbuf;
	size_t len;

	if(stream == NULL || buf == NULL || buflen == NULL || *buflen < 1){
		return NULL;
	}

	do{
		rc = fgets(&((*buf)[offset]), (*buflen)-offset, stream);
		if(feof(stream) || rc == NULL){
			return rc;
		}

		len = strlen(*buf);
		if(len == 0){
			return rc;
		}
		endchar = (*buf)[len-1];
		if(endchar == '\n'){
			return rc;
		}
		if((int)(len+1) < *buflen){
			/* Embedded nulls, invalid string */
			return NULL;
		}

		/* No EOL char found, so extend buffer */
		offset = (*buflen)-1;
		*buflen += 1000;
		newbuf = realloc(*buf, (size_t)*buflen);
		if(!newbuf){
			return NULL;
		}
		*buf = newbuf;
	}while(1);
}


#define INVOKE_LOG_FN(format, ...) \
		do{ \
			if(log_fn){ \
				int tmp_err_no = errno; \
				char msg[2*PATH_MAX]; \
				snprintf(msg, sizeof(msg), (format), __VA_ARGS__); \
				msg[sizeof(msg)-1] = '\0'; \
				(*log_fn)(msg); \
				errno = tmp_err_no; \
			} \
		}while(0)


int mosquitto_write_file(const char *target_path, bool restrict_read, int (*write_fn)(FILE *fptr, void *user_data), void *user_data, void (*log_fn)(const char *msg))
{
	int rc = 0;
	FILE *fptr = NULL;
	char tmp_file_path[PATH_MAX];

	if(!target_path || !write_fn){
		return MOSQ_ERR_INVAL;
	}

	rc = snprintf(tmp_file_path, PATH_MAX, "%s.new", target_path);
	if(rc < 0 || rc >= PATH_MAX){
		return MOSQ_ERR_INVAL;
	}

#ifndef WIN32
	/**
	*
	* If a system lost power during the rename operation at the
	* end of this file the filesystem could potentially be left
	* with a directory that looks like this after powerup:
	*
	* 24094 -rw-r--r--    2 root     root          4099 May 30 16:27 mosquitto.db
	* 24094 -rw-r--r--    2 root     root          4099 May 30 16:27 mosquitto.db.new
	*
	* The 24094 shows that mosquitto.db.new is hard-linked to the
	* same file as mosquitto.db.  If fopen(outfile, "wb") is naively
	* called then mosquitto.db will be truncated and the database
	* potentially corrupted.
	*
	* Any existing mosquitto.db.new file must be removed prior to
	* opening to guarantee that it is not hard-linked to
	* mosquitto.db.
	*
	*/
	if(unlink(tmp_file_path) && errno != ENOENT){
		INVOKE_LOG_FN("unable to remove stale tmp file %s, error %s", tmp_file_path, strerror(errno));
		return MOSQ_ERR_INVAL;
	}
#endif

	fptr = mosquitto_fopen(tmp_file_path, "wb", restrict_read);
	if(fptr == NULL){
		INVOKE_LOG_FN("unable to open %s for writing, error %s", tmp_file_path, strerror(errno));
		return MOSQ_ERR_INVAL;
	}

	if((rc = (*write_fn)(fptr, user_data)) != MOSQ_ERR_SUCCESS){
		goto error;
	}

	rc = MOSQ_ERR_ERRNO;
#ifndef WIN32
	/**
	*
	* Closing a file does not guarantee that the contents are
	* written to disk.  Need to flush to send data from app to OS
	* buffers, then fsync to deliver data from OS buffers to disk
	* (as well as disk hardware permits).
	*
	* man close (http://linux.die.net/man/2/close, 2016-06-20):
	*
	*   "successful close does not guarantee that the data has
	*   been successfully saved to disk, as the kernel defers
	*   writes.  It is not common for a filesystem to flush
	*   the  buffers  when  the stream is closed.  If you need
	*   to be sure that the data is physically stored, use
	*   fsync(2).  (It will depend on the disk hardware at this
	*   point."
	*
	* This guarantees that the new state file will not overwrite
	* the old state file before its contents are valid.
	*
	*/
	if(fflush(fptr) != 0 && errno != EINTR){
		INVOKE_LOG_FN("unable to flush %s, error %s", tmp_file_path, strerror(errno));
		goto error;
	}

	if(fsync(fileno(fptr)) != 0 && errno != EINTR){
		INVOKE_LOG_FN("unable to sync %s to disk, error %s", tmp_file_path, strerror(errno));
		goto error;
	}
#endif

	if(fclose(fptr) != 0){
		INVOKE_LOG_FN("unable to close %s on disk, error %s", tmp_file_path, strerror(errno));
		fptr = NULL;
		goto error;
	}
	fptr = NULL;

#ifdef WIN32
	if(remove(target_path) != 0 && errno != ENOENT){
		INVOKE_LOG_FN("unable to remove %s on disk, error %s", target_path, strerror(errno));
		goto error;
	}
#endif

	if(rename(tmp_file_path, target_path) != 0){
		INVOKE_LOG_FN("unable to replace %s by tmp file  %s, error %s", target_path, tmp_file_path, strerror(errno));
		goto error;
	}
	return MOSQ_ERR_SUCCESS;

error:
	if(fptr){
		fclose(fptr);
		unlink(tmp_file_path);
	}
	return MOSQ_ERR_ERRNO;
}


int mosquitto_read_file(const char *file, bool restrict_read, char **buf, size_t *buflen)
{
	FILE *fptr;
	long l;
	size_t buflen_i;

	*buf = NULL;
	if(buflen){
		*buflen = 0;
	}
	fptr = mosquitto_fopen(file, "rb", restrict_read);
	if(fptr == NULL){
		return MOSQ_ERR_ERRNO;
	}

	fseek(fptr, 0, SEEK_END);
	l = ftell(fptr);
	fseek(fptr, 0, SEEK_SET);
	if(l < 0){
		fclose(fptr);
		return MOSQ_ERR_ERRNO;
	}else if(l == 0){
		fclose(fptr);
		return MOSQ_ERR_SUCCESS;
	}
	buflen_i = (size_t)l;

	*buf = mosquitto_calloc(buflen_i+1, sizeof(char));
	if((*buf) == NULL){
		fclose(fptr);
		return MOSQ_ERR_NOMEM;
	}
	if(fread(*buf, 1, buflen_i, fptr) != buflen_i){
		mosquitto_FREE(*buf);
		fclose(fptr);
		return MOSQ_ERR_INVAL;
	}
	fclose(fptr);
	if(buflen){
		*buflen = buflen_i;
	}

	return MOSQ_ERR_SUCCESS;
}
