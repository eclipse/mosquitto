/*
Copyright (c) 2012-2020 Roger Light <roger@atchoo.org>

All rights reserved. This program and the accompanying materials
are made available under the terms of the Eclipse Public License 2.0
and Eclipse Distribution License v1.0 which accompany this distribution.
 
The Eclipse Public License is available at
   https://www.eclipse.org/legal/epl-2.0/
and the Eclipse Distribution License is available at
  http://www.eclipse.org/org/documents/edl-v10.php.
 
SPDX-License-Identifier: EPL-2.0 OR EDL-1.0

Contributors:
   Roger Light - initial implementation and documentation.
*/

#include "config.h"

#include <errno.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "get_password.h"
#include "password_mosq.h"

#ifdef WIN32
#  include <windows.h>
#  include <process.h>
#	ifndef __cplusplus
#		if defined(_MSC_VER) && _MSC_VER < 1900
#			define bool char
#			define true 1
#			define false 0
#		else
#			include <stdbool.h>
#		endif
#	endif
#   define snprintf sprintf_s
#	include <io.h>
#	include <windows.h>
#else
#  include <stdbool.h>
#  include <unistd.h>
#  include <termios.h>
#  include <sys/stat.h>
#endif

#define MAX_BUFFER_LEN 65536
#define SALT_LEN 12

#include "misc_mosq.h"

struct cb_helper {
	const char *line;
	const char *username;
	const char *password;
	int iterations;
	bool found;
};

static enum mosquitto_pwhash_type hashtype = pw_sha512_pbkdf2;

#ifdef WIN32
static FILE *mpw_tmpfile(void)
{
	return tmpfile();
}
#else

static char unsigned alphanum[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

static unsigned char tmpfile_path[36];
static FILE *mpw_tmpfile(void)
{
	int fd;
	size_t i;

	if(RAND_bytes(tmpfile_path, sizeof(tmpfile_path)) != 1){
		return NULL;
	}

	strcpy((char *)tmpfile_path, "/tmp/");

	for(i=strlen((char *)tmpfile_path); i<sizeof(tmpfile_path)-8; i++){
		tmpfile_path[i] = alphanum[tmpfile_path[i]%(sizeof(alphanum)-1)];
	}
	tmpfile_path[sizeof(tmpfile_path)-8] = '-';
	for(i=sizeof(tmpfile_path)-7; i<sizeof(tmpfile_path)-1; i++){
		tmpfile_path[i] = 'X';
	}
	tmpfile_path[sizeof(tmpfile_path)-1] = '\0';

	umask(077);
	fd = mkstemp((char *)tmpfile_path);
	if(fd < 0) return NULL;
	unlink((char *)tmpfile_path);

	return fdopen(fd, "w+");
}
#endif


void print_usage(void)
{
	printf("mosquitto_passwd is a tool for managing password files for mosquitto.\n\n");
	printf("Usage: mosquitto_passwd [-H sha512 | -H sha512-pbkdf2] [-c | -D] passwordfile username\n");
	printf("       mosquitto_passwd [-H sha512 | -H sha512-pbkdf2] [-c] -b passwordfile username password\n");
	printf("       mosquitto_passwd -U passwordfile\n");
	printf(" -b : run in batch mode to allow passing passwords on the command line.\n");
	printf(" -c : create a new password file. This will overwrite existing files.\n");
	printf(" -D : delete the username rather than adding/updating its password.\n");
	printf(" -H : specify the hashing algorithm. Defaults to sha512-pbkdf2, which is recommended.\n");
	printf("      Mosquitto 1.6 and earlier defaulted to sha512.\n");
	printf(" -U : update a plain text password file to use hashed passwords.\n");
	printf("\nSee https://mosquitto.org/ for more information.\n\n");
}

int output_new_password(FILE *fptr, const char *username, const char *password, int iterations)
{
	int rc;
	char *salt64 = NULL, *hash64 = NULL;
	struct mosquitto_pw pw;

	if(password == NULL){
		fprintf(stderr, "Error: Internal error, no password given.\n");
		return 1;
	}
	memset(&pw, 0, sizeof(pw));

	pw.hashtype = hashtype;

	if(pw__hash(password, &pw, true, iterations)){
		fprintf(stderr, "Error: Unable to hash password.\n");
		return 1;
	}

	rc = base64__encode(pw.salt, sizeof(pw.salt), &salt64);
	if(rc){
		free(salt64);
		fprintf(stderr, "Error: Unable to encode salt.\n");
		return 1;
	}

	rc = base64__encode(pw.password_hash, sizeof(pw.password_hash), &hash64);
	if(rc){
		free(salt64);
		free(hash64);
		fprintf(stderr, "Error: Unable to encode hash.\n");
		return 1;
	}

	if(pw.hashtype == pw_sha512_pbkdf2){
		fprintf(fptr, "%s:$%d$%d$%s$%s\n", username, hashtype, iterations, salt64, hash64);
	}else{
		fprintf(fptr, "%s:$%d$%s$%s\n", username, hashtype, salt64, hash64);
	}
	free(salt64);
	free(hash64);

	return 0;
}


static int pwfile_iterate(FILE *fptr, FILE *ftmp,
		int (*cb)(FILE *, FILE *, const char *, const char *, const char *, struct cb_helper *),
		struct cb_helper *helper)
{
	char *buf;
	int buflen = 1024;
	char *lbuf;
	int lbuflen;
	int rc = 1;
	int line = 0;
	char *username, *password;

	buf = malloc((size_t)buflen);
	if(buf == NULL){
		fprintf(stderr, "Error: Out of memory.\n");
		return 1;
	}
	lbuflen = buflen;
	lbuf = malloc((size_t)lbuflen);
	if(lbuf == NULL){
		fprintf(stderr, "Error: Out of memory.\n");
		free(buf);
		return 1;
	}

	while(!feof(fptr) && fgets_extending(&buf, &buflen, fptr)){
		if(lbuflen != buflen){
			free(lbuf);
			lbuflen = buflen;
			lbuf = malloc((size_t)lbuflen);
			if(lbuf == NULL){
				fprintf(stderr, "Error: Out of memory.\n");
				free(buf);
				return 1;
			}
		}
		memcpy(lbuf, buf, (size_t)buflen);
		line++;
		username = strtok(buf, ":");
		password = strtok(NULL, ":");
		if(username == NULL || password == NULL){
			fprintf(stderr, "Error: Corrupt password file at line %d.\n", line);
			free(lbuf);
			free(buf);
			return 1;
		}
		username = misc__trimblanks(username);
		password = misc__trimblanks(password);

		if(strlen(username) == 0 || strlen(password) == 0){
			fprintf(stderr, "Error: Corrupt password file at line %d.\n", line);
			free(lbuf);
			free(buf);
			return 1;
		}

		rc = cb(fptr, ftmp, username, password, lbuf, helper);
		if(rc){
			break;
		}
	}
	free(lbuf);
	free(buf);

	return rc;
}


/* ======================================================================
 * Delete a user from the password file
 * ====================================================================== */
static int delete_pwuser_cb(FILE *fptr, FILE *ftmp, const char *username, const char *password, const char *line, struct cb_helper *helper)
{
	if(strcmp(username, helper->username)){
		/* If this isn't the username to delete, write it to the new file */
		fprintf(ftmp, "%s", line);
	}else{
		/* Don't write the matching username to the file. */
		helper->found = true;
	}
	return 0;
}

int delete_pwuser(FILE *fptr, FILE *ftmp, const char *username)
{
	struct cb_helper helper;
	int rc;

	memset(&helper, 0, sizeof(helper));
	helper.username = username;
	rc = pwfile_iterate(fptr, ftmp, delete_pwuser_cb, &helper);

	if(helper.found == false){
		fprintf(stderr, "Warning: User %s not found in password file.\n", username);
		return 1;
	}
	return rc;
}



/* ======================================================================
 * Update a plain text password file to use hashes
 * ====================================================================== */
static int update_file_cb(FILE *fptr, FILE *ftmp, const char *username, const char *password, const char *line, struct cb_helper *helper)
{
	if(helper){
		return output_new_password(ftmp, username, password, helper->iterations);
	}else{
		return output_new_password(ftmp, username, password, PW_DEFAULT_ITERATIONS);
	}
}

int update_file(FILE *fptr, FILE *ftmp)
{
	return pwfile_iterate(fptr, ftmp, update_file_cb, NULL);
}


/* ======================================================================
 * Update an existing user password / create a new password
 * ====================================================================== */
static int update_pwuser_cb(FILE *fptr, FILE *ftmp, const char *username, const char *password, const char *line, struct cb_helper *helper)
{
	int rc = 0;

	if(strcmp(username, helper->username)){
		/* If this isn't the matching user, then writing out the exiting line */
		fprintf(ftmp, "%s", line);
	}else{
		/* Write out a new line for our matching username */
		helper->found = true;
		rc = output_new_password(ftmp, username, helper->password, helper->iterations);
	}
	return rc;
}

int update_pwuser(FILE *fptr, FILE *ftmp, const char *username, const char *password, int iterations)
{
	struct cb_helper helper;
	int rc;

	memset(&helper, 0, sizeof(helper));
	helper.username = username;
	helper.password = password;
	helper.iterations = iterations;
	rc = pwfile_iterate(fptr, ftmp, update_pwuser_cb, &helper);

	if(helper.found){
		return rc;
	}else{
		return output_new_password(ftmp, username, password, iterations);
	}
}


int copy_contents(FILE *src, FILE *dest)
{
	char buf[MAX_BUFFER_LEN];
	size_t len;

	rewind(src);
	rewind(dest);
	
#ifdef WIN32
	_chsize(fileno(dest), 0);
#else
	if(ftruncate(fileno(dest), 0)) return 1;
#endif

	while(!feof(src)){
		len = fread(buf, 1, MAX_BUFFER_LEN, src);
		if(len > 0){
			if(fwrite(buf, 1, len, dest) != len){
				return 1;
			}
		}else{
			return !feof(src);
		}
	}
	return 0;
}

int create_backup(const char *backup_file, FILE *fptr)
{
	FILE *fbackup;

	fbackup = fopen(backup_file, "wt");
	if(!fbackup){
		fprintf(stderr, "Error creating backup password file \"%s\", not continuing.\n", backup_file);
		return 1;
	}
	if(copy_contents(fptr, fbackup)){
		fprintf(stderr, "Error copying data to backup password file \"%s\", not continuing.\n", backup_file);
		fclose(fbackup);
		return 1;
	}
	fclose(fbackup);
	rewind(fptr);
	return 0;
}

void handle_sigint(int signal)
{
	get_password__reset_term();

	UNUSED(signal);

	exit(0);
}

int main(int argc, char *argv[])
{
	char *password_file_tmp = NULL;
	char *password_file = NULL;
	char *username = NULL;
	char *password_cmd = NULL;
	bool batch_mode = false;
	bool create_new = false;
	bool delete_user = false;
	FILE *fptr, *ftmp;
	char password[MAX_BUFFER_LEN];
	int rc;
	bool do_update_file = false;
	char *backup_file;
	int idx;
	int iterations = PW_DEFAULT_ITERATIONS;

	signal(SIGINT, handle_sigint);
	signal(SIGTERM, handle_sigint);

#if OPENSSL_VERSION_NUMBER < 0x10100000L || OPENSSL_API_COMPAT < 0x10100000L
	OpenSSL_add_all_digests();
#else
	OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS \
			| OPENSSL_INIT_ADD_ALL_DIGESTS \
			| OPENSSL_INIT_LOAD_CONFIG, NULL);
#endif

	if(argc == 1){
		print_usage();
		return 1;
	}

	idx = 1;
	for(idx = 1; idx < argc; idx++){
		if(!strcmp(argv[idx], "-H")){
			if(idx+1 == argc){
				fprintf(stderr, "Error: -H argument given but not enough other arguments.\n");
				return 1;
			}
			if(!strcmp(argv[idx+1], "sha512")){
				hashtype = pw_sha512;
			}else if(!strcmp(argv[idx+1], "sha512-pbkdf2")){
				hashtype = pw_sha512_pbkdf2;
			}else{
				fprintf(stderr, "Error: Unknown hash type '%s'\n", argv[idx+1]);
				return 1;
			}
			idx++;
		}else if(!strcmp(argv[idx], "-b")){
			batch_mode = true;
		}else if(!strcmp(argv[idx], "-c")){
			create_new = true;
		}else if(!strcmp(argv[idx], "-D")){
			delete_user = true;
		}else if(!strcmp(argv[idx], "-I")){
			if(idx+1 == argc){
				fprintf(stderr, "Error: -I argument given but not enough other arguments.\n");
				return 1;
			}
			iterations = atoi(argv[idx+1]);
			idx++;
			if(iterations < 1){
				fprintf(stderr, "Error: Number of iterations must be > 0.\n");
				return 1;
			}
		}else if(!strcmp(argv[idx], "-U")){
			do_update_file = true;
		}else{
			break;
		}
	}

	if(create_new && delete_user){
		fprintf(stderr, "Error: -c and -D cannot be used together.\n");
		return 1;
	}
	if(create_new && do_update_file){
		fprintf(stderr, "Error: -c and -U cannot be used together.\n");
		return 1;
	}
	if(delete_user && do_update_file){
		fprintf(stderr, "Error: -D and -U cannot be used together.\n");
		return 1;
	}
	if(delete_user && batch_mode){
		fprintf(stderr, "Error: -b and -D cannot be used together.\n");
		return 1;
	}

	if(create_new){
		if(batch_mode){
			if(idx+2 >= argc){
				fprintf(stderr, "Error: -c argument given but password file, username, or password missing.\n");
				return 1;
			}else{
				password_file_tmp = argv[idx];
				username = argv[idx+1];
				password_cmd = argv[idx+2];
			}
		}else{
			if(idx+1 >= argc){
				fprintf(stderr, "Error: -c argument given but password file or username missing.\n");
				return 1;
			}else{
				password_file_tmp = argv[idx];
				username = argv[idx+1];
			}
		}
	}else if(delete_user){
		if(idx+1 >= argc){
			fprintf(stderr, "Error: -D argument given but password file or username missing.\n");
			return 1;
		}else{
			password_file_tmp = argv[idx];
			username = argv[idx+1];
		}
	}else if(do_update_file){
		if(idx+1 != argc){
			fprintf(stderr, "Error: -U argument given but password file missing.\n");
			return 1;
		}else{
			password_file_tmp = argv[idx];
		}
	}else if(batch_mode == true && idx+3 == argc){
		password_file_tmp = argv[idx];
		username = argv[idx+1];
		password_cmd = argv[idx+1];
	}else if(batch_mode == false && idx+2 == argc){
		password_file_tmp = argv[idx];
		username = argv[idx+1];
	}else{
		print_usage();
		return 1;
	}

	if(username){
		if(strlen(username) > 65535){
			fprintf(stderr, "Error: Username must be less than 65536 characters long.\n");
			return 1;
		}
		if(strchr(username, ':')){
			fprintf(stderr, "Error: Username must not contain the ':' character.\n");
			return 1;
		}
	}
	if(password_cmd && strlen(password_cmd) > 65535){
		fprintf(stderr, "Error: Password must be less than 65536 characters long.\n");
		return 1;
	}

#ifdef WIN32
	password_file = _fullpath(NULL, password_file_tmp, 0);
	if(!password_file){
		fprintf(stderr, "Error getting full path for password file.\n");
		return 1;
	}
#else
	password_file = realpath(password_file_tmp, NULL);
	if(!password_file){
		if(errno == ENOENT){
			password_file = strdup(password_file_tmp);
			if(!password_file){
				fprintf(stderr, "Error: Out of memory.\n");
				return 1;
			}
		}else{
			fprintf(stderr, "Error reading password file: %s\n", strerror(errno));
			return 1;
		}
	}
#endif

	if(create_new){
		if(batch_mode == false){
			rc = get_password("Password: ", "Reenter password: ", false, password, MAX_BUFFER_LEN);
			if(rc){
				free(password_file);
				return rc;
			}
			password_cmd = password;
		}
		fptr = fopen(password_file, "wt");
		if(!fptr){
			fprintf(stderr, "Error: Unable to open file %s for writing. %s.\n", password_file, strerror(errno));
			free(password_file);
			return 1;
		}
		free(password_file);
		rc = output_new_password(fptr, username, password_cmd, iterations);
		fclose(fptr);
		return rc;
	}else{
		fptr = fopen(password_file, "r+t");
		if(!fptr){
			fprintf(stderr, "Error: Unable to open password file %s. %s.\n", password_file, strerror(errno));
			free(password_file);
			return 1;
		}

		backup_file = malloc((size_t)strlen(password_file)+5);
		if(!backup_file){
			fprintf(stderr, "Error: Out of memory.\n");
			free(password_file);
			return 1;
		}
		snprintf(backup_file, strlen(password_file)+5, "%s.tmp", password_file);
		free(password_file);
		password_file = NULL;

		if(create_backup(backup_file, fptr)){
			fclose(fptr);
			free(backup_file);
			return 1;
		}

		ftmp = mpw_tmpfile();
		if(!ftmp){
			fprintf(stderr, "Error: Unable to open temporary file. %s.\n", strerror(errno));
			fclose(fptr);
			free(backup_file);
			return 1;
		}
		if(delete_user){
			rc = delete_pwuser(fptr, ftmp, username);
		}else if(do_update_file){
			rc = update_file(fptr, ftmp);
		}else{
			if(batch_mode){
				/* Update password for individual user */
				rc = update_pwuser(fptr, ftmp, username, password_cmd, iterations);
			}else{
				rc = get_password("Password: ", "Reenter password: ", false, password, MAX_BUFFER_LEN);
				if(rc){
					fclose(fptr);
					fclose(ftmp);
					unlink(backup_file);
					free(backup_file);
					return rc;
				}
				/* Update password for individual user */
				rc = update_pwuser(fptr, ftmp, username, password, iterations);
			}
		}
		if(rc){
			fclose(fptr);
			fclose(ftmp);
			unlink(backup_file);
			free(backup_file);
			return rc;
		}

		if(copy_contents(ftmp, fptr)){
			fclose(fptr);
			fclose(ftmp);
			fprintf(stderr, "Error occurred updating password file.\n");
			fprintf(stderr, "Password file may be corrupt, check the backup file: %s.\n", backup_file);
			free(backup_file);
			return 1;
		}
		fclose(fptr);
		fclose(ftmp);

		/* Everything was ok so backup no longer needed. May contain old
		 * passwords so shouldn't be kept around. */
		unlink(backup_file);
		free(backup_file);
	}

	return 0;
}
