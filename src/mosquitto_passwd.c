/*
Copyright (c) 2012-2018 Roger Light <roger@atchoo.org>

All rights reserved. This program and the accompanying materials
are made available under the terms of the Eclipse Public License v1.0
and Eclipse Distribution License v1.0 which accompany this distribution.
 
The Eclipse Public License is available at
   http://www.eclipse.org/legal/epl-v10.html
and the Eclipse Distribution License is available at
  http://www.eclipse.org/org/documents/edl-v10.php.
 
Contributors:
   Roger Light - initial implementation and documentation.
*/

#include "config.h"

#include <errno.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/buffer.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


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
#endif

#define MAX_BUFFER_LEN 1024
#define SALT_LEN 12

int base64_encode(unsigned char *in, unsigned int in_len, char **encoded)
{
	BIO *bmem, *b64;
	BUF_MEM *bptr;

	b64 = BIO_new(BIO_f_base64());
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	bmem = BIO_new(BIO_s_mem());
	b64 = BIO_push(b64, bmem);
	BIO_write(b64, in, in_len);
	if(BIO_flush(b64) != 1){
		BIO_free_all(b64);
		return 1;
	}
	BIO_get_mem_ptr(b64, &bptr);
	*encoded = malloc(bptr->length+1);
	if(!(*encoded)){
		BIO_free_all(b64);
		return 1;
	}
	memcpy(*encoded, bptr->data, bptr->length);
	(*encoded)[bptr->length] = '\0';
	BIO_free_all(b64);

	return 0;
}


void print_usage(void)
{
	printf("mosquitto_passwd is a tool for managing password files for mosquitto.\n\n");
	printf("Usage: mosquitto_passwd [-c | -D] passwordfile username\n");
	printf("       mosquitto_passwd -b passwordfile username password\n");
	printf("       mosquitto_passwd -U passwordfile\n");
	printf(" -b : run in batch mode to allow passing passwords on the command line.\n");
	printf(" -c : create a new password file. This will overwrite existing files.\n");
	printf(" -D : delete the username rather than adding/updating its password.\n");
	printf(" -U : update a plain text password file to use hashed passwords.\n");
	printf("\nSee http://mosquitto.org/ for more information.\n\n");
}

int output_new_password(FILE *fptr, const char *username, const char *password)
{
	int rc;
	unsigned char salt[SALT_LEN];
	char *salt64 = NULL, *hash64 = NULL;
	unsigned char hash[EVP_MAX_MD_SIZE];
	unsigned int hash_len;
	const EVP_MD *digest;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	EVP_MD_CTX context;
#else
	EVP_MD_CTX *context;
#endif

	rc = RAND_bytes(salt, SALT_LEN);
	if(!rc){
		fprintf(stderr, "Error: Insufficient entropy available to perform password generation.\n");
		return 1;
	}

	rc = base64_encode(salt, SALT_LEN, &salt64);
	if(rc){
		free(salt64);
		fprintf(stderr, "Error: Unable to encode salt.\n");
		return 1;
	}


	digest = EVP_get_digestbyname("sha512");
	if(!digest){
		free(salt64);
		fprintf(stderr, "Error: Unable to create openssl digest.\n");
		return 1;
	}

#if OPENSSL_VERSION_NUMBER < 0x10100000L
	EVP_MD_CTX_init(&context);
	EVP_DigestInit_ex(&context, digest, NULL);
	EVP_DigestUpdate(&context, password, strlen(password));
	EVP_DigestUpdate(&context, salt, SALT_LEN);
	EVP_DigestFinal_ex(&context, hash, &hash_len);
	EVP_MD_CTX_cleanup(&context);
#else
	context = EVP_MD_CTX_new();
	EVP_DigestInit_ex(context, digest, NULL);
	EVP_DigestUpdate(context, password, strlen(password));
	EVP_DigestUpdate(context, salt, SALT_LEN);
	EVP_DigestFinal_ex(context, hash, &hash_len);
	EVP_MD_CTX_free(context);
#endif

	rc = base64_encode(hash, hash_len, &hash64);
	if(rc){
		free(salt64);
		free(hash64);
		fprintf(stderr, "Error: Unable to encode hash.\n");
		return 1;
	}

	fprintf(fptr, "%s:$6$%s$%s\n", username, salt64, hash64);
	free(salt64);
	free(hash64);

	return 0;
}

int delete_pwuser(FILE *fptr, FILE *ftmp, const char *username)
{
	char buf[MAX_BUFFER_LEN];
	char lbuf[MAX_BUFFER_LEN], *token;
	bool found = false;

	while(!feof(fptr) && fgets(buf, MAX_BUFFER_LEN, fptr)){
		memcpy(lbuf, buf, MAX_BUFFER_LEN);
		token = strtok(lbuf, ":");
		if(strcmp(username, token)){
			fprintf(ftmp, "%s", buf);
		}else{
			found = true;
		}
	}
	if(!found){
		fprintf(stderr, "Warning: User %s not found in password file.\n", username);
	}
	return 0;
}

int update_file(FILE *fptr, FILE *ftmp)
{
	char buf[MAX_BUFFER_LEN];
	char lbuf[MAX_BUFFER_LEN];
	char *username, *password;
	int rc;
	int len;

	while(!feof(fptr) && fgets(buf, MAX_BUFFER_LEN, fptr)){
		memcpy(lbuf, buf, MAX_BUFFER_LEN);
		username = strtok(lbuf, ":");
		password = strtok(NULL, ":");
		if(password){
			len = strlen(password);
			while(len && (password[len-1] == '\n' || password[len-1] == '\r')){
				password[len-1] = '\0';
				len = strlen(password);
			}
			rc = output_new_password(ftmp, username, password);
			if(rc) return rc;
		}else{
			fprintf(ftmp, "%s", username);
		}
	}
	return 0;
}

int update_pwuser(FILE *fptr, FILE *ftmp, const char *username, const char *password)
{
	char buf[MAX_BUFFER_LEN];
	char lbuf[MAX_BUFFER_LEN], *token;
	bool found = false;
	int rc = 1;

	while(!feof(fptr) && fgets(buf, MAX_BUFFER_LEN, fptr)){
		memcpy(lbuf, buf, MAX_BUFFER_LEN);
		token = strtok(lbuf, ":");
		if(strcmp(username, token)){
			fprintf(ftmp, "%s", buf);
		}else{
			rc = output_new_password(ftmp, username, password);
			found = true;
		}
	}
	if(found){
		return rc;
	}else{
		return output_new_password(ftmp, username, password);
	}
}

int gets_quiet(char *s, int len)
{
#ifdef WIN32
	HANDLE h;
	DWORD con_orig, con_quiet = 0;
	DWORD read_len = 0;

	memset(s, 0, len);
	h  = GetStdHandle(STD_INPUT_HANDLE);
	GetConsoleMode(h, &con_orig);
	con_quiet = con_orig;
	con_quiet &= ~ENABLE_ECHO_INPUT;
	con_quiet |= ENABLE_LINE_INPUT;
	SetConsoleMode(h, con_quiet);
	if(!ReadConsole(h, s, len, &read_len, NULL)){
		SetConsoleMode(h, con_orig);
		return 1;
	}
	while(s[strlen(s)-1] == 10 || s[strlen(s)-1] == 13){
		s[strlen(s)-1] = 0;
	}
	if(strlen(s) == 0){
		return 1;
	}
	SetConsoleMode(h, con_orig);

	return 0;
#else
	struct termios ts_quiet, ts_orig;
	char *rs;

	memset(s, 0, len);
	tcgetattr(0, &ts_orig);
	ts_quiet = ts_orig;
	ts_quiet.c_lflag &= ~(ECHO | ICANON);
	tcsetattr(0, TCSANOW, &ts_quiet);

	rs = fgets(s, len, stdin);
	tcsetattr(0, TCSANOW, &ts_orig);

	if(!rs){
		return 1;
	}else{
		while(s[strlen(s)-1] == 10 || s[strlen(s)-1] == 13){
			s[strlen(s)-1] = 0;
		}
		if(strlen(s) == 0){
			return 1;
		}
	}
	return 0;
#endif
}

int get_password(char *password, int len)
{
	char pw1[MAX_BUFFER_LEN], pw2[MAX_BUFFER_LEN];

	printf("Password: ");
	fflush(stdout);
	if(gets_quiet(pw1, MAX_BUFFER_LEN)){
		fprintf(stderr, "Error: Empty password.\n");
		return 1;
	}
	printf("\n");

	printf("Reenter password: ");
	fflush(stdout);
	if(gets_quiet(pw2, MAX_BUFFER_LEN)){
		fprintf(stderr, "Error: Empty password.\n");
		return 1;
	}
	printf("\n");

	if(strcmp(pw1, pw2)){
		fprintf(stderr, "Error: Passwords do not match.\n");
		return 1;
	}

	strncpy(password, pw1, len);
	return 0;
}

int copy_contents(FILE *src, FILE *dest)
{
	char buf[MAX_BUFFER_LEN];
	int len;

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
#ifndef WIN32
	struct termios ts;

	tcgetattr(0, &ts);
	ts.c_lflag |= ECHO | ICANON;
	tcsetattr(0, TCSANOW, &ts);
#endif
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

	signal(SIGINT, handle_sigint);
	signal(SIGTERM, handle_sigint);

	OpenSSL_add_all_digests();

	if(argc == 1){
		print_usage();
		return 1;
	}

	if(!strcmp(argv[1], "-c")){
		create_new = true;
		if(argc != 4){
			fprintf(stderr, "Error: -c argument given but password file or username missing.\n");
			return 1;
		}else{
			password_file_tmp = argv[2];
			username = argv[3];
		}
	}else if(!strcmp(argv[1], "-D")){
		delete_user = true;
		if(argc != 4){
			fprintf(stderr, "Error: -D argument given but password file or username missing.\n");
			return 1;
		}else{
			password_file_tmp = argv[2];
			username = argv[3];
		}
	}else if(!strcmp(argv[1], "-b")){
		batch_mode = true;
		if(argc != 5){
			fprintf(stderr, "Error: -b argument given but password file, username or password missing.\n");
			return 1;
		}else{
			password_file_tmp = argv[2];
			username = argv[3];
			password_cmd = argv[4];
		}
	}else if(!strcmp(argv[1], "-U")){
		if(argc != 3){
			fprintf(stderr, "Error: -U argument given but password file missing.\n");
			return 1;
		}else{
			do_update_file = true;
			password_file_tmp = argv[2];
		}
	}else if(argc == 3){
		password_file_tmp = argv[1];
		username = argv[2];
	}else{
		print_usage();
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
		rc = get_password(password, 1024);
		if(rc) return rc;
		fptr = fopen(password_file, "wt");
		if(!fptr){
			fprintf(stderr, "Error: Unable to open file %s for writing. %s.\n", password_file, strerror(errno));
			free(password_file);
			return 1;
		}
		free(password_file);
		rc = output_new_password(fptr, username, password);
		fclose(fptr);
		return rc;
	}else{
		fptr = fopen(password_file, "r+t");
		if(!fptr){
			fprintf(stderr, "Error: Unable to open password file %s. %s.\n", password_file, strerror(errno));
			free(password_file);
			return 1;
		}

		backup_file = malloc(strlen(password_file)+5);
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

		ftmp = tmpfile();
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
				rc = update_pwuser(fptr, ftmp, username, password_cmd);
			}else{
				rc = get_password(password, 1024);
				if(rc){
					fclose(fptr);
					fclose(ftmp);
					unlink(backup_file);
					free(backup_file);
					return rc;
				}
				/* Update password for individual user */
				rc = update_pwuser(fptr, ftmp, username, password);
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
