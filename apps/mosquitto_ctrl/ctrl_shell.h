/*
Copyright (c) 2023 Roger Light <roger@atchoo.org>

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
#ifndef CTRL_SHELL_H
#define CTRL_SHELL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <cjson/cJSON.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>

extern const char *ANSI_URL;
extern const char *ANSI_MODULE;
extern const char *ANSI_INPUT;
extern const char *ANSI_ERROR;
extern const char **ANSI_LABEL;
extern const char *ANSI_RESET;
extern const char *ANSI_TOPIC;
extern const char *ANSI_POSITIVE;
extern const char *ANSI_NEGATIVE;

/* This relatively complex structure is used to store the command tree. It
 * allows for commands to be shared between different parts of the tree, and
 * for commands to have multiple arguments. The completion_tree_arg_list
 * members exist to have a fixed memory location that never changes, so that
 * we can reallocate the list for where we have dynamically updated arguments,
 * for e.g. dynsec clients, where we want many commands to use the same list.
 */

struct completion_tree_arg {
	struct completion_tree_arg *next;
	char name[];
};

struct completion_tree_arg_list {
	struct completion_tree_arg *args;
	bool is_shared;
};

struct completion_tree_cmd {
	struct completion_tree_cmd *next;
	struct completion_tree_arg_list **arg_lists;
	int arg_list_count;
	char name[];
};

struct completion_tree_root {
	struct completion_tree_cmd *commands;
};

extern char prompt[200];

/* Helper functions for sending commands to the broker. */
int ctrl_shell_command_generic_arg0(const char *command);
int ctrl_shell_command_generic_arg1(const char *command, const char *itemlabel, char **saveptr);
int ctrl_shell_command_generic_arg2(const char *command, const char *itemlabel1, const char *itemlabel2, char **saveptr);
int ctrl_shell_command_generic_int_arg1(const char *command, const char *itemlabel, char **saveptr);


void ctrl_shell_completion_commands_set(struct completion_tree_root *new_commands);
void ctrl_shell_line_callback_set(void (*callback)(char *line));

/* Helper functions for building the command tree. */
void completion_tree_arg_list_free(struct completion_tree_arg_list *arg_list);
void completion_tree_arg_list_args_free(struct completion_tree_arg_list *arg_list);
void completion_tree_cmd_free(struct completion_tree_cmd *cmd);
void completion_tree_free(struct completion_tree_root *tree);
struct completion_tree_cmd *completion_tree_cmd_add(struct completion_tree_root *root, struct completion_tree_arg_list *help_arg_list, const char *name);
struct completion_tree_arg_list *completion_tree_cmd_new_arg_list(void);
void completion_tree_cmd_append_arg_list(struct completion_tree_cmd *cmd, struct completion_tree_arg_list *new_list);
struct completion_tree_arg_list *completion_tree_cmd_add_arg_list(struct completion_tree_cmd *cmd);
void completion_tree_arg_list_add_arg(struct completion_tree_arg_list *arg_list, const char *name);

void ctrl_shell_pre_connect_init(void);
void ctrl_shell_post_connect_init(void);

int ctrl_shell_publish_blocking(cJSON *j_command);
bool ctrl_shell_callback_final(char *line);

char *ctrl_shell_fgets(char *s, int size, FILE *stream);
bool ctrl_shell_get_password(char *buf, size_t len);
void ctrl_shell_rtrim(char *buf);

void ctrl_shell_printf(const char *fmt, ...);
void ctrl_shell_vprintf(const char *fmt, va_list va);
void ctrl_shell_print_label(unsigned int level, const char *label);
void ctrl_shell_print_label_value(unsigned int level, const char *label, int align, const char *fmt, ...);
void ctrl_shell_print_value(unsigned int level, const char *fmt, ...);
void ctrl_shell_print_help_command(const char *cmd);
void ctrl_shell_print_help_desc(const char *desc);
void ctrl_shell_print_help_final(const char *command, const char *modul);

#ifdef __cplusplus
}
#endif

#endif
