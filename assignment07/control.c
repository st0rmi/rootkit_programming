/*
 * This file manages the data structures used for determining
 * which files, processes, modules, sockets, ... need to be hidden.
 */
#include "control.h"
#include "include.h"

int
hide_file_name(char *name) {
	return -1;
}

int
unhide_file_name(char *name) {
	return -1;
}

int
hide_file_prefix(char *name) {
	return -1;
}

int
unhide_file_prefix(char *name) {
	return -1;
}

int
hide_process(pid_t pid) {
	return -1;
}

int
unhide_process(pid_t pid) {
	return -1;
}

int
hide_tcp_socket(int port) {
	return -1;
}

int
unhide_tcp_socket(int port) {
	return -1;
}

int
hide_udp_socket(int port) {
	return -1;
}

int
unhide_udp_socket(int port) {
	return -1;
}

int
hide_module(char *name) {
	return -1;
}

int
unhide_module(char *name) {
	return -1;
}
