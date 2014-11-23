#ifndef HIDE_SOCKET_HEADER
#define HIDE_SOCKET_HEADER

#include "include.h"

void hook_sockets(char *protocol, int port);
void unhook_sockets(void);

#endif
