#ifndef NET_KEYLOG_HEADER
#define NET_KEYLOG_HEADER

void enable_net_keylog(char *);
void disable_net_keylog(void);

void send_udp(const char *);

#endif
