#include <stdio.h>
#include <net/ethernet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <arpa/inet.h>

#include <netdb.h>

#include "ethdump.h"

void
displayip4addr(uint32_t ip)
{
	int i;
	for (i = 3; i >= 0; i--) {
		printf("%d", (ip >> 8 * i) & 0x000000ff);
		if (i != 0)
			printf(".");
	}
}

void
displayip(struct iphdr *iph)
{
	struct protoent *proto;
	proto = getprotobynumber(iph->protocol);
	printf("\t%s\t", proto->p_name);
	displayip4addr(ntohl(iph->saddr));
	printf("\t");
	displayip4addr(ntohl(iph->daddr));
}

void
displaymac(uint8_t addr[ETH_ALEN])
{
	int i;
	for (i = 0; i < ETH_ALEN; i++) {
		printf("%x", addr[i]);
		if (i < ETH_ALEN-1)
			printf(":");
	}
}

void
displaytype(struct packet *p)
{
	int t = p->eh->ether_type;

	switch (ntohs(t)) {
	case ETHERTYPE_PUP:
		printf("Xerox PUP");
		break;
	case ETHERTYPE_SPRITE:
		printf("Sprite");
		break;
	case ETHERTYPE_IP:
		printf("IP");
		break;
	case ETHERTYPE_ARP:
		printf("Address resolution");
		break;
	case ETHERTYPE_REVARP:
		printf("Reverse ARP");
		break;
	case ETHERTYPE_AT:
		printf("AppleTalk protocol");
		break;
	case ETHERTYPE_AARP:
		printf("AppleTalk ARP");
		break;
	case ETHERTYPE_VLAN:
		printf("IEEE 802.1Q VLAN tagging");
		break;
	case ETHERTYPE_IPX:
		printf("IPX");
		break;
	case ETHERTYPE_IPV6:
		printf("IP protocol version 6");
		break;
	case ETHERTYPE_LOOPBACK:
		printf("used to test interfaces");
		break;
	}

	printf("\t%x\t", ntohs(t));

	if (ntohs(t) == ETHERTYPE_IP) {
		displayip(p->iph);
	}
}

// Display the packet according to a specification.
void
displaypacket(struct packet *p)
{
	displaymac(p->eh->ether_shost);
	printf("\t");
	displaymac(p->eh->ether_dhost);
	printf("\t%d\t", p->len);	
	displaytype(p);
	printf("\n");
}
