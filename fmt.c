#include <stdio.h>
#include <net/ethernet.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>

#include "ethdump.h"

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
displaytype(uint16_t t)
{
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

	printf(" (%x)", ntohs(t));
}

// Display the packet according to a specification.
void
displaypacket(struct packet *p)
{
	displaymac(p->eh->ether_shost);
	printf(" -> ");
	displaymac(p->eh->ether_dhost);
	printf("\t(%d)\t", p->len);	
	displaytype(p->eh->ether_type);
	printf("\n");
}
