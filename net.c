#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <errno.h>

#include "tcpmud.h"

int
rawsocket(const char *name)
{
	int s;
	struct sockaddr_ll sll;

	s = socket(PF_PACKET, SOCK_RAW | SOCK_CLOEXEC, htons(ETH_P_ALL));
	if (s < 0) {
		fprintf(stderr, "Cannot create raw socket: %s\n", strerror(errno));
		return -1;
	}

	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = if_nametoindex(name);
	sll.sll_protocol = htons(ETH_P_ALL);
	if (bind(s, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
		fprintf(stderr, "bind to %s: %s", name, strerror(errno));
		close(s);
		return -1;
	}

	return s;
}

// Read a single packet from the raw socket.
int
readpacket(int socket, struct packet *p)
{
	int n = recvfrom(socket, p->buf, sizeof(p->buf), 0, 
		(struct sockaddr *)&p->sender, &p->senderlen);
	if (n < 0) {
		fprintf(stderr, "Error receiving packet: %s\n", strerror(errno));
		return -1;
	}

	return n;
}
