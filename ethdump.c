#include <stdio.h>
#include <unistd.h>
#include <limits.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <linux/ip.h>

#include "ethdump.h"

char *rawfilter;
extern struct filter filter;

void
usage(char * const *argv)
{
	fprintf(stderr, "Usage: %s [-f filter] -i interface\n", argv[0]);
}

int
main(int argc, char * const *argv)
{
	int opt, sock;
	const char *device = NULL;
	struct rawpacket rawpacket;
	struct packet packet;

	packet.eh = (struct ether_header *)rawpacket.buf;
	packet.iph = (struct iphdr *)((rawpacket.buf) + sizeof(struct ether_header));
	packet.buf = (char *)(rawpacket.buf + sizeof(struct ether_header) + sizeof(struct iphdr));

	while ((opt = getopt(argc, argv, "i:f:")) != -1) {
		switch (opt) {
		case 'i':
			device = strndup(optarg, PATH_MAX);
			if (!device) {
				fprintf(stderr, "Out of memory, could not copy device\n");
				return -1;
			}
			break;
		case 'f':
			// XXX: No reason to use PATH_MAX here. Decide a real limit.
			rawfilter = strndup(optarg, PATH_MAX);
			if (!rawfilter) {
				fprintf(stderr, "Out of memory, could not copy filter\n");
				return -1;
			}
			break;
		default:
			usage(argv);
			exit(1);
		}	
	}

	if (device == NULL) {
		usage(argv);
		exit(1);
	}

	if (rawfilter != NULL) {
		if (parsefilter() != 0)
			return -1;
	}


	sock = rawsocket(device);
 	if (sock < 0)
 		return 1;

	while (1) {
		if (readpacket(sock, &rawpacket) != 0)
			continue;
		packet.len = rawpacket.len - (sizeof(struct ether_header) + sizeof(struct iphdr));
		if (rawfilter == NULL || filterpacket(&packet, &filter) == Show)
			displaypacket(&packet);
	}
}
