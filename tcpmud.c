#include <stdio.h>
#include <unistd.h>
#include <limits.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "tcpmud.h"

void
usage(char * const *argv)
{
	fprintf(stderr, "Usage: %s -i interface\n",
		argv[0]);
}

int
main(int argc, char * const *argv)
{
	int opt;
	const char *device = NULL;

	struct packet packet;

	while ((opt = getopt(argc, argv, "i:")) != -1) {
		switch (opt) {
		case 'i':
			device = strndup(optarg, PATH_MAX);
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

	int s = rawsocket(device);
 	if (s < 0)
 		return 1;

	while (1) {
		packet.len = readpacket(s, &packet);
		if (!filterpacket(&packet))
			displaypacket(&packet);
	}
}
