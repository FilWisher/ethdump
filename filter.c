#include <netinet/in.h>

#include "ethdump.h"

enum {
	Show,
	Ignore,
};

// Determine whether the packet should be filtered or not.
int
filterpacket(struct packet *p)
{
	if (p->len == 0)
		return Ignore;

	return Show;
}
