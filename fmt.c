#include <stdio.h>
#include <netinet/in.h>

#include "tcpmud.h"

// Display the packet according to a specification.
void
displaypacket(struct packet *p)
{
	printf("Got a packet of length: %d\n", p->len);	
}
