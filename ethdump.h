struct rawpacket {
	char buf[1024];
	int len;
};

struct packet {
	struct ether_header *eh;
	struct iphdr *iph;
	char *buf;
	int len;
};

int readpacket(int socket, struct rawpacket *p);
int rawsocket(const char *name);
int filterpacket(struct packet *p);
void displaypacket(struct packet *p);
