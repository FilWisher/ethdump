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

enum {
	Address,
	Number,
};

struct value {
	int type;
	union {
		int number;
		uint8_t addr[ETH_ALEN];
	} v;
};

enum {
	Show,
	Ignore,
	Error,
};

struct filter {
	char *field;
	char *op;
	struct value value;
};

int readpacket(int socket, struct rawpacket *p);
int rawsocket(const char *name);
int filterpacket(struct packet *p, struct filter *f);
void displaypacket(struct packet *p);
int parsefilter();
void printvalue(struct value value);
void error(const char *fmt, ...);
