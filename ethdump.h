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
	None,
	EthAddr,
	IP4Addr,
	Number,
};

struct value {
	int type;
	union {
		uint8_t ethaddr[ETH_ALEN];
		uint32_t ipaddr;
		int number;
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
void displayip4addr(uint32_t ip);
int parsefilter();
void printvalue(struct value value);
void error(const char *fmt, ...);
