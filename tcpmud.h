struct packet {
	struct sockaddr_in sender;
	socklen_t senderlen;
	char buf[4096];
	int len;
};

int readpacket(int socket, struct packet *p);
int rawsocket(const char *name);
int filterpacket(struct packet *p);
void displaypacket(struct packet *p);
