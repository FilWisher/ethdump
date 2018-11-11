#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <net/ethernet.h>

#include "ethdump.h"

/* The type of a function for looking up fields in a packet. */
typedef struct value (*lookup_fn)(struct packet *p);

struct field_ent {
	char *name;
	lookup_fn fn;
};

struct value
ipsrc(struct packet *p)
{
	struct value value;
	if (ntohs(p->eh->ether_type) != ETHERTYPE_IP) {
		value.type = None;
		return value;
	}
	value.type = IP4Addr;
	value.v.ipaddr = ntohl(p->iph->saddr);

	return value;
}

struct value
ipdst(struct packet *p)
{
	struct value value;
	if (ntohs(p->eh->ether_type) != ETHERTYPE_IP) {
		value.type = None;
		return value;
	}
	value.type = IP4Addr;
	value.v.ipaddr = ntohl(p->iph->daddr);

	return value;
}

struct value
ipproto(struct packet *p)
{
	struct value value;
	if (htons(p->eh->ether_type) != ETHERTYPE_IP) {
		value.type = None;
		return value;
	}
	value.type = Number;
	value.v.number = p->iph->protocol;
	return value;
}

struct value
ethsrc(struct packet *p) {
	int i;
	struct value value;

	value.type = EthAddr;
	for (i = 0; i < ETH_ALEN; i++)
		value.v.ethaddr[i] = p->eh->ether_shost[i];

	return value;
}

struct value
ethdst(struct packet *p)
{
	int i;
	struct value value;

	value.type = EthAddr;
	for (i = 0; i < ETH_ALEN; i++)
		value.v.ethaddr[i] = p->eh->ether_dhost[i];

	return value;
}

struct value
ethtype(struct packet *p)
{
	struct value value;
	value.type = Number;
	value.v.number = ntohs(p->eh->ether_type);
	return value;
}

struct field_ent fieldtable[] = {
	{ .name = "ethsrc",  .fn = ethsrc },
	{ .name = "ethdst",  .fn = ethdst },
	{ .name = "ethtype", .fn = ethtype },
	{ .name = "ipsrc",   .fn = ipsrc },
	{ .name = "ipdst",   .fn = ipdst },
	{ .name = "iptype",  .fn = ipproto },
	{ NULL },
};

typedef int (*filter_fn)(struct value *, struct value *);

struct op_ent {
	char *name;
	filter_fn fn;
};

int
notequals(struct value *lhs, struct value *rhs)
{
	int i;

	if (!lhs)
		return !!rhs;
	
	if (lhs->type != rhs->type)
		return 1;

	switch (lhs->type) {
	case None:
		return 0;
	case Number:
		return lhs->v.number != rhs->v.number;
	case EthAddr:
		for (i = 0; i < ETH_ALEN; i++)
			if (lhs->v.ethaddr[i] == rhs->v.ethaddr[i])
				return 0;
		return 1;
	case IP4Addr:
		return lhs->v.ipaddr != rhs->v.ipaddr;
	}

	return 0;
}


int
equals(struct value *lhs, struct value *rhs)
{
	int i;

	if (!lhs)
		return lhs == rhs;
	
	if (lhs->type != rhs->type)
		return 0;

	switch (lhs->type) {
	case None:
		return 1;
	case Number:
		return lhs->v.number == rhs->v.number;
	case EthAddr:
		for (i = 0; i < ETH_ALEN; i++)
			if (lhs->v.ethaddr[i] != rhs->v.ethaddr[i])
				return 0;
		return 1;
	case IP4Addr:
		return lhs->v.ipaddr == rhs->v.ipaddr;
	}

	return 0;
}

struct op_ent optable[] = {
	{ .name = "==", .fn = equals },
	{ .name = "!=", .fn = notequals },
	{ NULL },
};

void
printvalue(struct value value)
{
	int i;
	switch (value.type) {
	case Number:
		printf("%d", value.v.number);
		break;
	case EthAddr:
		for (i = 0; i < ETH_ALEN; i++) {
			printf("%x", value.v.ethaddr[i]);
			if (i < ETH_ALEN - 1)
				printf(":");
		}
		break;
	}
}


/* Determine whether the packet should be filtered or not. */
int
filterpacket(struct packet *p, struct filter *f)
{
	struct value value;
	lookup_fn lookup = NULL;
	filter_fn filter = NULL;
	
	struct field_ent *fp;
	struct op_ent *op;

	if (!f)
		return Show;
	
	for (fp = fieldtable; fp->name != NULL; fp++) {
		if (strcmp(fp->name, f->field) == 0) {
			lookup = fp->fn;
			break;
		}
	}

	if (!lookup) {
		fprintf(stderr, "Unrecognized field: %s\n", f->field);
		return Error;
	}

	for (op = optable; op->name != NULL; op++) {
		if (strcmp(op->name, f->op) == 0) {
			filter = op->fn;
			break;
		}
	}

	if (!filter) {
		fprintf(stderr, "Unrecognized operator: %s\n", f->op);
		return Error;
	}

	value = lookup(p);
	if (filter(&value, &f->value))
		return Show;

	return Ignore;
}
