%{
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#include <net/ethernet.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>

#include "ethdump.h"

#define MAXBUF (1024)

/* Wraps a char * to be used as a source for lexing. */
struct stringsource {
	/* Current position in data */ 
	size_t pos;
	/* Raw string being parsed */
	char *data;

	/* Buffer for ungetting characters */
	char buf[64];
	/* Pointer into current position of buf */
	char *b;
};

typedef struct {
    union {
	char *string;
	struct value value;
    } v;
} yystype;

#define YYSTYPE yystype

FILE *yyfp;

void yyerror(const char *, ...);
int yylex(void);

typedef struct person person;

extern char *rawfilter;
struct stringsource src = {
	.pos = 0,
	.data = NULL,
};

struct filter filter;

%}

%token <v.value.v.addr> ADDR
%token <v.string> IDENTIFIER
%token <v.string> OPERATOR
%type <v.string> op
%type <v.string> field
%type <v.value> value

%%

top:		field op value {
   			filter.field = $1;
   			filter.op = $2;
			filter.value = $3;
		};

filter:		  /* empty */
      		| field op value
		| field op
		;

field:		IDENTIFIER;
op:		OPERATOR;
value: 	    	ADDR {
     			int i;
			for (i = 0; i < ETH_ALEN; i++)
				$$.v.addr[i] = $1[i];  
		};

%%

int
getch(struct stringsource *src)
{
	int c;
	
	if (src->b > src->buf) {
		c = *--src->b;
		return c;
	}

	if (src->data[src->pos] == '\0')
		return EOF;
	
	c = src->data[src->pos];
	src->pos++;
	return c;
}

void
ungetch(int c, struct stringsource *src)
{
	if (src->b == src->buf + sizeof(src->buf)) {
		yyerror("Attempted to unget too many characters");
		return;
	}
	*src->b++ = c;
}

void
error(const char *fmt, ...)
{
	va_list va;

	fprintf(stderr, "parse: ");
	va_start(va, fmt);
	vfprintf(stderr, fmt, va);
	fprintf(stderr, "\n");
	va_end(va);
	exit(1);
}

void
yyerror(const char *fmt, ...)
{
	va_list va;

	fprintf(stderr, "parse: ");
	va_start(va, fmt);
	vfprintf(stderr, fmt, va);
	fprintf(stderr, "\n");
	va_end(va);
}

int
yylex(void)
{   
	char buf[MAXBUF];
	char *p, *end;
	int c, i, j;

	p = buf;
	end = buf + MAXBUF;

	while ((c = getch(&src)) == ' ' || c == '\t')
		; /* nothing */
	if (c == EOF || c == '\0')
		return 0;
	ungetch(c, &src);

	// Attempt to parse MAC address
	for (i = 0; i < ETH_ALEN; i++) {
		p = buf;

		for (j = 0; j < 2; j++) {
			if ((c = getch(&src)) == EOF) {
				yyerror("Incomplete MAC address");
				return 1;
			}
			if (!isxdigit(c)) {
				if (i == 0) {
					while (p > buf)
						ungetch(*--p, &src);
					ungetch(c, &src);
					goto identifier;
				} else {
					yyerror("Not a valid MAC address");
					return 1;
				}
			}
			*p++ = c;
		}

		*p = '\0';
		yylval.v.value.type = Address;
		yylval.v.value.v.addr[i] = strtol(buf, NULL, 16);

		if (i != ETH_ALEN - 1 && (c = getch(&src)) != ':') {
			yyerror("Not a valid MAC address, expecting ':'");
			return 1;
		}
	}
	return ADDR;

identifier:
	while ((c = getch(&src)) != EOF && (isalnum(c) || c == '.')) {
		if (p + 1 >= end) {
			yyerror("identifier too long");
			return -1;
		}
		*p++ = c;
	}
	ungetch(c, &src);

	if (p > buf) {
		*p = '\0';
		yylval.v.string = strndup(buf, MAXBUF);
		return IDENTIFIER;
	}
		
	// operators
	switch (c = getch(&src)) {
	case '!':
	case '<':
	case '=':
	case '>':
		*p++ = c;
		while ((c = getch(&src)) != EOF && c != ' ') {
			if (p + 1 >= end) {
				yyerror("Operator too long");
				return -1;
			}
			*p++ = c;
		}
		ungetch(c, &src);
		*p = '\0';
		yylval.v.string = strndup(buf, MAXBUF);
		return OPERATOR;
	}

	return -1;
}

int
parsefilter()
{
	src.data = rawfilter;
	src.b = src.buf;
	
	return yyparse();
}
