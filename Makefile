CFLAGS=-Wall -Wextra -pedantic -std=c99 -D_POSIX_C_SOURCE=200809L

default: ethdump

%: %.c
	gcc $(CFLAGS) -c $< -o %@

y.tab.c: parse.y
	yacc parse.y

ethdump: ethdump.c net.o fmt.o filter.o y.tab.o
	gcc $(CFLAGS) net.o fmt.o filter.o y.tab.o ethdump.c -o ethdump

clean:
	rm -f ethdump net.o fmt.o filter.o y.tab.c y.tab.o
