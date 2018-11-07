CFLAGS=-Wall -Wextra -pedantic -std=c99 -D_POSIX_C_SOURCE=200809L

default: ethdump

%: %.c
	gcc $(CFLAGS) -c $< -o %@

ethdump: ethdump.c net.o fmt.o filter.o
	gcc $(CFLAGS) net.o fmt.o filter.o ethdump.c -o ethdump

clean:
	rm -f ethdump net.o fmt.o filter.o
