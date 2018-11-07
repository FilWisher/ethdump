CFLAGS=-Wall -Wextra -pedantic -std=c99 -D_POSIX_C_SOURCE=200809L

default: tcpmud

%: %.c
	gcc $(CFLAGS) -c $< -o %@

tcpmud: tcpmud.c net.o fmt.o filter.o
	gcc $(CFLAGS) net.o fmt.o filter.o tcpmud.c -o tcpmud

clean:
	rm -f tcpmud net.o fmt.o filter.o
