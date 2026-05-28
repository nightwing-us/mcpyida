# tests/fixtures/Makefile
#
# Builds test binary fixtures. Run from this directory:
#   make all
#
# Binaries are committed to the repo so CI doesn't need gcc.

CC = gcc
CFLAGS_CRACKME = -no-pie -O0
CFLAGS_TYPED = -g -no-pie -O0

all: crackme.elf typed_fixture.elf

crackme.elf: crackme.c
	$(CC) $(CFLAGS_CRACKME) -o $@ $<
	@echo "Built $@ ($(shell wc -c < $@) bytes)"

typed_fixture.elf: typed_fixture.c
	$(CC) $(CFLAGS_TYPED) -o $@ $<
	@echo "Built $@ ($(shell wc -c < $@) bytes)"

clean:
	rm -f crackme.elf typed_fixture.elf

.PHONY: all clean
