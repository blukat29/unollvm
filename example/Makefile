
LLVM_ROOT ?= /usr
CLANG = $(LLVM_ROOT)/bin/clang
CLANG_LIB = $(LLVM_ROOT)/lib/clang/*

CFLAGS = -I$(CLANG_LIB)/include

SRCS = $(wildcard *.c)
BINS = $(SRCS:.c=.fla)

all: $(BINS)

%.fla: %.c
	$(CLANG) $(CFLAGS) -o $@ $< -mllvm -fla

clean:
	rm -f *.fla
