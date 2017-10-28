
LLVM_ROOT ?= /usr
CLANG = $(LLVM_ROOT)/bin/clang
CLANG_LIB = $(LLVM_ROOT)/lib/clang/*

CFLAGS = -I$(CLANG_LIB)/include

SRCS = $(wildcard *.c)
BINS  = $(patsubst %.c,orig.%.out,$(SRCS))
BINS += $(patsubst %.c,opti.%.out,$(SRCS))
BINS += $(patsubst %.c,zero.%.out,$(SRCS))
BINS += $(patsubst %.c,one.%.out,$(SRCS))
BINS += $(patsubst %.c,three.%.out,$(SRCS))

all: $(BINS)

orig.%.out: %.c
	$(CLANG) $(CFLAGS) -O0 -o $@ $<

opti.%.out: %.c
	$(CLANG) $(CFLAGS) -O1 -o $@ $<

zero.%.out: %.c
	$(CLANG) $(CFLAGS) -O0 -o $@ $< -mllvm -fla

one.%.out: %.c
	$(CLANG) $(CFLAGS) -O1 -o $@ $< -mllvm -fla

three.%.out: %.c
	$(CLANG) $(CFLAGS) -O3 -o $@ $< -mllvm -fla

clean:
	rm -f *.fla *.out
