ODIR = bin
create_bin := $(shell mkdir -p $(ODIR))

SRCS = $(wildcard *.c)
PROGS = $(patsubst %.c, %, $(SRCS))
all: $(PROGS)

%: %.c
	$(CC) $(CFLAGS) -o $(ODIR)/$@ $< -lcap
