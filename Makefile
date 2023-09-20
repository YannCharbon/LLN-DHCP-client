# Flags
CC=/usr/bin/gcc
RM=rm -f
# Select all entries in current directory
# -> get all entries with a trailing / (corresponds to directories only)
# -> replace "/" by "" to remove trailing "/"
INCDIRS=$(subst /,,$(filter %/,$(wildcard */)))
#INC=-I. -IISM3_Linux -IWPAN -INetwork -IProtocol -ItestMenu -IRouter -Icse_protocol_gateway
INC=-I. $(INCDIRS:%=-I%)
CFLAGS=-c $(INC) -g
LDFLAGS=-lpthread
LDLIBS=

SRC_DIR=.
SRCS_C=$(wildcard $(SRC_DIR)/*.c)
OBJS_C=$(SRCS_C:.c=.o)
OUT=lln-dhcp-client

all: $(OUT)


# Rule for compiling C source files
%.o: %.c
	$(CC) $(LDFLAGS) $(CFLAGS) $< -o $@

$(OUT): $(OBJS_C) $(OBJS_CPP)
	$(CC) $(LDFLAGS) -o $(OUT) $(OBJS_C) $(LDLIBS)

clean:
	$(RM) $(OBJS_C)
	$(RM) $(OUT)
