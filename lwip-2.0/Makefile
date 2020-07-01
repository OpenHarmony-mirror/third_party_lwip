include $(LITEOSTOPDIR)/config.mk

ARFLAGS = cr
LIBOUT = $(BUILD)/net/lwip
LIB = $(OUT)/lib/liblwip.a
DIR = $(LIBOUT)/src/arch $(LIBOUT)/src/core/snmp $(LIBOUT)/src/netif $(LIBOUT)/src/api $(LIBOUT)/src/core/ipv4 $(LIBOUT)/src/core/ipv6

LITEOS_PLATFORM_CPU = $(subst /,_,$(LITEOS_PLATFORM))

LIBTCP = src/core/liblwip_tcp_$(LITEOS_CPU_TYPE).a
RM = -rm -rf

LOCAL_INCLUDE := \
        -I $(LITEOSTOPDIR)/kernel/base/include \

# user manul
# ENABLE_LWIP_SACKLIB=n: build the tcp objects from tcp source files.
# ENABLE_LWIP_SACKLIB=y: build the tcp objects from prebuild src/core/liblwip_tcp_$(LITEOS_CPU_TYPE).a library.
# ENABLE_LWIP_SACKLIB=m: build the tcp objects from tcp source files, meanwhile build a src/core/liblwip_tcp_$(LITEOS_CPU_TYPE).a library for customer use.
ENABLE_LWIP_SACKLIB=n

SRCS_FILES = $(wildcard src/arch/*.c) $(wildcard src/api/*.c) $(wildcard src/core/*.c) \
			$(wildcard src/core/ipv4/*.c) $(wildcard src/core/ipv6/*.c) $(wildcard src/netif/*.c)

SRCS_EXCLUDE = $(wildcard src/netif/ethernetif.c)

SRCS = $(filter-out $(SRCS_EXCLUDE) $(TCPSRCS) src/core/tftpc.c, $(SRCS_FILES))

ifeq ($(strip $(LOSCFG_NET_LWIP_SACK_TFTP)),y)
   SRCS += $(wildcard src/core/tftpc.c)
endif
OBJS = $(patsubst %.c,$(LIBOUT)/%.o,$(SRCS))

ifeq ($(strip $(LOSCFG_TEST_LWIP)), y)
LITEOS_LWIP_CFLAGS  := -DLWIP_TESTBED
endif

LITEOS_LWIP_CFLAGS  += -DLWIP_NOASSERT

ifeq ($(strip $(ENABLE_LWIP_SACKLIB)), m)
LITEOS_LWIP_CFLAGS  += -DLWIP_SACK=1 -DLWIP_WND_SCALE=0
TCPSRCS = src/core/tcp.c src/core/tcp_in.c src/core/tcp_out.c src/core/tcp_sack.c
TCPOBJS = $(patsubst %.c,$(LIBOUT)/%.o,$(TCPSRCS))
$(TCPOBJS): $(LIBOUT)/%.o : %.c
	@$(CC) $(LITEOS_CFLAGS) $(LITEOS_LWIP_CFLAGS) $(LOCAL_INCLUDE) -c $< -o $@

tcplib:	$(TCPOBJS)
	@$(AR) $(ARFLAGS) $(LIBTCP) $(TCPOBJS)

else ifeq ($(strip $(ENABLE_LWIP_SACKLIB)), n)
LITEOS_LWIP_CFLAGS  += -DLWIP_SACK=1 -DLWIP_WND_SCALE=0
TCPSRCS = src/core/tcp.c src/core/tcp_in.c src/core/tcp_out.c src/core/tcp_sack.c
TCPOBJS = $(patsubst %.c,$(LIBOUT)/%.o,$(TCPSRCS))
$(TCPOBJS): $(LIBOUT)/%.o : %.c
	@$(CC) $(LITEOS_CFLAGS) $(LITEOS_LWIP_CFLAGS) $(LOCAL_INCLUDE) -c $< -o $@
.PHONY: tcplib
tcplib:	$(TCPOBJS)

else ifeq ($(strip $(ENABLE_LWIP_SACKLIB)), y)
LITEOS_LWIP_CFLAGS  += -DLWIP_SACK=1 -DLWIP_WND_SCALE=0
TCPSRCS = src/core/tcp.c src/core/tcp_in.c src/core/tcp_out.c src/core/tcp_sack.c
TCPOBJS = $(patsubst %.c,$(LIBOUT)/%.o,$(TCPSRCS))
.PHONY: TCPOBJS_AR
TCPOBJS_AR: $(DIR) $(LIBTCP)
	$(AR) -x -o $(LIBTCP)
	mv  *.o $(LIBOUT)/src/core/
$(TCPOBJS): TCPOBJS_AR
.PHONY: tcplib
tcplib:	$(TCPOBJS)
endif

all: $(DIR) $(LIB)

$(OBJS): $(LIBOUT)/%.o : %.c
	@$(CC) $(LITEOS_CFLAGS) $(LITEOS_LWIP_CFLAGS) $(LOCAL_INCLUDE) -c $< -o $@

$(LIB):  tcplib $(OBJS)
	@$(AR) $(ARFLAGS) $@ $(OBJS) $(TCPOBJS)

$(DIR):
	mkdir -p $@

clean:
	@$(RM) $(LIBOUT)  $(LIB)  $(OBJS) $(TCPOBJS) *.bak *.o *~

.PHONY: all clean
