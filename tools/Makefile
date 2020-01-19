# makefile
#

KSRC=       $(HOME)/linux

CFLAGS+=	-std=gnu99 -Wall -Wextra
CFLAGS+=	-D_GNU_SOURCE -D_DEFAULT_SOURCE -D__EXPORTED_HEADERS__
CFLAGS+=	-I../include -Wno-unused-parameter


#kernel
BPF_DIR = $(KSRC)/tools/lib/bpf/
LIBBPF = $(BPF_DIR)libbpf.a
CFLAGS+= -I$(KSRC)/kernel/bpf/ \
	-I$(KSRC)/tools/include/uapi \
	-I$(KSRC)/tools/include \
	-I$(KSRC)/tools/lib/bpf \
	-I$(KSRC)/tools/perf

LIBS =  -lelf $(LIBBPF) -pthread -lrt
NODEBUG=	$(L4NODEBUG)
CFLAGS+=	-g -ggdb3 -DDEBUG -fno-omit-frame-pointer

all: xdp_sock xdp_sample xdp_redirect xdp_proto xdp_dump xdp_stats install

obj: $(OBJS)

lib: $(LIBNAME).la

%.lo: %.c
	libtool --mode=compile --tag CC $(CC) $(CFLAGS) -c $<

xdp_sock: xdp_sock.o
	libtool --mode=link --tag CC $(CC) $(LDFLAGS) $(LIBS) -o xdp_sock $(notdir $^)

xdp_sample: xdp_sample.o
	libtool --mode=link --tag CC $(CC) $(LDFLAGS) $(LIBS) -o xdp_sample $(notdir $^)
	
xdp_redirect: xdp_redirect.o
	libtool --mode=link --tag CC $(CC) $(LDFLAGS) $(LIBS) -o xdp_redirect $(notdir $^)

xdp_proto: xdp_proto.o
	libtool --mode=link --tag CC $(CC) $(LDFLAGS) $(LIBS) -o xdp_proto $(notdir $^)

xdp_dump: xdp_dump.o
	libtool --mode=link --tag CC $(CC) $(LDFLAGS) $(LIBS) -o xdp_dump $(notdir $^)

xdp_stats: xdp_stats.o
	libtool --mode=link --tag CC $(CC) $(LDFLAGS) $(LIBS) -o xdp_stats $(notdir $^)

clean:
	#libtool --mode=clean rm
	@rm -rf .libs *.o *.lo *.la xdp_sock xdp_sample xdp_redirect xdp_proto xdp_stats

install:
	@cp -f xdp_sock xdp_sample xdp_redirect xdp_proto xdp_dump xdp_stats ../dist

.PHONY: all obj lib install
