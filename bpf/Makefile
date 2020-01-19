src := $(HOME)/linux

DEBUGBPF = -DDEBUG
DEBUGFLAGS = -O0 -g -Wall
PFLAGS = $(DEBUGFLAGS)

#INCLUDEFLAGS = -I$(src)/usr/include \
#	       -I$(src)/include \
#	       -I/usr/include/bpf \
#	       -I$(src)/tools/testing/selftests/bpf

INCLUDEFLAGS = -I$(src)/usr/include \
	       -I$(src)/include \
	       -I$(src)/tools/testing/selftests/bpf

kfiles = xdp_proto_kern.o
kfiles += xdp_redirect_kern.o
kfiles += xdp_sample_kern.o
kfiles += xdp_dump_kern.o
kfiles += xdp_stats_kern.o

HOSTCFLAGS += $(INCLUDEFLAGS) $(PFLAGS)


LLC ?= llc
CLANG ?= clang

# Trick to allow make to be run from this directory
all: $(kfiles)
	@cp -f *.o ../dist
	
clean:
	@rm -f *.o

%.o: %.c
	$(CLANG) $(INCLUDEFLAGS) $(EXTRA_CFLAGS) \
	$(DEBUGBPF) -D__KERNEL__ -Wno-unused-value -Wno-pointer-sign \
		-Wno-compare-distinct-pointer-types \
		-O2 -emit-llvm -c -g $< -o -| $(LLC) -march=bpf -filetype=obj -o $@


