#
#

LIBS = $(wildcard bpf*) $(wildcard tool*)
.PHONY: clean $(LIBS)

all: $(LIBS)

$(LIBS):
	$(MAKE) -C $@

clean:$(LIBS)
	$(MAKE) -C $< clean

