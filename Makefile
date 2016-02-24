PROFTPD_PREFIX ?= /home/jbenden/src/proftpd-1.3.5a
PROFTPD_TEST_BIN = $(PROFTPD_PREFIX)/proftpd
MODCLAMAV_T = t/modules/mod_clamav.t
CP = cp

all: copy

tests: $(PROFTPD_TEST_BIN) $(MODCLAMAV_T) build
	/usr/bin/env "PROFTPD_TEST_BIN=$(PROFTPD_TEST_BIN)" \
		perl -I $(PROFTPD_PREFIX)/tests/t/lib $(MODCLAMAV_T)

copy: $(PROFTPD_PREFIX)/contrib mod_clamav.h mod_clamav.c
	$(CP) mod_clamav.c $(PROFTPD_PREFIX)/contrib
	$(CP) mod_clamav.h $(PROFTPD_PREFIX)/contrib
	touch $@

build: $(PROFTPD_PREFIX)/configure copy
	( cd $(PROFTPD_PREFIX); \
	./configure --with-modules=mod_clamav:mod_vroot; \
	$(MAKE); ); \
	touch $@

clean:
	rm -f build copy

.PHONY: clean all
