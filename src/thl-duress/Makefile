CC      = gcc
CFLAGS  = -Wall -Wextra -Werror -O2 -fPIC -fstack-protector-strong \
          -D_FORTIFY_SOURCE=2 -fno-strict-aliasing
LDFLAGS = -Wl,-z,relro,-z,now

PAM_MODULE = pam_thl_duress.so
SETUP_BIN  = thl-duress-setup

PAM_LIBS   = -lpam -lsodium
SETUP_LIBS = -lsodium

PAM_DIR    = /lib/$(shell dpkg-architecture -qDEB_HOST_MULTIARCH 2>/dev/null \
               || echo x86_64-linux-gnu)/security
BIN_DIR    = /usr/local/sbin
CONF_DIR   = /etc/thl

.PHONY: all clean install

all: $(PAM_MODULE) $(SETUP_BIN)

$(PAM_MODULE): pam_thl_duress.c
	$(CC) $(CFLAGS) -shared -o $@ $< $(PAM_LIBS) $(LDFLAGS)

$(SETUP_BIN): thl-duress-setup.c
	$(CC) $(CFLAGS) -o $@ $< $(SETUP_LIBS) $(LDFLAGS)

install: all
	install -d $(DESTDIR)$(PAM_DIR)
	install -m 0644 $(PAM_MODULE) $(DESTDIR)$(PAM_DIR)/
	install -d $(DESTDIR)$(BIN_DIR)
	install -m 0755 $(SETUP_BIN) $(DESTDIR)$(BIN_DIR)/
	install -d $(DESTDIR)$(CONF_DIR)
	chmod 0700 $(DESTDIR)$(CONF_DIR)

clean:
	rm -f $(PAM_MODULE) $(SETUP_BIN)
