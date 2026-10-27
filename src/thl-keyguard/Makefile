CC      = gcc
CFLAGS  = -Wall -Wextra -Werror -O2 -fPIE -fstack-protector-strong \
          -D_FORTIFY_SOURCE=2 -fno-strict-aliasing
LDFLAGS = -pie -Wl,-z,relro,-z,now

BIN     = thl-keyguard
LIBS    = -lsodium -lkeyutils

BIN_DIR = /usr/local/sbin

.PHONY: all clean install

all: $(BIN)

$(BIN): thl-keyguard.c
	$(CC) $(CFLAGS) -o $@ $< $(LIBS) $(LDFLAGS)

install: $(BIN)
	install -d $(DESTDIR)$(BIN_DIR)
	install -m 0755 $(BIN) $(DESTDIR)$(BIN_DIR)/

clean:
	rm -f $(BIN)
