CC      = gcc
CFLAGS  = -Wall -Wextra -O2 -fPIE -fstack-protector-strong \
          -D_FORTIFY_SOURCE=2
LDFLAGS = -pie -Wl,-z,relro,-z,now
LIBS    = -lncurses -lsodium

BIN     = gpggrid
BIN_DIR = /usr/local/bin

.PHONY: all clean install

all: $(BIN)

$(BIN): gpggrid.c
	$(CC) $(CFLAGS) -o $@ $< $(LIBS) $(LDFLAGS)

install: $(BIN)
	install -d $(DESTDIR)$(BIN_DIR)
	install -m 0755 $(BIN) $(DESTDIR)$(BIN_DIR)/

clean:
	rm -f $(BIN)
