CC      = gcc
CFLAGS  = -O2 -Wall -Wextra
TARGET  = bastille-dsm-config
PREFIX  = /usr/local/sbin

$(TARGET): bastille-dsm-config.c
	$(CC) $(CFLAGS) -o $(TARGET) bastille-dsm-config.c

install: $(TARGET)
	install -o root -g root -m 4750 $(TARGET) $(PREFIX)/$(TARGET)

clean:
	rm -f $(TARGET)
