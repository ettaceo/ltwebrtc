# cryptlib/cryplib.mk
-include config.mk
#CC = arm-linux-gnueabihf-gcc
#AR = arm-linux-gnueabihf-ar
#CC = $(CCPREFIX)gcc
#AR = $(CCPREFIX)ar

ifneq ($(BUILD), release)
  CFLAGS += -g
endif
CFLAGS += -Os -O2 -ffunction-sections -fdata-sections

MODULES=base64 crc hmac md4 md5 prng rc4 sha1 rc5
TARGET=cryptlib.a

all: $(TARGET)

$(TARGET):	$(MODULES:=.o)
	$(AR) rc $@ $^

%.o: %.c %.h
	$(CC) -c $(CFLAGS) $< -o $@

clean:
	rm -f *.o
	rm -f $(TARGET)

.PHONY: all clean
