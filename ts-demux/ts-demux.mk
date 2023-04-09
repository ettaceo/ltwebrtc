# ts-demux/ts-demux.mk
-include config.mk
#CC = arm-linux-gnueabihf-gcc
#AR = arm-linux-gnueabihf-ar
#CC = $(CCPREFIX)gcc
#AR = $(CCPREFIX)ar

ifneq ($(BUILD), release)
  CFLAGS += -g
endif
CFLAGS += -Os -O2 -ffunction-sections -fdata-sections

MODULES=ts-demux
TARGET=ts-demux.a

all: $(TARGET)

$(TARGET):	$(MODULES:=.o)
	$(AR) rc $@ $^

%.o: %.c %.h
	$(CC) -c $(CFLAGS) $< -o $@

clean:
	rm -f *.o
	rm -f $(TARGET)

.PHONY: all clean
