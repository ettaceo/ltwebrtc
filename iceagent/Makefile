# iceagent/Makefile

# pass build directive to submakes
export BUILD

SHELL = /bin/sh
#CC = $(CCPREFIX)gcc
#AR = $(CCPREFIX)ar
ifneq ($(BUILD), release)
  CCOPTS += -g
endif
CCOPTS += -Wall -O2 -pthread -std=gnu11 -Wno-missing-braces -Wno-strict-aliasing
CFLAGS += $(CCOPTS) -I../local/include
LDFLAGS= -L../local/lib -l:cryptlib.a -l:ts-demux.a -lcrypto -lssl -ldl -lrt -lm
MODULES = stun5389.o dtls5764.o sipagent.o x509cert.o ecdheapi.o aessuite.o \
          srtp3711.o mediartp.o sctp4960.o sctpdata.o tsplayer.o qtplayer.o

all : iceagent

%.o : %.c
	$(CC) $(CFLAGS) -o $@ -c $<

iceagent : iceagent.o  $(MODULES)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

x509cert : x509cert.c
	$(CC) $(CFLAGS) -DLOCAL_BUILD -o $@ $^ $(LDFLAGS)

ecdheapi : ecdheapi.c
	$(CC) $(CFLAGS) -DLOCAL_BUILD -o $@ $^ $(LDFLAGS)

aessuite : aessuite.c
	$(CC) $(CFLAGS) -DLOCAL_BUILD -o $@ $^ $(LDFLAGS)

srtp3711 : srtp3711.c
	$(CC) $(CFLAGS) -DLOCAL_BUILD -o $@ $^ $(LDFLAGS)

mediartp : mediartp.c srtp3711.o ts-demux.o msdbuser.o
	$(CC) $(CFLAGS) -DLOCAL_BUILD -o $@ $^ $(LDFLAGS)

sctp4960 : sctp4960.c
	$(CC) $(CFLAGS) -DLOCAL_BUILD -o $@ $^ $(LDFLAGS)

turn5766 : turn5766.c stun5389.o
	$(CC) $(CFLAGS) -DLOCAL_BUILD -o $@ $^ $(LDFLAGS)

clean:
	rm -f iceagent x509cert ecdheapi aessuite srtp3711 sctp4960 sctpdata \
	      mediartp turn5766 *.o
