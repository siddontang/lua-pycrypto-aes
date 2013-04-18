PYCRYPTO_AES_VERSION = 0.1
LUA_VERSION =   5.1

# See http://lua-users.org/wiki/BuildingModules for platform specific
# details.

## Linux/BSD
PREFIX  ?=          /usr/local/openresty
LDFLAGS +=         -shared

## OSX (Macports)
#PREFIX ?=          /opt/local
#LDFLAGS +=         -bundle -undefined dynamic_lookup

LUA_INCLUDE_DIR ?= $(PREFIX)/luajit/include/luajit-2.0
LUA_LIB_DIR ?=     $(PREFIX)/lualib

# Some versions of Solaris are missing isinf(). Add -DMISSING_ISINF to
# CFLAGS to work around this bug.

#CFLAGS ?=          -g -Wall -pedantic -fno-inline
CFLAGS ?=          -g -O3 -Wall -pedantic
override CFLAGS += -fpic -I$(LUA_INCLUDE_DIR) -DVERSION=\"$(PYCRYPTO_AES_VERSION)\"

INSTALL ?= install

.PHONY: all clean install

all: pycrypto_aes.so

pycrypto_aes.so: lua_pycrypto_aes.o aes.o
	$(CC) $(LDFLAGS) -o $@ $^

install:
	$(INSTALL) -d $(LUA_LIB_DIR)
	$(INSTALL) pycrypto_aes.so $(LUA_LIB_DIR) 

clean:
	rm -f *.o *.so


