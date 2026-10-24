# Vecta KMS PKCS#11 module: one shared library, linked only against libcurl.
#   make            build/libvecta-pkcs11.{so,dylib}
#   make check      unit tests (AddressSanitizer, UBSan)
#   make asan       the module and the contract driver with sanitizers
VERSION := $(shell cat ../../VERSION 2>/dev/null || echo dev)
UNAME   := $(shell uname -s)
CC      ?= cc
CURL_CFLAGS := $(shell curl-config --cflags 2>/dev/null)
CURL_LIBS   := $(shell curl-config --libs 2>/dev/null || echo -lcurl)

ifeq ($(UNAME),Darwin)
SO      := libvecta-pkcs11.dylib
SOFLAGS := -dynamiclib -install_name @rpath/$(SO)
DL      :=
else
SO      := libvecta-pkcs11.so
# -Bsymbolic: the function list must point at this module's C_* functions,
# never at another PKCS#11 library's that the process loaded first.
SOFLAGS := -shared -Wl,-Bsymbolic -Wl,-z,relro,-z,now -Wl,--no-undefined
DL      := -ldl
endif

CFLAGS ?= -O2
WARN   := -std=gnu11 -Wall -Wextra -Werror -Wshadow -Wformat=2 -Wstrict-prototypes
DEFS   := -DVECTA_VERSION=\"$(VERSION)\" -Iinclude -Isrc
HARDEN := -fPIC -fvisibility=hidden -fstack-protector-strong -D_FORTIFY_SOURCE=2
SAN    := -g -O1 -fno-omit-frame-pointer -fsanitize=address,undefined -fno-sanitize-recover=undefined
SRC    := src/vecta_p11.c src/kms.c src/json.c src/util.c
HDR    := $(wildcard src/*.h include/*.h)
B      := build

all: $(B)/$(SO)

$(B)/$(SO): $(SRC) $(HDR)
	@mkdir -p $(B)
	$(CC) $(CFLAGS) $(WARN) $(HARDEN) $(DEFS) $(CURL_CFLAGS) $(SOFLAGS) -o $@ $(SRC) $(CURL_LIBS) -lpthread

$(B)/unit: test/unit.c src/json.c src/util.c $(HDR)
	@mkdir -p $(B)
	$(CC) $(SAN) $(WARN) $(DEFS) -o $@ test/unit.c src/json.c src/util.c

check: $(B)/unit
	$(B)/unit

$(B)/p11check: test/p11check.c $(HDR)
	@mkdir -p $(B)
	$(CC) $(CFLAGS) $(WARN) $(DEFS) -o $@ test/p11check.c -lpthread $(DL)

asan: $(SRC) $(HDR) test/p11check.c
	@mkdir -p $(B)/asan
	$(CC) $(SAN) $(WARN) -fPIC -fvisibility=hidden $(DEFS) $(CURL_CFLAGS) $(SOFLAGS) -o $(B)/asan/$(SO) $(SRC) $(CURL_LIBS) -lpthread
	$(CC) $(SAN) $(WARN) $(DEFS) -o $(B)/asan/p11check test/p11check.c -lpthread $(DL)

clean:
	rm -rf $(B)

.PHONY: all check asan clean

# What TestPKCS11AgainstKeycore runs: the module and the driver, with
# sanitizers unless NO_ASAN=1 (musl has no AddressSanitizer).
ifeq ($(NO_ASAN),1)
contract: $(B)/$(SO) $(B)/p11check
	@echo "module: $(B)/$(SO)"
	@echo "driver: $(B)/p11check"
else
contract: asan
	@echo "module: $(B)/asan/$(SO)"
	@echo "driver: $(B)/asan/p11check"
endif
.PHONY: contract
