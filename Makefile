# omemo.hdll: the natives of hxomemo for HashLink (bytecode); HashLink/C builds compile native/omemo.c themselves.
#
# Needs the HashLink sources (hl.h, and the mbedtls 3 bundled with them), e.g.:
#   make HASHLINK_SRC=~/dev/norc/lib/hashlink
#
#   make          omemo.hdll
#   make install  into $(PREFIX)/lib (/usr/local/lib: next to HashLink's hdlls, where hl finds them)
#   make test     run the tests (HashLink)
#   make interop  with python-oldmemo (VENV: a python venv with `pip install 'oldmemo[xml]'`)

HASHLINK_SRC ?= ../hashlink
HL_INC ?= $(HASHLINK_SRC)/src
HL_LIB ?= /usr/local/lib
BUILD := build

CFLAGS := -O2 -fPIC -ffunction-sections -fdata-sections -std=c11 -Wall
MBEDTLS_INC := -I$(HASHLINK_SRC)/libs/ssl -I$(HASHLINK_SRC)/include/mbedtls/include \
	-DMBEDTLS_USER_CONFIG_FILE=\"mbedtls_user_config.h\"
MBEDTLS_SRC := $(wildcard $(HASHLINK_SRC)/include/mbedtls/library/*.c)
MBEDTLS_OBJ := $(patsubst $(HASHLINK_SRC)/include/mbedtls/library/%.c,$(BUILD)/mbedtls/%.o,$(MBEDTLS_SRC))
OMEMO_OBJ := $(BUILD)/omemo.o $(BUILD)/monocypher.o $(BUILD)/monocypher-ed25519.o

ifeq ($(shell uname -s),Darwin)
LDFLAGS := -shared -Wl,-dead_strip
else
LDFLAGS := -shared -Wl,--gc-sections
endif

.PHONY: all install test interop clean
PREFIX ?= /usr/local
VENV ?= venv
all: omemo.hdll

$(HL_INC)/hl.h:
	@echo "HashLink sources not found in $(HASHLINK_SRC): set HASHLINK_SRC" >&2
	@exit 1

$(BUILD)/mbedtls/%.o: $(HASHLINK_SRC)/include/mbedtls/library/%.c | $(HL_INC)/hl.h
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -fvisibility=hidden $(MBEDTLS_INC) -c $< -o $@

$(BUILD)/libmbedtls.a: $(MBEDTLS_OBJ)
	$(AR) rcs $@ $^

$(BUILD)/omemo.o: native/omemo.c | $(HL_INC)/hl.h
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -I$(HL_INC) $(MBEDTLS_INC) -c $< -o $@

$(BUILD)/%.o: native/monocypher/%.c
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -fvisibility=hidden -c $< -o $@

omemo.hdll: $(OMEMO_OBJ) $(BUILD)/libmbedtls.a
	$(CC) $(LDFLAGS) -o $@ $(OMEMO_OBJ) $(BUILD)/libmbedtls.a -L$(HL_LIB) -lhl -lpthread

install: omemo.hdll
	install -d $(DESTDIR)$(PREFIX)/lib
	install -m 755 omemo.hdll $(DESTDIR)$(PREFIX)/lib/

test: omemo.hdll
	haxe test.hxml
	LD_LIBRARY_PATH=$(CURDIR):$(HL_LIB) hl test.hl

interop: omemo.hdll
	haxe peer.hxml
	LD_LIBRARY_PATH=$(CURDIR):$(HL_LIB) $(VENV)/bin/python -I test/interop.py hl test/peer.hl

clean:
	rm -rf $(BUILD) omemo.hdll test.hl test/peer.hl
