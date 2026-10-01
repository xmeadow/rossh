# rossh — an SSH server for ReactOS.
#
#   make            native build (Linux) — the development loop
#   make win32      32-bit Windows build for ReactOS
#   make clean
#
# The vendored wolfSSL/wolfSSH are built out-of-tree into build/<flavor>/prefix
# by tools/build-deps.sh, from the pinned submodules in third_party/. The first
# run takes a few minutes; later runs reuse it.

CC      ?= gcc
WINCC   ?= i686-w64-mingw32-gcc
JOBS    ?= 8

FLAVOR  ?= native
BUILD   ?= build/$(FLAVOR)
PREFIX  ?= $(BUILD)/prefix

CC_BIN  ?= $(CC)
EXE     ?=

SRC     = $(wildcard src/*.c)

# WC_RNG_SEED_CB has to match how wolfSSL was configured (tools/build-deps.sh):
# it removes wolfSSL's own seeding, so all key material comes from src/rng.c.
# _POSIX_C_SOURCE: -std=c11 is strict ISO C, which hides clock_gettime from the
# native build. Ignored on Windows.
CFLAGS  = -std=c11 -Wall -Wextra -O2 -DWC_RNG_SEED_CB -D_POSIX_C_SOURCE=200809L \
          -I$(PREFIX)/include -Ibuild/shim

# DEBUG=1 turns on wolfSSH's internal tracing. The dependencies have to be built
# with the same define or the calls compile out:
#   make deps EXTRA_CPPFLAGS=-DDEBUG_WOLFSSH && make DEBUG=1
DEBUG ?= 0
ifeq ($(DEBUG),1)
CFLAGS += -DDEBUG_WOLFSSH
endif

LDLIBS_native = -lwolfssh -lwolfssl -lm
# crypt32: wolfSSL's X.509 store code. advapi32: CryptGenRandom in src/rng.c.
LDLIBS_win32  = -lwolfssh -lwolfssl -lws2_32 -lcrypt32 -ladvapi32
LDLIBS        = $(LDLIBS_$(FLAVOR))

.PHONY: all win32 clean deps

all:
	@$(MAKE) --no-print-directory binary

win32:
	@$(MAKE) --no-print-directory FLAVOR=win32 CC_BIN=$(WINCC) EXE=.exe binary

binary: $(PREFIX)/.deps $(SRC)
	$(CC_BIN) $(CFLAGS) $(SRC) -o rossh$(EXE) -L$(PREFIX)/lib $(LDLIBS)
	@echo "built rossh$(EXE)  [$(FLAVOR)]"

$(PREFIX)/.deps: tools/build-deps.sh
	JOBS=$(JOBS) EXTRA_CPPFLAGS="$(EXTRA_CPPFLAGS)" tools/build-deps.sh $(FLAVOR)
	@touch $@

# Rebuild the dependencies even if they are already there.
deps:
	JOBS=$(JOBS) EXTRA_CPPFLAGS="$(EXTRA_CPPFLAGS)" tools/build-deps.sh $(FLAVOR)

clean:
	rm -rf build rossh rossh.exe
