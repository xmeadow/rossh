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
NSIS    ?= makensis
VERSION ?= 0.5.0

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

# DEBUG=1 turns on wolfSSH's internal tracing. The define has to reach our
# translation units *and* the vendored libraries, which are built separately —
# so it goes into CFLAGS and into the dependency build (EXTRA_CPPFLAGS) at the
# same time. Otherwise the two-step path loses it: `make DEBUG=1` re-runs
# build-deps.sh (the .deps stamp is older than the script) without the define,
# silently rebuilding the dependencies clean and compiling every WLOG out.
# One `make DEBUG=1` is all it takes; it rebuilds the dependencies if they were
# built without tracing.
DEBUG ?= 0
ifeq ($(DEBUG),1)
CFLAGS += -DDEBUG_WOLFSSH
DEP_CPPFLAGS += -DDEBUG_WOLFSSH
endif
DEP_CPPFLAGS += $(EXTRA_CPPFLAGS)

# util: forkpty, the pty the native shell session runs on (src/session.c).
# pthread: one thread per connection (src/main.c).
LDLIBS_native = -lwolfssh -lwolfssl -lm -lutil -lpthread
# advapi32: RtlGenRandom in src/rng.c. No crypt32: wolfSSL is built
# --enable-cryptonly, so its X.509 store code never enters the image.
LDLIBS_win32  = -lwolfssh -lwolfssl -lws2_32 -ladvapi32

# Strip the Windows binary: we do not need debug info inside it, it halves the
# image (1.8 MB -> 894 KB, 16 sections -> 8) and every section the loader does not
# have to walk is welcome on ReactOS. See docs/reactos.md section 9.
STRIP_FLAG_native =
STRIP_FLAG_win32  = -s
STRIP_FLAG        = $(STRIP_FLAG_$(FLAVOR))
LDLIBS        = $(LDLIBS_$(FLAVOR))

.PHONY: all win32 clean deps FORCE_DEPS installer

all:
	@$(MAKE) --no-print-directory binary

win32:
	@$(MAKE) --no-print-directory FLAVOR=win32 CC_BIN=$(WINCC) EXE=.exe binary

# The dependencies are rebuilt only when the flag set changes — including the
# tracing define that DEBUG=1 adds. make cannot see a variable change, so the
# flags are kept in a stamp file and compared here, at parse time: when they
# match, the dependencies are left alone; when they differ (or nothing is built
# yet), `binary` takes the phony rule below as a prerequisite, which rebuilds the
# libraries once and records the new flags. (`binary` itself is phony and always
# relinks the application; this only decides whether the libraries are rebuilt.)
DEPS_STAMP     = $(BUILD)/.depflags
DEPS_FLAGS_NEW = $(DEP_CPPFLAGS)
DEPS_FLAGS_OLD = $(shell cat $(DEPS_STAMP) 2>/dev/null)

ifneq ($(DEPS_FLAGS_NEW),$(DEPS_FLAGS_OLD))
DEPS_PREREQ = FORCE_DEPS
endif
ifeq ($(wildcard $(PREFIX)/.deps),)
DEPS_PREREQ = FORCE_DEPS
endif

binary: $(DEPS_PREREQ) $(SRC)
	$(CC_BIN) $(CFLAGS) $(SRC) -o rossh$(EXE) $(STRIP_FLAG) -L$(PREFIX)/lib $(LDLIBS)
	@echo "built rossh$(EXE)  [$(FLAVOR)]"

# A prerequisite only when the flags changed or nothing is built yet, so it can
# never force a relink on an otherwise up-to-date tree.
FORCE_DEPS:
	@mkdir -p $(BUILD)
	JOBS=$(JOBS) EXTRA_CPPFLAGS="$(DEP_CPPFLAGS)" tools/build-deps.sh $(FLAVOR)
	@printf '%s' "$(DEP_CPPFLAGS)" > $(DEPS_STAMP)
	@touch $(PREFIX)/.deps

# Rebuild the dependencies even if the flags already match.
deps:
	JOBS=$(JOBS) EXTRA_CPPFLAGS="$(DEP_CPPFLAGS)" tools/build-deps.sh $(FLAVOR)
	@mkdir -p $(BUILD)
	@printf '%s' "$(DEP_CPPFLAGS)" > $(DEPS_STAMP)
	@touch $(PREFIX)/.deps

# The Windows installer: package the win32 binary and let `rossh setup` do the
# work. Needs makensis (NSIS), which runs on Linux and cross-builds the .exe.
installer:
	@$(MAKE) --no-print-directory win32
	$(NSIS) -DVERSION=$(VERSION) -DROOT="$(CURDIR)" installer/rossh.nsi
	@echo "built rossh-setup.exe  [installer]"

clean:
	rm -rf build rossh rossh.exe
