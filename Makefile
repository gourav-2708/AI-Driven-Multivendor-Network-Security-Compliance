# =============================================================================
# net-audit - build system (GNU make; Linux, macOS, Windows/MinGW)
# =============================================================================
#   make              release build        -> build/release/net-audit
#   make debug        debug build          -> build/debug/net-audit
#                     (ASan + UBSan where the toolchain supports them)
#   make test         build and run the unit + regression suite
#   make check        test + run the CLI over every fixture
#   make valgrind     run the test suite under valgrind (Linux)
#   make examples     regenerate the sample reports in examples/
#   make docs         Doxygen HTML into build/docs (needs doxygen)
#   make install      install the binary (POSIX; PREFIX=/usr/local)
#   make clean        remove build/
#
# Variables: CC, MODE=release|debug, SANITIZE=0|1, EXTRA_CFLAGS, PREFIX
# =============================================================================

MODE     ?= release
PREFIX   ?= /usr/local
ifeq ($(origin CC),default)
  CC := gcc
endif

# ---- Platform / shell detection ---------------------------------------------
# On Windows, GNU make runs recipes with sh.exe when one is on PATH (Git for
# Windows, MSYS) and with cmd.exe otherwise. `echo "x"` keeps its quotes only
# under cmd, which tells us which command syntax to emit.
ifeq ($(OS),Windows_NT)
  EXE := .exe
  ifeq ($(shell echo "x"),"x")
    CMD_SHELL := 1
  endif
else
  EXE :=
endif

ifdef CMD_SHELL
  native = $(subst /,\,$1)
  MKDIR  = if not exist $(call native,$1) mkdir $(call native,$1)
  RMDIR  = if exist $(call native,$1) rd /s /q $(call native,$1)
else
  native = $1
  MKDIR  = mkdir -p $1
  RMDIR  = rm -rf $1
endif

# ---- Flags -------------------------------------------------------------------
CSTD     := -std=c11
WARNINGS := -Wall -Wextra -Werror -pedantic -Wshadow -Wformat=2 \
            -Wstrict-prototypes -Wmissing-prototypes -Wold-style-definition \
            -Wpointer-arith -Wwrite-strings -Wundef
CPPFLAGS := -Iinclude -MMD -MP
CFLAGS   := $(CSTD) $(WARNINGS) $(EXTRA_CFLAGS)
LDFLAGS  :=
LDLIBS   :=

ifeq ($(OS),Windows_NT)
  # C99-conformant printf family on MinGW (%zu etc.)
  CPPFLAGS += -D__USE_MINGW_ANSI_STDIO=1
endif

ifeq ($(MODE),debug)
  CFLAGS += -O0 -g3 -fno-omit-frame-pointer
  # MinGW ships no sanitizer runtime; enable elsewhere unless SANITIZE=0.
  ifeq ($(OS),Windows_NT)
    SANITIZE ?= 0
  else
    SANITIZE ?= 1
  endif
  ifeq ($(SANITIZE),1)
    CFLAGS  += -fsanitize=address,undefined -fno-sanitize-recover=all
    LDFLAGS += -fsanitize=address,undefined
  endif
else ifeq ($(MODE),release)
  CFLAGS += -O2 -DNDEBUG
else
  $(error MODE must be 'release' or 'debug')
endif

# ---- Sources -----------------------------------------------------------------
BUILD    := build/$(MODE)
SRC_DIRS := src/core src/platform src/parser src/engine src/report src/app
LIB_SRCS := $(foreach d,$(SRC_DIRS),$(wildcard $(d)/*.c))
APP_SRCS := src/main.c
TST_SRCS := $(wildcard tests/*.c)

LIB_OBJS := $(patsubst %.c,$(BUILD)/obj/%.o,$(LIB_SRCS))
APP_OBJS := $(patsubst %.c,$(BUILD)/obj/%.o,$(APP_SRCS))
TST_OBJS := $(patsubst %.c,$(BUILD)/obj/%.o,$(TST_SRCS))
DEPS     := $(LIB_OBJS:.o=.d) $(APP_OBJS:.o=.d) $(TST_OBJS:.o=.d)

BIN      := $(BUILD)/net-audit$(EXE)
TEST_BIN := $(BUILD)/net-audit-tests$(EXE)
FIXTURES := tests/fixtures

.PHONY: all release debug test check valgrind examples docs install clean help
.DEFAULT_GOAL := all

all: $(BIN)

release:
	$(MAKE) MODE=release all

debug:
	$(MAKE) MODE=debug all

$(BIN): $(LIB_OBJS) $(APP_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@ $(LDLIBS)
	@echo Built $@

$(TEST_BIN): $(LIB_OBJS) $(TST_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@ $(LDLIBS)

$(BUILD)/obj/%.o: %.c
	@$(call MKDIR,$(@D))
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

test: $(TEST_BIN)
	$(call native,$(TEST_BIN)) $(FIXTURES)

check: test $(BIN)
	$(call native,$(BIN)) --quiet --exit-zero --format json --dir $(FIXTURES) --output $(BUILD)/check.json
	$(call native,$(BIN)) --quiet --exit-zero --format csv  --dir $(FIXTURES) --output $(BUILD)/check.csv
	$(call native,$(BIN)) --quiet --exit-zero --no-color    --dir $(FIXTURES) --output $(BUILD)/check.txt
	@echo CLI smoke run OK

valgrind: $(TEST_BIN) $(BIN)
	valgrind --error-exitcode=99 --leak-check=full --errors-for-leak-kinds=definite,indirect \
	    $(TEST_BIN) $(FIXTURES)
	valgrind --error-exitcode=99 --leak-check=full --errors-for-leak-kinds=definite,indirect \
	    $(BIN) --quiet --format json --dir $(FIXTURES) > /dev/null; \
	    test $$? -ne 99

examples: $(BIN)
	@$(call MKDIR,examples)
	$(call native,$(BIN)) -q --exit-zero --no-color $(FIXTURES)/cisco_sample.cfg -o examples/report_cisco.txt
	$(call native,$(BIN)) -q --exit-zero -f json $(FIXTURES)/cisco_sample.cfg -o examples/report_cisco.json
	$(call native,$(BIN)) -q --exit-zero -f json $(FIXTURES)/juniper_sample.conf -o examples/report_juniper.json
	$(call native,$(BIN)) -q --exit-zero -f json $(FIXTURES)/fortinet_sample.conf -o examples/report_fortinet.json
	$(call native,$(BIN)) -q --exit-zero -f json --dir $(FIXTURES) -o examples/report_fleet.json
	$(call native,$(BIN)) -q --exit-zero -f csv --dir $(FIXTURES) -o examples/report_fleet.csv
	$(call native,$(BIN)) -q --exit-zero --no-color --dir $(FIXTURES) -o examples/report_fleet.txt

docs:
	doxygen docs/Doxyfile

install: $(BIN)
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 0755 $(BIN) $(DESTDIR)$(PREFIX)/bin/net-audit

clean:
	$(call RMDIR,build)

help:
	@echo Targets: all release debug test check valgrind examples docs install clean

-include $(DEPS)
