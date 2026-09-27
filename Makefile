# ===========================================================================
# net-audit Makefile  (Windows/MinGW + Linux/GCC compatible)
# ===========================================================================
# Targets:
#   make          - release build
#   make debug    - debug build (ASan/UBSan on Linux; debug symbols on MinGW)
#   make test     - build and run all tests
#   make clean    - remove build artefacts
# ===========================================================================

CC      = gcc
CFLAGS  = -std=c11 -Wall -Wextra -Werror -pedantic -Iinclude
LDFLAGS =

RELEASE_FLAGS = -O2 -DNDEBUG

# ASan/UBSan available on Linux GCC; skip on MinGW which lacks libasan
ifeq ($(OS),Windows_NT)
    DEBUG_FLAGS = -g -O0
else
    DEBUG_FLAGS = -g -O0 -fsanitize=address,undefined -fno-omit-frame-pointer
    LDFLAGS_DEBUG = -fsanitize=address,undefined
endif

EXT =
ifeq ($(OS),Windows_NT)
    EXT = .exe
    MKDIR_P = if not exist $1 mkdir $1
else
    MKDIR_P = mkdir -p $1
endif

# Source files
SRCS = src/main.c \
       src/common/safe_str.c \
       src/common/model_init.c \
       src/parser/parser_registry.c \
       src/parser/cisco_parser.c \
       src/parser/juniper_parser.c \
       src/parser/fortinet_parser.c \
       src/engine/rule_engine.c \
       src/engine/rules_table.c \
       src/report/report.c \
       src/report/report_text.c \
       src/report/report_csv.c \
       src/report/report_json.c

# Object files: src/foo/bar.c -> build/foo/bar.o
OBJS = $(patsubst src/%.c,build/%.o,$(SRCS))

TARGET = net-audit$(EXT)

# Library objects (exclude main) for test linking
LIB_SRCS = $(filter-out src/main.c,$(SRCS))
LIB_OBJS = $(patsubst src/%.c,build/%.o,$(LIB_SRCS))

TEST_PARSER = build/test_parser$(EXT)
TEST_ENGINE = build/test_engine$(EXT)

.PHONY: all debug test clean

# ---- Release ----------------------------------------------------------------
all: build_dirs $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(RELEASE_FLAGS) $^ -o $@
	@echo Built: $@

build/%.o: src/%.c
	$(CC) $(CFLAGS) $(RELEASE_FLAGS) -c $< -o $@

# ---- Debug ------------------------------------------------------------------
debug: CFLAGS  += $(DEBUG_FLAGS)
debug: LDFLAGS += $(LDFLAGS_DEBUG)
debug: clean build_dirs $(TARGET)
	@echo Debug build complete

# ---- Tests ------------------------------------------------------------------
test: build_dirs $(TEST_PARSER) $(TEST_ENGINE)
	@echo === Parser Tests ===
	$(TEST_PARSER)
	@echo.
	@echo === Engine Tests ===
	$(TEST_ENGINE)

$(TEST_PARSER): $(LIB_OBJS) build/test/test_parser.o build/test/test_runner.o
	$(CC) $(CFLAGS) $(RELEASE_FLAGS) $^ -o $@

$(TEST_ENGINE): $(LIB_OBJS) build/test/test_engine.o build/test/test_runner.o
	$(CC) $(CFLAGS) $(RELEASE_FLAGS) $^ -o $@

build/test/%.o: tests/%.c
	$(CC) $(CFLAGS) $(RELEASE_FLAGS) -Itests -c $< -o $@

# ---- Directory creation (Windows-compatible) ---------------------------------
build_dirs:
	-@if not exist build\common      mkdir build\common
	-@if not exist build\parser      mkdir build\parser
	-@if not exist build\engine      mkdir build\engine
	-@if not exist build\report      mkdir build\report
	-@if not exist build\test        mkdir build\test

# ---- Clean ------------------------------------------------------------------
clean:
	-rd /s /q build 2>NUL
	-del /q $(TARGET) 2>NUL
