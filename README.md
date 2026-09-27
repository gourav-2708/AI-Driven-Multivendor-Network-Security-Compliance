# net-audit — AI-Driven Multi-Vendor Network Security Compliance Auditor

A production-quality C11 application that ingests raw network device
configuration files from multiple vendors, parses them through a pluggable
parser interface, runs them through a deterministic heuristic rule engine,
and outputs structured compliance reports in text, CSV, or JSON format.

---

## Features

| Capability | Details |
|---|---|
| **Vendors** | Cisco IOS, Juniper JunOS, Fortinet FortiOS (auto-detect or explicit) |
| **Rules** | 17 rules across AUTH, PASSWD, ACL, SNMP, SVC, LOG, NTP, INTF categories |
| **Formats** | Plain text (ANSI colour), CSV, JSON-lite (no external deps) |
| **Safety** | No `strcpy`/`gets`/unbounded `sprintf`; all ops through safe wrappers |
| **Memory** | Valgrind/ASan clean; fixed-size stack model (no dynamic allocation) |

---

## Build

### Prerequisites

- GCC (gcc) = 9 with C11 support
- GNU Make
- Optional: Doxygen (for `make docs`)

### Commands

```bash
# Release build (optimised, warnings-as-errors)
make

# Debug build (ASan + UBSan + debug symbols)
make debug

# Run all unit/regression tests
make test

# Remove all build artefacts
make clean

# Generate Doxygen HTML (requires doxygen in PATH)
make docs
```

---

## Usage

```
net-audit [OPTIONS] <config-file> [<config-file> ...]
net-audit [OPTIONS] --dir <config-directory>

Options:
  -v, --vendor <cisco|juniper|fortinet>  Force vendor (skip auto-detect)
  -f, --format <text|csv|json>           Output format (default: text)
  -o, --output <file>                    Write report to file (default: stdout)
  --severity <critical|high|medium|low>  Minimum severity to report (default: low)
  --no-color                             Disable ANSI colour in text output
  --verbose                              Enable debug logging
  -h, --help                             Show help
```

### Examples

```bash
# Audit a single Cisco config (auto-detect, text output)
./net-audit fixtures/cisco_sample.cfg

# Audit all configs in a directory, output CSV
./net-audit --dir fixtures/ --format csv --output report.csv

# Audit multiple configs, JSON output, high severity only
./net-audit -f json --severity high fixtures/*.cfg fixtures/*.conf

# Force vendor tag
./net-audit --vendor juniper --format json fixtures/juniper_sample.conf

# Debug build with ASan — verify clean run
make debug
./net-audit fixtures/cisco_sample.cfg > /dev/null
```

---

## Project Structure

```
net-audit/
+-- Makefile
+-- README.md
+-- include/
¦   +-- common.h      # Safe-string utils, error codes, logging macros
¦   +-- model.h       # Normalized device model (DeviceModel, AuditResult)
¦   +-- parser.h      # Pluggable parser vtable + registry
¦   +-- engine.h      # Rule engine API + Rule struct
¦   +-- report.h      # Report formatter API
+-- src/
¦   +-- main.c                      # CLI entry point
¦   +-- common/
¦   ¦   +-- safe_str.c              # Bounded string ops, logging
¦   ¦   +-- model_init.c            # model_init(), result_init(), severity tables
¦   +-- parser/
¦   ¦   +-- parser_registry.c       # VendorParser registry
¦   ¦   +-- cisco_parser.c          # Cisco IOS parser
¦   ¦   +-- juniper_parser.c        # Juniper JunOS parser
¦   ¦   +-- fortinet_parser.c       # Fortinet FortiOS parser
¦   +-- engine/
¦   ¦   +-- rule_engine.c           # Engine loop, scoring
¦   ¦   +-- rules_table.c           # All 17 rules + check functions
¦   +-- report/
¦       +-- report.c                # Format dispatcher
¦       +-- report_text.c           # ANSI text formatter
¦       +-- report_csv.c            # RFC 4180 CSV formatter
¦       +-- report_json.c           # Hand-rolled JSON formatter
+-- fixtures/
¦   +-- cisco_sample.cfg            # Cisco IOS with intentional violations
¦   +-- juniper_sample.conf         # Juniper JunOS with intentional violations
¦   +-- fortinet_sample.conf        # Fortinet FortiOS with intentional violations
+-- tests/
    +-- test_runner.h / test_runner.c   # Minimal harness (no external deps)
    +-- test_parser.c                   # Parser tests (20 test cases)
    +-- test_engine.c                   # Rule engine tests (32 test cases)
```

---

## Adding a New Vendor Parser

1. Create `src/parser/<vendor>_parser.c` implementing:
   ```c
   static bool <vendor>_detect(const char *filepath);
   static int  <vendor>_parse(const char *filepath, DeviceModel *out);
   void        <vendor>_parser_register(void);
   ```
2. Declare `<vendor>_parser_register()` in `include/parser.h`.
3. Call `<vendor>_parser_register()` from `main()` in `src/main.c`.
4. Add the new `.c` file to `SRCS` in `Makefile`.
5. **No other files need changing.**

---

## Adding a New Compliance Rule

1. Write a `static bool check_XYZNN(const DeviceModel *m, struct AuditResult *r, Finding *out)` function in `src/engine/rules_table.c`.
2. Add a `Rule` entry to the `s_rules[]` array in the same file.
3. **No other files need changing.**

---

## Compliance Rules Reference

| Rule ID | Severity | Category | Description |
|---|---|---|---|
| AUTH-001 | CRITICAL | Auth | Plaintext enable password without enable secret |
| AUTH-002 | HIGH | Auth | No AAA configuration |
| AUTH-003 | HIGH | Auth | Telnet permitted on VTY lines |
| AUTH-004 | HIGH | Auth | SSH not enabled or SSHv1 in use |
| PASSWD-001 | CRITICAL | Password | No service password-encryption |
| ACL-001 | CRITICAL | ACL | ACL contains permit any any |
| ACL-002 | HIGH | ACL | Management interface missing inbound ACL |
| SNMP-001 | CRITICAL | SNMP | SNMPv1/v2c with default community strings |
| SNMP-002 | HIGH | SNMP | SNMP without restricting ACL |
| SVC-001 | HIGH | Services | Plain HTTP server enabled |
| SVC-002 | MEDIUM | Services | CDP enabled globally |
| SVC-003 | MEDIUM | Services | TCP/UDP small servers enabled |
| LOG-001 | MEDIUM | Logging | No remote syslog server |
| LOG-002 | LOW | Logging | No local buffered logging |
| NTP-001 | MEDIUM | NTP | NTP not configured |
| NTP-002 | LOW | NTP | NTP without authentication |
| INTF-001 | LOW | Interface | Active interface with no IP or description |

### Scoring

`compliance_score = max(0, 100 - S(weight[sev] × count[sev]))`

| Severity | Weight |
|---|---|
| CRITICAL | 40 |
| HIGH | 20 |
| MEDIUM | 10 |
| LOW | 5 |

---

## Memory Safety Guarantees

- All string copies use `safe_strncpy()` (bounded, always NUL-terminates).
- All formatted writes use `safe_snprintf()` (bounded, truncation-warned).
- No raw `strcpy`, `strcat`, `gets`, `sprintf`, or `scanf %s` in the codebase.
- All buffers are fixed-size; no `malloc`/`free` in parsers or engine.
- Builds verified clean under `-fsanitize=address,undefined`.

---

## Non-Functional Requirements

- **Standard**: C11 (`-std=c11`)
- **Compiler flags**: `-Wall -Wextra -Werror -pedantic`
- **External deps**: None beyond libc (no libcjson, no libpcre)
- **Platform**: Linux/macOS; Windows supported via conditional `_WIN32` code in `main.c` directory enumeration
