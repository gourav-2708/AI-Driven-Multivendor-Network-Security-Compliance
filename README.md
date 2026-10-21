# net-audit — AI-Driven Multi-Vendor Network Security Compliance Auditor

A production-quality C11 application that ingests raw network device
configuration files from multiple vendors, parses them through a pluggable
parser interface, runs them through a deterministic heuristic rule engine,
and outputs structured compliance reports in text, CSV, or JSON format.

| Capability | Details |
|---|---|
| **Vendors** | Cisco IOS, Juniper JunOS, Fortinet FortiOS (auto-detect or explicit) |
| **Rules** | 17 rules across AUTH, PASSWD, ACL, SNMP, SVC, LOG, NTP, INTF categories |
| **Formats** | Plain text (ANSI colour), CSV (RFC 4180), JSON (no external deps) |
| **Safety** | No `strcpy`/`gets`/unbounded `sprintf`; all ops through safe wrappers, enforced at compile time |
| **Memory** | Fixed-size model, no heap allocation; ASan/UBSan clean |

---

## Quick start

```bash
make            # release build      -> build/release/net-audit
make test       # unit + regression suite (43 tests)
build/release/net-audit tests/fixtures/cisco_sample.cfg
```

Requirements: a C11 compiler (GCC ≥ 6 or Clang) and GNU make. On Windows use
MinGW (`mingw32-make`); the Makefile works from both `cmd.exe` and an MSYS/Git
Bash shell. No libraries beyond libc.

| Target | Purpose |
|---|---|
| `make` / `make release` | Optimised build, warnings are errors |
| `make debug` | `-O0 -g3` plus ASan + UBSan (where the toolchain ships them) → `build/debug/` |
| `make test` | Build and run the test suite against `tests/fixtures` |
| `make check` | `test` plus a CLI run over every fixture in all three formats |
| `make valgrind` | Tests and a fleet run under valgrind (Linux) |
| `make examples` | Regenerate the sample reports in `examples/` |
| `make docs` | Doxygen HTML into `build/docs/` |
| `make install` | Install to `$(PREFIX)/bin` (POSIX, default `/usr/local`) |
| `make clean` | Remove `build/` |

---

## Usage

```
net-audit [OPTIONS] <config-file>...
net-audit [OPTIONS] --dir <directory>

  -v, --vendor <name>        Force vendor (cisco, juniper, fortinet); default: auto-detect
  -f, --format <fmt>         text (default), csv or json
  -o, --output <file>        Write the report to a file instead of stdout
  -d, --dir <directory>      Audit every .cfg/.conf/.txt file in a directory
  -s, --severity <level>     Report findings at or above: critical, high, medium, low
      --color, --no-color    Force/disable ANSI colour (default: only on a terminal;
                             NO_COLOR is honoured)
      --verbose / -q         Debug logging / errors only (stderr)
      --exit-zero            Exit 0 even when findings are reported
      --list-rules           Print the rule catalogue
      --list-vendors         Print supported vendors
  -V, --version / -h, --help
```

Options accept `--opt value` and `--opt=value`. `--dir` may be repeated and
combined with explicit files. Diagnostics go to stderr; stdout carries only
the report.

**Exit status** — designed for CI pipelines:

| Code | Meaning |
|---|---|
| 0 | Every input audited; no finding at or above `--severity` |
| 1 | Every input audited; findings reported (suppressed by `--exit-zero`) |
| 2 | Usage error, unwritable output, or no input could be audited |
| 3 | Some inputs could not be audited (unreadable or vendor not detected) |

```bash
# Fail a pipeline on any CRITICAL finding across a directory of backups
net-audit --severity critical --dir /backups/configs

# Fleet report as CSV
net-audit -f csv -d tests/fixtures -o fleet.csv

# Force the parser when auto-detection is not confident
net-audit --vendor juniper -f json router.txt
```

### Reports

One input produces a device report; several produce a fleet report: every
device in turn, then fleet totals. Reports are streamed device by device. If
nothing can be audited, nothing is written to stdout. Sample output for every
format is in [`examples/`](examples/).

JSON schema (stable; the web/desktop front-ends depend on it):

```jsonc
// device report
{ "report_type": "device", "hostname": "...", "vendor": "...", "version": "...",
  "source": "...", "score": 0-100, "critical": n, "high": n, "medium": n, "low": n,
  "findings": [ { "rule_id", "severity", "section", "line", "description", "remediation" } ] }

// fleet report
{ "report_type": "aggregate", "devices": [ /* device objects without report_type */ ],
  "devices_audited": n, "avg_score": n, "total_critical": n, "total_high": n,
  "total_medium": n, "total_low": n }
```

Severity counts always describe the whole device; `--severity` filters only
the listed findings. `line` is the config line of the offending object, or
`-1` when a finding is about something *missing*.

Custom SNMP community strings are credentials, so they are never printed in
full: reports show only well-known defaults (`public`, `private`, …) verbatim
and reduce any other string to its first two characters (`Xr***`).

---

## Compliance rules

| Rule | Severity | Description | Fires when |
|---|---|---|---|
| AUTH-001 | CRITICAL | Plaintext enable password without enable secret | privileged password is plaintext/reversible and no hashed secret exists |
| AUTH-002 | HIGH | No AAA configuration | no `aaa new-model` / `authentication-order` / remote-auth or RADIUS/TACACS+/LDAP users |
| AUTH-003 | HIGH | Telnet permitted for management | VTY `transport input telnet\|all`, JunOS `services telnet`, FortiOS `allowaccess telnet\|all` |
| AUTH-004 | HIGH | SSH not enabled or SSHv1 in use | no SSH server; **MEDIUM** variant when SSHv1 is allowed |
| PASSWD-001 | CRITICAL | Plaintext passwords without password encryption | plaintext credentials present and no `service password-encryption` |
| ACL-001 | CRITICAL | ACL or policy permits any → any | `permit ip any any` (no port limit), JunOS term with `then accept` and no `from`, SRX/FortiOS policy with any/all source, destination and application/service |
| ACL-002 | HIGH | Management interface missing inbound ACL | active management port (name/description *mgmt/management*, `me0`, `fxp0`, `em0`) without an inbound filter |
| SNMP-001 | CRITICAL | SNMPv1/v2c with default or weak community strings | community is a known default, < 8 chars, or uses < 3 character classes; one finding per community |
| SNMP-002 | HIGH | SNMP community without restricting ACL | community not bound to an ACL / client list / host list |
| SVC-001 | HIGH | Plain HTTP management server enabled | `ip http server`, JunOS `web-management http`, FortiOS `allowaccess http\|all` |
| SVC-002 | MEDIUM | CDP enabled globally | IOS without `no cdp run` (CDP is on by default) |
| SVC-003 | MEDIUM | TCP/UDP small servers enabled | `service tcp-small-servers` / `udp-small-servers` |
| LOG-001 | MEDIUM | No remote syslog server | no `logging host`, `syslog host`, or enabled `log syslogd`/FortiAnalyzer with a server |
| LOG-002 | LOW | No local buffered logging | no `logging buffered`, `syslog file`, or FortiOS memory/disk log |
| NTP-001 | MEDIUM | NTP not configured | no NTP server (FortiOS FortiGuard sync counts) |
| NTP-002 | LOW | NTP without authentication | servers configured, authentication off |
| INTF-001 | LOW | Active interface with no IP or description | not shut down, not loopback, no address, no DHCP, no description |

`net-audit --list-rules` prints the catalogue from the binary itself.

### Scoring

`score = 100 − Σ min(per_finding[sev] × count[sev], cap[sev])`, floored at 0.

| Severity | Per finding | Cap |
|---|---|---|
| CRITICAL | 15 | 60 |
| HIGH | 8 | 24 |
| MEDIUM | 4 | 12 |
| LOW | 1 | 4 |

The caps keep one noisy category from zeroing a device on its own. A fleet
score is the integer mean of the device scores.

---

## Architecture

```
            ┌───────────── parser registry ─────────────┐
 config ──▶ │ probe(): each parser scores the first 40  │──▶ DeviceModel ──▶ rule engine ──▶ AuditResult ──▶ report session ──▶ text / CSV / JSON
  file      │ lines 0-100; most confident wins; parse() │    (vendor-      (17 rules,       (findings,        (streams one
            └───────────────────────────────────────────┘     neutral)     data-driven)      score)            device at a time)
```

* **Parsers** turn vendor syntax into one vendor-neutral `DeviceModel`. A
  field means the same thing for every vendor, so each rule is written once.
* **Rules** are static data (id, category, severity, wording) plus a check
  function that reports zero or more findings. The wording in reports comes
  only from the rule table.
* **Reports** are a small format interface (`begin` / `device` / `end`).
  The pipeline holds a single `DeviceModel` and `AuditResult` at any moment,
  so memory use does not grow with the number of files.

```
net-audit/
├── Makefile                    portable GNU make (Linux, macOS, MinGW cmd/sh)
├── include/netaudit/           public headers
│   ├── bounds.h                every capacity in one place
│   ├── banned.h                compile-time poison for unsafe libc + heap
│   ├── safe_str.h              bounded copy/concat/format, tokenizer
│   ├── model.h                 vendor-neutral device model + find-or-add helpers
│   ├── parser.h                VendorParser interface, registry, detection
│   ├── line_reader.h           shared line input (CRLF, BOM, long lines)
│   ├── engine.h                Rule, Finding, AuditResult, scoring
│   ├── report.h                streaming report session
│   ├── cli.h / platform.h      CLI options, exit codes, OS abstraction
│   └── log.h / status.h / severity.h / compiler.h
├── src/
│   ├── main.c                  parse argv, run
│   ├── app/                    cli.c (options), audit.c (pipeline)
│   ├── core/                   safe_str.c, model.c, log.c, status.c
│   ├── platform/platform.c     directory listing, TTY/ANSI, binary stdout
│   ├── parser/                 parser_registry.c, line_reader.c,
│   │                           cisco_ios.c, juniper_junos.c, fortinet_fortios.c
│   ├── engine/                 engine.c, rule_registry.c,
│   │                           rules_{auth,passwd,acl,snmp,svc,log,ntp,intf}.c
│   └── report/                 report.c, report_{text,csv,json}.c
├── tests/
│   ├── harness.[ch], test_main.c
│   ├── test_safe_str.c  test_parsers.c  test_rules.c  test_report.c
│   ├── test_regression.c       golden score + findings for every fixture
│   └── fixtures/               13 vendor configs + edge/ (BOM/CRLF, one-line
│                               JunOS, nested FortiOS, long lines, unknown vendor)
├── examples/                   generated sample reports (make examples)
├── frontends/                  optional UIs that shell out to the CLI
│   ├── web/                    Flask dashboard
│   ├── desktop/                tkinter app
│   └── viewer/index.html       zero-install viewer for saved JSON reports
├── index.py, vercel.json,      Vercel entrypoint, config and Python manifest
│   pyproject.toml
├── scripts/vercel-build.sh     Vercel build step (compile auditor, publish static/)
├── docs/Doxyfile
└── .github/workflows/ci.yml    Linux (gcc/clang, ASan, valgrind), macOS, Windows
```

### Vendor support notes

* **Cisco IOS** — global and sub-mode commands (`interface`, `line vty`,
  `ip access-list`), numbered and named ACLs with sequence numbers, `no`
  negations, `vrf` forms of `logging host` / `ntp server`. A `!` only starts
  a comment at the beginning of a line.
* **Juniper JunOS** — curly-brace configuration via a statement lexer: multi-line
  and one-line blocks, `#` and `/* */` comments, quoted strings, `[ lists ]`,
  `inactive:` statements, firewall-filter terms and SRX security policies.
  (`set`-style "display set" output is not supported.)
* **Fortinet FortiOS** — `config`/`edit`/`set`/`next`/`end` with nested sections
  (`config hosts`, `config ntpserver`), quoted values, disabled entries, and
  the FortiOS default action (deny) for firewall policies.

---

## Extending

**Add a rule** — append an entry and a check function to the matching
`src/engine/rules_<category>.c`. For example, with a new `finger_enabled`
field added to `ServiceFlags` in `model.h` and set by the parsers:

```c
static void check_svc004(const DeviceModel *m, FindingSink *sink)
{
    if (m->services.finger_enabled)
        finding_report(sink, -1, "service finger");
}
/* in RULES_SVC[]: */
{ "SVC-004", CAT_SVC, SEV_MEDIUM, "Finger service enabled",
  "Finger service discloses logged-in users", "Disable with 'no service finger'.",
  check_svc004 },
```

Then add a trigger/pass case to `tests/test_rules.c`, update the catalogue
test, and refresh any changed rows in `tests/test_regression.c`.

**Add a vendor** — create `src/parser/<vendor>.c` defining
`const VendorParser PARSER_<VENDOR> = { name, display_name, probe, parse }`,
add `&PARSER_<VENDOR>` to the table in `src/parser/parser_registry.c`, and add
fixtures and parser tests. `line_reader.h` and `str_tokenize()` handle input
plumbing; `model_interface()`, `model_acl()` etc. enforce capacities.

---

## Safety and memory model

* **Banned functions are a compile error.** `banned.h` poisons `strcpy`,
  `strcat`, `sprintf`, `vsprintf`, `gets`, `scanf`/`sscanf`/`fscanf`,
  `atoi`/`atol`/`atof`, `strtok`, and `malloc`/`calloc`/`realloc`/`free`.
  All writes go through `safe_strcpy` / `safe_strcat` / `safe_snprintf`,
  which always NUL-terminate and report truncation.
* **No heap.** Every collection has a fixed capacity in `bounds.h`. When a
  config exceeds one, the extra elements are dropped and the run logs a
  warning. Large objects (one `DeviceModel` ≈ 0.6 MB) live in static
  storage, not on the stack.
* **Untrusted input.** Lines over 1023 bytes are truncated (one warning per
  file), not overflowed. JSON and CSV output escape quotes, backslashes and
  control characters; the test suite feeds hostile names through both.
* **Strict compilation**: `-std=c11 -Wall -Wextra -Werror -pedantic -Wshadow
  -Wformat=2 -Wstrict-prototypes -Wmissing-prototypes -Wwrite-strings …`
* **Sanitizers**: `make debug` builds with ASan + UBSan; the suite and a fleet
  run are clean. On Linux kernels with 32-bit mmap randomisation, older ASan
  runtimes loop on `AddressSanitizer:DEADLYSIGNAL`. Run
  `sudo sysctl vm.mmap_rnd_bits=28` (as CI does) or
  `setarch $(uname -m) -R make MODE=debug test`.

---

## Front-ends

The C binary is the product. The optional front-ends call it with
`--format json` and expect it at `build/release/net-audit[.exe]`. Set
`NET_AUDIT_BIN` to point elsewhere.

```bash
# Web dashboard (http://localhost:5000)
pip install -r frontends/web/requirements.txt
python frontends/web/app.py            # or: frontends/web/start.ps1 on Windows

# Desktop app
python frontends/desktop/gui.py        # or: frontends/desktop/launch_gui.bat
```

`frontends/viewer/index.html` opens saved JSON reports in a browser with no
server.

### Deploying the web front-end to Vercel

The repository is deployment-ready for Vercel's Flask preset. Nothing here
deploys automatically.

| File | Role |
|---|---|
| `vercel.json` | Flask preset, build command, 30 s function limit, files to bundle/exclude, security headers |
| `pyproject.toml` | Python ≥ 3.12, `Flask>=3.1,<4`, and the entrypoint `index:app` |
| `.python-version` | Pins Python 3.12 |
| `index.py` | Re-exports the Flask `app` from `frontends/web/app.py` |
| `scripts/vercel-build.sh` | On Vercel's Linux image: installs gcc/make with `dnf` if missing, compiles `build/release/net-audit`, runs the full test suite, and copies `frontends/web/static` to `public/static` for the CDN |
| `.vercelignore` | Keeps local builds and local audit history/uploads out of the upload |

**Deploy** (from the repository root, with the [Vercel CLI](https://vercel.com/docs/cli)):

```bash
vercel          # preview deployment
vercel --prod   # production
```

Or import the repository in the Vercel dashboard. The settings above are read
from the repository, so no dashboard configuration is needed. After deploying,
`GET /api/health` returns `{"ok": true}` when the auditor binary is present.

**Reproduce the build locally** on Linux or macOS with `bash scripts/vercel-build.sh`.

**Behaviour on Vercel** (when the `VERCEL` environment variable is set):

* **History is temporary.** Functions can write only to `/tmp`, so audit
  history lives in `/tmp/net-audit` and resets when an instance is recycled.
  The History page says so. Set `NET_AUDIT_DATA_DIR` to change the location.
  Persistent history would need external storage.
* **Uploads** are limited to 4 MB per audit, below Vercel's 4.5 MB request
  cap, so users get a clear message. Uploaded configs are deleted as soon as
  the audit finishes.
* **Audits** time out after 25 s, inside the 30 s function limit.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the development workflow.
