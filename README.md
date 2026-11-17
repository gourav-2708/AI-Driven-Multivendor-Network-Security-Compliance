# net-audit — AI-Driven Multi-Vendor Network Security Compliance Auditor

A production-quality C11 application that ingests raw network device
configuration files from multiple vendors, parses them through a pluggable
parser interface, runs them through a deterministic heuristic rule engine,
and outputs structured compliance reports in text, CSV, or JSON format.
A web dashboard on top of it adds accounts and organizations, a device
inventory with score trends, a workflow for findings, compliance-framework
views and reports for managers and auditors.

| Capability | Details |
|---|---|
| **Vendors** | Cisco IOS, NX-OS and ASA, Juniper JunOS (brace and `set` form), Fortinet FortiOS, Palo Alto PAN-OS (XML and `set` form), Arista EOS; auto-detect or explicit |
| **Rules** | 28 rules across AUTH, PASSWD, ACL, SNMP, SVC, LOG, NTP, INTF categories |
| **Frameworks** | Every rule is mapped to CIS Controls v8, PCI DSS v4.0, ISO/IEC 27001:2022 and NIST SP 800-53 Rev. 5 |
| **Formats** | Plain text (ANSI colour), CSV (RFC 4180), JSON (no external deps) |
| **Dashboard** | Logins, organizations and roles; device inventory; scheduled audits from Git, Oxidized or a folder; finding workflow; executive PDF and auditor evidence pack; Docker image for self-hosting |
| **Safety** | No `strcpy`/`gets`/unbounded `sprintf`; all ops through safe wrappers, enforced at compile time |
| **Memory** | Fixed-size model, no heap allocation; ASan/UBSan clean |

---

## Quick start

```bash
make            # release build      -> build/release/net-audit
make test       # unit + regression suite (58 tests)
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
| `make web-test` | End-to-end tests of the web dashboard (needs Python and `pip install -r frontends/web/requirements.txt`) |
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

  -v, --vendor <name>        Force vendor (cisco, juniper, fortinet, paloalto, arista,
                             nxos, asa); default: auto-detect
  -f, --format <fmt>         text (default), csv or json
  -o, --output <file>        Write the report to a file instead of stdout
  -d, --dir <directory>      Audit every .cfg/.conf/.txt/.xml file in a directory
  -s, --severity <level>     Report findings at or above: critical, high, medium, low
      --color, --no-color    Force/disable ANSI colour (default: only on a terminal;
                             NO_COLOR is honoured)
      --verbose / -q         Debug logging / errors only (stderr)
      --exit-zero            Exit 0 even when findings are reported
      --list-rules           Print the rule catalogue (with --format json: includes
                             the framework mapping)
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
  "findings": [ { "rule_id", "severity", "section", "line", "description", "remediation",
                  "frameworks": { "cis_v8": [...], "pci_dss_4": [...],
                                  "iso_27001_2022": [...], "nist_800_53_r5": [...] } } ] }

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
| AUTH-005 | MEDIUM | Management sessions do not time out when idle | no idle timeout, or one longer than 15 minutes (`exec-timeout 0 0`, no JunOS `idle-timeout`, FortiOS `admintimeout`, ASA `ssh timeout`, PAN-OS default of 60) |
| AUTH-006 | LOW | No login banner | no `banner login`/`motd`, JunOS `login message`, FortiOS `pre-login-banner`, PAN-OS `login-banner` |
| AUTH-007 | MEDIUM | Management access not restricted to trusted hosts | a VTY block without `access-class`, no input filter on JunOS `lo0`, a FortiOS admin without `trusthost`, EOS `management ssh` without an ACL, ASA `ssh`/`telnet`/`http` from `0.0.0.0`, PAN-OS without `permitted-ip` |
| AUTH-008 | MEDIUM | No lockout after failed logins | no `login block-for`, `aaa local authentication attempts max-fail`, JunOS `retry-options`, EOS lockout policy or PAN-OS `admin-lockout` |
| PASSWD-001 | CRITICAL | Plaintext passwords without password encryption | plaintext credentials present and no `service password-encryption` |
| PASSWD-002 | MEDIUM | No local password policy | no `security passwords min-length`, JunOS `password minimum-length`, FortiOS `password-policy`, ASA `password-policy`, PAN-OS `password-complexity`; NX-OS with `no password strength-check` |
| PASSWD-003 | MEDIUM | Credentials stored with a legacy hash | IOS type 4, 5 or 7, an MD5-crypt (`$1$`) hash, ASA `encrypted` |
| ACL-001 | CRITICAL | ACL or policy permits any → any | `permit ip any any` (no port limit), JunOS term with `then accept` and no `from`, SRX/FortiOS policy with any/all source, destination and application/service |
| ACL-002 | HIGH | Management interface missing inbound ACL | active management port (name/description *mgmt/management*, `me0`, `fxp0`, `em0`) without an inbound filter |
| SNMP-001 | CRITICAL | SNMPv1/v2c with default or weak community strings | community is a known default, < 8 chars, or uses < 3 character classes; one finding per community |
| SNMP-002 | HIGH | SNMP community without restricting ACL | community not bound to an ACL / client list / host list |
| SNMP-003 | HIGH | Read-write SNMP community | a v1/v2c community with write access; one finding per community |
| SNMP-004 | MEDIUM | SNMPv1/v2c in use without SNMPv3 | communities configured and no SNMPv3 user or group |
| SVC-001 | HIGH | Plain HTTP management server enabled | `ip http server`, JunOS `web-management http`, FortiOS `allowaccess http\|all` |
| SVC-002 | MEDIUM | CDP enabled globally | IOS without `no cdp run` (CDP is on by default) |
| SVC-003 | MEDIUM | TCP/UDP small servers enabled | `service tcp-small-servers` / `udp-small-servers` |
| SVC-004 | MEDIUM | IP source routing enabled | IOS or NX-OS without `no ip source-route` (on by default) |
| LOG-001 | MEDIUM | No remote syslog server | no `logging host`, `syslog host`, or enabled `log syslogd`/FortiAnalyzer with a server |
| LOG-002 | LOW | No local buffered logging | no `logging buffered`, `syslog file`, or FortiOS memory/disk log |
| LOG-003 | LOW | Log entries are not timestamped | IOS without `service timestamps log datetime`, ASA without `logging timestamp` |
| NTP-001 | MEDIUM | NTP not configured | no NTP server (FortiOS FortiGuard sync counts) |
| NTP-002 | LOW | NTP without authentication | servers configured, authentication off |
| NTP-003 | LOW | Only one NTP server | exactly one server configured |
| INTF-001 | LOW | Active interface with no IP or description | not shut down, not loopback, no address, no DHCP, no description |

`net-audit --list-rules` prints the catalogue from the binary itself.

Adding rules lowers the score of a device that was audited before, because
more is checked. Expect a one-time drop in score trends after upgrading from
a version with fewer rules.

### Compliance frameworks

Each rule names the controls it gives evidence for. The mapping is part of
the rule table (`src/engine/rules_*.c`), so every JSON finding and
`net-audit --list-rules --format json` carry it and nothing else keeps a copy.

| Rule | CIS Controls v8 | PCI DSS v4.0 | ISO/IEC 27001:2022 | NIST SP 800-53 r5 |
|---|---|---|---|---|
| AUTH-001 | | 8.3.2 | A.5.17, A.8.5 | IA-5(1) |
| AUTH-002 | 6.7, 12.5 | 8.2.1 | A.5.15, A.5.16, A.8.5 | AC-2, IA-2 |
| AUTH-003 | 3.10, 4.6, 12.6 | 2.2.7, 8.3.2 | A.8.5, A.8.20, A.8.24 | AC-17(2), CM-7, SC-8 |
| AUTH-004 | 4.6, 12.6 | 2.2.7 | A.8.20, A.8.24 | AC-17(2), SC-8, SC-13 |
| AUTH-005 | 4.3 | 8.2.8 | A.8.5 | AC-12, SC-10 |
| AUTH-006 | | | | AC-8 |
| AUTH-007 | 12.3 | | A.8.3, A.8.20 | AC-17, SC-7 |
| AUTH-008 | | 8.3.4 | A.8.5 | AC-7 |
| PASSWD-001 | | 8.3.2 | A.5.17, A.8.5 | IA-5(1) |
| PASSWD-002 | 5.2 | 8.3.6 | A.5.17 | IA-5(1) |
| PASSWD-003 | | 8.3.2 | A.5.17, A.8.24 | IA-5(1), SC-13 |
| ACL-001 | 12.2, 13.4 | 1.2.5, 1.3.1, 1.4.2 | A.8.20, A.8.22 | AC-4, SC-7(5) |
| ACL-002 | 12.3 | | A.8.20, A.8.22 | AC-4, SC-7 |
| SNMP-001 | 4.7 | 2.2.2 | A.5.17, A.8.9 | IA-5 |
| SNMP-002 | 12.3 | 2.2.6 | A.8.20, A.8.21 | AC-3, SC-7 |
| SNMP-003 | | 2.2.6 | A.8.2, A.8.21 | AC-6, CM-7 |
| SNMP-004 | 3.10, 12.6 | 1.2.6, 2.2.5 | A.8.21, A.8.24 | CM-7, SC-8 |
| SVC-001 | 4.6, 12.6 | 2.2.7 | A.8.20, A.8.24 | AC-17(2), SC-8 |
| SVC-002 | 4.8 | 2.2.4 | A.8.9 | CM-7 |
| SVC-003 | 4.8 | 2.2.4 | A.8.9 | CM-7, SC-5 |
| SVC-004 | 4.8 | 1.4.3, 2.2.4 | A.8.20 | CM-7, SC-7 |
| LOG-001 | 8.2, 8.9 | 10.2.1, 10.3.3 | A.8.15, A.8.16 | AU-4(1), AU-9(2) |
| LOG-002 | 8.2, 8.3 | 10.2.1 | A.8.15 | AU-4, AU-12 |
| LOG-003 | 8.5 | 10.2.2 | A.8.15, A.8.17 | AU-3, AU-8 |
| NTP-001 | 8.4 | 10.6.1, 10.6.2 | A.8.17 | AU-8, SC-45(1) |
| NTP-002 | 8.4 | 10.6.3 | A.8.17 | AU-8, SC-45 |
| NTP-003 | 8.4 | 10.6.2 | A.8.17 | SC-45(2) |
| INTF-001 | 4.8 | 2.2.4 | A.8.9 | CM-7 |

The CIS column refers to the vendor-neutral CIS Controls, not to the
per-vendor CIS Benchmarks, whose recommendation numbers differ for every
platform and version. A mapping is a judgement about which control a check
supports: review it against your own copy of each framework before you rely
on it in an audit. A finding is evidence that a control is not met on that
device; no finding is evidence only for what the rule checks.

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
  file      │ lines 0-100; most confident wins; parse() │    (vendor-      (28 rules,       (findings,        (streams one
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
│   │                           cisco_ios.c (IOS, NX-OS, ASA, Arista EOS),
│   │                           juniper_junos.c, fortinet_fortios.c,
│   │                           paloalto_panos.c
│   ├── engine/                 engine.c, rule_registry.c,
│   │                           rules_{auth,passwd,acl,snmp,svc,log,ntp,intf}.c
│   └── report/                 report.c, report_{text,csv,json}.c
├── tests/
│   ├── harness.[ch], test_main.c
│   ├── test_safe_str.c  test_parsers.c  test_rules.c  test_report.c
│   ├── test_regression.c       golden score + findings for every fixture
│   └── fixtures/               20 vendor configs + edge/ (BOM/CRLF, one-line
│                               JunOS, nested FortiOS, one-line PAN-OS XML, long
│                               lines, unknown vendor)
├── examples/                   generated sample reports (make examples)
├── frontends/                  UIs that shell out to the CLI
│   ├── web/                    Flask dashboard (accounts, inventory, workflow,
│   │                           frameworks, reports) and its tests
│   ├── desktop/                tkinter app
│   └── viewer/index.html       zero-install viewer for saved JSON reports
├── Dockerfile,                 self-hosted image: engine + dashboard + database
│   docker-compose.yml
├── DATA-HANDLING.md            what the dashboard stores, for how long, who sees it
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
  `set`-style ("display set") output is read through the same handlers: each
  `set` line is cut into the block headers and leaf statement the brace form
  would have had. Of `deactivate` lines, only those for the management
  services (`system services telnet`, `ssh`, `web-management`) are applied;
  other deactivated statements are still counted as active.
* **Fortinet FortiOS** — `config`/`edit`/`set`/`next`/`end` with nested sections
  (`config hosts`, `config ntpserver`), quoted values, disabled entries, and
  the FortiOS default action (deny) for firewall policies.

* **Palo Alto PAN-OS** — the XML export (`running-config.xml`, also when it
  is one long line) and `set`-format output. Both are reduced to the same
  path-plus-value statements. Reads device settings, administrators,
  interface management profiles, Ethernet interfaces and the security
  rulebase (also Panorama pre-/post-rulebases). Rules in NAT and other
  rulebases, and sub-interfaces, are not read.
* **Arista EOS** — the IOS-style parser with EOS defaults: SSH on unless
  `management ssh` is shut down, `management telnet` / `management api
  http-commands` sections, prefix-length addresses, `banner ... EOF`.
* **Cisco NX-OS** — `feature` lines, SSH on unless `no feature ssh`,
  `snmp-server community X group|use-acl`, `logging server`, `nxapi`,
  password strength check on by default.
* **Cisco ASA** — `nameif` interfaces with `access-group ... interface`,
  `access-list NAME extended` with netmasks and object groups, `ssh`/`telnet`
  /`http` source networks, `logging enable`. A community that the export
  masks as `*****` cannot be judged and is skipped.

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

### Web dashboard

```bash
pip install -r frontends/web/requirements.txt
python frontends/web/app.py        # http://localhost:5000, then create the first account
```

Every page and API route except sign-in, sign-up, password reset and
`/api/health` needs a signed-in user or an API token, and shows only that
user's organization.

| Area | What it does |
|---|---|
| **Accounts** | Sign-up creates an organization and its first admin. Admins invite users and set roles: *viewer* (read-only), *auditor* (run audits, work on findings, edit devices), *admin* (users, tokens, sources, integrations, delete audits). Password reset by one-time link; five wrong passwords lock an account for 15 minutes; changing a password signs out other sessions. |
| **Audit log** | Who ran, viewed, exported or deleted what, with time and address. Settings > Audit log, downloadable as CSV. |
| **Devices** | Every audited device with site, owner, current score, change since the previous audit and a score-over-time chart, per device and for the fleet. |
| **Findings** | Each finding is open, assigned, risk accepted, fixed or verified. Assign it to a person; accept its risk with a written reason and an expiry date (it reopens when that passes); mark it fixed. The next audit of the device verifies a fix when the finding is gone and reopens it when it is not. |
| **Alerts** | A drift alert when a device scores lower than at its previous audit, or a critical finding is new. Sent to Slack and email when set up. |
| **Compliance** | Per framework: which controls pass, which fail (and on which devices), which have an accepted risk, and which no rule covers yet. |
| **Sources** | Audit a Git repository of configs (also Oxidized's Git output, or RANCID kept in Git), an Oxidized server over its REST API, or a folder on the server (a RANCID base directory, a backup share) every day or week. Fetched files are deleted when the audit finishes. |
| **Reports** | An executive PDF (score, trend, top risks in plain language) and an auditor evidence pack (ZIP: per-control status as PDF and CSV, every finding with its dates, a manifest with checksums). The executive report can be emailed weekly or monthly. |
| **Integrations** | Slack webhook and email for alerts; a ticket in Jira or ServiceNow from any finding. |

Uploaded and fetched configurations are deleted as soon as the audit
finishes; reports, findings and device records are kept.
[DATA-HANDLING.md](DATA-HANDLING.md) lists everything that is stored.

**API.** Create a token under Settings > API tokens and send it as
`Authorization: Bearer <token>`. A token is read-only or may submit audits;
only a hash of it is stored.

```bash
# Submit configs from a backup job or pipeline; the reply holds the report
curl -H "Authorization: Bearer $NET_AUDIT_TOKEN" \
     -F files=@core-router-01.cfg -F files=@edge-fw-02.conf \
     https://net-audit.example.com/api/audit
```

| Route | |
|---|---|
| `POST /api/audit` | audit uploaded `files` (optional `vendor`, `severity`) |
| `GET /api/history`, `GET /api/result/<id>`, `GET /api/download/<id>/<json\|csv\|txt>` | audits |
| `DELETE /api/result/<id>` | delete an audit (admin; not available to tokens) |
| `GET /api/devices`, `GET /api/devices/<id>`, `GET /api/trend` | inventory and score history |
| `GET /api/findings?status=&severity=&q=`, `POST /api/findings/<id>` | findings; `action` = `assign`, `accept_risk`, `fix`, `reopen`, `comment`, `ticket` |
| `GET /api/compliance`, `GET /api/alerts` | control status per framework; drift alerts |
| `POST /api/sources/<id>/run` | run a source now |
| `GET /api/health` | no login needed; `{"ok": true}` when the engine and database work |

**Settings** are environment variables; [`.env.example`](.env.example)
documents each one. The ones that matter most:

| Variable | Purpose |
|---|---|
| `MONGODB_URI` | store everything in MongoDB; unset, a SQLite file in the data directory is used |
| `NET_AUDIT_SECRET_KEY` | signs session cookies; unset, a key is generated in the data directory |
| `NET_AUDIT_SIGNUP` | `closed`: after the first account, users must be invited |
| `NET_AUDIT_BASE_URL` | public address, for links in emails |
| `SMTP_HOST`, `SMTP_FROM`, ... | email for invitations, resets, alerts and reports; without it, one-time links are shown to the admin and written to the server log |
| `NET_AUDIT_INTAKE_ROOT` | the only folder "folder" sources may read; unset, they are switched off |
| `NET_AUDIT_BLOCK_PRIVATE_URLS` | `1`: refuse outbound calls to private addresses; turn on when strangers can sign up |

**Storage.** With `MONGODB_URI` unset, the dashboard keeps everything in
`net-audit.db` (SQLite) in the data directory: `frontends/web` locally,
`/data` in Docker, or `NET_AUDIT_DATA_DIR`. With it set, everything goes to
MongoDB (database named by the URI, else `MONGODB_DB`, else `net_audit`).
Use a database user limited to read/write on that database.

**Upgrading from 2.x.** Audits saved by 2.x (JSON files in
`frontends/web/history`, or the `audits` collection in MongoDB) had no owner.
The first organization that is created adopts them, so create your own
account first after upgrading, before giving anyone else the address. The
JSON files are imported into SQLite once and left where they are.

### Self-hosting with Docker

Device configs are sensitive, and many networks will not send them to a
cloud. The image holds the auditor, the dashboard and the database (SQLite
on a volume); it needs no other service and no network access at run time.

```bash
docker compose up -d        # builds the image, serves http://localhost:8080
```

or without Compose:

```bash
docker build -t net-audit .
docker run -d --name net-audit -p 8080:8080 -v net-audit-data:/data net-audit
```

* **Data** lives in the `/data` volume: the database and the session key.
  Back up that volume.
* **HTTPS.** Put a reverse proxy with a certificate in front and set
  `NET_AUDIT_COOKIE_SECURE=1` and `NET_AUDIT_BASE_URL`.
* **Limits.** There is no 4 MB upload or 25-second limit here: uploads
  default to 100 MB (`NET_AUDIT_MAX_UPLOAD_MB`), an audit may run for 5
  minutes (`NET_AUDIT_TIMEOUT_S`), and a large set of files is audited in
  batches and merged into one fleet report.
* **Backups folder.** Mount a folder of configs at `/backups` (read-only)
  to use it as a "folder" source.
* **One worker.** The container runs one worker process with threads,
  because the scheduler lives in it. Do not raise `--workers`.

**Air-gapped install.** Build the image on a machine with internet access,
move it as a file, and load it on the isolated host:

```bash
docker build -t net-audit:3.0.0 .
docker save net-audit:3.0.0 | gzip > net-audit-3.0.0.tar.gz
# ... carry the file across ...
gunzip -c net-audit-3.0.0.tar.gz | docker load
docker run -d -p 8080:8080 -v net-audit-data:/data -e NET_AUDIT_OFFLINE=1 net-audit:3.0.0
```

`NET_AUDIT_OFFLINE=1` stops pages from asking browsers to load web fonts
from the internet; system fonts are used instead. Git and Oxidized sources,
Slack, Jira, ServiceNow and email only reach hosts you configure. The
auditor binary alone (`build/release/net-audit`) has no dependency beyond
libc and can be copied to any host of the same OS and architecture.

### Deploying the web front-end to Vercel

The repository is deployment-ready for Vercel's Flask preset. Nothing here
deploys automatically.

| File | Role |
|---|---|
| `vercel.json` | Flask preset, build command, 30 s function limit, files to bundle/exclude, a daily cron call, security headers |
| `pyproject.toml` | Python ≥ 3.12, `Flask>=3.1,<4`, `pymongo>=4.8,<5`, and the entrypoint `index:app` |
| `.python-version` | Pins Python 3.12 |
| `index.py` | Re-exports the Flask `app` from `frontends/web/app.py` |
| `scripts/vercel-build.sh` | On Vercel's Linux image: installs gcc/make with `dnf` if missing, compiles `build/release/net-audit`, runs the full test suite, and copies `frontends/web/static` to `public/static` for the CDN |
| `.vercelignore` | Keeps local builds and local data out of the upload |

**Deploy** (from the repository root, with the [Vercel CLI](https://vercel.com/docs/cli)):

```bash
vercel          # preview deployment
vercel --prod   # production
```

Set these environment variables in the Vercel dashboard:

| Variable | Why |
|---|---|
| `MONGODB_URI` | Functions can write only to `/tmp`, which resets. Without MongoDB, accounts and all data are lost when an instance is recycled. |
| `NET_AUDIT_SECRET_KEY` | Without it every instance signs sessions with its own key and users are signed out at random. |
| `CRON_SECRET` | Lets the daily Vercel Cron call `/api/cron`, which runs due sources, expires risk acceptances and sends scheduled reports. |

Vercel's outbound IP addresses change, so a MongoDB Atlas network access
list must allow them (typically `0.0.0.0/0` on plans without private
networking). After deploying, `GET /api/health` returns `{"ok": true}` when
the auditor binary is present and the database is reachable.

**Limits on Vercel** (when the `VERCEL` environment variable is set):

* **Uploads** are limited to 4 MB per audit, below Vercel's 4.5 MB request
  cap, and **audits** stop after 25 s, inside the 30 s function limit. Use
  the Docker image for large fleets.
* **Schedules** run when the daily cron call arrives, not every minute as
  with the built-in scheduler. Git sources need a `git` program, which the
  function runtime may not provide.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the development workflow.
