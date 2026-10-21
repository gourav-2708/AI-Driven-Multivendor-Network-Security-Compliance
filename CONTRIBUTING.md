# Contributing to net-audit

## Setup

| Tool | Version | Used for |
|---|---|---|
| GCC or Clang | C11 (GCC ≥ 6) | the auditor |
| GNU make | 3.82+ | build (`mingw32-make` on Windows) |
| Python | ≥ 3.10 | optional web/desktop front-ends |
| Doxygen | any | optional, `make docs` |

```bash
make            # release build -> build/release/net-audit
make test       # must pass before every commit
make check      # tests + CLI run over all fixtures
make debug && make MODE=debug test   # sanitizers (Linux/macOS)
```

## Where things live

| Change | Files |
|---|---|
| New compliance rule | `src/engine/rules_<category>.c`, `tests/test_rules.c`, `tests/test_regression.c`, README rule table |
| New vendor | `src/parser/<vendor>.c`, table in `src/parser/parser_registry.c`, fixtures, `tests/test_parsers.c` |
| New model field | `include/netaudit/model.h`, every parser that can set it |
| New output format | `src/report/report_<fmt>.c`, table in `src/report/report.c`, `ReportFormat` in `report.h` |
| New capacity / limit | `include/netaudit/bounds.h` only |
| CLI option | `src/app/cli.c`, `include/netaudit/cli.h`, README usage |

The architecture overview is in the [README](README.md#architecture).

## Rules of the code base

* **C11, no extensions, no warnings.** The build uses `-Werror` with a broad
  warning set; fix warnings, do not silence them.
* **No heap, no unsafe libc.** `banned.h` makes `strcpy`, `sprintf`, `sscanf`,
  `atoi`, `malloc`/`free` and friends compile errors. Use `safe_strcpy`,
  `safe_strcat`, `safe_snprintf`, `str_tokenize`, `str_to_int`.
* **Include order:** system/OS headers first, then `netaudit/...` headers
  (the poison pragmas must come after the system declarations).
* **Bounded everything.** Add elements to the model only through the
  `model_*` helpers; they enforce capacities and count overflow.
* **Rules read the model, never the file.** Vendor knowledge belongs in the
  parser that fills the model, so each rule stays vendor-neutral.
* **Report text comes from the rule table.** Use `finding_report()`; reach
  for `finding_report_variant()` only when a sub-case needs a different
  severity or wording (see AUTH-004).
* **Never print secrets.** Treat community strings, keys and passwords as
  credentials in any new finding text.
* Style: 4-space indent, `snake_case`, `/* */` comments, braces on the same
  line except for function bodies.

## Tests

`make test` runs one binary with five suites: `safe_str`, `parsers`,
`rules`, `report` and `golden`. Run a subset with
`build/release/net-audit-tests tests/fixtures <suite-or-name>`.

`tests/test_regression.c` pins the score and the ordered findings for every
fixture. If your change alters them on purpose, update the rows and explain
the difference in the commit message. If you did not expect a change there,
you have found a regression.

Put new fixtures that should count toward the fleet example in
`tests/fixtures/`. Put targeted edge cases in `tests/fixtures/edge/`, which
`--dir` does not pick up.

## Front-ends

`frontends/web` (Flask) and `frontends/desktop` (tkinter) run the CLI with
`--format json`. Keep the JSON schema in `src/report/report_json.c`
backwards compatible: add keys, never rename or remove them.

## Reporting bugs

Include the OS and compiler version, the exact command line, the expected and
actual output, and a config snippet that reproduces the problem with
addresses, secrets and hostnames anonymised.
