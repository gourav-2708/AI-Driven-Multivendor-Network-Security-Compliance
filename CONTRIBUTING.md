# Contributing to net-audit

Thank you for your interest in contributing! Here's how to get started.

## 🛠️ Setup

### Prerequisites
| Tool | Version | Purpose |
|---|---|---|
| GCC (MinGW on Windows) | ≥ 9.0 | Compile the C core |
| Python | ≥ 3.10 | Web dashboard & desktop GUI |
| Flask | ≥ 2.3 | Web server |
| Git | Any | Version control |

### Clone & Build
```bash
git clone https://github.com/YOUR_USERNAME/net-audit.git
cd net-audit

# Build the C binary (Windows)
mingw32-make

# OR compile manually
gcc -Wall -Wextra -O2 -Iinclude src/**/*.c src/main.c -o net-audit.exe

# Run tests
.\net-audit.exe --help
```

### Run the Web Dashboard
```bash
cd webapp
pip install -r requirements.txt
python app.py
# Open http://localhost:5000
```

### Run the Desktop GUI
```bash
python desktop/gui.py
```

## 📁 Project Structure

```
net-audit/
├── include/          # C headers (common.h, model.h, parser.h, engine.h, report.h)
├── src/
│   ├── common/       # safe_str.c, model_init.c
│   ├── parser/       # cisco_parser.c, juniper_parser.c, fortinet_parser.c
│   ├── engine/       # rule_engine.c, rules_table.c
│   ├── report/       # report_json.c, report_csv.c, report_text.c
│   └── main.c        # CLI entry point
├── tests/            # test_parser.c, test_engine.c, test_runner.c
├── fixtures/         # Sample vendor config files for testing
├── webapp/           # Flask web dashboard
│   ├── app.py
│   ├── templates/    # Jinja2 HTML templates
│   ├── static/       # CSS, JS, charts
│   └── requirements.txt
├── desktop/          # tkinter desktop GUI
│   └── gui.py
├── Makefile
└── README.md
```

## 🧪 Running Tests
```bash
# Parser tests (21 cases)
gcc -Iinclude tests/test_runner.c tests/test_parser.c src/**/*.c -o test_parser.exe
.\test_parser.exe

# Engine tests (23 cases)
gcc -Iinclude tests/test_runner.c tests/test_engine.c src/**/*.c -o test_engine.exe
.\test_engine.exe
```

## 🔧 Adding a New Rule
1. Open `src/engine/rules_table.c`
2. Add a new `Rule` entry to the `RULES[]` array
3. Implement the check function following the existing pattern
4. Add a test case in `tests/test_engine.c`
5. Update the rules table in `README.md`

## 🔌 Adding a New Vendor Parser
1. Create `src/parser/myvendor_parser.c`
2. Implement the `VendorParser` vtable interface from `include/parser.h`
3. Register it in `src/parser/parser_registry.c`
4. Add fixture file in `fixtures/myvendor_sample.conf`
5. Add parser tests in `tests/test_parser.c`

## 📝 Code Style
- C: follow existing style — 4-space indent, `snake_case`, `/* C89-style comments */`
- Python: PEP 8, 4-space indent
- JavaScript: 2-space indent, `'use strict'`

## 🐛 Reporting Bugs
Open an issue with:
- OS and GCC version
- Steps to reproduce
- Expected vs actual behavior
- Config file snippet (anonymize sensitive data)
