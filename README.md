# Inj3ct0r

# Advanced SQL Injection Testing Tool

A comprehensive SQL injection testing tool that supports multiple injection techniques, WAF detection and bypass, and detailed reporting.

## Features

- Multiple SQL injection techniques:
  - Error-based injection
  - Union-based injection
  - Blind injection
  - Time-based injection
  - Stacked queries injection

- WAF detection and bypass:
  - Automatic WAF detection
  - Multiple bypass techniques
  - Confidence scoring

- Database support:
  - MySQL
  - PostgreSQL
  - MSSQL
  - SQLite

- Output formats:
  - JSON
  - HTML
  - Text

- Additional features:
  - Configurable request settings
  - Detailed logging
  - Progress tracking
  - Vulnerability reporting
  - Statistics collection

## Installation

1. Clone the repository:
```bash
git clone https://github.com/anshika0721/Inj3ct0r.git
cd sql-injection-tool
```

2. Create a virtual environment (optional but recommended):
```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

Basic usage:
```bash
python sql_injector.py -u "http://example.com/page.php?id=1"
```

Specify injection techniques:
```bash
python sql_injector.py -u "http://example.com/page.php?id=1" -t error union blind
```

Set output format and file:
```bash
python sql_injector.py -u "http://example.com/page.php?id=1" -f html -o results.html
```

Specify target DBMS:
```bash
python sql_injector.py -u "http://example.com/page.php?id=1" --dbms mysql
```

Disable WAF detection:
```bash
python sql_injector.py -u "http://example.com/page.php?id=1" --no-waf
```

Set request timeout and threads:
```bash
python sql_injector.py -u "http://example.com/page.php?id=1" --timeout 60 --threads 20
```

Enable verbose output:
```bash
python sql_injector.py -u "http://example.com/page.php?id=1" --verbose
```

## Configuration

The tool uses a JSON configuration file (`config.json`) for default settings. You can create a custom configuration file and specify it using the `-c` option:

```bash
python sql_injector.py -u "http://example.com/page.php?id=1" -c custom_config.json
```

Configuration sections:
- `request`: Request settings (timeout, SSL, headers)
- `injection`: Injection settings (techniques, parameters)
- `waf`: WAF settings (detection, bypass)
- `database`: Database settings (types, ports)
- `logging`: Logging settings (level, file)
- `output`: Output settings (format, file)

## Output

The tool generates detailed reports in the selected format (JSON, HTML, or text) containing:
- Scan information
- WAF detection results
- Database information
- Vulnerability details
- Test statistics

## Security Notice

This tool is designed for security testing and educational purposes only. Always:
1. Obtain proper authorization before testing any system
2. Follow responsible disclosure practices
3. Respect privacy and data protection laws
4. Use the tool ethically and responsibly

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. 
