# Inj3ct0r

# Advanced SQL Injection Testing and Exploitation Tool

A Python-based command-line tool for detecting, testing, and exploiting SQL injection vulnerabilities in web applications. This tool supports various SQL injection techniques and can help identify and exploit potential security issues in your web applications.

## Features

- Support for both GET and POST methods
- Multiple SQL injection techniques:
  - Error-based SQL injection
  - Boolean-based blind SQL injection
  - Time-based blind SQL injection
  - Union-based SQL injection
  - Stacked queries
- Database fingerprinting and enumeration:
  - MySQL, PostgreSQL, MSSQL, SQLite support
  - Database version detection
  - Table and column enumeration
  - Data extraction
- Advanced exploitation features:
  - Web shell upload (PHP, ASP, JSP)
  - OS shell access
  - Database dumping
  - Custom payload support
- WAF evasion techniques:
  - Random User-Agent
  - Custom headers and cookies
  - Request timing control
  - Payload encoding
- Colored output for better readability
- JSON output support

## Installation

1. Clone this repository
2. Install the required dependencies:
```bash
pip install -r requirements.txt
```

## Usage

Basic usage:
```bash
python sql_injector.py -u "http://example.com/page.php?id=1"
```

### Command Line Arguments

#### Basic Options
- `-u, --url`: Target URL (required)
- `-m, --method`: HTTP method (GET or POST, default: GET)
- `-H, --headers`: Custom headers in JSON format
- `-c, --cookies`: Custom cookies in JSON format
- `-d, --data`: POST data in JSON format
- `-p, --proxy`: Proxy URL (e.g., http://127.0.0.1:8080)
- `-o, --output`: Output file path
- `-f, --format`: Output format (text or json, default: text)
- `-v, --verbose`: Enable verbose output
- `--timeout`: Request timeout in seconds (default: 30)
- `--no-ssl-verify`: Disable SSL certificate verification
- `--payload-file`: Custom payload file (JSON format)

#### Advanced Options
- `--exploit`: Enable exploitation mode
- `--dbms`: Specify target DBMS (MySQL, PostgreSQL, MSSQL, SQLite)
- `--dump`: Dump database contents
- `--tables`: Enumerate database tables
- `--columns`: Enumerate table columns
- `--shell`: Attempt to upload a web shell
- `--os-shell`: Attempt to get an OS shell
- `--batch`: Never ask for user input, use the default behavior
- `--random-agent`: Use randomly selected User-Agent header value
- `--level`: Level of tests to perform (1-5, default: 1)
- `--risk`: Risk of tests to perform (1-3, default: 1)
- `--technique`: SQL injection techniques to use (B=Boolean, E=Error, U=Union, S=Stacked, T=Time-based, Q=Query)

### Examples

1. Basic test with custom headers:
```bash
python sql_injector.py -u "http://example.com/page.php?id=1" -H '{"User-Agent": "Mozilla/5.0"}'
```

2. POST request with data:
```bash
python sql_injector.py -u "http://example.com/login.php" -m POST -d '{"username": "test", "password": "test"}'
```

3. Database enumeration:
```bash
python sql_injector.py -u "http://example.com/page.php?id=1" --dbms MySQL --tables --columns
```

4. Exploitation with shell upload:
```bash
python sql_injector.py -u "http://example.com/page.php?id=1" --dbms MySQL --exploit --shell
```

5. Advanced exploitation with specific technique:
```bash
python sql_injector.py -u "http://example.com/page.php?id=1" --dbms MySQL --exploit --technique U --dump
```

## Security Notice

This tool is intended for security testing and educational purposes only. Always:
- Obtain proper authorization before testing any website
- Use responsibly and ethically
- Do not use for malicious purposes
- Follow applicable laws and regulations

## Disclaimer

The authors of this tool are not responsible for any misuse or damage caused by this program. Users are responsible for complying with all applicable laws and regulations when using this tool. 
