# Inj3ct0r

# SQL Injection Testing Tool

A Python-based command-line tool for detecting and testing SQL injection vulnerabilities in web applications. This tool supports various SQL injection techniques and can help identify potential security issues in your web applications.

## Features

- Support for both GET and POST methods
- Error-based SQL injection detection
- Boolean-based blind SQL injection testing
- Time-based blind SQL injection testing
- Database fingerprinting (MySQL, PostgreSQL, SQLite)
- Custom headers and cookies support
- Colored output for better readability

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

- `-u, --url`: Target URL (required)
- `-m, --method`: HTTP method (GET or POST, default: GET)
- `-H, --headers`: Custom headers in JSON format
- `-c, --cookies`: Custom cookies in JSON format
- `-d, --data`: POST data in JSON format

### Examples

1. Test a GET request with custom headers:
```bash
python sql_injector.py -u "http://example.com/page.php?id=1" -H '{"User-Agent": "Mozilla/5.0"}'
```

2. Test a POST request with data:
```bash
python sql_injector.py -u "http://example.com/login.php" -m POST -d '{"username": "test", "password": "test"}'
```

3. Test with custom cookies:
```bash
python sql_injector.py -u "http://example.com/page.php?id=1" -c '{"session": "abc123"}'
```

## Security Notice

This tool is intended for security testing and educational purposes only. Always:
- Obtain proper authorization before testing any website
- Use responsibly and ethically
- Do not use for malicious purposes
- Follow applicable laws and regulations

## Disclaimer

The authors of this tool are not responsible for any misuse or damage caused by this program. Users are responsible for complying with all applicable laws and regulations when using this tool. 
