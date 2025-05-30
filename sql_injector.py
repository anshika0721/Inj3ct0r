#!/usr/bin/env python3

import argparse
import logging
from typing import Dict, List, Optional
from core.request_engine import RequestEngine
from core.payload_manager import PayloadManager
from core.waf_detector import WAFDetector
from core.db_fingerprinter import DatabaseFingerprinter
from core.output_manager import OutputManager
from modules.error_based import ErrorBasedInjector
from modules.union_based import UnionBasedInjector
from modules.blind_based import BlindBasedInjector
from modules.stack_queries import StackedQueriesInjector

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class SQLInjector:
    def __init__(self, url: str, method: str = "GET", headers: Optional[Dict[str, str]] = None,
                 cookies: Optional[Dict[str, str]] = None, data: Optional[Dict[str, str]] = None,
                 timeout: int = 10, verify_ssl: bool = True):
        """Initialize the SQL injection scanner."""
        self.request_engine = RequestEngine(url, method, headers, cookies, data, timeout, verify_ssl)
        self.payload_manager = PayloadManager()
        self.waf_detector = WAFDetector(self.request_engine)
        self.db_fingerprinter = DatabaseFingerprinter(self.request_engine)
        self.output_manager = OutputManager()
        
        # Initialize injectors
        self.error_injector = ErrorBasedInjector(self.request_engine, self.payload_manager)
        self.union_injector = UnionBasedInjector(self.request_engine, self.payload_manager)
        self.blind_injector = BlindBasedInjector(self.request_engine, self.payload_manager)
        self.stacked_injector = StackedQueriesInjector(self.request_engine, self.payload_manager)
    
    def detect_waf(self) -> bool:
        """Detect if target is protected by WAF."""
        try:
            return self.waf_detector.detect()
        except Exception as e:
            logging.error(f"WAF detection failed: {str(e)}")
            return False
    
    def fingerprint_database(self) -> str:
        """Fingerprint the database type and version."""
        try:
            return self.db_fingerprinter.fingerprint()
        except Exception as e:
            logging.error(f"Database fingerprinting failed: {str(e)}")
            return "unknown"
    
    def _run_injection_tests(self) -> List[Dict]:
        """Run all injection tests."""
        results = []
        
        # Run error-based tests
        error_results = self.error_injector.test_all_parameters()
        results.extend(error_results)
        
        # Run union-based tests
        union_results = self.union_injector.test_all_parameters()
        results.extend(union_results)
        
        # Run blind-based tests
        blind_results = self.blind_injector.test_all_parameters()
        results.extend(blind_results)
        
        # Run stacked queries tests
        stacked_results = self.stacked_injector.test_all_parameters()
        results.extend(stacked_results)
        
        return results
    
    def scan(self) -> None:
        """Run the complete SQL injection scan."""
        logging.info("Starting SQL injection scan...")
        
        # Check for WAF
        if self.detect_waf():
            logging.warning("WAF detected! Scan may be blocked.")
        else:
            logging.info("No WAF detected.")
        
        # Fingerprint database
        db_type = self.fingerprint_database()
        logging.info(f"Database type: {db_type}")
        
        # Run injection tests
        results = self._run_injection_tests()
        
        # Display results
        self.output_manager.display_results(results)
        
        # Export report
        self.output_manager.export_report(results, "sql_injection_report.html")
        
        logging.info("Scan completed.")

def main():
    parser = argparse.ArgumentParser(description="SQL Injection Scanner")
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-m", "--method", default="GET", choices=["GET", "POST"], help="HTTP method")
    parser.add_argument("-H", "--headers", help="Custom headers (JSON format)")
    parser.add_argument("-c", "--cookies", help="Custom cookies (JSON format)")
    parser.add_argument("-d", "--data", help="POST data (JSON format)")
    parser.add_argument("-t", "--timeout", type=int, default=10, help="Request timeout in seconds")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL verification")
    
    args = parser.parse_args()
    
    # Parse JSON arguments
    import json
    headers = json.loads(args.headers) if args.headers else None
    cookies = json.loads(args.cookies) if args.cookies else None
    data = json.loads(args.data) if args.data else None
    
    # Initialize and run scanner
    scanner = SQLInjector(
        args.url,
        args.method,
        headers,
        cookies,
        data,
        args.timeout,
        not args.no_verify
    )
    scanner.scan()

if __name__ == "__main__":
    main() 
