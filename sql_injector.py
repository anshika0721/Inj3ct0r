#!/usr/bin/env python3

import argparse
import sys
from typing import List, Optional, Dict, Any

from core.config_manager import ConfigManager
from core.logger import Logger
from core.output_manager import OutputManager
from core.request_engine import RequestEngine
from core.payload_manager import PayloadManager
from core.waf_detector import WAFDetector
from core.db_connector import DatabaseConnector
from core.db_fingerprinter import DatabaseFingerprinter

from modules.error_based import ErrorBasedInjector
from modules.union_based import UnionBasedInjector
from modules.blind import BlindInjector
from modules.time_based import TimeBasedInjector
from modules.stacked_queries import StackedQueriesInjector

class SQLInjector:
    def __init__(self, url: str, method: str = "GET", headers: Optional[Dict[str, str]] = None,
                 cookies: Optional[Dict[str, str]] = None, data: Optional[Dict[str, str]] = None,
                 timeout: int = 10, verify_ssl: bool = True):
        """Initialize SQL injector with target URL and request parameters."""
        self.request_engine = RequestEngine(url, method, headers, cookies, data, timeout, verify_ssl)
        self.output_manager = OutputManager()
        self.waf_detector = WAFDetector()
        self.db_fingerprinter = DatabaseFingerprinter()
        
    def detect_database(self) -> Dict[str, Any]:
        """Detect database type and version."""
        return self.db_fingerprinter.fingerprint(self.request_engine)
        
    def detect_waf(self) -> Dict[str, Any]:
        """Detect WAF presence and type."""
        return self.waf_detector.detect(self.request_engine)
        
    def scan(self) -> None:
        """Run SQL injection scan."""
        try:
            # Start scan
            self.output_manager.start_scan(self.request_engine.url)
            
            # Detect WAF
            waf_info = self.detect_waf()
            self.output_manager.set_waf_info(waf_info)
            
            # Detect database
            db_info = self.detect_database()
            self.output_manager.set_database_info(db_info)
            
            # Run injection tests
            self._run_injection_tests()
            
            # End scan and save results
            self.output_manager.end_scan()
            
        except Exception as e:
            logging.error(f"Scan failed: {str(e)}")
            raise
            
    def _run_injection_tests(self) -> None:
        """Run all injection tests."""
        # Initialize injectors
        error_injector = ErrorBasedInjector(self.request_engine)
        union_injector = UnionBasedInjector(self.request_engine)
        blind_injector = BlindInjector(self.request_engine)
        stacked_injector = StackedQueriesInjector(self.request_engine)
        
        # Run tests based on detected database
        db_type = self.output_manager.get_database_info().get("type", "unknown")
        
        if db_type == "mysql":
            self._run_mysql_tests(error_injector, union_injector, blind_injector, stacked_injector)
        elif db_type == "postgresql":
            self._run_postgres_tests(error_injector, union_injector, blind_injector, stacked_injector)
        elif db_type == "mssql":
            self._run_mssql_tests(error_injector, union_injector, blind_injector, stacked_injector)
        else:
            # Run all tests if database type is unknown
            self._run_all_tests(error_injector, union_injector, blind_injector, stacked_injector)
            
    def _run_mysql_tests(self, error_injector, union_injector, blind_injector, stacked_injector) -> None:
        """Run MySQL-specific tests."""
        # Error-based tests
        results = error_injector._test_mysql_error()
        for result in results:
            self.output_manager.add_vulnerability(result)
            
        # Union-based tests
        results = union_injector._test_mysql_union()
        for result in results:
            self.output_manager.add_vulnerability(result)
            
        # Blind tests
        results = blind_injector._test_mysql_blind()
        for result in results:
            self.output_manager.add_vulnerability(result)
            
        # Stacked queries tests
        results = stacked_injector._test_mysql_stacked()
        for result in results:
            self.output_manager.add_vulnerability(result)
            
    def _run_postgres_tests(self, error_injector, union_injector, blind_injector, stacked_injector) -> None:
        """Run PostgreSQL-specific tests."""
        # Error-based tests
        results = error_injector._test_postgres_error()
        for result in results:
            self.output_manager.add_vulnerability(result)
            
        # Union-based tests
        results = union_injector._test_postgres_union()
        for result in results:
            self.output_manager.add_vulnerability(result)
            
        # Blind tests
        results = blind_injector._test_postgres_blind()
        for result in results:
            self.output_manager.add_vulnerability(result)
            
        # Stacked queries tests
        results = stacked_injector._test_postgres_stacked()
        for result in results:
            self.output_manager.add_vulnerability(result)
            
    def _run_mssql_tests(self, error_injector, union_injector, blind_injector, stacked_injector) -> None:
        """Run MSSQL-specific tests."""
        # Error-based tests
        results = error_injector._test_mssql_error()
        for result in results:
            self.output_manager.add_vulnerability(result)
            
        # Union-based tests
        results = union_injector._test_mssql_union()
        for result in results:
            self.output_manager.add_vulnerability(result)
            
        # Blind tests
        results = blind_injector._test_mssql_blind()
        for result in results:
            self.output_manager.add_vulnerability(result)
            
        # Stacked queries tests
        results = stacked_injector._test_mssql_stacked()
        for result in results:
            self.output_manager.add_vulnerability(result)
            
    def _run_all_tests(self, error_injector, union_injector, blind_injector, stacked_injector) -> None:
        """Run all tests for all database types."""
        self._run_mysql_tests(error_injector, union_injector, blind_injector, stacked_injector)
        self._run_postgres_tests(error_injector, union_injector, blind_injector, stacked_injector)
        self._run_mssql_tests(error_injector, union_injector, blind_injector, stacked_injector)

def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Advanced SQL Injection Testing Tool")
    
    # Required arguments
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    
    # Optional arguments
    parser.add_argument("-t", "--techniques", nargs="+", help="Injection techniques to use")
    parser.add_argument("-c", "--config", default="config.json", help="Configuration file")
    parser.add_argument("-o", "--output", help="Output file")
    parser.add_argument("-f", "--format", choices=["json", "html", "txt"], help="Output format")
    parser.add_argument("--dbms", choices=["mysql", "postgresql", "mssql", "sqlite"], help="Target DBMS")
    parser.add_argument("--no-waf", action="store_true", help="Disable WAF detection")
    parser.add_argument("--no-bypass", action="store_true", help="Disable WAF bypass")
    parser.add_argument("--timeout", type=int, help="Request timeout in seconds")
    parser.add_argument("--threads", type=int, help="Number of threads")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    
    args = parser.parse_args()
    
    # Create SQL injector
    injector = SQLInjector(args.url)
    
    # Update configuration from arguments
    if args.output:
        injector.config.set_value("output", "file", args.output)
    if args.format:
        injector.config.set_value("output", "format", args.format)
    if args.dbms:
        injector.config.set_value("database", "type", args.dbms)
    if args.no_waf:
        injector.config.set_value("waf", "detection", False)
    if args.no_bypass:
        injector.config.set_value("waf", "bypass", False)
    if args.timeout:
        injector.config.set_value("request", "timeout", args.timeout)
    if args.threads:
        injector.config.set_value("injection", "threads", args.threads)
    if args.verbose:
        injector.config.set_value("output", "verbose", True)
        injector.logger.set_level("DEBUG")
        
    # Run scan
    injector.scan()
    
if __name__ == "__main__":
    main() 
