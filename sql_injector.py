#!/usr/bin/env python3

import argparse
import sys
from typing import List, Optional

from core.config_manager import ConfigManager
from core.logger import Logger
from core.output_manager import OutputManager
from core.request_engine import RequestEngine
from core.payload_manager import PayloadManager
from core.waf_detector import WAFDetector
from core.db_connector import DatabaseConnector

from modules.error_based import ErrorBasedInjector
from modules.union_based import UnionBasedInjector
from modules.blind import BlindInjector
from modules.time_based import TimeBasedInjector
from modules.stacked_queries import StackedQueriesInjector

class SQLInjector:
    def __init__(self, config_file: str = "config.json"):
        """Initialize SQL injector."""
        # Initialize components
        self.config = ConfigManager(config_file)
        self.logger = Logger(
            self.config.get_value("logging", "file"),
            self.config.get_value("logging", "level")
        )
        self.output = OutputManager(
            self.config.get_value("output", "file"),
            self.config.get_value("output", "format")
        )
        
        # Initialize request engine with default URL
        request_config = self.config.get_request_config()
        self.request_engine = RequestEngine(
            url="http://localhost",  # Default URL, will be updated in run() method
            method="GET",
            timeout=request_config["timeout"],
            verify_ssl=request_config["verify_ssl"],
            headers=request_config["headers"]
        )
        
        # Initialize payload manager
        self.payload_manager = PayloadManager()
        
        # Initialize WAF detector
        self.waf_detector = WAFDetector(self.request_engine, self.payload_manager)
        
        # Initialize database connector
        self.db_connector = DatabaseConnector()
        
        # Initialize injectors
        self.injectors = {
            "error": ErrorBasedInjector(self.request_engine, self.payload_manager),
            "union": UnionBasedInjector(self.request_engine, self.payload_manager),
            "blind": BlindInjector(self.request_engine, self.payload_manager),
            "time": TimeBasedInjector(self.request_engine, self.payload_manager),
            "stacked": StackedQueriesInjector(self.request_engine, self.payload_manager)
        }
        
    def run(self, url: str, techniques: Optional[List[str]] = None) -> None:
        """Run SQL injection scan."""
        try:
            # Start scan
            self.logger.info(f"Starting SQL injection scan for {url}")
            self.output.start_scan(url, techniques or self.config.get_value("injection", "techniques"))
            
            # Update target URL
            self.request_engine.url = url
            
            # Detect WAF
            if self.config.get_value("waf", "detection"):
                self.logger.info("Detecting WAF...")
                waf_info = self.waf_detector.detect_waf()
                self.output.set_waf_info(waf_info)
                
                if waf_info["detected"]:
                    self.logger.warning(f"WAF detected: {waf_info['type']} (Confidence: {waf_info['confidence']}%)")
                    
                    if self.config.get_value("waf", "bypass"):
                        self.logger.info("Testing WAF bypass techniques...")
                        bypass_results = self.waf_detector.test_waf_bypass()
                        if bypass_results["successful"]:
                            self.logger.success(f"WAF bypass successful using: {bypass_results['technique']}")
                        else:
                            self.logger.warning("No successful WAF bypass found")
                            
            # Run selected techniques
            total_tests = 0
            successful_tests = 0
            failed_tests = 0
            
            for technique in (techniques or self.config.get_value("injection", "techniques")):
                if technique not in self.injectors:
                    self.logger.warning(f"Unknown technique: {technique}")
                    continue
                    
                self.logger.info(f"Running {technique} injection tests...")
                injector = self.injectors[technique]
                
                # Test all parameters
                results = injector.test_all_parameters()
                
                # Update statistics
                total_tests += len(results)
                successful_tests += sum(1 for r in results if r["success"])
                failed_tests += sum(1 for r in results if not r["success"])
                
                # Add vulnerabilities
                for result in results:
                    if result["success"]:
                        self.output.add_vulnerability(
                            technique,
                            {
                                "parameter": result["parameter"],
                                "payload": result["payload"],
                                "details": result["details"]
                            }
                        )
                        
            # Update statistics
            self.output.update_statistics(total_tests, successful_tests, failed_tests)
            
            # End scan
            self.output.end_scan()
            self.logger.info("Scan completed")
            
            # Save results
            self.output.save_results()
            self.logger.info(f"Results saved to {self.config.get_value('output', 'file')}")
            
        except Exception as e:
            self.logger.error(f"Error during scan: {str(e)}")
            sys.exit(1)
            
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
    injector = SQLInjector(args.config)
    
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
    injector.run(args.url, args.techniques)
    
if __name__ == "__main__":
    main() 
