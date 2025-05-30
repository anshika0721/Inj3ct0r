#!/usr/bin/env python3

import json
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime
from colorama import init, Fore, Style
import os

class OutputManager:
    def __init__(self):
        """Initialize output manager."""
        init()  # Initialize colorama
        self.results = {
            "scan_start": None,
            "scan_end": None,
            "target_url": None,
            "waf_info": None,
            "database_info": None,
            "vulnerabilities": [],
            "statistics": {
                "total_tests": 0,
                "successful_tests": 0,
                "failed_tests": 0
            }
        }
        
    def start_scan(self, url: str) -> None:
        """Start scan and initialize results."""
        self.results["scan_start"] = datetime.now().isoformat()
        self.results["target_url"] = url
        print(f"{Fore.CYAN}[*] Starting SQL injection scan on {url}{Style.RESET_ALL}")
        
    def end_scan(self) -> None:
        """End scan and finalize results."""
        self.results["scan_end"] = datetime.now().isoformat()
        print(f"\n{Fore.CYAN}[*] Scan completed{Style.RESET_ALL}")
        self._print_summary()
        
    def set_waf_info(self, waf_info: Dict[str, Any]) -> None:
        """Set WAF detection results."""
        self.results["waf_info"] = waf_info
        if waf_info["detected"]:
            print(f"{Fore.YELLOW}[!] WAF detected: {waf_info['type']}{Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}[+] No WAF detected{Style.RESET_ALL}")
            
    def set_database_info(self, db_info: Dict[str, Any]) -> None:
        """Set database detection results."""
        self.results["database_info"] = db_info
        if db_info["detected"]:
            version_str = f" (version {db_info['version']})" if db_info["version"] else ""
            print(f"{Fore.GREEN}[+] Database detected: {db_info['type']}{version_str}{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[!] Database type unknown{Style.RESET_ALL}")
            
    def add_vulnerability(self, vulnerability: Dict[str, Any]) -> None:
        """Add vulnerability to results."""
        self.results["vulnerabilities"].append(vulnerability)
        self.results["statistics"]["successful_tests"] += 1
        
        # Print vulnerability details
        print(f"\n{Fore.RED}[!] Found SQL injection vulnerability:{Style.RESET_ALL}")
        print(f"    Type: {vulnerability['type']}")
        print(f"    Parameter: {vulnerability['parameter']}")
        print(f"    Payload: {vulnerability['payload']}")
        print(f"    Status: {vulnerability['status']}")
        if "data" in vulnerability:
            print(f"    Data: {vulnerability['data']}")
            
    def update_statistics(self, total: int, successful: int, failed: int) -> None:
        """Update scan statistics."""
        self.results["statistics"]["total_tests"] = total
        self.results["statistics"]["successful_tests"] = successful
        self.results["statistics"]["failed_tests"] = failed
        
    def _print_summary(self) -> None:
        """Print scan summary."""
        stats = self.results["statistics"]
        print(f"\n{Fore.CYAN}=== Scan Summary ==={Style.RESET_ALL}")
        print(f"Total tests: {stats['total_tests']}")
        print(f"Successful tests: {stats['successful_tests']}")
        print(f"Failed tests: {stats['failed_tests']}")
        print(f"Vulnerabilities found: {len(self.results['vulnerabilities'])}")
        
    def save_results(self, output_file: str, format: str = "json") -> None:
        """Save results to file in specified format."""
        try:
            if format.lower() == "json":
                with open(output_file, "w") as f:
                    json.dump(self.results, f, indent=2)
            elif format.lower() == "txt":
                with open(output_file, "w") as f:
                    f.write(f"SQL Injection Scan Results\n")
                    f.write(f"=======================\n\n")
                    f.write(f"Target URL: {self.results['target_url']}\n")
                    f.write(f"Scan Start: {self.results['scan_start']}\n")
                    f.write(f"Scan End: {self.results['scan_end']}\n\n")
                    
                    if self.results["waf_info"]:
                        f.write(f"WAF Detection:\n")
                        f.write(f"  Detected: {self.results['waf_info']['detected']}\n")
                        f.write(f"  Type: {self.results['waf_info']['type']}\n\n")
                        
                    if self.results["database_info"]:
                        f.write(f"Database Detection:\n")
                        f.write(f"  Detected: {self.results['database_info']['detected']}\n")
                        f.write(f"  Type: {self.results['database_info']['type']}\n")
                        if self.results["database_info"]["version"]:
                            f.write(f"  Version: {self.results['database_info']['version']}\n")
                        f.write("\n")
                        
                    f.write(f"Vulnerabilities:\n")
                    for vuln in self.results["vulnerabilities"]:
                        f.write(f"  - Type: {vuln['type']}\n")
                        f.write(f"    Parameter: {vuln['parameter']}\n")
                        f.write(f"    Payload: {vuln['payload']}\n")
                        f.write(f"    Status: {vuln['status']}\n")
                        if "data" in vuln:
                            f.write(f"    Data: {vuln['data']}\n")
                        f.write("\n")
                        
                    f.write(f"Statistics:\n")
                    f.write(f"  Total Tests: {self.results['statistics']['total_tests']}\n")
                    f.write(f"  Successful Tests: {self.results['statistics']['successful_tests']}\n")
                    f.write(f"  Failed Tests: {self.results['statistics']['failed_tests']}\n")
                    
            print(f"{Fore.GREEN}[+] Results saved to {output_file}{Style.RESET_ALL}")
            
        except Exception as e:
            logging.error(f"Failed to save results: {str(e)}")
            raise
            
    def get_results(self) -> Dict[str, Any]:
        """Get current results."""
        return self.results 
